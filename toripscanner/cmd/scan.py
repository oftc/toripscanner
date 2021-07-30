from argparse import ArgumentParser
from queue import Queue, Empty
from typing import Tuple, Union, Iterable, Optional, Set, Collection
import logging
import os
import re
import socks  # type: ignore
import socket
import time
import yaml
from .. import tor_client as tor_client_builder
from ..results_logger import log_result
from ..state_file import StateFile
from ..test_utils import get_socks_port, build_gaps_circuit, get_good_relays,\
    circuit_str, attach_stream_to_circuit_listener
from stem.control import Controller  # type: ignore


log = logging.getLogger(__name__)
#: Stores state that may need, or that definitely needs, to persist across
#: invocations.
STATE_FILE: StateFile
#: State key for queued relay fingerprints we want to test
K_RELAY_FP_QUEUE = 'relay_fp_queue'
#: State key for dict storing when we last successfully scanned each relay
K_RELAY_FP_DONE = 'relay_fp_done'
#: The stem Controller for our tor client
TOR_CLIENT: Controller
#: Queue for NEWCONSENSUS events to make it from the stem thread to the main
#: thread.
Q_TOR_EV_NEWCONSENSUS: Queue = Queue()


def gen_parser(sub) -> ArgumentParser:
    ''' Add the cmd line options for this command '''
    d = 'Scan Tor exits periodically'
    p = sub.add_parser('scan', description=d)
    return p


def initialize_directories(conf) -> None:
    ''' Create any directories that need to be created before we run. This
    should be run very early in our init process. '''
    os.makedirs(conf.getpath('scan', 'datadir'), mode=0o700, exist_ok=True)
    os.makedirs(conf.getpath('scan', 'resultsdir'), mode=0o700, exist_ok=True)


def initialize_state(s: StateFile) -> None:
    ''' Idempotently set initial state in the given state file (if the option
    is already set, don't overwrite it). '''
    for key, default in [  # type: ignore
        (K_RELAY_FP_QUEUE, []),
        (K_RELAY_FP_DONE, {}),
    ]:
        if not s.is_set(key):
            s.set(key, default, skip_write=True)
    s.write()


def get_tor_client(conf) -> \
        Tuple[bool, Union[Controller, str]]:
    ''' Create a Tor client, connect to its control socket, authenticate, and
    return the :class:`Controller`. On success, return True and the controller.
    Otherwise return False and a operator-meaningful error message. '''
    # TODO: what happens if tor client disappears? Exception thrown? What??
    # And what should we do about it? Try to relaunch? Just die? Choose
    # **something**.
    c = tor_client_builder.launch(
        conf.getpath('tor', 'tor_bin'),
        conf.getpath('scan', 'tor_datadir'),
        {}, {},
        conf.get('tor', 'torrc_extra_lines')
    )
    if not c:
        return False, 'Unable to launch and connect to tor client'
    c.add_event_listener(
        lambda e: Q_TOR_EV_NEWCONSENSUS.put(e), 'NEWCONSENSUS')
    return True, c


def get_servers_yaml(fname: str) -> Tuple[bool, Union[dict, str]]:
    ''' Load servers.yaml and return it if possible. Caller is responsible for
    paring it down to useful data. '''
    if not os.path.exists(fname):
        return False, f'{fname} does not exist. Copy it from OFTC infra.'
    with open(fname) as fd:
        try:
            d = yaml.safe_load(fd.read())
        except Exception as e:
            return False, f'Unable to load servers.yaml: {e}'
        return True, d


def get_servers(fname: str) -> Tuple[bool, Union[dict, str]]:
    ''' Load servers.yaml and reduce it down to just servers that should be
    connected to. If possible, return a dict like this::

        {
            'server1': ( ipv4 or None, ipv6 or None),
            'server2': ( ipv4 or None, ipv6 or None),
        }
    '''
    success, yaml_or_err = get_servers_yaml(fname)
    if not success:
        return success, yaml_or_err

    def is_good_server(d: dict) -> bool:
        # is a leaf. A server is a leaf by default, and becomes not-leaf by
        # having hub defined and having hub set to True
        if 'hub' not in d or ('hub' in d and not d['hub']):
            # But even if it is a leaf, we still need to make sure it is
            # supposed to listen for users. It does by default if userlisten is
            # not specified.
            if 'userlisten' not in d:
                return True
            return d['userlisten']
        # is a hub, but still might be configured explicity to listen for users
        return 'userlisten' in d and d['userlisten']

    assert isinstance(yaml_or_err, dict)
    yaml = yaml_or_err
    out = {}
    for s in yaml['servers']:
        if not is_good_server(s):
            continue
        out[s['name']] = (
            s['ip'] if 'ip' in s else None,
            s['ip6'] if 'ip6' in s else None,
        )
    return True, out


def schedule_new_relays(
        state: StateFile, tor: Controller,
        dest: Tuple[str, int], interval: int):
    ''' Query the current consensus for relays. Add ones we haven't measured
    recently to the queue to be measured (if they aren't already in it). '''
    log.info('Looking for any new relays that need measured.')
    exits = set()
    for desc in tor.get_server_descriptors():
        if not desc.exit_policy or not desc.exit_policy.can_exit_to(*dest):
            continue
        # log.debug('%s can exit to %s', desc.nickname, dest)
        exits.add(desc.fingerprint)
    not_waiting_exits = exits - set(state.get(K_RELAY_FP_QUEUE))
    log.info(
        '%d/%d relays in consensus are not already waiting',
        len(not_waiting_exits), len(exits))
    oldest_allowed = time.time() - interval
    need_new_exits = set()
    for e in not_waiting_exits:
        if e not in state.get(K_RELAY_FP_DONE):
            need_new_exits.add(e)
            continue
        t = state.get(K_RELAY_FP_DONE)[e]
        if t < oldest_allowed:
            need_new_exits.add(e)
    log.info(
        '%d/%d relays need a new result',
        len(need_new_exits), len(not_waiting_exits))
    for e in need_new_exits:
        state.list_append(K_RELAY_FP_QUEUE, e, skip_write=True)
    if len(need_new_exits):
        state.write()


def host_from_resp(resp: str) -> Optional[str]:
    for line in resp.split('\n'):
        if not line.startswith('ERROR'):
            continue
        match = re.match('ERROR :Closing Link: (.+) ()', line)
        if not match:
            continue
        return match.group(1)
    log.warning('Unable to find IP in the following response:')
    log.warning(resp)
    return None


def ips_from_hostname(hostname: str) -> Collection[str]:
    out = set()
    for ret in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP):
        _, _, _, _, sockaddr = ret
        out.add(sockaddr[0])
    return out


def measure(
        tor: Controller, fp: str, dest: Tuple[str, int],
        good_relays: Iterable[str]) -> Collection[str]:
    socks_addrport = get_socks_port(tor)
    assert socks_addrport
    ips: Set[str] = set()
    descriptor = tor.get_server_descriptor(fp)
    if not descriptor:
        log.warning(f'No descriptor for {fp} so can\'t measure it.')
        return ips
    ips.add(descriptor.address)
    for or_addr, _, _ in descriptor.or_addresses:
        ips.add(or_addr)
    success, circid_or_err = build_gaps_circuit(
        [None, fp], tor, good_relays)
    if not success:
        log.warning(f'Unable to measure {fp} (1): {circid_or_err}')
        return ips
    circid = circid_or_err
    log.debug(f'Will measure {fp} on {circid} {circuit_str(tor, circid)}')
    listener = attach_stream_to_circuit_listener(tor, circid)
    tor.add_event_listener(listener, 'STREAM')
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, *socks_addrport)
    try:
        s.connect(dest)
        s.sendall(b'QUIT\n')
    except Exception as e:
        log.warning(e)
        try:
            s.close()
        except Exception as e2:
            log.warning(e2)
        tor.remove_event_listener(listener)
        try:
            tor.close_circuit(circid)
        except Exception as e2:
            log.warning(e2)
        return ips
    resp = ''
    while True:
        new = s.recv(4096).decode('utf-8')
        if not len(new):
            break
        resp += new
    host = host_from_resp(resp)
    if host:
        ips.update(ips_from_hostname(host))
    s.close()
    tor.remove_event_listener(listener)
    try:
        tor.close_circuit(circid)
    except Exception as e:
        log.warning(e)
    return ips


def main(args, conf) -> None:
    global STATE_FILE
    global TOR_CLIENT
    initialize_directories(conf)
    STATE_FILE = StateFile.from_file(conf.getpath('scan', 'state'))
    initialize_state(STATE_FILE)
    success, servers_or_err = get_servers(conf.getpath('scan', 'servers_yaml'))
    if not success:
        log.error(servers_or_err)
        return
    servers = servers_or_err
    success, tor_client_or_err = get_tor_client(conf)
    if not success:
        log.error(tor_client_or_err)
        return
    assert not isinstance(tor_client_or_err, str)
    TOR_CLIENT = tor_client_or_err
    dest = conf.getaddr('scan', 'destination')
    interval = conf.getint('scan', 'interval')
    heartbeat_interval = conf.getint('scan', 'heartbeat_interval')
    last_action = time.time()
    schedule_new_relays(STATE_FILE, TOR_CLIENT, dest, interval)
    while True:
        if last_action + heartbeat_interval < time.time():
            log.debug(
                'We\'re still alive. There just hasn\'t been anything to do')
            last_action = time.time()
        # Handle a NEWCONSENSUS event, if any
        try:
            # event only contains new/changed entries. So we will just query
            # the consensus ourself if there's an event telling us there's a
            # new one
            _ = Q_TOR_EV_NEWCONSENSUS.get(timeout=1)
        except Empty:
            pass
        else:
            schedule_new_relays(STATE_FILE, TOR_CLIENT, dest, interval)
            last_action = time.time()
        # .... Add any other rare event handling here, probably
        # Finally, measure a single relay
        relay_fp = STATE_FILE.list_popleft(K_RELAY_FP_QUEUE, default=None)
        if relay_fp is None:
            continue
        assert relay_fp is not None
        last_action = time.time()
        log.info(
            f'Measuring {relay_fp}. '
            f'{len(STATE_FILE.get(K_RELAY_FP_QUEUE))} relays remain')
        good_relays = get_good_relays(
            TOR_CLIENT, conf.getpath('scan', 'good_relays'))
        ips = measure(TOR_CLIENT, relay_fp, dest, good_relays)
        if ips:
            log_result(relay_fp, time.time(), ips)
            d = STATE_FILE.get(K_RELAY_FP_DONE)
            d[relay_fp] = time.time()
            STATE_FILE.set(K_RELAY_FP_DONE, d)
