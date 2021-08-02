from argparse import ArgumentParser
from copy import copy
from functools import lru_cache
from queue import Queue, Empty
from typing import Tuple, Union, Iterable, Optional, Set, Collection, Dict,\
    List
import itertools
import logging
import os
import random
import re
import socks  # type: ignore
import socket
import ssl
import time
import yaml
from .. import __version__
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
#: Defined in main, a function that takes a socket and wraps it in SSL. We do
#: it this way instead of something more obvious so that we don't have to pass
#: all the way down the measurement function call stack the SSL parameters that
#: don't ever change.
WRAP_SSL_FN = None


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


@lru_cache()
def can_exit_to(
        desc, addr: Optional[str], port: int, v6: bool) -> bool:
    ''' Small cacheable wrapper to stem.

    We expect big gains in find_reachable_servers() by checking *:port against
    exit policies first. If the exit doesn't allow exiting to ANY host on that
    port, then we only need to go to stem once for that exit and port. If it
    does allow exiting to >0 host on that port, we'll actually check if any of
    our hosts are lucky.

    The cache should be cleared periodically because exit policies can change.

    We always call can_exit_to() with strict=False. We expect either to have a
    wildcard host, in which case we don't watch strict, OR we have both a host
    and port, in which case strict is meaningless.
    '''
    if not v6:
        return desc.exit_policy.can_exit_to(addr, port, strict=False)
    return desc.exit_policy_v6.can_exit_to(addr, port, strict=False)


def find_reachable_servers(
        desc, servers: dict, webclient: Tuple[str, int],
        ports: Collection[int]) \
        -> Iterable[Tuple[str, int]]:
    ''' Given a server descriptor and other stuff,
    determine if this relay can exit to any server.

    Yields (ip, port) as we find them. The IPs can be v4 or v6. Expect between
    0 and 4 tuples to be returned. (but you should handle any number! :p)

    - 0: this relay can't reach anything
    - ... various possibilities ...
    - 4: the relay can reach an ircd on ipv4, on ipv6, and can reach the web
    client on both ipv4 and ipv6.
    '''
    servers_ipv4 = [s[0] for s in servers.values() if s[0] is not None]
    servers_ipv6 = [s[1] for s in servers.values() if s[1] is not None]
    random.shuffle(servers_ipv4)
    random.shuffle(servers_ipv6)
    web_ips = ips_from_hostname(webclient[0])
    web_port = webclient[1]
    web_ipv4 = [ip for ip in web_ips if ':' not in ip]
    web_ipv6 = [ip for ip in web_ips if ':' in ip]
    random.shuffle(web_ipv4)
    random.shuffle(web_ipv6)
    # has an ipv4 exit policy
    if desc.exit_policy:
        # find an ircd it can exit to
        for ipv4, port in itertools.product(servers_ipv4, ports):
            # If the exit can't exit to >0 hosts on this port, stop early. This
            # is cached by our can_exit_to() function, meaning we can avoid
            # going to stem and repeatedly parsing exit policies for no good
            # reason.
            if not can_exit_to(desc, None, port, v6=False):
                continue
            # The desc CAN exit to the port to >0 host on the internet. Let's
            # see if this host one of the lucky ones.
            if can_exit_to(desc, ipv4, port, v6=False):
                yield ipv4, port
                break
        # see if it can exit to the web irc client
        if len(web_ipv4) and \
                can_exit_to(desc, web_ipv4[0], web_port, v6=False):
            yield web_ipv4[0], web_port
    # has an ipv6 exit policy
    if desc.exit_policy_v6:
        # find an ircd it can exit to
        for ipv6, port in itertools.product(servers_ipv6, ports):
            # See comment in ipv6 block: this is cacheable to speed up this
            # function.
            if not can_exit_to(desc, None, port, v6=True):
                continue
            # See comment in ipv4 block.
            if can_exit_to(desc, ipv6, port, v6=True):
                yield ipv6, port
                break
        # see if it can exit to the web irc client
        if len(web_ipv6) and \
                can_exit_to(desc, web_ipv6[0], web_port, v6=True):
            yield web_ipv6[0], web_port


def schedule_new_relays(
        state: StateFile, tor: Controller,
        servers: dict, webclient: Tuple[str, int], irc_ports: Collection[int]):
    ''' Query the current consensus for relays. Add ones we haven't measured
    recently to the queue to be measured (if they aren't already in it). '''
    log.info('Looking for any new relays that need measured.')
    exits: Dict[str, List[Tuple[str, int]]] = {}
    for desc in tor.get_server_descriptors():
        dests = [_ for _ in find_reachable_servers(
            desc, servers, webclient, irc_ports)]
        if not len(dests):
            continue
        exits[desc.fingerprint] = dests
    # log.debug(can_exit_to.cache_info())
    can_exit_to.cache_clear()
    not_waiting_exits = exits.keys() - {
        item[0] for item in state.get(K_RELAY_FP_QUEUE)}
    log.info(
        '%d/%d relays in consensus are not already waiting',
        len(not_waiting_exits), len(exits))
    need_new_exits = set()
    for e in not_waiting_exits:
        if e not in state.get(K_RELAY_FP_DONE):
            need_new_exits.add(e)
            continue
        if state.get(K_RELAY_FP_DONE)[e]['expire_ts'] < time.time():
            need_new_exits.add(e)
    log.info(
        '%d/%d relays need a new result',
        len(need_new_exits), len(not_waiting_exits))
    for e in need_new_exits:
        state.list_append(K_RELAY_FP_QUEUE, (e, exits[e]), skip_write=True)
        # state.list_append(K_RELAY_FP_QUEUE, e, skip_write=True)
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


# maxsize of 1 because when we lookup the web irc client hostname, we do so
# over and over again. We don't really want to do additional caching ourselves,
# except in this instance. This should be fine. Don't increase it lightly.
@lru_cache(maxsize=1)
def ips_from_hostname(hostname: str) -> Set[str]:
    out = set()
    try:
        for ret in socket.getaddrinfo(
                hostname, None, proto=socket.IPPROTO_TCP):
            _, _, _, _, sockaddr = ret
            out.add(sockaddr[0])
    except Exception:
        return out
    return out


def hostnames_from_ip(ip: str) -> Set[str]:
    try:
        ret = socket.gethostbyaddr(ip)
    except Exception:
        return set()
    return {ret[0]} | set(ret[1])


def do_one_dest(
        dest: Tuple[str, int], socks_addrport: Tuple[str, int], use_ssl: bool,
        irc_names: Tuple[str, str]) -> Tuple[bool, Union[Set[str], str]]:
    ips: Set[str] = set()
    msg = f'USER {irc_names[0]} * * :{irc_names[1]}\nQUIT\n'
    resp = ''
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, *socks_addrport)
    s.settimeout(15)
    try:
        s.connect(dest)
        if use_ssl:
            assert WRAP_SSL_FN
            s = WRAP_SSL_FN(s)
        s.sendall(msg.encode('utf-8'))
        while True:
            new = s.recv(4096).decode('utf-8')
            if not new:
                break
            resp += new
    except Exception as e:
        return False, f'{type(e).__name__} {e}'
    host = host_from_resp(resp)
    if host:
        ips.update(ips_from_hostname(host))
    return True, ips


def measure(
        tor: Controller, fp: str, dests: Collection[Tuple[str, int]],
        do_dns_discovery: bool, good_relays: Iterable[str],
        irc_ssl_ports: Collection[int],
        irc_names: Tuple[str, str]) -> Collection[str]:
    socks_addrport = get_socks_port(tor)
    assert socks_addrport
    ips: Set[str] = set()
    try:
        descriptor = tor.get_server_descriptor(fp)
    except Exception as e:
        log.warning(f'No descriptor for {fp} so can\'t measure it. {e}')
        return ips
    if not descriptor:
        log.warning(f'No descriptor for {fp} so can\'t measure it.')
        return ips
    ips.add(descriptor.address)
    for or_addr, _, _ in descriptor.or_addresses:
        ips.add(or_addr)
    # Only build a circuit if we have ircd destinations to connect to.
    if len(dests):
        success, circid_or_err = build_gaps_circuit(
            [None, fp], tor, good_relays)
        if not success:
            log.warning(f'Unable to measure {fp} (1): {circid_or_err}')
            return ips
        circid = circid_or_err
        log.debug(f'Will measure {fp} on {circid} {circuit_str(tor, circid)}')
        listener = attach_stream_to_circuit_listener(tor, circid)
        tor.add_event_listener(listener, 'STREAM')
        for dest in dests:
            log.debug(f'{fp} to {dest}')
            use_ssl = dest[1] in irc_ssl_ports
            success, ips_or_err = do_one_dest(
                dest, socks_addrport, use_ssl, irc_names)
            if not success:
                log.warning(ips_or_err)
                continue
            assert not isinstance(ips_or_err, str)
            ips.update(ips_or_err)
        tor.remove_event_listener(listener)
        try:
            tor.close_circuit(circid)
        except Exception as e:
            log.warning(e)
    if do_dns_discovery:
        # for every IP we found, do the DNS discovery trick to see if we can
        # find any more. The copy() is so we iterate over a copy of ips and can
        # update it directly.
        ips.update({
            new_ip
            for ip in copy(ips)
            for host in hostnames_from_ip(ip)
            for new_ip in ips_from_hostname(host)
        })
    return ips


def wrap_ssl_fn(host):
    context = ssl.create_default_context()

    def closure(sin):
        return context.wrap_socket(sin, server_hostname=host)
    return closure


def main(args, conf) -> None:
    global STATE_FILE
    global TOR_CLIENT
    global WRAP_SSL_FN
    WRAP_SSL_FN = wrap_ssl_fn(conf['scan']['ssl_hostname'])
    initialize_directories(conf)
    STATE_FILE = StateFile.from_file(conf.getpath('scan', 'state'))
    initialize_state(STATE_FILE)
    success, servers_or_err = get_servers(conf.getpath('scan', 'servers_yaml'))
    if not success:
        log.error(servers_or_err)
        return
    assert not isinstance(servers_or_err, str)
    servers = servers_or_err
    success, tor_client_or_err = get_tor_client(conf)
    if not success:
        log.error(tor_client_or_err)
        return
    assert not isinstance(tor_client_or_err, str)
    TOR_CLIENT = tor_client_or_err
    interval_range = (
        conf.getint('scan', 'interval_min'),
        conf.getint('scan', 'interval_max'))
    heartbeat_interval = conf.getint('scan', 'heartbeat_interval')
    webclient = conf.getaddr('scan', 'webclient_addr')
    irc_ssl_ports = set([int(_) for _ in conf['scan']['ssl_ports'].split(',')])
    irc_ports = set([int(_) for _ in conf['scan']['plain_ports'].split(',')]) \
        | irc_ssl_ports
    irc_names = (
        conf['scan']['irc_username'],
        f"{conf['scan']['irc_realname']} v{__version__}",
    )
    last_action = time.time()
    schedule_new_relays(STATE_FILE, TOR_CLIENT, servers, webclient, irc_ports)
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
            # read servers.yaml again, just in case it changed while we were
            # running
            success, servers_or_err = get_servers(
                conf.getpath('scan', 'servers_yaml'))
            if not success:
                log.error(servers_or_err)
            else:
                assert not isinstance(servers_or_err, str)
                servers = servers_or_err
            # do the scheduling
            schedule_new_relays(
                STATE_FILE, TOR_CLIENT, servers, webclient, irc_ports)
            last_action = time.time()
        # .... Add any other rare event handling here, probably
        # Finally, measure a single relay
        relay_fp, dests = STATE_FILE.list_popleft(
            K_RELAY_FP_QUEUE, default=(None, None))
        if relay_fp is None:
            continue
        assert relay_fp is not None
        last_action = time.time()
        log.info(
            f'Measuring {relay_fp}. '
            f'{len(STATE_FILE.get(K_RELAY_FP_QUEUE))} relays remain')
        good_relays = get_good_relays(
            TOR_CLIENT, conf.getpath('scan', 'good_relays'))
        # only measure to the ircd dests
        ircd_dests = [d for d in dests if d[1] != webclient[1]]
        ips = measure(
            TOR_CLIENT, relay_fp, ircd_dests, True, good_relays,
            irc_ssl_ports, irc_names)
        if ips:
            log.info(f'{relay_fp} is {ips}')
            log_result(relay_fp, time.time(), ips)
            d = STATE_FILE.get(K_RELAY_FP_DONE)
            d[relay_fp] = {
                'ts': time.time(),
                'expire_ts': time.time() + random.uniform(*interval_range),
            }
            STATE_FILE.set(K_RELAY_FP_DONE, d)
        else:
            log.warning(f'{relay_fp} has no IPs?')
