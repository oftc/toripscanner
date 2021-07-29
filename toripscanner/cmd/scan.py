from argparse import ArgumentParser
from typing import Tuple, Union
import logging
import os
from .. import tor_client as tor_client_builder
from ..state_file import StateFile
from stem.control import Controller  # type: ignore
from stem.response.events import NewConsensusEvent  # type: ignore


log = logging.getLogger(__name__)
#: Stores state that may need, or that definitely needs, to persist across
#: invocations.
STATE_FILE: StateFile
#: The stem Controller for our tor client
TOR_CLIENT: Controller
#: State key for queued relay fingerprints we want to test
K_RELAY_FP_QUEUE = 'relay_fp_queue'
#: State key for dict storing when we last successfully scanned each relay
K_RELAY_FP_DONE = 'relay_fp_done'


def gen_parser(sub) -> ArgumentParser:
    ''' Add the cmd line options for this command '''
    d = 'Scan Tor exits periodically'
    p = sub.add_parser('scan', description=d)
    return p


def initialize_directories(conf) -> None:
    ''' Create any directories that need to be created before we run. This
    should be run very early in our init process. '''
    os.makedirs(conf.getpath('scan', 'datadir'), mode=0o700, exist_ok=True)


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


def _notif_tor_event_NEWCONSENSUS(event: NewConsensusEvent) -> None:
    ''' Called from stem in a different thread for NEWCONSENSUS events. '''


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
    c.add_event_listener(_notif_tor_event_NEWCONSENSUS, 'NEWCONSENSUS')
    return True, c


def main(args, conf) -> None:
    global STATE_FILE
    global TOR_CLIENT
    initialize_directories(conf)
    STATE_FILE = StateFile.from_file(conf.getpath('scan', 'state'))
    initialize_state(STATE_FILE)
    success, tor_client_or_err = get_tor_client(conf)
    if not success:
        log.error(tor_client_or_err)
        return
    assert not isinstance(tor_client_or_err, str)
    TOR_CLIENT = tor_client_or_err
    log.debug('Ready!')
