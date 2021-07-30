''' Code that is not specific to any one test and many tests may find useful.
'''
import logging
import os
import random
from typing import Sequence, Optional, Tuple, Iterable, Set
import stem  # type: ignore
from stem.control import Controller  # type: ignore


log = logging.getLogger(__name__)


def circuit_str(c: Controller, circ_id: str) -> str:
    ''' Given a ``circ_id``, use the :class:`Controller` to determine the nicks
    and fingerprints of the relays in the circuit. If there is an issue, return
    ``'[unknown]'`` '''
    unknown = '[unknown]'
    assert isinstance(circ_id, str)
    int(circ_id)
    try:
        circ = c.get_circuit(circ_id)
    except ValueError as e:
        log.warning('Circuit %s no longer seems to exist so can\'t return '
                    'a valid circuit string for it: %s', circ_id, e)
        return unknown
    # exceptions raised when stopping the scanner
    except Exception as e:
        log.debug(e)
        return unknown
    s = ' -> '.join(['%s (%s)' % (n, fp[0:8]) for fp, n in circ.path])
    return '[' + s + ']'


def gen_circuit(
        circ: Sequence[Optional[str]], c: Controller,
        preferred_relays: Iterable[str]) -> Optional[Sequence[str]]:
    ''' Given a partial circuit, fill in the gaps with uniformly randomly
    selected relays.

    The circuit is a list of strings, where gaps are indicated with None. If
    the last item is None, an exit will be chosen for it. All other positions
    will have non-exits.

    In the case where it is impossible to build a circuit, for example because
    the number of relays in the network is smaller than the number of gaps in
    the input circuit, then we return None.
    '''
    all_relays = [r for r in c.get_network_statuses()]
    non_exit_fps = [
        r.fingerprint for r in all_relays
        if 'Exit' not in r.flags and r.fingerprint not in circ
    ]
    exit_fps = [
        r.fingerprint for r in all_relays
        if 'Exit' in r.flags and r.fingerprint not in circ
    ]
    preferred_relays = list(preferred_relays)
    random.shuffle(non_exit_fps)
    random.shuffle(exit_fps)
    random.shuffle(preferred_relays)
    # Move preferred relays to the back of the lists so they are used first
    for preferred_relay in preferred_relays:
        if preferred_relay in non_exit_fps:
            non_exit_fps.remove(preferred_relay)
            non_exit_fps.append(preferred_relay)
        elif preferred_relay in exit_fps:
            exit_fps.remove(preferred_relay)
            exit_fps.append(preferred_relay)
    # build output circuit
    out = []
    for position, relay_or_none in enumerate(circ):
        is_last = position == len(circ) - 1
        if relay_or_none is None:
            if (not is_last) and len(non_exit_fps):
                out.append(non_exit_fps.pop())
            elif len(exit_fps):
                out.append(exit_fps.pop())
            else:
                return None
        else:
            out.append(relay_or_none)
    assert None not in out
    return out


def build_circuit(
        circ: Sequence[str], c: Controller) -> Tuple[bool, str]:
    ''' Build a circuit, as represented by a list of fingerprints.

    Returns a 2-tuple. On success, the first item is True and the second is the
    (str) circuit ID. On failure, the first item is False and the second is an
    error message.

    To build a circuit with gaps (e.g. [fp1, None, fp2]), use
    :meth:`build_gaps_circuit`.
    '''
    try:
        circ_id = c.new_circuit(circ, await_build=True)
    except Exception as e:
        return False, str(e)
    return True, circ_id


def build_gaps_circuit(
        circ_in: Sequence[Optional[str]], c: Controller,
        preferred_relays: Iterable[str]) -> Tuple[bool, str]:
    ''' Same as :meth:`build_circuit`, but the given circuit can contain gaps
    (``None``s).
    '''
    circ = gen_circuit(circ_in, c, preferred_relays)
    if not circ:
        return False, 'Could not find enough relays for circuit'
    return build_circuit(circ, c)


def get_socks_port(c: Controller) -> Optional[Tuple[str, int]]:
    ''' Get a SocksPort from Tor. If there is none, return None.

    Return value is an (address, port) tuple. Tor may have multiple socks ports
    open for some reason; this function always returns the first. If this
    consistency is actually needed, hopefully first is always the same ...
    '''
    addr_ports = c.get_listeners('SOCKS', default=None)
    if addr_ports is None:
        return None
    return addr_ports[0]


def get_good_relays(c: Controller, fname: str) -> Iterable[str]:
    out: Set[str] = set()
    if not os.path.exists(fname):
        return out
    with open(fname, 'rt') as fd:
        for line in fd:
            line = line.strip()
            if not len(line) or line[0] == '#':
                continue
            if not c.get_network_status(line, default=None):
                continue
            out.add(line)
    log.debug(f'{len(out)} good-relays seem to be running.')
    return out


def attach_stream_to_circuit_listener(c: Controller, circ_id: str):
    ''' Returns a function that should be given to
    :meth:`Controller.add_event_listener`. It looks for newly created streams
    and attaches them to the given circ_id '''

    def closure_stream_event_listener(st):
        if st.status == 'NEW' and st.purpose == 'USER':
            log.debug('Attaching stream %s to circ %s %s', st.id, circ_id,
                      circuit_str(c, circ_id))
            try:
                c.attach_stream(st.id, circ_id)
            except (stem.UnsatisfiableRequest, stem.InvalidRequest) as e:
                log.warning('Couldn\'t attach stream to circ %s: %s',
                            circ_id, e)
            except stem.OperationFailed as e:
                log.exception("Error attaching stream %s to circ %s: %s",
                              st.id, circ_id, e)
        else:
            pass
    return closure_stream_event_listener
