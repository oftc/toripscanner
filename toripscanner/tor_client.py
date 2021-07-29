''' Stem helper stuff. '''
from stem.control import Controller  # type: ignore
from stem.connection import IncorrectSocketType  # type: ignore
from stem.process import launch_tor_with_config  # type: ignore
from stem import SocketError, ProtocolError  # type: ignore
import copy
import os
import logging
from typing import Optional, List, Union, Dict


log = logging.getLogger(__name__)


#: A dictionary of torrc options we need before launching tor that do not
#: depend on runtime configuration and apply for all commands.
#: Options only **known** at runtime (e.g. the DataDirectory) are added in
#: launch(...). Options that should not be **set** until runtime (e.g.
#: __LeaveStreamsUnattached) are in TORRC_RUNTIME_OPTIONS.
TORRC_BASE: Dict[str, Union[str, List]] = {
    # We'll learn it from the control port
    'SocksPort': 'auto',
    # Easier than any other type of auth
    'CookieAuthentication': '1',
    # Unecessary, and avoids path bias warnings
    'UseEntryGuards': '0',
    # To make logs more useful
    'SafeLogging': '0',
    'LogTimeGranularity': '1',
    # We may be inactive for long periods of time, so set this to something
    # biiiiig so that tor will keep considering us active and delivering us new
    # consensuses.
    'DormantClientTimeout': '208 weeks',
    'DormantCanceledByStartup': '1',
    # For full exit policies we need full server descriptors
    'UseMicrodescriptors': '0',
}


def _connect(loc: str):
    ''' Connect to a Tor client via its ControlSocket at *loc*

    Returns None if unable to connect for any reason. Tor must not require
    password authentication; i.e. it requires cookie authentication or no
    authentication.
    '''
    try:
        c = Controller.from_socket_file(path=loc)
    except (IncorrectSocketType, SocketError) as e:
        log.error('Error connecting to Tor control socket %s: %s', loc, e)
        return None
    try:
        c.authenticate()
    except (IncorrectSocketType, ProtocolError) as e:
        log.error('Error authenticating to Tor on %s: %s', loc, e)
        return None
    log.info('Connected to Tor at %s', loc)
    return c


def _update_torrc(
        torrc: Dict[str, Union[str, List]],
        key: str, val: str) -> None:
    ''' Update the given torrc to contain the given key/value pair. If the key
    already exists and the associated value is not a list, make it a list and
    append the new value to that list. If the key already exists and the value
    is already a list, append the new value to that list. Otherwise the key is
    not in the torrc, so add it and its associate value. '''
    log.debug('Adding key="%s" val="%s" to the torrc', key, val)
    if key not in torrc:
        torrc.update({key: val})
        return
    # Turn the existing `val` into `[val]` and append the new value to the
    # list. Or if it's already a list, simply append.
    existing = torrc[key]
    if isinstance(existing, str):
        torrc.update({key: [existing, val]})
        return
    assert isinstance(existing, list)
    existing.append(val)
    return


def _parse_torrc_str(
        s: str,
        torrc: Dict[str, Union[str, List]] = None
        ) -> Dict[str, Union[str, List]]:
    ''' Take the given multi-line string `s` thats the contents of a torrc
    file. Optionally take an existing torrc as a starting point, otherwise
    start with an empty dict. Parse each line of `s` into the torrc dict, and
    return the final result. '''
    if torrc is None:
        torrc = {}
    for line in s.split('\n'):
        # Remove leading/trailing whitespace
        line = line.strip()
        # Ignore blank lines and comment lines
        if not len(line) or line[0] == '#':
            continue
        kv = line.split(None, 1)
        # If this is ever not true, look at how sbws handles torrc options
        # without a value. For some reason for sbws I claimed that torrc
        # options can be just a key with no value, but right now I can't
        # picture why that would ever be the case. - Matt
        assert len(kv) > 1
        _update_torrc(torrc, kv[0], kv[1])
    return torrc


def launch(
        tor_bin: str, tor_datadir: str,
        torrc_extra_dict: Dict[str, str],
        torrc_extra_dict_runtime: Dict[str, str],
        torrc_extra: str) -> \
        Optional[Controller]:
    ''' Launch and connect to Tor, returning the
    :class:`stem.control.Controller` on success, or ``None`` on failure.

    :param tor_bin: How to execute tor. I.e. either "tor" or "./path/to/tor"
    :param tor_datadir: DataDirectory to use
    :param torrc_extra_dict: Extra torrc options to add to the torrc. Intended
        to be used internally for command-specific options (e.g. a worker needs
        additional options set that the coordinator doesn't).
    :param torrc_extra_dict_runtime: Extra torrc options to add to the torrc,
        intended to be used internally for command-specific options that must
        be set at runtime.
    :param torrc_extra: Extra arbitrary lines to add to the torrc we use
    '''
    ''' Launch and connect to Tor using the given tor binary (or path to tor
    binary) and using the given Tor DataDirectory. Returns an authenticated
    stem Controller object when successful. If any error occurs, this module
    logs about it and returns ``None``. '''
    opj = os.path.join
    os.makedirs(tor_datadir, mode=0o700, exist_ok=True)
    # Get a copy of the starting torrc without any dynamic options
    torrc = copy.deepcopy(TORRC_BASE)
    # Save a copy of this as it will be used a few times in this function
    sock_path = os.path.abspath(opj(tor_datadir, 'control'))
    # Update the torrc with everything that depends on runtime config
    torrc.update({
        'DataDirectory': tor_datadir,
        'PidFile': opj(tor_datadir, 'tor.pid'),
        'ControlSocket': sock_path,
        'Log': ['NOTICE file ' + opj(tor_datadir, 'notice.log')],
    })
    # Update the torrc with command-specific options
    torrc.update(torrc_extra_dict)
    # And finally, update with any config file lines
    torrc = _parse_torrc_str(torrc_extra, torrc)
    # log.debug(torrc)
    # Blocks while launching Tor
    try:
        launch_tor_with_config(
            torrc, tor_cmd=tor_bin, init_msg_handler=log.debug,
            take_ownership=True)
    except OSError as e:
        log.error('Problem launching Tor: %s', e)
        return None
    c = _connect(sock_path)
    if c is None:
        log.error('Unable to connect to Tor')
        return None
    assert isinstance(c, Controller)
    c.set_options(torrc_extra_dict_runtime)
    log.info(
        'Started and connected to Tor %s via %s',
        c.get_version(),
        sock_path)
    return c
