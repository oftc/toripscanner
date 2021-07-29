import logging
from argparse import ArgumentParser
from typing import Dict, Any
import toripscanner.cmd.scan
import toripscanner.cmd.parse
from . import __version__
from .config import get_config, config_logging


log = logging.getLogger(__name__)


def create_parser():
    p = ArgumentParser()
    p.add_argument('--version', action='version', version=__version__)
    p.add_argument('-c', '--config', help='Path to toripscanner config file')
    # p.add_argument(
    #     '-d', '--datadir', help='If provided, overwrite the coord/worker '
    #     'datadir config file option with this')
    # p.add_argument('--log-level',
    #                choices=['debug', 'info', 'warning', 'error', 'critical'],
    #                help='Override the configured toripscanner log level')
    sub = p.add_subparsers(dest='cmd')
    toripscanner.cmd.scan.gen_parser(sub)
    toripscanner.cmd.parse.gen_parser(sub)
    return p


def overwrite_conf(args, conf) -> None:
    ''' Some arguments will overwrite configuration values. Do that. '''
    pass
    # if args.datadir:
    #     assert args.cmd
    #     old = conf[args.cmd]['datadir']
    #     log.debug(
    #         f'Changing {args.cmd}.datadir from {old} to {args.datadir}')
    #     conf[args.cmd]['datadir'] = args.datadir


# This function needs **some sort** of type annotation so that mypy will check
# the things it does. Adding the return value (e.g. '-> None') is enough
def call_real_main(args, conf) -> None:
    ''' Figure out what command the user gave and call into that
    command's main function where the real work begins to happen. The only
    logic here should be figuring out what command's main to call. '''
    # Most (actually, all as of right now) command's main functions take these
    # arguments
    def_args = [args, conf]
    def_kwargs: Dict[str, Any] = {}
    # How to call in to each command's main
    cmds = {
        'scan': {
            'f': toripscanner.cmd.scan.main,
            'a': def_args, 'kw': def_kwargs,
        },
        'parse': {
            'f': toripscanner.cmd.parse.main,
            'a': def_args, 'kw': def_kwargs,
        },
    }
    # The keys in the `cmds` dict must be the same as each command specified in
    # its gen_parser(...) function, thus it will be in `cmds`. args.cmd will
    # also be non-None because our caller must have checked that already.
    assert args.cmd in cmds
    # Here we go!
    cmd = cmds[args.cmd]
    return cmd['f'](*cmd['a'], *cmd['kw'])  # type: ignore


def main() -> None:
    ''' Entry point when called on the command line as `toripscanner ...`.

    Do boring boilerplate stuff to get started initially. Parse the command
    line arguments and configuration file, then hand off control. This is where
    the bulk of the startup boring crap should happen.  '''
    p = create_parser()
    args = p.parse_args()
    if args.cmd is None:
        p.print_help()
        return
    try:
        conf = get_config(args.config)
    except FileNotFoundError as e:
        log.critical('Unable to open a config file: %s', e)
        return
    assert conf
    config_logging(conf)
    overwrite_conf(args, conf)
    call_real_main(args, conf)
