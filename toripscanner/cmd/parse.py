# stdlib imports
import gzip
import json
import logging
import os
import time
from argparse import ArgumentParser
from collections import defaultdict
from datetime import datetime
from typing import Any, IO, Mapping, List, Set
from .. import PKG_DIR


log = logging.getLogger(__name__)


def header_tmpl(fname: str) -> str:
    with open(fname, 'rt') as fd:
        return fd.read()


def parse_results_from_fd(fd: IO, max_age_days: int):
    start_ts = time.time() - max_age_days * 24 * 60 * 60
    for line in fd:
        try:
            j = json.loads(line.strip())
        except Exception:
            log.warning(f'Cannot parse line into json: {line}')
            continue
        if 'ts' not in j:
            log.warning(f'No "ts" member, ignoring: {j}')
            continue
        elif j['ts'] < start_ts:
            # log.debug(f'Ignoring too old line: {j}')
            continue
        yield j


def file_into_results(
        fname: str, max_age_days: int) -> List[Any]:
    try:
        fd = None
        if fname.endswith('.gz'):
            fd = gzip.open(fname, 'rt')
        else:
            fd = open(fname, 'rt')
        results = []
        log.info(f'Reading results from {fname}')
        for res in parse_results_from_fd(fd, max_age_days):
            results.append(res)
        return results
    except FileNotFoundError:
        log.warn(f'{fname} does not exist')
    except Exception as e:
        log.warn(f'Uncaught exception parsing {fname} into results: {e}')
    finally:
        if fd:
            fd.close()
    return []


def aggregate(results: List[Any]) -> Mapping[str, Set[str]]:
    ''' Flatten the results from::

            {fp1: '', ips: []}
            {fp2: '', ips: []}
            {fp1: '', ips: []}

    into one dict::

        {
            'fp1': [ ips ],
            'fp2': [ ips ],
        }

    The input data may have multiple results for the same fp. That's fine. We
    aggregate the unique IPs for each.
    '''
    out = defaultdict(set)
    for res in results:
        out[res['fp']].update(res['ips'])
    return out


def unique_ips(d: Mapping[str, Set[str]]) -> Set[str]:
    out = set()
    for v in d.values():
        out.update(v)
    return out


def gen_parser(sub) -> ArgumentParser:
    ''' Add the cmd line options for this RelayScan command '''
    d = 'Control a deployment of RelayScan'
    p = sub.add_parser('parse', description=d)
    p.add_argument(
        '--max-age', type=int, default=5,
        help='Results older than this, in days, will not be considered.')
    p.add_argument(
        'results_files', type=str, nargs='+',
        help='One or more files from which to read results, as logged by a '
        'coord by default to data-coord/results/results.log. File names '
        'ending in .gz will be assumed to be gzip-compressed. Files that do '
        'not exist are ignored. Lines that are not understood are ignored.')
    return p


def main(args, conf) -> None:
    # get lists of results, one per file
    results_lists = [
        file_into_results(fname, args.max_age)
        for fname in args.results_files]
    # flatten the lists of results into a single list
    results = [
        item
        for lst in results_lists if lst is not None
        for item in lst
    ]
    results_agg = aggregate(results)
    ips = unique_ips(results_agg)
    num_ipv4 = len([ip for ip in ips if ':' not in ip])
    num_ipv6 = len([ip for ip in ips if ':' in ip])
    assert num_ipv4 + num_ipv6 == len(ips)
    header = header_tmpl(os.path.join(PKG_DIR, 'parse-header.txt')).format(
        date=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        num_ipv4=num_ipv4,
        num_ipv6=num_ipv6,
        num_total=len(ips),
        max_age_days=args.max_age)
    print(header, end='')
    for ip in sorted(ips):
        print(ip)
