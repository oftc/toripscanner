import json
import logging
from typing import Collection

log = logging.getLogger(__name__)


def log_result(fp: str, ts: float, ips: Collection[str]):
    if not len(ips):
        return
    log.info(json.dumps({
        'fp': fp,
        'ts': ts,
        'ips': [_ for _ in ips],
    }))
