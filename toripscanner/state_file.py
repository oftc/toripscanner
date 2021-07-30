''' State file '''
import json
from typing import Dict, Any, Optional
import gzip
import logging
import os


log = logging.getLogger(__name__)
VERSION: int = 1


class StateFile:
    #: The data
    d: Dict[str, Any]
    #: The filename we were loaded from, if any
    fname: Optional[str]

    def __init__(self):
        self.d = {
            'version': VERSION,
        }
        self.fname = None

    @staticmethod
    def from_file(fname: str) -> 'StateFile':
        ''' Load a state object from the given filename. If the file doesn't
        exist, just return a new object. '''
        state = StateFile()
        state.fname = fname
        if not os.path.exists(fname):
            return state
        with gzip.open(fname, 'r') as fd:
            state.d = json.loads(fd.read().decode('utf-8'))
        if state.d['version'] > VERSION:
            log.warning(
                'Loaded state from %s with version %d, but the latest '
                'version we know is %d. Bad things may happen.',
                fname, state.d['version'], VERSION)
        if state.d['version'] < VERSION:
            log.warning(
                'Need to update state format in %s from %d to %d, but nothing '
                'to do that has been written yet.',
                fname, state.d['version'], VERSION)
        state.fname = fname
        return state

    def to_file(self, fname: Optional[str] = None):
        ''' Write ourselves out to the given filename, overwriting anything
        that might already exist there.

        - If no file is given and we don't know what file we were read from, do
          nothing.
        - If no file is given but we do know from where we were read, write out
          to that file.
        - If a file is given, write out to that regardless of where we were
          read (if anywhere).
        '''
        fname = fname or self.fname
        if not fname:
            return
        # log.debug('Writing state to %s', fname)
        with gzip.open(fname, 'w') as fd:
            fd.write(json.dumps(self.d).encode('utf-8'))
        return

    def is_set(self, key: str) -> bool:
        ''' Return whether or not ``key`` is set to something '''
        return key in self.d

    def write(self):
        ''' Force a write of the stored state into the backing file '''
        return self.to_file()

    def set(self, key: str, val: Any, skip_write: bool = False):
        ''' Set ``key`` to ``val``, and write out this change to the state
        file, unless ``skip_write`` is set to ``True``.
        '''
        # log.debug('Setting %s => %s', key, val)
        self.d[key] = val
        if not skip_write:
            self.write()

    def get(self, key: str, default: Any = None) -> Any:
        ''' Get the value stored at ``key``, or the provided ``default`` value
        if there is no such key. By default, ``default`` is ``None``. '''
        if key not in self.d:
            return default
        return self.d[key]

    def list_append(self, key: str, val: Any, skip_write: bool = False):
        ''' Append the given ``val`` to the end of the list stored at ``key``.

        If no such list exists yet, create it and add ``val`` to it.
        '''
        self.set(
            key,
            self.get(key, default=[]) + [val],
            skip_write=skip_write)

    def list_popleft(
            self, key: str,
            default: Any = None, skip_write: bool = False) -> Any:
        ''' Remove and return the first item in the list stored at ``key``.

        If no such list exists or the list is empty, return ``default``.
        '''
        the_list = self.get(key)
        if the_list is None or not len(the_list):
            return default
        item, the_list = the_list[0], the_list[1:]
        self.set(key, the_list, skip_write=skip_write)
        return item
