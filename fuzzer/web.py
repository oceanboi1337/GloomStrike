import requests, threading, logger, helpers, time
from collections import defaultdict

class UrlFuzzer:

    def __init__(self, dirs : str, files : str, exts : str, logger : logger.Logger=None) -> None:
        
        self._dirs = dirs
        self._files = files
        self._exts = exts

        self._logger = logger

        self._handlers = {
            '_dirs': helpers.QueueHandler([]),
            '_files': helpers.QueueHandler([]),
            '_exts': helpers.QueueHandler([])
        }

    def _load(self):

        for attr in ['_dirs', '_files', '_exts']:

            if not hasattr(self, attr):
                return False    

            try:

                with open(getattr(self, attr), 'r') as f:

                    while line := f.readline().rstrip():

                        print(line)
                        self._handlers[attr].add(f.readline())

            except Exception as e:
                print(e)
        
        return True
        
    def _fuzzer(self, target : str):

        for dir in self._handlers['_dirs']:

            url = target + dir

            print(url)

        """for fuzz in queue:

            url = target + fuzz

            if self._event.is_set():
                break

            try:

                resp = requests.get(url, timeout=self._timeout)

                if resp.status_code == 429:
                    self._logger.warning('Too many requests')

                if resp.status_code not in [429, 404]:
                    self._add_result(target, url)

            except Exception as e:
                self._logger.error(url, e)"""

    def start(self, target : str, threads : int=25, background : bool=False):

        if not self._load():
            return False
        
        self._fuzzer(target)