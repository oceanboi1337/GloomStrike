import requests, threading, logger, helpers, time

class UrlFuzzer:

    def __init__(self, target : str, wordlist : str, timeout : int=3, status_codes : list[int]=None, logger : logger.Logger=None) -> None:
        
        self._target = target
        self._wordlist = wordlist
        self._timeout = timeout
        self._logger = logger
        self._status_codes = status_codes

        self._event = threading.Event()
        self._threads : list[threading.Thread] = []
        self._paths = []
        self._results = []

        if self._target[-1] != '/':
            self._target += '/'

    def _worker(self):
            
        for path in self._paths:

            if self._event.is_set():
                break
            
            url = self._target + path

            try:

                resp = requests.get(url, timeout=self._timeout)

                if resp.status_code == 429:
                    self._logger.warning('Too many requests')

                if resp.status_code not in [429, 404]:
                    self._logger.info(f'Found {self._target}{path}')

            except Exception as e:
                self._logger.error(url, e)

    def start(self, threads : int=25, background : bool=False):

        lines = []

        with open(self._wordlist, 'r+b') as f:

            while line := f.readline():

                lines.append(line.rstrip().decode())

        self._paths = helpers.QueueHandler(lines)

        self._logger.info('Starting threads...')

        for tid in range(threads):

            thread = threading.Thread(target=self._worker)
            thread.setDaemon = True
            thread.start()

            self._threads.append(thread)

        if background:
            return True

        while not self._event.is_set():

            try:

                if self._paths.queue.empty():
                    self._event.set()

                time.sleep(1 / 1000)

            except KeyboardInterrupt:
                self._event.set()

        for thread in self._threads:
            thread.join()

        return self._results