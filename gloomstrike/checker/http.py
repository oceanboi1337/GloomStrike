import mmap, requests, threading, time
from gloomstrike import logger, helpers

class Proxy:

    def __init__(self, proxy_type : str, endpoint : str, username : str=None, password : str=None) -> None:

        self._proxy_type = proxy_type
        self._endpoint = endpoint
        self._username = username
        self._password = password

class HttpChecker:

    def __init__(self, url : str, csrf : str=None, parameters: list[list[str, str]]=None, logger : logger.Logger=None) -> None:

        self._url = url
        self._csrf = csrf
        self._parameters = parameters
        self._logger = logger

        self._credentials = helpers.QueueHandler()
        self._event = threading.Event()
        self._threads = []
        self._results = []
        self._mmap = None

    def load(self, wordlist : str, proxies : str):

        try:

            with open(wordlist, 'r+b') as f:

                self._mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

            return True

        except Exception as e:
            self._logger.error(e)

        return False

    def _ingestion(self, threads : int):

        while not self._event.is_set():

            while self._credentials.length < threads * 3 and not self._event.is_set():

                line = self._mmap.readline().rstrip().decode()
            
                username, password = line.split(':')

                self._credentials.add([username, password])

            try:
                time.sleep(1 / 1000)
            except KeyboardInterrupt:
                self._event.set()

        for thread in self._threads:
            thread.join()

        return self._results

    def _check(self, url: str, username: str, password: str, parameters: list[list[str, str]]):

        resp = requests.post(url, data={parameters[0]: username, parameters[1]: password})

        return resp

    def _checker(self):

        while not self._event.is_set():

            for username, password in self._credentials:

                if not (result := self._check(self._url, username, password, self._parameters)):
                    continue

                print(result.text)

            time.sleep(1 / 1000)

    def start(self, threads: int, background: bool=False):

        for _ in range(threads):

            thread = threading.Thread(target=self._checker)
            thread.daemon = True
            thread.start()

            self._threads.append(thread)

        if background:

            self._ingestion_thread = threading.Thread(target=self._ingestion, args=[threads])
            self._ingestion_thread.daemon = True
            self._ingestion_thread.start()
        
        else:
            return self._ingestion(threads)