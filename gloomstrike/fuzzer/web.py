import requests, threading, time, time, json
from gloomstrike import logger, helpers

class UrlFuzzer:

    def __init__(self, dirs : str, files : str, exts : str, logger : logger.Logger=None) -> None:
        
        self._dirs = dirs
        self._files = files
        self._exts = exts
        self._logger = logger

        self._threads = []
        self._results = []

        self._targets = helpers.QueueHandler()
        self._session = requests.Session()
        self._event = threading.Event()

        self._handlers = {
            '_dirs': None,
            '_files': None
            #'_exts': helpers.QueueHandler([])
        }

    def _load(self):

        for attr in ['_dirs', '_files']:

            tmp = []

            if not hasattr(self, attr):
                return False

            try:

                with open(getattr(self, attr), 'r') as f:

                    while line := f.readline().rstrip():

                        tmp.append(line)
                
                    self._handlers[attr] = helpers.QueueHandler(tmp, max_size=0)

            except Exception as e:

                self._logger.error(e)
                return False
        
        return True
    
    def _request(self, target : str, method : str='GET', timeout : int=3):

        try:

            resp = self._session.request(method, target, timeout=timeout, allow_redirects=False)

            match resp.status_code:

                case 404:
                    return False
                case 429:
                    self._logger.warning('Too many requests')
                    return False
                
            return resp
        
        except requests.exceptions.ConnectionError as e:
            self._logger.error('Connection refused')
        except requests.exceptions.RetryError as e:
            pass
        except requests.exceptions.Timeout as e:
            self._logger.error('Request timeout')
        except Exception as e:
            self._logger.error(e)

    def _process_request(self, resp : requests.Response):

        url = resp.url

        size = len(resp.text)
        location = resp.headers.get('Location')

        ret = None

        match resp.status_code:

            case 301 | 302:
                self._logger.warning(f'Code: {resp.status_code}\tSize: {size}\t\t{url} -> {location}')
                self._results.append(location)
                ret = location
            case _:

                self._logger.info(f'Code: {resp.status_code}\tSize: {size}\t\t{url}')
                self._results.append(url)
                ret = resp.url

        return ret

    def _fuzzer(self, max_depth : int, threads : int):

        depth = 0

        for target in self._targets:

            if target[-1] != '/':
                target += '/'

            if depth > max_depth or self._event.is_set():
                break

            for file in self._handlers['_files']:

                if self._event.is_set():
                    break

                url = target + file

                #print(url)

                if resp := self._request(url):

                    self._process_request(resp)

            #self._handlers['_files'].reset()

            for dir in self._handlers['_dirs']:

                if self._event.is_set():
                    break

                url = target + dir

                #print(url)

                if resp := self._request(url):

                    if location := self._process_request(resp):

                        self._targets.add(location)

            time.sleep(3) # Bad temporary fix

            self._handlers['_files'].reset()
            self._handlers['_dirs'].reset()

            depth += 1

        self._logger.warning(f'Exiting thread ({threading.current_thread().native_id})')

    def _worker(self):

        while not self._event.is_set():

            try:

                for thread in self._threads:

                    if not thread.is_alive():

                        thread.join()
                        self._threads.remove(thread)

                    if len(self._threads) == 0:
                        self._event.set()

                time.sleep(1 / 1000)

            except KeyboardInterrupt:

                self._event.set()
                break

        return self._results

    def start(self, target : str, max_depth : int=2, threads : int=25, background : bool=False):

        if not self._load():
            return False

        for _ in range(threads):

            thread = threading.Thread(target=self._fuzzer, args=[max_depth, threads])
            thread.daemon = True

            self._threads.append(thread)
            self._targets.add(target)

            thread.start()

        if background:

            self.background_thread = threading.Thread(target=self._worker)
            self.background_thread.daemon = True
            self.background_thread.start()

            return True

        else:

            return self._worker()