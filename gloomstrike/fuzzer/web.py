import requests, threading, time, time, json
from gloomstrike import logger, helpers

class UrlFuzzer:

    '''
    UrlFuzzer finds files or directories on a web server.

    Multithreading is used to send requests to a web server with directories and filenames from a wordlist.

    Attributes:
        _dirs (str): The path to directories wordlist.
        _files (str): The path to the files wordlist.
        _exts (str): The path to the extensions wordlist.
        _threads (list[multithreading.Thread]): List of all the running threads.
        _targets (helpers.QueueHandler): The list of URLs to fuzz.
        _session (requests.Session): The session object used to make requests.
        _event (threading.Event): Event which is used to stop threads.
        _handlers (dict): Dict that contains the list of directories and files to use.
    '''

    def __init__(self, dirs: str, files: str, exts: str, logger: logger.Logger = None) -> None:

        '''
        Args:
           dirs (str): Path to the directory wordlist.
           files (str): Path to the files wordlist.
           exts (str): Path to the extensions wordlist.
        '''

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

        '''
        Loads the directories, files and extensions into memory.

        Iterates over the keys of _handlers to dynamically get the path for _dirs, _files and _exts.
        
        Returns:
            bool: Returns False if it failed to read the files, True if successful.
        '''

        for attr in self._handlers.keys():

            tmp = []

            # Check if the key exists as a variable on the class.
            if not hasattr(self, attr):
                return False

            try:

                # Gets the filename for the key in _handlers
                filename = getattr(self, attr)

                with open(filename, 'r') as f:

                    while line := f.readline().rstrip():

                        tmp.append(line)
                
                    # Create a new QueueHandler for the _dirs, _files or _exts
                    self._handlers[attr] = helpers.QueueHandler(tmp, max_size=0)

            except Exception as e:

                self._logger.error(e)
                return False
        
        return True
    
    def _request(self, target : str, method : str='GET', timeout : int=3):

        '''
        Sends a HTTP request to the target.

        Checks if the response code is 404 or 429.
        Will not follow redirects.
        Args:
            target (str): The target URL to request.
            method (str): Http method GET and POST etc.
            timeout (int): Timeout in seconds to wait for request.

        Returns:
            bool: False if the request fails.
            requests.Response: Returns the response if the request was a success.
        '''

        try:

            resp = self._session.request(method, target, timeout=timeout, allow_redirects=False)

            match resp.status_code:

                case 404:
                    return False
                case 429:
                    self._logger.warning('Too many requests')
                    return False
            
            if resp.ok:
                return resp

            return False
        
        except requests.exceptions.ConnectionError as e:
            self._logger.error('Connection refused')
        except requests.exceptions.RetryError as e:
            pass
        except requests.exceptions.Timeout as e:
            self._logger.error('Request timeout')
        except Exception as e:
            self._logger.error(e)

    def _process_request(self, resp : requests.Response):

        '''
        Used to determine if the request should be accepted as a result.

        If the response code is a redirect it will add the original URL with the redirected URL to the results.

        Args:
            resp (requests.Response): The response to check.
        
        Returns:
            str: The URL of the request or redirect.
        '''

        url = resp.url

        size = len(resp.text)

        # The redirect URL.
        location = resp.headers.get('Location')

        ret = None

        match resp.status_code:

            # Check if the response was a redirect.
            case 301 | 302:
                self._logger.warning(f'Code: {resp.status_code}\tSize: {size}\t\t{url} -> {location}')
                self._results.append(f'{url} -> {location}')
                ret = location
            
            case _:

                self._logger.info(f'Code: {resp.status_code}\tSize: {size}\t\t{url}')
                self._results.append(url)
                ret = resp.url

        return ret

    def _fuzzer(self, max_depth : int, threads : int):

        '''
        Iterates over the directories and files in the wordlists.

        Will use a user defined max depth value to prevent endless scanning.
        A directory that is found on the web server will be added back to the _targets to be scanned in later iterations.

        Args:
            max_depth (int): How many directories deep to scan.
            threads (int): How many threads are being used.
        '''

        depth = 0

        for target in self._targets:

            if target[-1] != '/':
                target += '/'

            if depth > max_depth or self._event.is_set():
                break

            # Checks every file
            for file in self._handlers['_files']:

                if self._event.is_set():
                    break

                url = target + file

                if resp := self._request(url):
                    self._process_request(resp)

            # Checks every directory
            for dir in self._handlers['_dirs']:

                if self._event.is_set():
                    break

                url = target + dir

                if resp := self._request(url):

                    if location := self._process_request(resp):

                        self._targets.add(location)

            # Waits for other threads to finish before resetting the directories list.
            # If its reset before all threads finish their iteration it will cause a infinite loop.
            time.sleep(3)

            # Reset the lists as the directories and file names are being popped when iterated.
            self._handlers['_files'].reset()
            self._handlers['_dirs'].reset()

            depth += 1

        self._logger.warning(f'Exiting thread ({threading.current_thread().native_id})')

    def _worker(self):

        '''
        Waits for the threads to finish while checking for KeyboardInterrupt.

        Returns:
            Returns the result of the fuzzing.
        '''

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

        '''
        Loads the wordlists and start the fuzzing process.

        Args:
            target (str): The target web server to fuzz.
            max_depth (int): How many directories deep to fuzz.
            threads (int): How many threads to use.
            background (bool): Will background the fuzzing if True.

        Returns:
            list: Returns the list of URLs found if background is False.
            bool: Returns True or False if background is True and the scan started successfully.
        '''

        # Return false if loading the wordlists failed.
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
