import requests, threading, time, time, json
from gloomstrike import logger, helpers

class UrlFuzzer:

    '''
    UrlFuzzer finds files or directories on a web server.

    Multithreading is used to send requests to a web server with directories and filenames from a wordlist.

    Attributes:
        _dirs (str): The path to directories wordlist.
        _files (str): The path to the files wordlist.
        _threads (list[multithreading.Thread]): List of all the running threads.
        _targets (helpers.QueueHandler): The list of URLs to fuzz.
        _session (requests.Session): The session object used to make requests.
        _event (threading.Event): Event which is used to stop threads.
        _handlers (dict): Dict that contains the list of directories and files to use.
    '''

    def __init__(self, dirs: str | list, files: str | list) -> None:

        '''
        Args:
           dirs (str): Path to the directory wordlist.
           files (str): Path to the files wordlist.
        '''

        self._handlers = {
            '_dirs': None,
            '_files': None
        }

        if type(dirs) == list:
            self._handlers['_dirs'] = helpers.QueueHandler(dirs)
        else:
            self._dirs = dirs

        if type(files) == list:
            self._handlers['_files'] = helpers.QueueHandler(files)
        else:
            self._files = files

        self._threads = []
        self._results = []
        self._progress = 0

        self._targets = helpers.QueueHandler()
        self._session = requests.Session()
        self._event = threading.Event()

    def _load(self):

        '''
        Loads the directories and files into memory.

        Iterates over the keys of _handlers to dynamically get the path for _dirs and _files.
        
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
                
                    # Create a new QueueHandler for the _dirs and _files
                    self._handlers[attr] = helpers.QueueHandler(tmp, max_size=0)

            except Exception as e:

                logger.log(e, level=logger.Level.ERROR)
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

            resp = self._session.request(method, target, timeout=timeout, allow_redirects=True)

            match resp.status_code:

                case 404:
                    return False
                case 429:
                    logger.log('Too many requests', level=logger.Level.WARNING)
                    return False
            
            if resp.ok:
                return resp

            return False
        
        except requests.exceptions.ConnectionError as e:
            pass
            logger.log(f'Connection error: {e}', level=logger.Level.ERROR)
        except requests.exceptions.RetryError as e:
            pass
        except requests.exceptions.Timeout as e:
            logger.log('Request timeout', level=logger.Level.ERROR)
        except Exception as e:
            logger.log(e, level=logger.Level.ERROR)

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
                logger.log(f'Code: {resp.status_code}\tSize: {size}\t\t{url} -> {location}', level=logger.Level.LOG)
                self._results.append({'url': location, 'code': resp.status_code, 'size': size})
                ret = location
            
            case _:
                logger.log(f'Code: {resp.status_code}\tSize: {size}\t\t{url}', level=logger.Level.LOG)
                self._results.append({'url': url, 'code': resp.status_code, 'size': size})
                ret = resp.url

        return ret

    def _fuzzer(self, max_depth : int):

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

                self._progress += 1

                if resp := self._request(url):

                    self._process_request(resp)

            # Checks every directory
            for dir in self._handlers['_dirs']:

                if self._event.is_set():
                    break

                url = target + dir

                self._progress += 1

                if url[-1] != '/':
                    url += '/'

                if resp := self._request(url):

                    if location := self._process_request(resp):

                        self._targets.add(url)

            # Use a context manager to get a mutex lock and then reset the queues.
            if not self._handlers['_files']._mutex.locked() and not self._handlers['_dirs']._mutex.locked():

                with self._handlers['_files']._mutex:
                    self._handlers['_files'].reset()
                
                with self._handlers['_dirs']._mutex:
                    self._handlers['_dirs'].reset()

            # Wait the threads until the reset is done
            while self._handlers['_files']._mutex.locked() or self._handlers['_dirs']._mutex.locked():
                
                time.sleep(1 / 100)

            depth += 1

        logger.log(f'Exiting thread ({threading.current_thread().native_id})', level=logger.Level.INFO)

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
        if (self._handlers['_dirs'] == None and self._handlers['_files'] == None) and not self._load():
            return False

        for _ in range(threads):

            thread = threading.Thread(target=self._fuzzer, args=[max_depth])
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
