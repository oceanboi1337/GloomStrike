import requests, threading, time, re
from gloomstrike import helpers, logger

class SubFuzzer:

    '''
    USed to bruteforce subdomains on a target.

    Takes a wordlist with subdomains to check.
    '''

    def __init__(self, domain: str, wordlist: str):

        '''
        Strips http(s)://www from the domain if there is any.

        Args:
            domain (str): The domain to scan.
            wordlist (str): The wordlist to use (1 subdomain per line).
        '''

        # Removes http(s)://www. from thte domain.
        self._domain = re.sub(r'(https?://)?(www.)?(!*\/)?', '', domain)

        self._wordlist = wordlist
        self._subdomains = helpers.QueueHandler(max_size=0)
        self._results = []
        self._threads = []
        self._protocol = 'http://'
        self._event = threading.Event()

        if 'https://' in self._domain:
            self._protocol = 'https://'

    def _load(self) -> bool:

        '''
        Loads the wordlist into a list.

        Returns:
            bool: If the file operation failed or not.
        '''

        try:

            with open(self._wordlist, 'r+b') as f:

                while line := f.readline().rstrip():

                    self._subdomains.add(line.decode())

            return True

        except Exception as e:
            logger.log(f'Failed to load file {self._wordlist} {e}', level=logger.Level.ERROR)

        return False

    def _fuzzer(self):

        for sub in self._subdomains:

            if self._event.is_set():
                break

            try:

                logger.log(f'\x1b[0K{sub}', end='\r', level=logger.Level.LOG)

                url = f'{self._protocol}{sub}.{self._domain}'

                resp = requests.get(url, timeout=3)

                if resp.ok:

                    logger.log(f'Found subdomain: {sub}.{self._domain}')
                    self._results.append(url)

            except Exception as e:
                pass
                
    def _background(self) -> list:
        
        while not self._event.is_set():

            try:
                time.sleep(1 / 1000)
            except KeyboardInterrupt:
                self._event.set()

        for thread in self._threads:

            thread.join()
            self._threads.remove(thread)

        return self._results

    def start(self, threads: int, background: bool = False):

        for _ in range(threads):

            thread = threading.Thread(target=self._fuzzer)
            thread.daemon = True
            thread.start()

            self._threads.append(thread)

        if background:
            
            self._background_thread = threading.Thread(target=self._background)
            self._background_thread.daemon = True
            self._background_thread.start()

            return True
        
        else:
            return self._background()
