import requests, threading, time, bs4
from gloomstrike import logger, helpers

class Proxy:

    def __init__(self, proxy_type: str, endpoint: str, username: str=None, password: str=None) -> None:

        '''
        Create a Proxy object that can be passed to the HttpChecker.

        Allows the HttpChecker to send requets through a proxy.

        Args:
            proxy_type (str): The proxy type, SOCK4, SOCK5, HTTPS.
            endpoint (str): The host:port of the proxy server.
            username (str) Username for the proxy server (Optional).
            password (str) Password for the proxy server (Optional).
        '''

        self._proxy_type = proxy_type
        self._endpoint = endpoint
        self._username = username
        self._password = password

class HttpChecker:

    def __init__(self, url: str, params: str, csrf: str = None, csrf_url: str = None) -> None:

        '''
        Creates a HttpChecker object used to check logins.

        Args:
            url (str): The url for the target's login page.
            params (str): HTTP like parameter string, username=$USERNAME&password=$PASSWORD.
            csrf (str): Takes the "name" attribute value of a HTML <input> element.
            csrf_url (str): The URL where the csrf-token is generated before logging in.
        '''

        self._url = url
        self._params = params
        self._csrf = csrf
        self._csrf_url = csrf_url
        
        self._credentials = helpers.QueueHandler()
        self._event = threading.Event()

        self._threads = []
        self._results = []

        self._combolist = None
        self._usernames = None
        self._passwords = None

    def load(self, combolist_path: str, usernames_path: str, passwords_path: str, proxies_path: str) -> bool:

        '''
        Loads the specified combolist, usernames and passwords files into memory.

        If only a combolist is loaded, it will read username:password from the file into a list.

        If a username and password file is loaded, it will read both files and assign every password to every username.

        Args:
            combolist_path (str): Path to the combolist file with username:password format.
            usernames_path (str): Path to the usernames file, one username per line.
            passwords_path (str): Path to the passwords file, one password per line.
        '''

        usernames = []
        passwords = []

        # while line := f.readline() will read a line until all lines are read.
        # rstrip() is used to remove any trailing newline character.
        # The UnicodeDecodeError exception is used to catch potential decode('utf-8') errors.
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
                            logger.log(f'Failed to decode {line}: {e}', level=logger.Level.ERROR)
                    
                return True
            
            if usernames_path and passwords_path:

                with open(usernames_path, 'r+b') as f:

                    while line := f.readline().rstrip():

                        usernames.append(line)

                with open(passwords_path, 'r+b') as f:
                    
                    while line := f.readline().rstrip():

                        passwords.append(line)

                # Iterate over each username and password to combine them into a combination
                for username in usernames:

                    for password in passwords:

                        try:

                            self._credentials.add([username.decode('utf-8'), password.decode('utf-8')])

                        except UnicodeDecodeError as r:
                            logger.log(f'Failed to decode {line}: {e}', level=logger.Level.ERROR)

                return True

        except Exception as e:
            logger.log(e, level=logger.Level.ERROR)

        return False

    def _background(self) -> list:

        '''
        Function used to wait for threads to finish.
        
        Uses a infinite while loop to wait for the KeyboardInterrupt exception, it will also exit the loop if all the usernames and passwords have been checked.

        Returns:
            list: A list containing the valid [["username", "password"]] combinations.
        '''

        while not self._event.is_set():

            try:

                time.sleep(1 / 1000)

            except KeyboardInterrupt:

                self._event.set()

        for thread in self._threads:
            
            thread.join()
            self._threads.remove(thread)

        return self._results

    def _parse_params(self, params: str) -> dict:

        '''
        Converts a HTTP parameter like string into a dict.

        Will convert username=foo&password=bar into {"username": "foo", "password": "bar"}

        Args:
            params (str): A HTTP parameter like string, username=foo&password=bar.

        Returns:
            dict: {"username": "foo", "password": "bar"}
        '''

        data = {}

        for param in params.split('&'):
            
            if '=' in param:

                k, v = param.split('=', 1)
                data[k] = v
                
        return data

    def _get_csrf(self) -> tuple:

        '''
        Gets the CSRF-Token for a webpage if the csrf variable was passed on class init.

        Sends a GET request to the URL specified by csrf_url passed on class init.

        Checks the HTML response for a <input name="csrf-token"> element where the csrf-token value is based on the self._csrf variable.
        
        Returns:
            tuple: A tuple with the csrf-token and cookies (csrf-token, cookies).
            None: Will be returned if it failed to fetch the csrf-token.
        '''
    
        resp = None

        try:

            resp = requests.get(self._csrf_url)
            
        except requests.ConnectTimeout:
            logger.log(f'Connection to {self._csrf_url} timeout', level=logger.Level.ERROR)
        except requests.ConnectionError:
            logger.log(f'Connection to {self._csrf_url} failed', level=logger.Level.ERROR)
        except Exception as e:
            logger.log(f'Error while requesting {self._csrf_url}', level=logger.Level.ERROR)

        if not resp:
            return None
        
        soup = bs4.BeautifulSoup(resp.text, 'html.parser')
        
        # Finds the first <input name="self._csrf"> HTML element.
        # Returns the value="" attribute.
        if csrf := soup.find('input', {'name': self._csrf}):
            
            return csrf.attrs.get('value'), resp.cookies

        return None

    def _check(self, url: str, username: str, password: str) -> bool:

        '''
        Sends a POST request to the specified URL with a username and password.

        Replaces the $USERNAME, $PASSWORD and $CSRF values in the self._params value declared on class init.

        Args:
            url (str): The URL where the POST request should be sent.
            username (str): The username $USERNAME will be replaced with.
            password (str): The password $PASSWORD will be replaced with.

        Returns:
            bool: A boolean value, True if the login was success and False if it failed.
        '''

        params = self._params.replace('$USERNAME', username)
        params = params.replace('$PASSWORD', password)

        cookiejar = {}

        if self._csrf:

            if (csrf := self._get_csrf()) == None:
                return False
            
            csrf_token, cookies = csrf
            cookiejar = cookies

            params = params.replace('$CSRF', csrf_token)

        data = self._parse_params(params)

        try:
            return requests.post(url,  data=data, cookies=cookiejar).ok
        except Exception as e:
            logger.log(f'Error while sending request: {e}', level=logger.Level.ERROR)

    def load_list(self, usernames: list = None, passwords: list = None, combolist: list = None):

        try:

            if usernames and passwords:

                for username in usernames:

                    for password in passwords:

                        self._credentials.add([username, password])

            if combolist:

                for combo in combolist:

                    if ':' in combo:

                        username, password = combo.split(':')
                        self._credentials.add([username, password])

            return True
    
        except Exception as e:
            logger.log(f'Failed to generate credential list: {e}')
            return False

    def _checker(self):

        '''
        Sends a POST login request for each username:password combination.

        When a valid combination is found, it will be added to self._results in a [[username, password]] format.

        Returns:
            list: The self._results list, contains [[username, password]].
        '''
            
        for username, password in self._credentials:

            if self._event.is_set():
                break

            logger.log(f'{username}:{password}', level=logger.Level.ERROR, end='\r', flush=True)

            if self._check(self._url, username, password):

                self._results.append([username, password])
                logger.log(f'Found valid credentials "{username}:{password}"', level=logger.Level.INFO)

        self._event.set()

        return self._results

    @property
    def progress(self):
        return round((1 - (self._credentials.length / len(self._credentials._items))) * 100, 2)

    def stop(self):

        self._event.set()

    def start(self, threads: int, background: bool=False) -> bool:

        logger.log('Starting threads...', level=logger.Level.INFO)

        for _ in range(threads):

            thread = threading.Thread(target=self._checker)
            thread.daemon = True
            thread.start()

            self._threads.append(thread)

        if background:

            self._background_thread = threading.Thread(target=self._background)
            self._background_thread.daemon = True
            self._background_thread.start()

            return True
        
        else:
            return self._checker()