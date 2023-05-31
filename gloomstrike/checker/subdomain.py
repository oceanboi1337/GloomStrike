import requests

class SubFuzzer:

    def __init__(self, domain: str, wordlist: str):
        
        self._domain = domain
        self._wordlist = wordlist
        self._session = requests.Session()

    def _request(self, 
