import requests
from gloomstrike import QueueHandler

class SubFuzzer:

    '''
    USed to bruteforce subdomains on a target.

    Takes a wordlist with subdomains to check.
    '''

    def __init__(self, domain: str, wordlist: str):

        '''
        Args:
            domain (str): The domain to bruteforce.
            wordlist (str): The wordlist to use (1 subdomain per line).
        '''

        self._domain = domain
        self._wordlist = wordlist
        self._subdomains = helpers.QueueHandler(max_size=0)

    def _load(self) -> bool:

        '''
        Loads the wordlist into a list.

        Returns:
            bool: If the file operation failed or not.
        '''

        try:

            with open(self._wordlist, 'r+b') as f:

                while line := f.readline().rstrip():

                    self._subdomains.append(line)

            return True

        except Exception as e:
            #logger.error(f'Failed to load file {self._wordlist} {e}')
            pass

        return False

    def start():
