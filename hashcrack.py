import hashlib, threading, sqlite3

class Hashcrack:
    
    def __init__(self, db : str=None) -> None:
        self.db = db

    def worker(self, wordlist : str, algorithm : str, hash : str):

        try:

            with open(wordlist, 'rb') as f:
            
                for i, password in enumerate(f):

                    password = password.rstrip(b'\n')

                    h = hashlib.new(algorithm)
                    h.update(password)

                    password_hash = h.hexdigest()

                    if password_hash == hash:
                        print(f'Found Hash:', password)
                        break

        except Exception as e:
            print(e)
            return None

    def crack(self, wordlist : str, algorithm : str, hash : str, threaded : bool=False):

        valid = False

        if algorithm not in hashlib.algorithms_available:
            raise Exception('Hash algorithm not supported.')

        if threaded:

            thread = threading.Thread(target=self.worker, args=[wordlist, algorithm, hash])
            thread.start()

            return thread
        
        else:

            return self.worker(wordlist, algorithm, hash)
        
hashcrack = Hashcrack()
thread = hashcrack.crack('wordlists/rockyou.txt', 'md5', '202cb962ac59075b964b07152d234b70',  threaded=True)