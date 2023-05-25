import mmap, hashlib, threading, time, multiprocessing, helpers, os
from logger import Logger

def _worker(fileno, results, hash, start, end):

    with open(fileno, 'r+b') as f:

        wordlist = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        if start > 256:
            wordlist.seek(start - 256)
        else:
            wordlist.seek(start)

        while word := wordlist.readline():

            word = word.rstrip()

            m = hashlib.new('md5')
            m.update(word)
            word_hash = m.hexdigest()

            if word_hash == hash:
                results[hash] = word

            if wordlist.tell() > end:
                break

class Hashcrack:

    def __init__(self, db : str=None, logger : Logger=None) -> None:

        self.db = db
        self.logger = logger
        self.processes = []
        self.hash = None
        self.event = threading.Event()
        self.manager = multiprocessing.Manager()
        self._results = self.manager.dict()

    def load_wordlist(self, wordlist : str):

        try:

            self.f = open(wordlist, 'r+b')
                
            self.wordlist = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)

            return True
        
        except Exception as e:

            self.logger.error(f'Failed to mmap() file {wordlist}')
            return False

    def load_hashes(self, hash_file : str):

        try:

            with open(hash_file, 'r+b') as f:

                self.hashes = mmap.mmap(f.fileno(), 0)

            return True
        
        except Exception as e:

            self.logger.error(f'Failed to mmap() file {hash_file}')
            return False

    def crack(self):

        self.hash = self.hashes.readline().rstrip().decode()
        print(self.hash)

        for cpus in range(1, os.cpu_count()):

            self.wordlist.seek(0, 2)

            #cpus = os.cpu_count()
            file_size = self.wordlist.tell()
            increment = int(file_size / cpus)

            self.wordlist.seek(0)

            start = 0
            end = int(increment)

            start_time = time.time()

            for tid in range(cpus):

                proc = multiprocessing.Process(target=_worker, args=[self.f.fileno(), self._results, self.hash, start, end])
                proc.start()

                start = int(end)
                end += int(increment)

                self.processes.append(proc)

            for proc in self.processes:
                proc.join()
                self.processes.remove(proc)

            print(f'Processes: {cpus}\nFile Processing Time: {round(time.time() - start_time, 2)} seconds\nResults: {self._results}')

        