import mmap, hashlib, threading, time, multiprocessing, os, sys
from gloomstrike import logger

def _worker(line):

    print(line)

def _worker(algorithm, path, results, hashes, start, end):

    with open(path, 'r+b') as f:

        wordlist = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        if 'linux' in sys.platform:
            wordlist.madvise(mmap.MADV_DONTNEED)

    index = 0

    while 1:

        wordlist.seek(start)

        if index >= len(hashes):
            break

        hash = hashes[index].decode()

        while word := wordlist.readline():

            word = word.rstrip()

            m = hashlib.new(algorithm)
            m.update(word)
            word_hash = m.hexdigest()

            if word_hash == hash:

                results[hash] = word
                index += 1
                break

            if wordlist.tell() > end:
                break

        index += 1
        
    wordlist.close()

class Hashcrack:

    def __init__(self, db : str=None, logger : logger.Logger=None) -> None:

        self.db = db
        self.logger = logger

        self._processors = os.cpu_count() - 1
        self._processes : list(multiprocessing.Process) = []

        self.manager = multiprocessing.Manager()
        self._results = self.manager.dict()
        self._hashes = None

        self._wordlist_size = 0
        self._wordlist_path = None

    @property
    def status(self):
        return len(self._processes)

    def load_wordlist(self, wordlist : str):

        self._wordlist_path = wordlist

        try:

            with open(wordlist, 'rb') as f:

                f.seek(0, 2)
                self._wordlist_size = f.tell()

                return True
        
        except Exception as e:

            self.logger.error(f'Failed to mmap() file {wordlist}')
            return False

    def load_hashes(self, hash_file : str):

        try:

            hashes = []

            with open(hash_file, 'rb') as f:

                while line := f.readline():
                    hashes.append(line.rstrip())

            #self._hashes = self.manager.list(hashes)
            self._hashes = hashes

            return True

        except Exception as e:
            self.logger.error(f'Failed to load hashes: {e}')

    def _crack(self, algorithm : str):

        log_list = []
        start_time = time.time()

        while 1:

            for hash, word in self._results.items():

                if hash in log_list:
                    continue

                self.logger.info(f'Cracked Hash in {round(time.time() - start_time, 2)} sec {hash} -> {word}')
                log_list.append(hash)

            if len([proc for proc in self._processes if proc.is_alive()]) == 0:
                break

            if len(self._results) == len(self._hashes):
                break

            time.sleep(1 / 1000)

        self.logger.warning(f'Killing processes')

        self._results = dict(self._results)

        for proc in [proc for proc in self._processes]:
            proc.kill()
            self._processes.remove(proc)

        self.manager.shutdown()

        return self._results

    def start(self, algorithm : str, background : bool=False):

        if self._wordlist_size <= 0 and len(self._hashes) > 0:
            return False
        
        if algorithm not in hashlib.algorithms_available:
            
            self.logger.error(f'Hashing algorithm {algorithm} is not available')
            return False

        self.logger.info(f'Logical CPUs: {self._processors + 1}')
        self.logger.info(f'Using {self._processors}')

        increment = int(self._wordlist_size / self._processors)

        start = 0
        end = int(increment)

        for pid in range(self._processors):

            proc = multiprocessing.Process(target=_worker, args=[algorithm, self._wordlist_path, self._results, self._hashes, start, end])
            proc.start()

            start = int(end) - 1024
            end += int(increment)

            self._processes.append(proc)

            self.logger.info(f'Started {proc.name}')

        if background:

            self.background_thread = threading.Thread(target=self._crack, args=[algorithm])
            self.background_thread.setDaemon = True
            self.background_thread.start()

            return True
        
        else:
            return self._crack(algorithm)