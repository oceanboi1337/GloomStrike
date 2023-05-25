import mmap, hashlib, threading, time, multiprocessing, helpers, os
from logger import Logger

def _worker(path, results, hashes, start, end):

    with open(path, 'r+b') as f:

        wordlist = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    done = False
    index = 0

    while not done:

        wordlist.seek(start)

        if index >= len(hashes):
            break

        hash = hashes[index].decode()

        while word := wordlist.readline():

            word = word.rstrip()

            m = hashlib.new('md5')
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

    def __init__(self, db : str=None, logger : Logger=None) -> None:

        self.db = db
        self.logger = logger

        self.processors = os.cpu_count() - 1
        self.processes : list(multiprocessing.Process) = []

        self.manager = multiprocessing.Manager()
        self._results = self.manager.dict()
        self._hashes = None

        self._wordlist_size = 0
        self._wordlist_path = None

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

            self._hashes = self.manager.list(hashes)

        except Exception as e:
            self.logger.error(f'Failed to load hashes: {e}')

    def crack(self):

        self.logger.info(f'Logical CPUs: {self.processors + 1}')
        self.logger.info(f'Using {self.processors}')

        if self._wordlist_size <= 0 and len(self._hashes) > 0:
            return False

        increment = int(self._wordlist_size / self.processors)

        start = 0
        end = int(increment)

        start_time = time.time()

        for pid in range(self.processors):

            proc = multiprocessing.Process(target=_worker, args=[self._wordlist_path, self._results, self._hashes, start, end])
            proc.start()

            start = int(end) - 1024
            end += int(increment)

            self.processes.append(proc)

            self.logger.info(f'Started {proc.name}')

        log_list = []

        while 1:

            for hash, word in self._results.items():

                if hash in log_list:
                    continue

                self.logger.info(f'Cracked Hash in {round(time.time() - start_time, 2)} sec {hash} -> {word}')
                log_list.append(hash)

            if len([proc for proc in self.processes if proc.is_alive()]) == 0:
                break

            if len(self._results) == len(self._hashes):
                break

            time.sleep(1 / 1000)

        self.logger.warning(f'Killing processes')

        for proc in self.processes:
            proc.join()
            self.processes.remove(proc)

        return self._results

        