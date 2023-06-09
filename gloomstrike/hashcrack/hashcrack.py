import mmap, hashlib, threading, time, multiprocessing, os, sys
from gloomstrike import logger

def _worker(algorithm: str, path: str, results: dict, hashes: list, start: int, end: int, progress):

    '''
    Iterates over each word in the wordlist and checks if the generated hash matches the input hash.

    Uses mmap to create a memory map of the wordlist.
    Maps the whole file and uses seek(start) function to set the starting point in the file and read until it has passed the "end" argument.
    If multiprocessing is used each process should have their own start - end range to improve performance.

    Args:
        algorithm (str): The hashing algorithm to use.
        path (str): The path to the wordlist.
        results (dict): References the results dict, this is where cracked hashes are added.
        hashes (list): List of the hashes to crack.
        start (int): Index of where to start reading from the file.
        end (int): Where to stop reading the file.
    '''

    # Open the file in binary read mode.
    with open(path, 'r+b') as f:

        # Creates a memory map of the file.
        wordlist = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # madvise(MADV_DONTNEED) is used to free up memory that is not needed anymore.
        if 'linux' in sys.platform:
            wordlist.madvise(mmap.MADV_DONTNEED)



    # Uses list indexing to access the hashes instead of a queue.
    # This is to prevent locking and releasing of a mutex when accessing the list.

    index = 0
    while index < len(hashes):

        wordlist.seek(start)

        hash = hashes[index]

        while word := wordlist.readline():

            # Removes trailing newline characters
            word = word.rstrip()

            m = hashlib.new(algorithm)
            m.update(word)
            word_hash = m.hexdigest()

            #progress.value += len(word)

            if word_hash == hash:

                # Adds the cracked hash to the results.
                results[hash] = word.decode()
                index += 1
                break

            # Stop reading the mapped file when passing the end index.
            if wordlist.tell() > end:
                index += 1
                break

    wordlist.close()

class Hashcrack:

    '''
    The Hashcrack class is used to crack hashes using a wordlist using multiprocessing.

    The amount of processes spawned is based on the amount of logical cpu's available on the system - 1.
    Each process is assigned a start - end range on where to read from the memory mapped wordlist file.

    Attributes:
        _potfile (str): The path to the file to store the cracked hashes (Optional).
        _processors (int): The amount of processes to spawn.
        _processes (list): List containing the running processes.
        _manager (multiprocessing.Manager): A memory manager that allows for shared memory between the child processes and the main process.
        _results (dict): Dictionary created using the multiprocessing manager.
        _hashes (list): List containing the hashes to crack.
        _wordlist_size (int): Size of the wordlist.
        _wordlist_path (str): Path to the wordlist.
    '''

    def __init__(self, potfile: str=None) -> None:

        '''
        Initializes the variables needed to run.

        Args:
            potfile (str): The path to the file to store cracked hashes.
        '''

        self._potfile = potfile

        self._processors = os.cpu_count() - 1
        self._processes : list(multiprocessing.Process) = []

        self._manager = multiprocessing.Manager()
        self._results = self._manager.dict()
        self._progress = self._manager.Value('i', 0)
        self._hashes = []
        self._hashes_length = 0

        self._wordlist_size = 0
        self._wordlist_path = None

    @property
    def status(self):
        '''
        Returns the amount of processes running.
        '''
        return len(self._processes)

    def load_wordlist(self, wordlist : str):

        '''
        Checks if the wordlist is available and gets the size of the file.

        Opens the file and seek() to the end to determine the file size.

        Args:
            wordlist (str): Path to the wordlist.

        Returns:
            bool: Returns False if it failed to read the file and True if successful.
        '''

        self._wordlist_path = wordlist

        try:

            with open(wordlist, 'r+b') as f:

                # Move the file cursor to the end of the file.
                # Uses f.tell() to get the position of the cursor, which is the end of the file.
                f.seek(0, 2)
                self._wordlist_size = f.tell()

                return True
        
        except Exception as e:

            logger.log(f'Failed to read file {wordlist}', level=logger.Level.ERROR)
            return False

    def load_hashes(self, hashes: str | list):

        '''
        Reads the file  with the hashes into a list.

        Args:
            hashes (str | list): A string can be passed to read the hashes from a file. Or a list with the hashes can be passed instead.

        Returns:
            bool: Weather or not the file read was successful.
        '''

        # Checks if the hashes argument is a list or file path.
        # Skip the file reading if its a list.
        if type(hashes) == list:
            self._hashes = hashes
            self._hashes_length = len(hashes)
            return True

        try:

            # Reset the hashes if the object is gonna be reused.
            self._hashes = []

            with open(hashes, 'r+b') as f:

                while line := f.readline():

                    line = line.rstrip().decode()

                    self._hashes.append(line)

            self._hashes_length = len(self._hashes)

            return True

        except Exception as e:
            logger.log(f'Failed to load hashes: {e}', level=logger.Level.ERROR)

    def _watcher(self):

        '''
        Watches the _results dict for any cracked hashes and reports it to STDOUT.
        
        Will stop watching if there are no processes running or if all the hashes has been cracked.

        Returns:
            dict: The dictionary with the cracked hashes (hash: plaintext)
        '''

        log_list = []
        start_time = time.time()

        while 1:

            for hash, word in self._results.items():

                # Continue if the cracked hash has already been printed
                if hash in log_list:
                    continue

                # How long it took to crack the hash
                crack_time = round(time.time() - start_time, 2)

                logger.log(f'Cracked Hash in {crack_time} sec {hash} -> {word}', level=logger.Level.LOG)
                log_list.append(hash)

                if self._potfile and not self.check_potfile(hash):
                    self.add_potfile(hash, word)

            # Checks if there are any running processes left
            # Exits when none are found
            if len([proc for proc in self._processes if proc.is_alive()]) == 0:
                break

            # Exits if all hashes have been cracked
            if len(self._results) == len(self._hashes):
                break

            time.sleep(1 / 1000)

        logger.log(f'Killing processes', level=logger.Level.WARNING)

        # Convert the results to a normal dict
        self._results = dict(self._results)

        # Kill any leftover processes
        for proc in [proc for proc in self._processes]:

            proc.kill()
            self._processes.remove(proc)

        logger.log(f'Cracked {len(self._results)} / {self._hash_count} hashes', level=logger.Level.LOG)

        # Shutdown the multiprocess memory manager
        self._manager.shutdown()

        return self._results

    def check_potfile(self, hash: str):

        try:
            with open(self._potfile, 'r+b') as f:

                while line := f.readline():

                    line = line.rstrip()
                    cracked_hash, word = line.decode().split(':')

                    if cracked_hash == hash:
                        return word

        except Exception as e:
            logger.log(f'Failed to check potfile: {e}', level=logger.Level.ERROR)

    def add_potfile(self, hash: str, word: str):

        try:
            with open(self._potfile, 'a+') as f:

                f.write(f'{hash}:{word}\n')

        except Exception as e:
            logger.log(f'Failed to add to potfile: {e}', level=logger.Level.ERROR)

    @property
    def progress(self):
        
        if self._hash_count == len(self._results):
            return 100
        else:
            return round((self._progress.value / self._wordlist_size) * 100, 2)

    def start(self, algorithm : str, background : bool=False):

        '''
        Starts the cracking process.

        Divides the workload over multiple processes and starts the result watcher.

        Args:
            algorithm (str): The hashing algorithm to use.
            background (bool): Will run the cracking process in the background if True.

        Returns:
            dict: The cracked hashes.
            bool: True if the process was started in the background, False if it failed to do so.
        '''

        self._hash_count = len(self._hashes)

        # Check if the hash has been cracked before.
        if self._potfile:

            for hash in list(self._hashes):

                if (word := self.check_potfile(hash)) == None:
                    continue

                logger.log(f'Found hash in potfile: {hash} -> {word}', level=logger.Level.LOG)

                self._hashes.remove(hash)
                self._results[hash] = word

        if len(self._hashes) == 0:

            logger.log(f'Cracked {len(self._results)} / {self._hash_count} hashes', level=logger.Level.LOG)
            return self._results

        # Return false if the wordlist or hashes have not been loaded.
        if self._wordlist_size <= 0 and len(self._hashes) > 0:
            return False
        
        # Check if the algorithm is available in hashlib.
        if algorithm not in hashlib.algorithms_available:
            
            logger.log(f'Hashing algorithm {algorithm} is not available', level=logger.Level.ERROR)
            return False

        logger.log(f'Logical CPUs: {self._processors + 1}', level=logger.Level.INFO)
        logger.log(f'Using {self._processors}', level=logger.Level.INFO)

        # How many bytes from the wordlist each process should read.
        increment = int(self._wordlist_size / self._processors)

        start = 0
        end = int(increment)

        for pid in range(self._processors):

            proc = multiprocessing.Process(target=_worker, args=[algorithm, self._wordlist_path, self._results, self._hashes, start, end, self._progress])
            proc.start()

            # The next process should start where the previous ends.
            # Each process start 1024 bytes before the actual start.
            # This is to make sure every line is being read.
            start = int(end) - 1024
            end += int(increment)

            self._processes.append(proc)

            logger.log(f'Started {proc.name}', level=logger.Level.INFO)

        if background:

            self.background_thread = threading.Thread(target=self._watcher)
            self.background_thread.daemon = True # Set daemon so the process will exit when main thread does.
            self.background_thread.start()

            return True
        
        else:
            return self._watcher()
