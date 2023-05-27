from collections.abc import Iterable
import queue, threading

class QueueHandler:

    def __init__(self, items: list = None, max_size: int = 0) -> None:

        self._items = items
        self._length = 0

        self._mutex = threading.Lock()

        if items != None:

            self._length = len(self._items)
            self._queue = queue.Queue(maxsize=len(self._items))

            for item in self._items:
                self._queue.put(item)

        else:
            self._items = []
            self._queue = queue.Queue()

    @property
    def length(self):
        return self._length

    def reset(self):
        
        if not self._queue.empty():
            return False

        for item in self._items:
            self.add(item)

    def add(self, item, timeout: int = None):

        try:

            self._queue.put(item, block=True, timeout=timeout)
            self._items.append(item)
            self._length += 1
            
            return True
        
        except queue.Full as e:
            return False

    def get(self, timeout : int=3):

        item = None

        try:

            if self._mutex.locked():
                item = self._queue.get(block=True)

            item = self._queue.get(block=True, timeout=timeout)
        
        except queue.Empty:
            raise StopIteration
        
        self._length -= 1
        return item
    
    def __iter__(self):
        return self
    
    def __next__(self):
        try:
            return self.get()
        except queue.Empty:
            raise StopIteration