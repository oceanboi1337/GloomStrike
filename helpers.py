from collections.abc import Iterable
from typing import Any
import queue, threading

class QueueHandler:

    def __init__(self, items : Iterable[any]=None, max_size : int=0, infinite : bool=False) -> None:

        self.items = items
        self.infinite = infinite
        self.mutex = threading.Lock()

        if items != None:

            self.queue = queue.Queue(maxsize=max_size)

            for item in self.items:
                self.queue.put(item)

        else:
            self.queue = queue.Queue()

    def reset(self):
        
        if not self.queue.empty():
            return False

        for item in self.items:
            self.queue.put(item)

    def add(self, item : Any):
        self.queue.put(item)

    def get(self, timeout : int=3):

        try:

            if self.mutex.locked():

                return self.queue.get(block=True)
            
            return self.queue.get(block=True, timeout=timeout)
        
        except queue.Empty:

            if self.infinite:

                self.mutex.acquire()

                self.reset()

                self.mutex.release()


            raise StopIteration
    
    def __iter__(self):
        return self
    
    def __next__(self):
        try:
            return self.get()
        except queue.Empty:
            raise StopIteration