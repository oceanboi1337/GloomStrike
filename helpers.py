from collections.abc import Iterable
from typing import Any
import queue, threading

class QueueHandler:

    def __init__(self, items : Iterable[any]=None, max_size : int=0) -> None:

        self.items = items
        self.mutex = threading.Lock()

        if items != None:

            self.queue = queue.Queue(maxsize=max_size)

            for item in self.items:
                self.queue.put(item)

        else:
            self.queue = queue.Queue()

    def reset(self):
        
        for item in self.items:
            self.queue.put(item)

    def add(self, item : Any):
        self.queue.put(item)

    def get(self, timeout : int=3):

        try:
            return self.queue.get(block=True, timeout=timeout)
        except queue.Empty:
            raise StopIteration
    
    def __iter__(self):
        return self
    
    def __next__(self):
        try:
            return self.get()
        except queue.Empty:
            raise StopIteration