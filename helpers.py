from collections.abc import Iterable
from typing import Any
import queue

class QueueHandler:

    def __init__(self, items : Iterable[any]) -> None:

        self.items = items
        self.queue = queue.Queue(maxsize=len(items))

        for item in items:
            self.queue.put(item)

    def reset(self):

        for item in self.items:
            self.queue.put(item)

    def add(self, item : Any):
        self.queue.put(item)
        self.queue.maxsize += 1

    def get(self):
        try:
            return self.queue.get(block=False)
        except queue.Empty:
            raise StopIteration
    
    def __iter__(self):
        return self
    
    def __next__(self):
        try:
            return self.get()
        except queue.Empty:
            raise StopIteration