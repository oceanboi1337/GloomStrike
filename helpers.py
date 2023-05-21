from collections.abc import Iterable
import queue

class QueueHandler:

    def __init__(self, items : Iterable[any]) -> None:

        self.items = items
        self.queue = queue.Queue(maxsize=len(items))

        for item in items:
            self.queue.put(item)

    def get(self):
        return self.queue.get()
    
    def __iter__(self):
        return self
    
    def __next__(self):
        try:
            return self.get()
        except queue.Empty:
            return StopIteration