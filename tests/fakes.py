import threading

from rift.models import Observation


class ScriptedRequester:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self._lock = threading.Lock()

    def get(self, url: str, include_body: bool = False) -> Observation:
        with self._lock:
            self.calls.append(url)
        try:
            return self.handler(url, include_body=include_body)
        except TypeError:
            return self.handler(url)
