"""Synchronization policies for a trusted, immutable scope directory."""

from contextlib import contextmanager
from threading import Condition, Lock


class WriterPreferringRWLock:
    """Share reads until a writer queues; release a lease from any thread."""

    def __init__(self):
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    def acquire_read(self):
        with self._condition:
            self._condition.wait_for(lambda: not self._writer and self._waiting_writers == 0)
            self._readers += 1

    def release_read(self):
        with self._condition:
            if not self._readers:
                raise RuntimeError('Read lease released without acquisition')
            self._readers -= 1
            if not self._readers:
                self._condition.notify_all()

    def acquire_write(self):
        with self._condition:
            self._waiting_writers += 1
            try:
                self._condition.wait_for(lambda: not self._writer and self._readers == 0)
                self._writer = True
            finally:
                self._waiting_writers -= 1
                if not self._writer:
                    self._condition.notify_all()

    def release_write(self):
        with self._condition:
            if not self._writer:
                raise RuntimeError('Write lease released without acquisition')
            self._writer = False
            self._condition.notify_all()

    @contextmanager
    def read(self):
        self.acquire_read()
        try:
            yield
        finally:
            self.release_read()

    @contextmanager
    def write(self):
        self.acquire_write()
        try:
            yield
        finally:
            self.release_write()


class ScopeRWLocks:
    def __init__(self, scopes):
        self._locks = {scope: WriterPreferringRWLock() for scope in scopes}

    def read(self, scope):
        return self._locks[scope].read()

    def write(self, scope):
        return self._locks[scope].write()

    def acquire_read(self, scope):
        self._locks[scope].acquire_read()

    def release_read(self, scope):
        self._locks[scope].release_read()


class GlobalLock:
    def __init__(self, scopes):
        self._scopes = frozenset(scopes)
        self._lock = Lock()

    def read(self, scope):
        if scope not in self._scopes:
            raise KeyError(scope)
        return self._lock

    def write(self, scope):
        return self.read(scope)

    def acquire_read(self, scope):
        self.read(scope).acquire()

    def release_read(self, scope):
        self.read(scope).release()
