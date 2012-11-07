from datetime import datetime, timedelta
from functools import wraps

_my_datetime = datetime

def utcnow():
    return _my_datetime.utcnow()

class MockTime(object):
    def __init__(self, start_time=None):
        if start_time:
            self.time = start_time
        else:
            self.time = datetime.utcnow()

    def __enter__(self):
        self._cleanup = []
        class Mock_datetime(datetime):
            @staticmethod
            def utcnow():
                return self.get_time()
            now = utcnow
        global _my_datetime
        self._old_datetime = _my_datetime
        self.mocktime = Mock_datetime
        _my_datetime = Mock_datetime
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        global _my_datetime
        _my_datetime = self._old_datetime
        for f, args, kwargs in self._cleanup:
            f(*args, **kwargs)

    def add_time(self, *args, **kwargs):
        self.time += timedelta(*args, **kwargs)

    def add_delta(self, delta):
        self.time += delta

    def get_time(self):
        return self.time

    def patch_modules(self, modules):
        if any(hasattr(m, 'timezone') for m in modules):
            # Django 1.4
            timeclassname = 'timezone'
        else:
            # Django < 1.4
            timeclassname = 'datetime'
        for m in modules:
            old_datetime = getattr(m, timeclassname)
            setattr(m, timeclassname, self.mocktime)
            self._add_cleanup(setattr, m, timeclassname, old_datetime)

    def _add_cleanup(self, f, *args, **kwargs):
        self._cleanup.append((f, args, kwargs))


class IncrementalMockTime(MockTime):
    def __init__(self, interval=timedelta(minutes=1), start_time=None):
        super(MockTime, self).__init__(start_time)
        self.interval = interval

    def get_time(self):
        self.add_delta(self.interval)
        return self.time


def mock_time(f):
    @wraps(f)
    def test_method(self):
        with MockTime() as t:
            return f(self, t)
    return test_method
