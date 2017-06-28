from itertools import cycle
from threading import Lock


class CyclicResourceProvider(object):
    """Simple class that provides one or multiple hash keys, cycling through
     them."""

    def __init__(self, *attr):
        self.resources = []
        self.picker = None
        self.access_lock = Lock()
        if attr and len(attr) > 0:
            for resource in attr:
                self.add_resource(resource)

    def is_empty(self):
        return len(self.resources) == 0

    def add_resource(self, resource):
        self.resources.append(resource)

    def set_single_resource(self, resource):
        del self.resources[:]
        self.add_resource(resource)
        del self.picker
        self.picker = cycle(self.resources)

    def next(self):
        self.access_lock.acquire()
        if not self.resources:
            raise Exception("CyclicResourceProvider without any resource!")
        if not self.picker:
            self.picker = cycle(self.resources)
        next_resource = self.picker.next()
        self.access_lock.release()
        return next_resource
