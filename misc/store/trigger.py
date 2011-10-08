import logging
### trigger infrastructure
class event(object): pass
class INSERT(event): pass
class UPDATE(event): pass
class DELETE(event): pass

class __base__(object):
    def __init__(self):
        self.state = {}

    def keys(self):
        return self.state.keys()

    def __getitem__(self, id):
        return self.state[id]

    # hook primitives
    def register(self, id, function):
        '''add a callback function to id'''
        assert callable(function), 'Function %s is not callable'% repr(function)
        if id not in self.state:
            self.state[id] = set()
        self.state[id].add(function)

    def unregister(self, id, function=None):
        '''remove the specified function(s) keyed by id'''
        self.state[id]

        if function is None:
            result = self.state[id]
            del(self.state[id])
            return result

        self.state[id].discard(function)
        if len(self.state[id]) == 0:
            return self.unregister(id)
        return function

    def execute(self, id, *args, **kwds):
        '''execute all functions stored in id. if a true value is returned, then a stop is requested'''
        result = False
        if id not in self.state:
            logging.warning('callback for %s not found'% repr(id))
            return result

        for fn in self.state[id]:
            if fn(id, *args, **kwds):
                result = True
            continue
        return result

