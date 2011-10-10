### trigger infrastructure
# sqlite offers these methods to hook. http://www.sqlite.org/c3ref/c_alter_table.html
class __base__(object):
    def __init__(self):
        self.state = {}

    def keys(self):
        return self.state.keys()

    def __getitem__(self, id):
        return self.state[id]

    # hook primitives
    def add(self, id, function):
        '''add a callback function to id'''
        assert callable(function), 'Function %s is not callable'% repr(function)
        if id not in self.state:
            self.state[id] = set()
        self.state[id].add(function)

    def remove(self, id, function=None):
        '''remove the specified function(s) keyed by id'''
        self.state[id]

        if function is None:
            result = self.state[id]
            del(self.state[id])
            return result

        self.state[id].discard(function)
        if len(self.state[id]) == 0:
            return self.remove(id)
        return function

    def execute(self, id, *args, **kwds):
        '''execute all functions stored in id'''
        result = False
        for fn in self.state[id]:
            if fn(*args, **kwds):
                result = True
            continue
        return result

