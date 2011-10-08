import logging
try:
    import fu as pickle
except ImportError:
    logging.info("unable to load fu serialization module")
    try:
        import cPickle as pickle
    except ImportError:
        logging.info("unable to load cPickle serialization module")
        import pickle

import string
printable = set(x for x in string.printable)
def dumps(object):
    if type(object) in (int,long):
        return object
    if type(object) in (str,unicode) and reduce(lambda x,y:x+(1,0)[y in printable],object,0) == 0:
        return object
    return buffer(pickle.dumps(object))

def loads(string):
    if type(string) in (int,long):
        return string
    if type(string) in (str,unicode):
        return string.encode('ascii')
    return pickle.loads(str(string))

class Deploy(object):
    def create(self):
        raise NotImplementedError
    def session(self, id):
        raise NotImplementedError
    def drop(self, id):
        raise NotImplementedError

class Session(object):
    def commit(self):
        raise NotImplementedError
    def rollback(self):
        raise NotImplementedError

class Store(set):
    id = property(fget=lambda x:x.__session.id)
    session = property(fget=lambda x:x.__session)

class Context(dict):
    id = property(fget=lambda x:x.__id)
    store = property(fget=lambda x:x.__store)

    def reset(self):
        raise NotImplementedError
    def keys(self):
        raise NotImplementedError

class Content(dict):
    id = property(fget=lambda x:x.__id)
    context = property(fget=lambda x:x.__context)
    store = property(fget=lambda x:x.__context.store)

    def reset(self):
        raise NotImplementedError
    def keys(self):
        raise NotImplementedError

    def edge(self, (destination,address)):
        raise NotImplementedError
