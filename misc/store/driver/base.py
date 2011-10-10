import logging
try:
    import fu as pickle
except ImportError:
    logging.warning("unable to load fu serialization module")
    try:
        import cPickle as pickle
    except ImportError:
        logging.warning("unable to load cPickle serialization module")
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

### definitions
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

class Driver(object):
    @staticmethod
    def tag_fetch(session):
        raise NotImplementedError
    @staticmethod
    def tag_add(session, *names):
        raise NotImplementedError
    @staticmethod
    def tag_discard(session, *names):
        raise NotImplementedError

    @staticmethod
    def ctx_select(session, query):
        raise NotImplementedError
    @staticmethod
    def ctx_update(session, ea, dictionary):
        raise NotImplementedError
    @staticmethod
    def ctx_remove(session, query, names):
        raise NotImplementedError

    @staticmethod
    def con_edge(session, (ctx_source,con_source),(ctx_target,con_target)):
        raise NotImplementedError
    @staticmethod
    def con_unedge(session, (ctx_source,con_source),(ctx_target,con_target)):
        raise NotImplementedError

    @staticmethod
    def con_select(session, query):
        raise NotImplementedError
    @staticmethod
    def con_update(session, ctx, ea, dictionary):
        raise NotImplementedError
    @staticmethod
    def con_remove(session, query, names):
        raise NotImplementedError
