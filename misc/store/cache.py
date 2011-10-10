import logging
from datetime import datetime

import driver,trigger
import query

logging.root=logging.RootLogger(logging.DEBUG)

class trigger(trigger.__base__):
    '''ID=node address'''

class watch(set):
    def __init__(self, view, tags):
        self.view = view
        super(watch,self).__init__()
        super(watch,self).update(tags)
        return None

    def add(self, *tag):
        self.view.dirty()
        return [ super(watch,self).add(x) for x in tag ]

class view(object):
    '''
    this groups multiple record sources together and provides an interface for
    selecting/modifying nodes in a query. this can be used to update recordsets to update a graph.
    '''
    node = dict     # list of nodes to watch

    def __init__(self, store, render, tags=set()):
        self.node = {}

        self.store = store              # data store
        self.render = render            # render store
        self.watch = watch(self, tags)  # default tags to transfer
        self.trigger = trigger()        # callback object

        self.dirty()
        self.update()
        return

    def __repr__(self):
        nodes = '[%s]'%(','.join(map(hex,self.node.keys())))
        return '%s %s node:%s'%(type(self), repr(self.watch), nodes)

    ## syncing records with db
    def dirty(self):
        self.__age = datetime(1,1,1)    # near epoch
        return

    def commit(self):
        return self.store.commit()

    def rollback(self):
        self.store.rollback()
        self.dirty()
        return self.update()

    def update(self):
        ''' call this every once in a while '''
        # context
        if not self.watch:
            logging.info('refusing to update due to an empty tag list')
            return {}

        # query all contexts and update nodes
        result = {}
        for k,v in self.store.select(query.newer(self.__age),query.attribute(*self.watch),query.address(*self.node.keys())).iteritems():
            if not v:
                continue
            self.node[k].update(v)
            result[k] = v

        # execute callback for all nodes
        for address,updates in result.iteritems():
            node = self.node[address]
            if self.trigger.execute(node.id, node, updates):
                logging.warning('callback for %x returned non-zero value')
            continue

        completed = set(result.keys())

        # now for content
        for address in self.node:
            result = self.store.select_content(query.newer(self.__age),query.attribute(*self.watch),query.context(address))

            node = self.node[address]
            names = set()

            # collect names for updates
            for ea,d in result.iteritems():
                names.update(d.keys())

            # callbacks for content
            for n in names:
                r = ((ea,d[n]) for ea,d in result.iteritems() if n in d)
                self.trigger.execute((node.id,n), (node,n), dict(r))

            node.content.update(result)

        self.__age = datetime.now()
        return completed

    ## adding nodes to view
    def add(self, *address):
        '''add a list of addresses to the current view'''

        # callbacks for some nodes
        def __update_context(node, update):
            logging.debug('updating %x with %s'%(node.id,repr(update)))
            for key,value in update.iteritems():
                self.render.address(node.id)[key] = value
            return

        # callbacks for some content
        def __update_content((node,name), update):
            logging.debug('updating %x:%s with %s'%(node.id,name,repr(update)))
            for ea,value in update.iteritems():
                self.render.address(node.id).address(ea)[name] = value
            return

        if len(address) > 0:
            for i,ea in enumerate(address):
                self.node[ea] = node(self, self.store.address(ea))
                self.trigger.add(self.node[ea].id, __update_context)
                [self.trigger.add((self.node[ea].id,n), __update_content) for n in self.watch]
            return i+1
        return 0

    def extend(self, *q):
        '''extend the current view with other nodes using the given query'''
        return self.add( *self.store.select(*q).keys() )

    ## modifying current view
    def select(self, *q):
        '''return a subview with the given query on a function's context'''
        result = type(self)(self.store, self.watch)
        if self.node:
            nodes = tuple(k for k in self.node.iterkeys())
            result.add(*self.store.select(query.address(*nodes), *q).keys())
        return result

    def grow(self, depth):
        result = type(self)(self.store, self.watch)
        result.add(*self.node.keys())
        for k,v in self.iteritems():
            result.extend(query.depth(k, depth))
        return result

class node(dict):
    id = property(fget=lambda s:s.__id)
    view = None     # the view we belong to
    store = property(fget=lambda s:s.view.store)
    data = property(fget=lambda s:s.__data)

    # node navigation
    def __init__(self, view, ctx):
        self.__id = ctx.id
        self.__data = ctx
        self.view = view
        self.content = {}

    def up(self):
        return set(self.store.select(query.depth(self.id,-1)).keys())
    def down(self):
        return set(self.store.select(query.depth(self.id,1)).keys())

    # fronting a dictionary
    def __repr__(self):
        return '%s 0x%08x %s len(content):%d'%(type(self), self.id, super(node,self).__repr__(), len(self.content))

    def select(self, *q):
        ''' perform a query on this node's contents '''
        return self.data.select(*q)
   
if False and __name__ == '__main__':
    import sqlite3
    import viewcache,store,query
    reload(viewcache)
    import query as q

#    s = sqlite3.connect('./test.db')
    s = sqlite3.connect('c:/users/arizvisa/blah.db')
    u = store.interface.sql(s)
    if False:
        print 'creating schema'
        a = store.deploy.sql(s)
        a.create_schema()
        import sys
        sys.exit(0)

    if True:
        v = viewcache.view(u, u.tag.list())
#        v.watch.add('__name__')
#        v.watch.add('down')

    if False:
        u.tag.add('synopsis')
        u.tag.add('fuck')
        v.extend(query.all())
        v.watch.add('synopsis')
        v.watch.add('fuck')

    if False:
        def update_context(*args):
            print 'context -> %s'% repr(args)

        def update_content(*args):
            print 'content -> %s'% repr(args)

        u.trigger.add('context', update_context)
        u.trigger.add('content', update_content)

    if False:
        import time,random
        for x in range(25):
            address = int(random.random()*0x100000 + 0x80000000)
            string = ''.join(chr(random.randint(ord('0'),ord('9'))) for x in range(random.randint(10,15)))
            u.context.set(address, synopsis=string, fuck=x)

    if True:
#        print v
#        v.extend(q.all())
#        v = v.select(q.andv(select=1))
        v.extend(q.andv(select=1))

#    u.commit()
#    u.content.set(0, 5, synopsis='test', fuck='notag')

    ctx = 0x4023d0
    ea = 4204247

    print 'context'
    v[ctx]['note'] = 'fuckyou'
    v.commit()
    v.update()

    print 'content'
    v[ctx].content[ea]['note'] = 'fuckyou'
    v.commit()
    v.update()


if False:
    s = store.open()
    r = store.ida

    import store
    reload(store)
    reload(store.cache)
    reload(store.driver)
    reload(store.driver.sql)

    key,ea = 'test',0x615D1090

    v = store.cache.view( s, r )
    v.watch.add(key)
    v.add(ea)

    a = v.node[ea]
#    print a.data
#    s.commit()

    a.data[key] = 'blahblahblah'
    s.commit()
    print a.update()

#    print hex(a.data.id)
#    print a.data['__name__']

if False and __name__ == '__main__':
    import store
    reload(store)
    import store.cache
    reload(store.cache)
    s = store.open()
    v=store.cache.view(s,store.ida)
    v.watch.add('node-type','frame-size','blockcount')
    v.extend(store.query.address(1633488896,1633489024))
    print v.update()
