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

        result = set(tag).difference(self)
        super(watch,self).update(tag)
        return len(result)

    def discard(self, *tag):
        tag,view = set(tag),self.view
        for i,ea in enumerate(view.node):
            n = view.node[ea]
            update.discard_context(view, n,*tag)
            update.discard_content(view, n,*tag)
        [view.watch.remove(n) for n in tag.intersection(self)]
        return

class update:
    # callbacks for some content
    @staticmethod
    def context(self, node, updates, content):
        # clearing old stuff...probably too slow(?)
        p = self.render.address(node.id)
        if False:
            for key,value in self.render.select(query.address(p.id), query._not(query.attribute(*self.watch))).iteritems():
                value = set(value.keys())
                p.unset( *value.difference(p.keys()) )

        logging.debug('removing %x'%(node.id))
        for address,value in self.render.select(query.address(p.id)).iteritems():
            value = set(value.keys())
            p.unset( *value.difference(p.keys()))

        logging.debug('updating %x with %s'%(node.id,repr(updates)))
        p.set(**updates)
        update.content(self, node, content)

    @staticmethod
    def content(self, node, updates):
        p = self.render.address(node.id)

        # delete old content (slow?)
        if False:
            for address,value in self.render.c(node.id).select(query._not(query.attribute(*self.watch))).iteritems():
                v = set(value.keys())
                p.address(address).unset( *v.difference(p.keys()) )

        logging.debug('removing content of %x'%(node.id,))
        for address,value in p.select(query.address(p.id)).iteritems():
            value = set(value.keys())
            p.unset( *value.difference(p.keys()))

        logging.debug('updating content of %x with %s'%(node.id,repr(updates)))
        for address,value in updates.iteritems():
            p.address(address).set( **value )
        return

    @staticmethod
    def discard_context(self, node, *tags):
        raise NotImplementedError("Need to empty the specified tags properly for both context and content")
        tags = set(tags)
        r = self.render.address(node.id)

        # context
        value = set(r.keys())
        r.unset( *value.intersection(tags) )

        # content
        [update.discard_content(self, node, *tags)]
        [self.trigger.remove((node.id,n)) for n in tags]
        return

    @staticmethod
    def discard_content(self, node, *tags):
        tags = set(tags)
        r = self.render.address(node.id)
        for ea in r.select(query.attribute(*tags)):
            v = set(r.keys())
            r.address(ea).unset( *v.intersection(tags) )
        return

class view(object):
    '''
    this groups multiple record sources together and provides an interface for
    selecting/modifying nodes in a query. this can be used to update recordsets to update a graph.
    '''
    node = dict     # list of nodes to watch

    # fronts to the watch list
    def add(self, *name):
        return self.watch.add(*name)
    def discard(self, *name):
        return self.watch.discard(*name)

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

    def callback(self, address, n=None, fn=None):
        ''' add callback to the specific node address '''
        id = ((self.node[address].id,n), self.node[address].id)[n is None]
        if id in self.trigger:
            self.trigger.remove(id)
        if fn is None:
            fn = lambda *args,**kwds: update.context(self, *args, **kwds)
        return self.trigger.add(id,fn)

    def update(self):
        ''' call this every once in a while '''
        # context
        if not self.watch:
            logging.info('refusing to update due to an empty tag list')
            return {}

        # query all contexts
        if False:
            context = {}
            for k,v in self.store.select(query.newer(self.__age),query.attribute(*self.watch),query.address(*self.node.keys())).iteritems():
                if not v:
                    continue
                context[k] = v

        context = {}
#        for k,v in self.store.select(query.newer(self.__age),query.attribute(*self.watch),query.address(*self.node.keys())).iteritems():
        for k in self.node.keys():
            v = self.store.select(query.newer(self.__age),query.attribute(*self.watch), query.address(k))
            if not v:
                continue
            context[k] = v[k]
            self.node[k].update(v[k])
            logging.info('updated %x %s',k,repr(v[k]))

        completed = set(context.keys())

        # now for content
        content = {}
        for address in self.node:
            result = self.store.select_content(query.newer(self.__age),query.attribute(*self.watch),query.context(address))
            content[address] = result

        # execute callback for all nodes
        for address,updates in content.iteritems():
            node = self.node[address]

            if self.trigger.execute(node.id, node, context.get(address,{}), updates):
                logging.warning('callback for %x returned non-zero value')

            # call subscribed triggers
            names = set()
            for ea,d in updates.iteritems():
                names.update(d.keys())
            [ self.trigger.execute((node.id,n), (node,n), context.get(address,{}), updates) for n in names ]

            node.update(context.get(address,{}))
            node.content.update(updates)

        self.__age = datetime.now()
        return completed

    ## adding nodes to view
    def __add(self, *address):
        '''add a list of addresses to the current view'''
        result = set(address).difference(set(self.node.keys()))
        if len(result) > 0:
            for i,ea in enumerate(result):
                self.node[ea] = node(self, self.store.address(ea))
                self.callback(ea)
            return i+1
        return 0

    def extend(self, *q):
        '''extend the current view with other nodes using the given query'''
        return self.__add( *self.store.select(*q).keys() )

    ## modifying current view
    def select(self, *q):
        '''return a subview with the given query on a function's context'''
        result = type(self)(self.store, self.watch)
        if self.node:
            nodes = tuple(k for k in self.node.iterkeys())
            result.extend(query.address(*nodes))
        return result

    def grow(self, depth):
        result = type(self)(self.store, self.watch)
        result.__add(*self.node.keys())
        for k,v in self.iteritems():
            result.extend(query.depth(k, depth))
        return result

class node(dict):
    id = property(fget=lambda s:s.__id)
    view = None     # the view we belong to
    store = property(fget=lambda s:s.view.store)
    data = property(fget=lambda s:s.__data)

    l = property(fget=lambda s: s.sync())
    def sync(self):
        return self.update(self.data.l)

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
   
if __name__ == '__main__':
    import store
    s=store.open()
    import store.cache
    reload(store.cache)
    v=store.cache.view(s, store.ida)
    v.watch.add('frame-size','completed','name')
    v.extend(q.address(top()))
    print v.update()
    v.watch.discard('frame-size','completed')
    print v.update()

