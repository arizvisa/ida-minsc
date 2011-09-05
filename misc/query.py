import re,logging

# this module is broken down between 2 components
# conjunctions, and clauses.
# a clause is tested against a specific attribute of an object
# a conjunctions joins specific clauses together

### base types
class matcher(object):
    '''base shell module for providing some type of meaning with a language-like syntax'''
    def has(self, object):
        raise NotImplementedError
    def sqlq(self):
        raise NotImplementedError
    def sqld(self):
        raise NotImplementedError

class conjunction(matcher):
    '''a conjunction joins a list of clauses together via some operation'''
    clause = list
    def __init__(self, *clauses):
        self.clause = list(clauses)

class clause(matcher):
    '''a clause is used to describe a proposition that could be queried with'''
    def has(self, object):
        raise NotImplementedError

class operator(clause):
    '''used for describing a token that would define an operator'''
    def __init__(self, attribute, operand):
        self.attribute = attribute
        self.operand = operand

    def sqld(self):
        return self.attribute,self.operand,

class empty(matcher):
    '''true if the given id contains no attributes'''
    def has(self, object):
        return bool(object) is False
    def sqlq(self):
        return 'not exists(select 1 where context.id=?)'
    def sqld(self):
        return ()

class all(matcher):
    def has(self, object):
        return bool(object) is True
    def sqlq(self):
        return '1=1'
    def sqld(self):
        return ()

## misc
class hasattr(clause):
    '''true if the given id contains specified attribute'''
    def __init__(self, attribute):
        self.operand = attribute
    def has(self, object):
        return self.operand in object
    def sqlq(self):
        return 'exists(select 1 where tag.name=?)'
    def sqld(self):
        return self.operand,

class hasvalue(operator):
    '''true if the object has the specified key=value pair defined'''
    def has(self, object):
        return self.attribute in object and object[self.attribute] == self.operand
    def sqlq(self):
        return 'tag.name=? and value=?'
    def sqld(self):
        return self.attribute,self.operand

class address(clause):
    def __init__(self, address):
        self.address = address
    def has(self, object):
        return object['__address__'] == self.address    # XXX: magic
    def sqlq(self):
        return 'dataset.address=?'
    def sqld(self):
        return self.address,

class between(clause):
    def __init__(self, left, right):
        self.left,self.right = left,right
    def has(self, object):
        return object['__address__'] >= left and object['__address__'] < right
    def sqlq(self):
        return 'dataset.address>=? and dataset.address<?'
    def sqld(self):
        return self.left,self.right

### default conjunctions
class _and(conjunction):
    ''' base and conjunction '''
    def has(self, object):
        for c in self.clause:
            if not c.has(object):
                return False
            continue
        return True

    def sqlq(self):
        return ' and '.join( "(%s)"%c.sqlq() for c in self.clause)
    def sqld(self):
        result = []
        for c in self.clause:
            result.extend(c.sqld())
        return tuple(result)

class _or(conjunction):
    ''' base or conjunction '''
    def has(self, object):
        for c in self.clause:
            if c.has(object):
                return True
            continue
        return False

    def sqlq(self):
        return ' or '.join( "(%s)"%c.sqlq() for c in self.clause)
    def sqld(self):
        result = []
        for c in self.clause:
            result.extend(c.sqld())
        return tuple(result)

## wraps a conjunction
class _not(matcher):
    '''inverts a conjunction'''
    def __init__(self, conjunction):
        self.conjunction = conjunction

    def has(self, object):
        return not self.conjunction.has(object)

    def sqlq(self):
        return 'not(%s)'% self.conjunction.sqlq()
    def sqld(self):
        return self.conjunction.sqld()

## friendly conjunctions
class anda(_and):
    '''and attribute'''
    def __init__(self, *attributes):
        self.clause = [ hasattr(x) for x in attributes ]

class ora(_or):
    '''or attribute'''
    def __init__(self, *attributes):
        self.clause = [ hasattr(x) for x in attributes ]
class andv(_and):
    '''and attribute=value'''
    def __init__(self, **attributes):
#        self.clause = [ _and(hasattr(k),hasvalue(k,v)) for k,v in attributes.iteritems() ]
        self.clause = [ hasvalue(k,v) for k,v in attributes.iteritems() ]
class orv(_or):
    '''or attribute=value'''
    def __init__(self, **attributes):
#        self.clause = [ _and(hasattr(k),hasvalue(k,v)) for k,v in attributes.iteritems() ]
        self.clause = [ hasvalue(k,v) for k,v in attributes.iteritems() ]

class attribute(_or):
    '''accept _only_ the specified list of attributes'''
    def __init__(self, *keys):
        self.keys = set(keys)
        if not self.keys:
            logging.warning("user requested a query of no attributes due to an empty 'attribute' conjunction")

    def has(self, object):
        if not self.keys:
            return False

        for x in self.keys:
            if x not in object:
                return False
            continue
        return True
    def sqlq(self):
        if self.keys:
            return '(%s)'% ' or '.join('(tag.name=?)' for x in self.keys)
        return '(1=0)'  # kill the query
    def sqld(self):
        return tuple(self.keys)

### clauses
## for integers

class lt(operator):
    def has(self, object):
        return self.attribute in object and object[self.attribute] < self.operand
    def sqlq(self):
        return 'tag.name=? and cast(dataset.value as integer)<?'
class lte(operator):
    def has(self, object):
        return self.attribute in object and object[self.attribute] <= self.operand
    def sqlq(self):
        escaped_operand = self.operand  # XXX
        return 'tag.name=? and cast(dataset.value as integer)<=?'
class gt(operator):
    def has(self, object):
        return self.attribute in object and object[self.attribute] > self.operand
    def sqlq(self):
        escaped_operand = self.operand  # XXX
        return 'tag.name=? and cast(dataset.value as integer)>?'
class gte(operator):
    def has(self, object):
        return self.attribute in object and object[self.attribute] >= self.operand
    def sqlq(self):
        escaped_operand = self.operand  # XXX
        return 'tag.name=? and cast(dataset.value as integer)>=?'
class eq(operator):
    def has(self, object):
        return self.attribute in object and object[self.attribute] == self.operand
    def sqlq(self):
        escaped_operand = self.operand  # XXX
        return 'tag.name=? and dataset.value=?'

## string
class similar(eq):
    def has(self, object):
        return re.match(self.operand, object[self.attribute]) is not None
    def sqlq(self):
        return 'tag.name=? and dataset.value glob ?'% self.attribute
    def sqld(self):
        return self.attribute,self.operand

### complex clauses
class depth(clause):
    def __init__(self, address, depth, conjunction):
        self.depth = depth
        self.conjunction = conjunction
        raise NotImplementedError

    def has(self, object):
        # descend some amount of depth into object, and then
        #   apply the conjunction
        assert type(object) is function
        return False

    def sqlq(self, object):
        raise NotImplementedError

if __name__ == '__main__' and False:
    import query
    reload(query)

    result = [
        {'synopsis':'test', 'address':0},
        {'synopsis':'test2', 'eip':0},
        {'synopsis':'test3', 'note':0},
        {'snopsis':'test4', 'note':0},
    ]

    select = query._and( query.orv(address=0, note=1), query.hasattr('synopsis') )
    select = query._not( query._or(query.orv(address=0, eip=0),query.hasattr('snopsis') ))
    for x in result:
        print select.has(x)

if __name__ == '__main__':
    import query as q
    reload(q)

    a = q._not(q._and(q.lt('address', 0x200), q.gt('address',200)))
    print a.sqlq()
    print a.sqld()
    a = q._not(q._or(q.andv(group='dispatch', ea=100),q.orv(group='fuck',group2='fuck2',group3='fuck3')))
    print a.sqlq()
    print a.sqld()

