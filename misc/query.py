import re

# this module is broken down between 2 components
# conjunctions, and clauses.
# a clause is tested against a specific attribute of an object
# a conjunctions joins specific clauses together

### base types
class matcher(object):
    def has(self, object):
        raise NotImplementedError

class conjunction(matcher):
    clause = list
    def __init__(self, *clauses):
        self.clause = list(clauses)

class clause(matcher):
    def has(self, object):
        raise NotImplementedError

class operator(clause):
    def __init__(self, attribute, operand):
        self.attribute = attribute
        self.operand = operand

class empty(matcher):
    def has(self, object):
        return bool(object) is False

## misc
class hasattr(clause):
    def __init__(self, attribute):
        self.operand = attribute
    def has(self, object):
        return self.operand in object

class hasvalue(operator):
    def has(self, object):
        return object[self.attribute] == self.operand

### default conjunctions
class _and(conjunction):
    ''' and clause '''
    def has(self, object):
        for c in self.clause:
            if not c.has(object):
                return False
            continue
        return True

class _or(conjunction):
    ''' or clause '''
    def has(self, object):
        for c in self.clause:
            if c.has(object):
                return True
            continue
        return False

## wraps a conjunction
class _not(matcher):
    '''inverts a conjunction'''
    def __init__(self, conjunction):
        self.conjunction = conjunction

    def has(self, object):
        return not self.conjunction.has(object)

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
        self.clause = [ _and(hasattr(k),hasvalue(k,v)) for k,v in attributes.iteritems() ]
class orv(_or):
    '''or attribute=value'''
    def __init__(self, **attributes):
        self.clause = [ _and(hasattr(k),hasvalue(k,v)) for k,v in attributes.iteritems() ]

### clauses
## for integers
class lt(operator):
    def has(self, object):
        return object[self.attribute] < self.operand
class lte(operator):
    def has(self, object):
        return object[self.attribute] <= self.operand
class gt(operator):
    def has(self, object):
        return object[self.attribute] > self.operand
class gte(operator):
    def has(self, object):
        return object[self.attribute] >= self.operand
class eq(operator):
    def has(self, object):
        return object[self.attribute] == self.operand

## string
class similar(eq):
    def has(self, object):
        return re.match(self.operand, object[self.attribute]) is not None

### complex clauses
class depth(clause):
    def __init__(self, depth, conjunction):
        self.depth = depth
        self.conjunction = conjunction

    def has(self, object):
        # descend some amount of depth into object, and then
        #   apply the conjunction
        assert type(object) is function
        return False

if __name__ == '__main__':
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
