import database as db,function as fn

def function(ea):
    res = {}
    for ea,t in fn.select(ea):
        res[ea] = t
    return res

def globals():
    '''Return all the global tags.'''
    res = {}
    for ea,t in db.select():
        res[ea] = t
    return res

def everything():
    '''Return all the tags within the database.'''
    res = { ea : function(ea) for ea in db.functions() if fn.tags(ea) }
    return globals(), res
