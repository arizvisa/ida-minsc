## default stuff that gets imported into ida's namespace

# import the default modules
import database,segment,function
import instruction

import database as db,function as fn

# shortcuts
def top():
    import function     # ida's usage of python sucks.
    return function.top(db.h())

def hex(i):
    return '%x'% i

h,go = database.h,database.go

import helper
from helper import remote
