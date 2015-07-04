## ida-python specific modules
import _idaapi as idaapi, ida

## contextual modules
import segment,database,function,instruction
import structure,enum

import database as db,function as fn

# shortcuts
def top():
    return function.top(database.h())

def hex(i):
    return '%x'% i

h,go = database.h,database.go

import utils
from utils import remote
