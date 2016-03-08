## ida-python specific modules
import _idaapi as idaapi,ida

## contextual modules
import segment,database,function,instruction
import structure,enum

import database as db,function as func,instruction as ins,structure as struc

# default logging that displays any info
__import__('logging').root.level = __import__('logging').INFO

# shortcuts
def top(ea=None):
    return function.top(ea is not None and ea or database.h())

def hex(i):
    return '%x'% i

h,go,goof = database.h,database.go,database.goof

import utils,ui
from utils import remote

#import custom,app
