## default python modules
import __builtin__,sys,os,itertools,operator

## ida-python specific modules
import idaapi
import idc,idautils

## contextual modules
import database,function,segment,structure,enum
import instruction,helper

import database as db,function as fn

# shortcuts
def top():
    import function     # ida's usage of python sucks.
    return function.top(db.h())

def hex(i):
    return '%x'% i

h,go = database.h,database.go

import helper
from helper import remote,colormarks,checkmarks,recovermarks
