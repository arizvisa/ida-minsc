import sys,os
import idc,idautils
from base import *

# store the root path
import __root__
root = __root__.__file__[ : __root__.__file__.rfind(os.sep) ]

# add subdirs to the search path
for h in ['base','app', 'misc', 'user']:
    sys.path.append('%s%c%s'% (root, os.sep, h))

# shortcuts
(db,fn) = (database,function)
h,go = (db.h, db.go)
hex = lambda i: '%x'% i

'''
todo:

need utils for searching for specific instructions
x need way of navigating blocks
  x need to also navigate multiple code paths in a function for searching
    need to figure out how to merge emulator into this thing
'''
