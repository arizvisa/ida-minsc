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

# try and execute our user's idapythonrc.py
try:
    if os.getenv('HOME'):
        execfile( '%s%cidapythonrc.py'% (os.getenv('HOME'), os.sep) )
    elif os.getenv('USERPROFILE'):
        execfile( '%s%cidapythonrc.py'% (os.getenv('USERPROFILE'), os.sep) )
    else:
        raise OSError('Unable to figure out home directory')
    pass
except IOError:
    print 'warning: No idapythonrc.py file found in home directory'
