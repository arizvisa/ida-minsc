import sys,os,logging
import idaapi,idc,idautils

# grab ida's user directory
root = idaapi.get_user_idadir()
sys.path.append(root)

# add subdirs to the search path
for h in ('base','app','misc','user'):
    sys.path.append('%s%c%s'% (root, os.sep, h))

# populate default namespace
from __root__ import *

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
    logging.warn('No idapythonrc.py file found in home directory')

except Exception, e:
    print 'warning: Exception %s raised'% repr(e)
    import traceback
#    tb = traceback.format_stack()
#    print ''.join(tb)
    traceback.print_exc()

if False:
    import logging
    def notified(code, old=0):
        global s
        if code == idaapi.NW_OPENIDB:
            s = store.open()
        elif code == idaapi.NW_CLOSEIDB:
            if s:
                logging.info('committed changes back to database %s'% path)
                s.commit()
            s = None
        return True

    idaapi.notify_when(idaapi.NW_OPENIDB|idaapi.NW_CLOSEIDB, notified)
