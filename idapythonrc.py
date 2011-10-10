import sys,os
import idc,idautils

# store the root path
import __root__
root = __root__.__file__[ : __root__.__file__.rfind(os.sep) ]

# add subdirs to the search path
# XXX: we might be able to do this via the ihooka module
for h in ('base','app','misc','user'):
    sys.path.append('%s%c%s'% (root, os.sep, h))

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
