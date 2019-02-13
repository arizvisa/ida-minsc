"""
Root module

This module contains the root namespace that IDA starts up with. Any
thing defined within this module is used to replace the globals that
IDA starts up with.

This module also is responsible for assigning the default hooks in
order to trap what the user is doing to perform any extra maintenance
that needs to occur.
"""

### ida-python specific modules
import idaapi, ida

### detect which version of IDA is being used

## needed because IDA 6.95 is fucking stupid and sets the result of idaapi.get_kernel_version() to a string
def __version__():
    # api doesn't exist, go back to a crazy version.
    if not hasattr(idaapi, 'get_kernel_version'):
        return 6, 0, 6.0

    import math
    res = str(idaapi.get_kernel_version())      # force it to a str because IDA 7.0 "fixed" it
    major, minor = map(int, res.split('.', 2))
    minor = int("{:<02d}".format(minor))
    if minor > 0:
        count = math.floor(math.log(minor) / math.log(10) + 1)
        return major, minor, float(major) + minor/10**count
    return major, minor, float(major)

## inject the version info into idaapi
idaapi.__version_major__, idaapi.__version_minor__, idaapi.__version__ = __version__()

## now we can delete the function because we're done with it
del __version__

## IDA 6.9 requires the _idaapi module exists in the global namespace
if idaapi.__version__ <= 6.9:
    import _idaapi

## IDA 6.95 requires these couple modules to exist in the global namespace
if idaapi.__version__ >= 6.95:
    import ida_idaapi, ida_kernwin, ida_diskio

### customize the root namespace
import functools, operator, itertools, types
from six.moves import builtins

## context modules from ida-minsc
import segment, database, function, instruction
import structure, enumeration

## some aliases for them
import database as db
import function as func
import instruction as ins
import structure as struc
import enumeration as enum
import segment as seg

## default log setting for notifying the user
# FIXME: actually use the logging module properly instead of assuming
#        control of the root logger.
#__import__('logging').root.setLevel(__import__('logging').INFO)

## shortcuts
h, top, go, goof = database.h, func.top, database.go, database.go_offset

## other useful things that we can grab from other modules

# snag the fake utilities module to share some things with the user...
utils = __import__('internal').utils

# import all its combinators by copying them directly into locals()
locals().update({name : item for name, item in utils.__dict__.iteritems() if name in utils.__all__})

# construct some pattern matching types
AnyRegister = AnyReg = utils.PatternAnyType(__import__('internal').interface.register_t)
AnyInteger = AnyInt = utils.PatternAnyType(__import__('six').integer_types)
AnyString = AnyStr = utils.PatternAnyType(basestring)
Any = utils.PatternAny()

# ...and that's it for the utils
del(utils)

# some types that the user might want to compare with
architecture_t, register_t, symbol_t = (getattr(__import__('internal').interface, _) for _ in ('architecture_t', 'register_t', 'symbol_t'))

# other miscellaneous modules to expose to the user
import ui, tools, custom, app

### namespace customization stops here

### hooks for different parts of ida start here...

## entire scope for execution queue and hooks
ui.hook.__start_ida__()
ui.hook.ui.add('term', ui.hook.__stop_ida__, 10000)

## setup default integer types for the typemapper once the loader figures everything out
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('newprc', __import__('internal').interface.typemap.__newprc__, 0)
else:
    ui.hook.idp.add('ev_newprc', __import__('internal').interface.typemap.__ev_newprc__, 0)

## monitor when ida enters its various states
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('init', __import__('hooks').on_init, 0)
    ui.hook.idp.add('newfile', __import__('hooks').on_newfile, 0)
    ui.hook.idp.add('oldfile', __import__('hooks').on_oldfile, 0)
    ui.hook.idp.add('auto_empty', __import__('hooks').on_ready, 0)
else:
    ui.hook.idp.add('ev_init', __import__('hooks').on_init, 0)
    ui.hook.idp.add('ev_newfile', __import__('hooks').on_newfile, 0)
    ui.hook.idp.add('ev_oldfile', __import__('hooks').on_oldfile, 0)
    ui.hook.idp.add('ev_auto_queue_empty', __import__('hooks').auto_queue_empty, 0)

## create the tagcache netnode when a database is created
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('init', __import__('internal').comment.tagging.__init_tagcache__, 0)
else:
    ui.hook.idp.add('ev_init', __import__('internal').comment.tagging.__init_tagcache__, 0)

## hook any user-entered comments so that they will also update the tagcache
if idaapi.__version__ < 7.0:
    [ ui.hook.idb.add(_, __import__('hooks').noapi, 40) for _ in ('changing_cmt', 'cmt_changed', 'changing_area_cmt', 'area_cmt_changed') ]
else:
    [ ui.hook.idb.add(_, __import__('hooks').noapi, 40) for _ in ('changing_cmt', 'cmt_changed', 'changing_range_cmt', 'range_cmt_changed') ]

if idaapi.__version__ < 7.0:
    ui.hook.idp.add('init', __import__('hooks').address.database_init, 45)
    ui.hook.idp.add('init', __import__('hooks').globals.database_init, 45)
    ui.hook.idb.add('changing_area_cmt', __import__('hooks').globals.changing, 45)
    ui.hook.idb.add('area_cmt_changed', __import__('hooks').globals.changed, 45)
else:
    ui.hook.idp.add('ev_init', __import__('hooks').address.database_init, 45)
    ui.hook.idp.add('ev_init', __import__('hooks').globals.database_init, 45)
    ui.hook.idb.add('changing_range_cmt', __import__('hooks').globals.changing, 45)
    ui.hook.idb.add('range_cmt_changed', __import__('hooks').globals.changed, 45)

ui.hook.idb.add('changing_cmt', __import__('hooks').address.changing, 45)
ui.hook.idb.add('cmt_changed', __import__('hooks').address.changed, 45)

## hook naming and "extra" comments to support updating the implicit tags
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('rename', __import__('hooks').rename, 40)
else:
    ui.hook.idp.add('ev_rename', __import__('hooks').rename, 40)
ui.hook.idb.add('extra_cmt_changed', __import__('hooks').extra_cmt_changed, 40)

## hook function transformations so we can shuffle their tags between types
if idaapi.__version__ < 7.0:
    ui.hook.idb.add('removing_func_tail', __import__('hooks').removing_func_tail, 40)
    [ ui.hook.idp.add(_, getattr(__import__('hooks'), _), 40) for _ in ('add_func', 'del_func', 'set_func_start', 'set_func_end') ]
else:
    ui.hook.idb.add('deleting_func_tail', __import__('hooks').removing_func_tail, 40)
    ui.hook.idb.add('func_added', __import__('hooks').add_func, 40)
    ui.hook.idb.add('deleting_func', __import__('hooks').del_func, 40)
    ui.hook.idb.add('set_func_start', __import__('hooks').set_func_start, 40)
    ui.hook.idb.add('set_func_end', __import__('hooks').set_func_end, 40)
[ ui.hook.idb.add(_, getattr(__import__('hooks'), _), 40) for _ in ('thunk_func_created', 'func_tail_appended') ]

## rebase the entire tagcache when the entire database is rebased.
ui.hook.idb.add('allsegs_moved', __import__('hooks').rebase, 50)

## switch the instruction set when the processor is switched
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('newprc', instruction.__newprc__, 50)
else:
    ui.hook.idp.add('ev_newprc', instruction.__ev_newprc__, 50)

## just some debugging notification hooks
#[ ui.hook.ui.add(n, __import__('hooks').notify(n), -100) for n in ('range','idcstop','idcstart','suspend','resume','term','ready_to_run') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('newfile','oldfile','savebase','closebase','init','term','newprc','newasm','loader_finished','loader') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('auto_empty','auto_queue_empty') ]
#[ ui.hook.idb.add(n, __import__('hooks').notify(n), -100) for n in ('thunk_func_created','func_tail_appended','removing_func_tail') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('add_func','del_func','set_func_start','set_func_end') ]
#ui.hook.idb.add('allsegs_moved', __import__('hooks').notify('allsegs_moved'), -100)

## delete the temporary variable we used for list comprehensions
del _

### ...and that's it for all the hooks
