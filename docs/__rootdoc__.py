## ida-python specific modules
import idaapi, ida
import __builtin__ as builtin

# needed because IDA 6.95 is fucking stupid and sets the result of idaapi.get_kernel_version() to a string
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

# inject version into idaapi
# idaapi.__version_major__, idaapi.__version_minor__, idaapi.__version__ = __version__()
# del __version__

"""
# IDA 6.9 requires the _idaapi module to exist in the global namespace
if idaapi.__version__ <= 6.9:
    import _idaapi

# IDA 6.95 requires these modules to exist in the global namespace
if idaapi.__version__ >= 6.95:
    import ida_idaapi, ida_kernwin, ida_diskio
"""

## contextual modules
import segment, database, function, instruction
import structure, enum

import database as db, function as func, instruction as ins, structure as struc, segment as seg, segment as seg

# default logging that displays any info
__import__('logging').root.level = __import__('logging').INFO

# shortcuts
h, top, go, goof = database.h, func.top, database.go, database.goof

# functional tools
import functools, itertools, operator
fbox,fboxed,box,boxed,funbox,unbox,finstance,fconstant,fpassthru,fpass,fidentity,fid,first,second,third,last,fcompose,compose,fdiscard,fcondition,fmaplist,fap,flazy,fmemo,fpartial,partial,fapply,fcurry,frpartial,freversed,frev,fexc,fexception,fcatch,fcomplement,fnot,ilist,liter,ituple,titer,itake,iget,imap,ifilter = map(functools.partial(getattr, __import__('internal').utils), __import__('internal').utils.__all__)

# pattern matching
AnyRegister = AnyReg = __import__('internal').utils.PatternAnyType(instruction.register_t)
AnyInteger = AnyInt = __import__('internal').utils.PatternAnyType(__import__('six').integer_types)
AnyString = AnyStr = __import__('internal').utils.PatternAnyType(basestring)
Any = _ = __import__('internal').utils.PatternAny()
architecture_t, register_t, symbol_t = instruction.architecture_t, instruction.register_t, __import__('internal').interface.symbol_t

import tools, ui
from tools import remote

import custom, app
### namespace stops here

### begin hooking ida to monitor it's state
# scope for execution queue and hooks
ui.queue.__start_ida__(), ui.hook.__start_ida__()
ui.hook.ui.add('term', ui.queue.__stop_ida__, 1000), ui.hook.ui.add('term', ui.hook.__stop_ida__, 10000)

# start and stop execution queue when database is open or closed
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('init', ui.queue.__open_database__, 0)
    ui.hook.idp.add('term', ui.queue.__close_database__, 0)
else:
    ui.hook.idp.add('ev_init', ui.queue.__open_database__, 0)
    ui.hook.idp.add('ev_term', ui.queue.__close_database__, 0)

# setup default integer types for the typemapper once the loader figures everything out
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('newprc', __import__('internal').interface.typemap.__newprc__, 0)
else:
    ui.hook.idp.add('ev_newprc', __import__('internal').interface.typemap.__ev_newprc__, 0)

# update database state when ida's enter various states
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

# create the tagcache netnode in any new database
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('init', __import__('internal').comment.tagging.__init_tagcache__, 0)
else:
    ui.hook.idp.add('ev_init', __import__('internal').comment.tagging.__init_tagcache__, 0)

# hook any user-entered comments so that they update the tagcache
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

# hook naming and extra comments to support implicit tags in the tagcache
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('rename', __import__('hooks').rename, 40)
else:
    ui.hook.idp.add('ev_rename', __import__('hooks').rename, 40)
ui.hook.idb.add('extra_cmt_changed', __import__('hooks').extra_cmt_changed, 40)

# hook function creation/modification so they shuffle any tags between the differing tagcache types
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

# rebase the tagcache if the entire database was rebased.
ui.hook.idb.add('allsegs_moved', __import__('hooks').rebase, 50)

# switch the instruction set
if idaapi.__version__ < 7.0:
    ui.hook.idp.add('newprc', instruction.__newprc__, 50)
else:
    ui.hook.idp.add('ev_newprc', instruction.__ev_newprc__, 50)

#[ ui.hook.ui.add(n, __import__('hooks').notify(n), -100) for n in ('range','idcstop','idcstart','suspend','resume','term','ready_to_run') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('newfile','oldfile','savebase','closebase','init','term','newprc','newasm','loader_finished','loader') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('auto_empty','auto_queue_empty') ]
#[ ui.hook.idb.add(n, __import__('hooks').notify(n), -100) for n in ('thunk_func_created','func_tail_appended','removing_func_tail') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('add_func','del_func','set_func_start','set_func_end') ]
#ui.hook.idb.add('allsegs_moved', __import__('hooks').notify('allsegs_moved'), -100)

del _
