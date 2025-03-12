"""
Internal module (hooks)

This is an internal module that contains implementations of all the hooks
that are used. Some of the things that are hooked are things such as
comment creation, function and segment scoping, etc. This is not intended
to be used by the average user.
"""

import six
import builtins, sys, logging, heapq, traceback, contextlib
import functools, operator, itertools
logging = logging.getLogger(__name__)

import database, function, ui
import internal, internal.tags
from internal import utils, interface, exceptions

import idaapi

def greeting():
    barrier = 86

    loaders, loader_suffix = {}, '__loader__'
    for item in sys.meta_path:
        if item.__module__.endswith(loader_suffix):
            if hasattr(item, '__iter__'):
                name = getattr(item, '__name__', None)
            else:
                name, item = None, [item.__name__]
            loaders.setdefault(name, []).append(item)
        continue

    # iterate through our loaders to try and find the one that actually contains
    # our plugin state. we abuse each loader's __module__ attribute and consolidate
    # them into a set so that we can take the first.
    items = {item.__module__ for item in itertools.chain(*(items for _, items in loaders.items())) if hasattr(item, '__module__')}
    module_name = next((name for name in items), loader_suffix)

    # next we trim out the module suffix and use it to find the actual module
    # that should contain our plugin so we can extract our plugin state. if the
    # module name is empty, then we assume we've been loaded persistently.
    module_name = module_name[:-len(loader_suffix)] if module_name.endswith(loader_suffix) else module_name
    load_state = sys.modules[module_name].MINSC.state if module_name and module_name in sys.modules else 'persistent'

    # now we iterate through all of the loaders that do not have a module name
    # while ignoring any dunder-prefixed modules because they're just state.
    items = itertools.chain(*(items for name, items in loaders.items() if name is None))
    available = sorted(item for item in itertools.chain(*items) if not item.startswith('__'))

    # hide the internal submodule from our display.
    loaders.pop('internal', None)

    # grab all the loaders that represent a submodule.
    submodules = ((name, itertools.chain(*map(sorted, items))) for name, items in loaders.items() if name)
    loaded = {name: ['.'.join([name, item]) for item in items if not item.startswith('_')] for name, items in submodules}
    maximum = 1 + max(map(len, loaded))
    submodules = (' '.join(["{:<{:d}s}".format(name + ':', maximum), ', '.join(loaded[name])] if loaded[name] else ["{:<{:d}s}".format(name + ':', maximum)]) for name in sorted(loaded, key=len))

    six.print_("Welcome to the ida-minsc plugin!")
    six.print_("")
    six.print_("The plugin is {:s} and is currently using python {:s} in IDA {:.1f} ({:s}).".format(load_state, '.'.join("{:d}".format(getattr(sys.version_info, field, 0)) for field in ['major', 'minor', 'micro']), idaapi.__version__, sys.platform))
    six.print_("")

    if available:
        six.print_("The following namespaces have been introduced into IDAPython:")
        six.print_("    {:s}".format(', '.join(available)))
        six.print_("")

    if submodules:
        six.print_("The following modules are available and may also be imported for additional functionality:")
        [six.print_("    {:s}".format(submodule)) for submodule in submodules]
        six.print_("")

    # List all of the known modules that we support.
    # FIXME: Why isn't binsync or ipyida in this list?
    useful_modules = [
        ('ida_hexrays', 'https://hex-rays.com/decompiler/', 'for a freaking decompiler'),
        ('networkx', 'https://pypi.org/project/networkx/', 'for a real graph api'),
        ('dill', 'https://pypi.org/project/dill/', 'to save (and load) your game'),
    ]

    # Figure out which loader implementation to use depending on the python version.
    if sys.version_info.major < 3:
        find_loader = __import__('imp').find_module
    elif sys.version_info.minor < 10:
        find_loader = __import__('importlib').find_loader
    else:
        find_loader = (lambda imp: lambda name: (lambda spec: spec and imp.util.module_from_spec(spec))(imp.util.find_spec(name)))(__import__('importlib.util'))

    # Iterate through all the known and supported modules so
    # that we can check which ones are actually available.
    results = []
    for name, url, description in useful_modules:
        try:
            if find_loader(name) is None:
                raise ImportError
        except ImportError:
            results.append((name, url, description))
        continue

    if results:
        for name, url, description in results:
            six.print_("You should consider installing the `{:s}` module ({:s}){:s}.".format(name, url, " {:s}".format(description) if description else ''))
        six.print_("")

    six.print_("Your globals have been cleaned, use `dir()` to see your work.")
    six.print_("")
    six.print_("Please use `help(namespace)` or `help(modulename)` for general usage.")
    six.print_("You may also visit {:s} for html-based help.".format('https://arizvisa.github.io/ida-minsc'))
    six.print_('-' * barrier)

### comment hooks
class changingchanged(object):
    """
    This base class is for dealing with 2-part events where one part is the
    "changing" event which is dispatched before any changes are made, and the
    second part is the "changed" event which happens after they've been completed.
    """
    @classmethod
    def database_init(cls, idp_modname):
        return cls.initialize()

    @classmethod
    def nw_database_init(cls, nw_code, is_old_database):
        idp_modname = idaapi.get_idp_name()
        return cls.database_init(idp_modname)

    @classmethod
    def initialize(cls):
        """
        This method just initializes our states dictionary and should be
        called prior to a database being loaded. This way any changing/changed
        events will be able to be stored according to the address that they're
        acting upon.
        """
        states = getattr(cls, '__states__', {})
        if states:
            logging.info(u"{:s}.init() : Removing {:d} incomplete state{:s} due to re-initialization of database.".format('.'.join([__name__, cls.__name__]), len(states), '' if len(states) == 1 else 's'))
        cls.__states__ = {}

    @classmethod
    def new(cls, ea):
        '''This registers a new state for a given address that can later be fetched.'''
        states = cls.__states__
        description = "{:#x}".format(ea) if isinstance(ea, internal.types.integer) else "{!r}".format(ea)

        # If we're being asked to recreate the state for an address that is still
        # incomplete, then warn the user about it. This will only happen when the
        # "changing" event is called for the same address more than once without
        # the "changed" event being used to complete it.
        if ea in states:
            res = states.pop(ea)
            logging.info(u"{:s}.new({:s}) : Forcefully closing the state for key {:s} by request.".format('.'.join([__name__, cls.__name__]), description, description))
            res.close()

        # Define a closure that is responsible for keeping track
        # of a subclass' updater so that when it completes its
        # execution it can be removed from our states dictionary.
        def consumer(ea, states, handler):
            next(handler)

            # Consume our handler until it's finished. When we
            # leave this handler it should be safe to close.
            try:
                while True:
                    handler.send((yield))
            except StopIteration:
                pass
            finally:
                handler.close()

            # Consume anything and discard it until we're
            # being closed and need to perform cleanup.
            try:
                while True:
                    yield
            except GeneratorExit:
                states.pop(ea)
            return

        # Initialize a new consumer based on the class updater method,
        # and then set off prior to storing it in our state dictionary.
        coroutine = consumer(ea, states, cls.updater())
        next(coroutine)
        return states.setdefault(ea, coroutine)

    @classmethod
    def resume(cls, ea):
        '''This will return the currently state that is stored for a particular address.'''
        states = cls.__states__
        if ea in states:
            return states[ea]
        description = "{:#x}".format(ea) if isinstance(ea, internal.types.integer) else "{!r}".format(ea)
        raise exceptions.AddressNotFoundError(u"{:s}.resume({:s}) : Unable to locate a currently available state for key {:s}.".format('.'.join([__name__, cls.__name__]), description, description))

    @classmethod
    def updater(cls):
        '''This coroutine is intended to be implemented by a user and is responsible for keeping track of the changes for a particular address.'''
        raise NotImplementedError
        (yield)

class address(changingchanged):
    """
    This class handles 2-part events that are used to modify comments at an arbitrary
    address. This address will either be a contents tag if it's within the boundaries
    of a function, or a globals tag if it's just some arbitrary address.
    """
    @classmethod
    def get_func_extern(cls, ea):
        """Return the function at the given address and whether the address is a function populated by the rtld (an external).

        This is necessary to determine whether this is an actual function, or is really
        just an address to an import.
        """
        get_flags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags

        # If there's a function defined at our address, then return True (we're an rtld)
        # if we're in an external segment, otherwise we return True if we're not pointing to data.
        f, seg = idaapi.get_func(ea), idaapi.getseg(ea)
        return f, seg.type in {idaapi.SEG_XTRN} if f else (get_flags(ea) & idaapi.as_uint32(idaapi.MS_CLS) == idaapi.FF_DATA)

    @classmethod
    def _update_refs(cls, ea, old, new):
        f, rt = cls.get_func_extern(ea)
        oldkeys, newkeys = ({item for item in content.keys()} for content in [old, new])

        # check the original keys against the modified ones and iterate through
        # them figuring out whether we're removing the key or just adding it.
        logging.debug(u"{:s}.update_refs({:#x}) : Updating old keys ({!s}) to new keys ({!s}){:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(oldkeys), utils.string.repr(newkeys), ' for runtime-linked function' if rt else ''))
        for key in oldkeys ^ newkeys:
            if key not in new:
                logging.debug(u"{:s}.update_refs({:#x}) : Decreasing reference count for {!s} at {:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
                if f and not rt: internal.tags.reference.contents.decrement(ea, key)
                else: internal.tags.reference.globals.decrement(ea, key)
            if key not in old:
                logging.debug(u"{:s}.update_refs({:#x}) : Increasing reference count for {!s} at {:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
                if f and not rt: internal.tags.reference.contents.increment(ea, key)
                else: internal.tags.reference.globals.increment(ea, key)
            continue
        return

    @classmethod
    def _create_refs(cls, ea, content):
        f, rt = cls.get_func_extern(ea)

        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.create_refs({:#x}) : Creating keys ({!s}){:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(contentkeys), ' for runtime-linked function' if rt else ''))
        for key in contentkeys:
            logging.debug(u"{:s}.create_refs({:#x}) : Increasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
            if f and not rt: internal.tags.reference.contents.increment(ea, key)
            else: internal.tags.reference.globals.increment(ea, key)
        return

    @classmethod
    def _delete_refs(cls, ea, content):
        f, rt = cls.get_func_extern(ea)

        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.delete_refs({:#x}) : Deleting keys ({!s}){:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(contentkeys), ' from runtime-linked function' if rt else ''))
        for key in contentkeys:
            logging.debug(u"{:s}.delete_refs({:#x}) : Decreasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
            if f and not rt: internal.tags.reference.contents.decrement(ea, key)
            else: internal.tags.reference.globals.decrement(ea, key)
        return

    @classmethod
    def updater(cls):
        # Receive the new comment and its type from the cmt_changing
        # event. After receiving it, then we can use the address to
        # figure out what the old comment was.
        ea, rpt, new = (yield)
        old = utils.string.of(idaapi.get_cmt(ea, rpt))

        # Decode the comments into their tags (dictionaries), and
        # then update their references before we update the comment.
        f, o, n = idaapi.get_func(ea), internal.comment.decode(old), internal.comment.decode(new)
        cls._update_refs(ea, o, n)

        # Wait for cmt_changed event...
        try:
            newea, nrpt, none = (yield)

        # If we end up catching a GeneratorExit then that's because
        # this event is being violently closed due to receiving a
        # changing event more than once for the very same address.
        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while the {:s} comment at {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), 'repeatable' if rpt else 'non-repeatable', ea, utils.string.repr(old), utils.string.repr(new)))
            return

        # Now to fix the comment the user typed.
        if (newea, nrpt, none) == (ea, rpt, None):
            ncmt = utils.string.of(idaapi.get_cmt(ea, rpt))

            if (ncmt or '') != new:
                logging.warning(u"{:s}.updater() : Comment from event at address {:#x} is different from database. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new), utils.string.repr(ncmt)))

            # If the comment is of the correct format, then we can simply
            # write the comment to the given address.
            if internal.comment.check(new):
                idaapi.set_cmt(ea, utils.string.to(new), rpt)

            # If there's a comment to set, then assign it to the requested
            # address.
            elif new:
                idaapi.set_cmt(ea, utils.string.to(new), rpt)

            # Otherwise, we can just delete all the references at the address.
            else:
                cls._delete_refs(ea, o)
            return

        # If the changed event doesn't happen in the right order.
        logging.fatal(u"{:s}.updater() : Comment events are out of sync at address {:#x}, updating tags from previous comment. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o), utils.string.repr(n)))

        # Delete the old comment and its references.
        cls._delete_refs(ea, o)
        idaapi.set_cmt(ea, '', rpt)
        logging.warning(u"{:s}.updater() : Deleted comment at address {:#x} was {!s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o)))

        # Create the references for the new comment.
        new = utils.string.of(idaapi.get_cmt(newea, nrpt))
        n = internal.comment.decode(new)
        cls._create_refs(newea, n)

    @classmethod
    def changing(cls, ea, repeatable_cmt, newcmt):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changing({:#x}, {:d}, {!s}) : Ignoring address.changing event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, utils.string.repr(newcmt), 'repeatable' if repeatable_cmt else 'non-repeatable', ea))

        # Construct our new state, and then grab our old comment. This is because
        # we're going to submit this to the state that we've constructed after we've
        # disabled the necessary events.
        logging.debug(u"{:s}.changing({:#x}, {:d}, {!s}) : Received address.changing event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, utils.string.repr(newcmt), 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        event, oldcmt = cls.new(ea), utils.string.of(idaapi.get_cmt(ea, repeatable_cmt))

        # First disable our hooks so that we can prevent re-entrancy issues
        [ ui.hook.idb.disable(item) for item in ['changing_cmt', 'cmt_changed'] ]

        # Now we can use our coroutine to begin the comment update, so that
        # later, the "changed" event can do the actual update.
        try:
            event.send((ea, bool(repeatable_cmt), utils.string.of(newcmt)))

        # If a StopIteration was raised when submitting the comment to the coroutine,
        # then something failed and we need to let the user know about it.
        except StopIteration:
            logging.fatal(u"{:s}.changing({:#x}, {:d}, {!s}) : Abandoning {:s} comment at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, utils.string.repr(newcmt), 'repeatable' if repeatable_cmt else 'non-repeatable', ea), exc_info=True)

        # Last thing to do is to re-enable the hooks that we disabled
        finally:
            [ ui.hook.idb.enable(item) for item in ['changing_cmt', 'cmt_changed'] ]

        # And then we can leave..
        return

    @classmethod
    def changed(cls, ea, repeatable_cmt):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {:d}) : Ignoring address.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))

        # Resume the state that was created by the changing event, and then grab
        # our new comment that we will later submit to it.
        logging.debug(u"{:s}.changed({:#x}, {:d}) : Received address.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        event, newcmt = cls.resume(ea), utils.string.of(idaapi.get_cmt(ea, repeatable_cmt))

        # First disable our hooks so that we can prevent re-entrancy issues
        [ ui.hook.idb.disable(item) for item in ['changing_cmt', 'cmt_changed'] ]

        # Now we can use our coroutine to update the comment state, so that the
        # coroutine will perform the final update.
        try:
            event.send((ea, bool(repeatable_cmt), None))

        # If a StopIteration was raised when submitting the comment to the
        # coroutine, then we something bugged out and we need to let the user
        # know about it.
        except StopIteration:
            logging.fatal(u"{:s}.changed({:#x}, {:d}) : Abandoning update of {:s} comment at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea), exc_info=True)

        # Re-enable our hooks that we had prior disabled
        finally:
            [ ui.hook.idb.enable(item) for item in ['changing_cmt', 'cmt_changed'] ]

        # Updating the comment was complete, that should've been it and so we can
        # just close our event since we're done.
        event.close()

    @classmethod
    def old_changed(cls, ea, repeatable_cmt):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.old_changed({:#x}, {:d}) : Ignoring address.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))

        # first we'll grab our comment that the user updated
        logging.debug(u"{:s}.old_changed({:#x}, {:d}) : Received address.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        cmt = utils.string.of(idaapi.get_cmt(ea, repeatable_cmt))
        fn, rt = cls.get_func_extern(ea)

        # if we're in a function but not a runtime-linked one, then we need to
        # to clear the tags for our contents address.
        if fn and not rt:
            internal.tags.reference.contents.erase_address(fn, ea)

        # otherwise, we can simply clear the tags from the global address.
        else:
            internal.tags.reference.globals.erase_address(ea)

        # grab the comment and then re-create its references.
        res = internal.comment.decode(cmt)
        if res:
            cls._create_refs(ea, res)

        # otherwise, there's nothing to do since it's empty.
        else:
            return

        # re-encode the comment back to its address, but not before disabling
        # our hooks that brought us here so that we can avoid any re-entrancy issues.
        ui.hook.idb.disable('cmt_changed')
        try:
            idaapi.set_cmt(ea, utils.string.to(internal.comment.encode(res)), repeatable_cmt)

        # now we can "finally" re-enable our hook
        finally:
            ui.hook.idb.enable('cmt_changed')

        # and then leave because this should've updated things properly.
        return

class globals(changingchanged):
    """
    This class handles 2-part events that are used to modify comments for a particular
    range. In most cases this should be a function comment, or a chunk associated
    with a function, but just to be certain we check the start_ea of the range
    to determine whether we update the global or content tag cache.
    """
    @classmethod
    def _update_refs(cls, fn, old, new):
        oldkeys, newkeys = ({item for item in content.keys()} for content in [old, new])
        logging.debug(u"{:s}.update_refs({:#x}) : Updating old keys ({!s}) to new keys ({!s}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(oldkeys), utils.string.repr(newkeys)))
        for key in oldkeys ^ newkeys:
            if key not in new:
                logging.debug(u"{:s}.update_refs({:#x}) : Decreasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
                internal.tags.reference.globals.decrement(interface.range.start(fn), key)
            if key not in old:
                logging.debug(u"{:s}.update_refs({:#x}) : Increasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
                internal.tags.reference.globals.increment(interface.range.start(fn), key)
            continue
        return

    @classmethod
    def _create_refs(cls, fn, content):
        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.create_refs({:#x}) : Creating keys ({!s}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(contentkeys)))
        for key in contentkeys:
            logging.debug(u"{:s}.create_refs({:#x}) : Increasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
            internal.tags.reference.globals.increment(interface.range.start(fn), key)
        return

    @classmethod
    def _delete_refs(cls, fn, content):
        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.delete_refs({:#x}) : Deleting keys ({!s}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(contentkeys)))
        for key in contentkeys:
            logging.debug(u"{:s}.delete_refs({:#x}) : Decreasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
            internal.tags.reference.globals.decrement(interface.range.start(fn), key)
        return

    @classmethod
    def updater(cls):
        # Receive the new comment and its type from the cmt_changing
        # event. After receiving it, then we can determine what function
        # it's for and then get the function's comment.
        ea, rpt, new = (yield)
        fn = idaapi.get_func(ea)
        old = utils.string.of(idaapi.get_func_cmt(fn, rpt))

        # Decode the old and new function comment into their tags so
        # that we can update their references before the comment.
        o, n = internal.comment.decode(old), internal.comment.decode(new)
        cls._update_refs(fn, o, n)

        # Wait for cmt_changed event...
        try:
            newea, nrpt, none = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while the {:s} function comment at {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), 'repeatable' if rpt else 'non-repeatable', ea, utils.string.repr(old), utils.string.repr(new)))
            return

        # Now we can fix the user's new comment.
        if (newea, nrpt, none) == (ea, rpt, None):
            ncmt = utils.string.of(idaapi.get_func_cmt(fn, rpt))

            if (ncmt or '') != new:
                logging.warning(u"{:s}.updater() : Comment from event for function {:#x} is different from database. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new), utils.string.repr(ncmt)))

            # If the comment is correctly formatted as a tag, then we
            # can simply write the comment at the given address.
            if internal.comment.check(new):
                idaapi.set_func_cmt(fn, utils.string.to(new), rpt)

            # If there's a comment to set, then assign it to the requested
            # function address.
            elif new:
                idaapi.set_func_cmt(fn, utils.string.to(new), rpt)

            # Otherwise, there's no comment there and we need to delete
            # all references at the address.
            else:
                cls._delete_refs(fn, o)
            return

        # If the changed event doesn't happen in the right order.
        logging.fatal(u"{:s}.updater() : Comment events are out of sync for function {:#x}, updating tags from previous comment. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o), utils.string.repr(n)))

        # Delete the old function comment and its references.
        cls._delete_refs(fn, o)
        idaapi.set_func_cmt(fn, '', rpt)
        logging.warning(u"{:s}.updater() : Deleted comment for function {:#x} was ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o)))

        # Create the references for the new function comment.
        newfn = idaapi.get_func(newea)
        new = utils.string.of(idaapi.get_func_cmt(newfn, nrpt))
        n = internal.comment.decode(new)
        cls._create_refs(newfn, n)

    @classmethod
    def changing(cls, cb, a, cmt, repeatable):
        if interface.node.identifier(interface.range.start(a)):
            return logging.debug(u"{:s}.changing({!s}, {:#x}, {!s}, {:d}) : Ignoring globals.changing event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))

        # First we'll check to see if this is an actual function comment by confirming
        # that we're in a function, and that our comment is not empty.
        logging.debug(u"{:s}.changing({!s}, {:#x}, {!s}, {:d}) : Received globals.changing event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        fn = idaapi.get_func(interface.range.start(a))
        if fn is None and not cmt:
            return

        # Construct our new state and grab our old comment so that we can send the
        # old comment to the state after we've disabled the necessary events.
        event, oldcmt = cls.new(interface.range.start(a)), utils.string.of(idaapi.get_func_cmt(fn, repeatable))

        # We need to disable our hooks so that we can prevent re-entrancy issues
        hooks = ['changing_area_cmt', 'area_cmt_changed'] if idaapi.__version__ < 7.0 else ['changing_range_cmt', 'range_cmt_changed']
        [ ui.hook.idb.disable(item) for item in hooks ]

        # Now we can use our coroutine to begin the comment update, so that
        # later, the "changed" event can do the actual update.
        try:
            event.send((interface.range.start(fn), bool(repeatable), utils.string.of(cmt)))

        # If a StopIteration was raised when submitting the comment to the
        # coroutine, then something terrible has happened and we need to let
        # the user know what's up.
        except StopIteration:
            logging.fatal(u"{:s}.changing({!s}, {:#x}, {!s}, {:d}) : Abandoning {:s} function comment at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', ea), exc_info=True)

        # Last thing to do is to re-enable the hooks that we disabled
        finally:
            [ ui.hook.idb.enable(item) for item in hooks ]

        # And then we're ready for the "changed" event
        return

    @classmethod
    def changed(cls, cb, a, cmt, repeatable):
        if interface.node.identifier(interface.range.start(a)):
            return logging.debug(u"{:s}.changed({!s}, {:#x}, {!s}, {:d}) : Ignoring globals.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))

        # First we'll check to see if this is an actual function comment by confirming
        # that we're in a function, and that our comment is not empty.
        logging.debug(u"{:s}.changed({!s}, {:#x}, {!s}, {:d}) : Received globals.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        fn = idaapi.get_func(interface.range.start(a))
        if fn is None and not cmt:
            return

        # Resume the state that was prior created by the changing event, and grab
        # our new comment. As the state keeps track of the old comment and the new
        # one we're going to send to it once we disable some events, it will know
        # what to do.
        event, newcmt = cls.resume(interface.range.start(a)), utils.string.of(idaapi.get_func_cmt(fn, repeatable))

        # We need to disable our hooks so that we can prevent re-entrancy issues
        hooks = ['changing_area_cmt', 'area_cmt_changed'] if idaapi.__version__ < 7.0 else ['changing_range_cmt', 'range_cmt_changed']
        [ ui.hook.idb.disable(item) for item in hooks ]

        # Now we can use our coroutine to update the comment state, so that the
        # coroutine will perform the final update.
        try:
            event.send((interface.range.start(fn), bool(repeatable), None))

        # If a StopIteration was raised when submitting the comment to the
        # coroutine, then we something terrible has happend that the user will
        # likely need to know about.
        except StopIteration:
            logging.fatal(u"{:s}.changed({!s}, {:#x}, {!s}, {:d}) : Abandoning update of {:s} function comment at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', ea), exc_info=True)

        # Last thing to do is to re-enable the hooks that we disabled
        finally:
            [ ui.hook.idb.enable(item) for item in hooks ]

        # We're done updating the comment and our state is done, so we can
        # close it to release it from existence.
        event.close()

    @classmethod
    def old_changed(cls, cb, a, cmt, repeatable):
        if interface.node.identifier(interface.range.start(a)):
            return logging.debug(u"{:s}.old_changed({!s}, {:#x}, {!s}, {:d}) : Ignoring globals.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))

        # first thing to do is to identify whether we're in a function or not,
        # so we first grab the address from the area_t...
        logging.debug(u"{:s}.old_changed({!s}, {:#x}, {!s}, {:d}) : Received globals.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        ea = interface.range.start(a)

        # then we can use it to verify that we're in a function. if not, then
        # this is a false alarm and we can leave.
        fn = idaapi.get_func(ea)
        if fn is None:
            return

        # we're using an old version of ida here, so start out empty
        internal.tags.reference.globals.erase_address(ea)

        # grab our comment here and re-create its refs
        res = internal.comment.decode(utils.string.of(cmt))
        if res:
            cls._create_refs(fn, res)

        # if it's empty, then there's nothing to do and we can leave
        else:
            return

        # now we can simply re-write it it, but not before disabling our hooks
        # that got us here, so that we can avoid any re-entrancy issues.
        ui.hook.idb.disable('area_cmt_changed')
        try:
            idaapi.set_func_cmt(fn, utils.string.to(internal.comment.encode(res)), repeatable)

        # now we can "finally" re-enable our hook
        finally:
            ui.hook.idb.enable('area_cmt_changed')

        # that should've been it, so we can now just leave
        return

class typeinfo(changingchanged):
    # FIXME: should check whether the type was applied as a solid type, or if it
    #        was guessed.
    @classmethod
    def updater(cls):
        # All typeinfo are global tags unless they're being applied to an
        # operand...which is never handled by this class.
        ctx = internal.tags.reference.globals

        # Receive the changing_ti event...
        ea, original, expected = (yield)

        # First check if we need to remove the typeinfo that's stored at the
        # given address. Afterwards we can unpack our original values.
        if any(original):
            ctx.decrement(ea, '__typeinfo__')
        old_type, old_fname = original

        # Wait until we get the ti_changed event...
        try:
            new_ea, tidata = (yield)

        # If we end up catching a GeneratorExit then that's because
        # this event is being violently closed due to receiving a
        # changing event more than once for the very same address.
        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while the type information at {:#x} was being changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ea, bytes().join(original), bytes().join(expected)))
            return

        # Verify that the typeinfo we're changing to is the exact same as given
        # to use by both events. If they're not the same, then we need to make
        # an assumption and that assumption is to take the values given to us
        # by the changing_ti event.
        if (ea, expected) != (new_ea, tidata):
            logging.warning(u"{:s}.updater() : The {:s} event has a different address ({:#x} != {:#x}) and type information ({!r} != {!r}) than what was given by the {:s} event. Using the values from the {:s} event.".format('.'.join([__name__, cls.__name__]), 'ti_changed', ea, new_ea, bytes().join(expected), bytes().join(tidata), 'changing_ti', 'ti_changed'))
        elif ea != new_ea:
            logging.warning(u"{:s}.updater() : The {:s} event has a different address ({:#x} != {:#x}) than what was given by the {:s} event. Using the address {:#x} from the {:s} event.".format('.'.join([__name__, cls.__name__]), 'changing_ti', ea, new_ea, 'ti_changed', ea, 'changing_ti'))
            new_ea = ea
        elif expected != tidata:
            logging.warning(u"{:s}.updater() : The {:s} event for address {:#x} has different type information ({!r} != {!r}) than what was received by the {:s} event. Re-fetching the type information for the address at {:#x}.".format('.'.join([__name__, cls.__name__]), 'changing_ti', ea, bytes().join(expected), bytes().join(tidata), 'ti_changed', new_ea))
            tidata, _, _ = interface.address.typeinfo(ea)

        # Okay, we now have the data that we need to compare in order to determine
        # if we're removing typeinfo, adding it, or updating it. Since we
        # already decremented the tag from the previous address, we really
        # only need to determine if we need to add its reference back.
        if any(tidata):
            ctx.increment(new_ea, '__typeinfo__')
            logging.debug(u"{:s}.updater() : Updated the type information at address {:#x} and {:s} its reference ({!r} -> {!r}).".format('.'.join([__name__, cls.__name__]), new_ea, 'kept' if original == tidata else 'increased', bytes().join(original), bytes().join(tidata)))

        # For the sake of debugging, log that we just removed the typeinfo
        # from the current address. We don't need to decrease our reference
        # here because we did it already when we git our "changing" event.
        else:
            logging.debug(u"{:s}.updater() : Removed the type information from address {:#x} and its reference ({!r} -> {!r}).".format('.'.join([__name__, cls.__name__]), new_ea, bytes().join(original), bytes().join(tidata)))
        return

    @classmethod
    def changing(cls, ea, new_type, new_fname):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Ignoring typeinfo.changing event (not an address) with new type ({!s}) and new name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except exceptions.OutOfBoundsError:
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Ignoring typeinfo.changing event (not a valid address) with new type ({!s}) and new name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname, ea))

        # Extract the previous type information from the given address. If none
        # was found, then just use empty strings because these are compared to the
        # new values by the event.
        logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Received typeinfo.changing for new_type ({!s}) and new_fname ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname))

        ti = interface.address.typeinfo(ea)
        old_type, old_fname, _ = (b'', b'', None) if ti is None else ti.serialize()

        # Construct a new state for this address, and pre-pack both our tuple
        # containing the original type information and the new type information so
        # that we can submit both of them to the state once we disable the events.
        event = cls.new(ea)
        original, new = (old_type, old_fname or b''), (new_type or b'', new_fname or b'')

        # First disable our hooks so that we can prevent re-entrancy issues.
        [ ui.hook.idb.disable(item) for item in ['changing_ti', 'ti_changed'] ]

        # Now we can use our coroutine to begin updating the typeinfo tag. We
        # submit the previous values (prior to the typeinfo being changed) because
        # the "changed" event (which will be dispatched afterwards) is responsible
        # for performing the actual update of the cache.
        try:
            event.send((ea, original, new))

        # If we encounter a StopIteration while submitting the comment, then the
        # coroutine has gone out of control and we need to let the user know.
        except StopIteration:
            logging.fatal(u"{:s}.changed({:#x}, {!s}, {!s}) : Abandoning type information at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), ea), exc_info=True)

        # Last thing to do is to re-enable the hooks that we disabled and then leave.
        finally:
            [ ui.hook.idb.enable(item) for item in ['changing_ti', 'ti_changed'] ]
        return

    @classmethod
    def changed(cls, ea, type, fnames):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {!s}, {!s}) : Ignoring typeinfo.changed event (not an address) with type ({!s}) and name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(type), utils.string.repr(fnames), utils.string.repr(type), fnames, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except exceptions.OutOfBoundsError:
            return logging.debug(u"{:s}.changed({:#x}, {!s}, {!s}) : Ignoring typeinfo.changed event (not a valid address) with type ({!s}) and name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(type), utils.string.repr(fnames), utils.string.repr(type), fnames, ea))

        # Resume the state for the current address, and then take the data from
        # our parameters (which IDA is telling us was just written) and pack
        # them into a tuple. This way we can send them to the state after we
        # disable the necessary hooks to prevent re-entrancy.
        logging.debug(u"{:s}.changed({:#x}, {!s}, {!s}) : Received typeinfo.changed event with type ({!s}) and name ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(type), utils.string.repr(fnames), utils.string.repr(type), fnames))
        event, new = cls.resume(ea), (type or b'', fnames or b'')

        # First disable our hooks so that we can prevent re-entrancy issues.
        [ ui.hook.idb.disable(item) for item in ['changing_ti', 'ti_changed'] ]

        # Now we can use our coroutine to update the typeinfo tag. As IDA was
        # kind enough to provide the new values, we can just submit them to the
        # coroutine.
        try:
            event.send((ea, new))

        # If we encounter a StopIteration while submitting the comment, then the
        # coroutine has terminated unexpectedly which is a pretty critical issue.
        except StopIteration:
            logging.fatal(u"{:s}.changed({:#x}, {!s}, {!s}) : Abandoning update of type information at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(type), utils.string.repr(fnames), ea), exc_info=True)

        # Last thing to do is to re-enable the hooks that we disabled and then
        # close our state since we're done with it and there shouldn't be
        # anything left to do for this address.
        finally:
            [ ui.hook.idb.enable(item) for item in ['changing_ti', 'ti_changed'] ]
        event.close()

### database scope
def on_close():
    '''IDB_Hooks.closebase'''
    import hook
    scheduler = hook.scheduler

    # Database was closed, so we need to reset our state.
    ok, state = any([scheduler.is_initialized(), hook.scheduler.is_loaded(), scheduler.is_ready()]), scheduler.reset()
    if not ok:
        logging.debug(u"{:s}.on_close() : Received unexpected state transition from state {!s} to {!s}.".format(__name__, state, scheduler.database.unavailable))
    else:
        logging.debug(u"{:s}.on_close() : Transition from {!s} to {!s} due to database being closed.".format(__name__, state, scheduler.database.unavailable))
    return

def on_init(idp_modname):
    '''IDP_Hooks.init'''
    import hook
    scheduler = hook.scheduler

    # Database has just been opened, setup the initial state.
    state = scheduler.modulate(scheduler.database.initialized)
    if state is not scheduler.database.unavailable:
        logging.debug(u"{:s}.on_init({!s}) : Received unexpected state transition from {!s} to {!s}.".format(__name__, utils.string.repr(idp_modname), state, scheduler.database.initialized))
    else:
        logging.debug(u"{:s}.on_init({!s}) : Transitioned from {!s} to {!s} during initialization of database.".format(__name__, utils.string.repr(idp_modname), state, scheduler.database.initialized))
    return

def nw_on_init(nw_code, is_old_database):
    idp_modname = idaapi.get_idp_name()
    return on_init(idp_modname)

def on_newfile(fname):
    '''IDP_Hooks.newfile'''
    import hook
    scheduler = hook.scheduler

    # Database has been created, switch the state to loaded.
    if scheduler.is_initialized():
        state = scheduler.modulate(scheduler.database.loaded)
        logging.debug(u"{:s}.on_newfile({!s}) : Transitioned from {!s} to {!s}.".format(__name__, utils.string.repr(fname), state, scheduler.database.loaded))
    else:
        logging.debug(u"{:s}.on_newfile({!s}) : Received unexpected state transition from {!s} to {!s}.".format(__name__, utils.string.repr(fname), scheduler.get(), scheduler.database.loaded))

    # FIXME: save current state like base addresses and such
    __execute_rcfile()

def nw_on_newfile(nw_code, is_old_database):
    if is_old_database:
        return
    fname = idaapi.cvar.database_idb
    return on_newfile(fname)

def on_oldfile(fname):
    '''IDP_Hooks.oldfile'''
    import hook
    scheduler = hook.scheduler

    # Database has been loaded, switch the state to ready.
    if scheduler.is_initialized():
        state = scheduler.modulate(scheduler.database.ready)
        logging.debug(u"{:s}.on_oldfile({!s}) : Transitioned from state {!s} to {!s} while opening up old database.".format(__name__, utils.string.repr(fname), state, scheduler.database.ready))
        __check_functions()
    else:
        logging.debug(u"{:s}.on_oldfile({!s}) : Received unexpected state transition from {!s} to {!s}.".format(__name__, utils.string.repr(fname), scheduler.get(), scheduler.database.ready))

    # FIXME: save current state like base addresses and such
    __execute_rcfile()

def nw_on_oldfile(nw_code, is_old_database):
    if not is_old_database:
        return
    fname = idaapi.cvar.database_idb
    return on_oldfile(fname)

def __check_functions():
    # FIXME: check if tagcache needs to be created
    return

def on_ready():
    '''IDP_Hooks.auto_empty'''
    import hook
    scheduler = hook.scheduler

    # Queues have just been emptied, so now we can enable the relevant hooks.
    if scheduler.is_loaded():
        state = scheduler.modulate(scheduler.database.ready)
        logging.debug(u"{:s}.on_ready() : Transitioned from {!s} to {!s} due to the auto queue being empty.".format(__name__, state, scheduler.database.ready))

        # update tagcache using function state
        __process_functions()

    elif scheduler.is_ready():
        logging.debug(u"{:s}.on_ready() : Ignoring request to transition to {!s} as database is currently at {!s}.".format(__name__, scheduler.database.ready, scheduler.get()))
    else:
        logging.debug(u"{:s}.on_ready() : Received unexpected transition from {!s} to {!s}.".format(__name__, scheduler.get(), scheduler.database.ready))
    return

def auto_queue_empty(type):
    """This waits for the analysis queue to be empty.

    If the database is ready to be tampered with, then we proceed by executing
    the `on_ready` function which will perform any tasks required to be done
    on the database at startup.
    """
    if type == idaapi.AU_FINAL:
        on_ready()
    return

def __process_functions(percentage=0.10):
    """This prebuilds the tag cache and index for the entire database so that we can differentiate tags made by the user and the application.

    It's intended to be called once the database is ready to be tampered with.
    """
    implicit = {'__typeinfo__', '__name__'}
    P, globals = ui.Progress(), {ea : count for ea, count in internal.tags.reference.globals.iterate()}

    # Now we need to gather all of our imports so that we can clean up any functions
    # that are runtime-linked addresses. This is because IDA seems to create a
    # func_t for certain imports.
    imports = {item for item in []}
    for idx in range(idaapi.get_import_module_qty()):
        idaapi.enum_import_names(idx, lambda address, name, ordinal: imports.add(address) or True)

    # Now that we have our imports, we can iterate through all of the functions.
    total, funcs = 0, [ea for ea in database.functions()]
    P.update(current=0, max=len(funcs), title=u"Pre-building the tag cache and its index...")
    P.open()
    six.print_(u"Indexing the tags for {:d} functions.".format(len(funcs)))
    for i, fn in enumerate(funcs):
        chunks = [interface.range.bounds(item) for item in interface.function.chunks(fn)]

        # Check to see if the progress bar was cancelled for "some reason". If
        # so, we double-check if that's what the user really wanted.
        if P.canceled:
            six.print_(u"User opted to cancel building the tag cache at function {:#x} ({:d} of {:d}) after having indexed {:d} tag{:s}.".format(fn, 1 + i, len(funcs), total, '' if total == 1 else 's'))

            # Confirm with the user that they really don't care for indexing.
            message = []
            start, stop = interface.address.bounds()
            message.append(u"We are {:.02f}% complete at function {:#x} ({:d} of {:d}) having indexed only {:d} tag{:s} for the range {:#x}<>{:#x}.".format(100. * i / float(len(funcs)), fn, 1 + i, len(funcs),  total, '' if total == 1 else 's', start, stop))
            message.append(u"If you cancel now, some of the notations made by the application prior to this process will be non-queryable via select.")
            message.append(u'Are you sure?')
            if ui.ask.yn('\n'.join(message), no=True):
                six.print_(u"User aborted the build of the tag cache at function {:#x} ({:d} of {:d}) and has indexed only {:d} tag{:s}.".format(fn, 1 + i, len(funcs), total, '' if total == 1 else 's'))
                break

            # Okay, so they changed their mind...
            six.print_(u"Resuming build of tag cache at function {:#x} ({:d} of {:d}) with {:d} tag{:s} having been indexed.".format(fn, 1 + i, len(funcs), total, '' if total == 1 else 's'))
            P.canceled = False

        # If the current function is in our imports, then we skip it because
        # it's a runtime-linked address and shouldn't have been cached anyways.
        if fn in imports:
            continue

        # Update the progress bar with the current function we're working on.
        text = functools.partial(u"Processing function {:#x} ({chunks:d} chunk{plural:s}) -> {:d} of {:d}".format, fn, 1 + i, len(funcs))
        P.update(current=i)
        ui.navigation.procedure(fn)
        if i % (int(len(funcs) * percentage) or 1) == 0:
            six.print_(u"Processing function {:#x} -> {:d} of {:d} ({:.02f}%)".format(fn, 1 + i, len(funcs), i / float(len(funcs)) * 100.0))

        # If the current function is not in our globals, but it has a name tag, then
        # we need to include it. IDA seems to name some addresses before promoting
        # them to a function.
        available = {} if fn in globals else internal.tags.function.get(fn)
        if fn not in globals and available:
            [ internal.tags.reference.globals.increment(fn, k) for k in implicit if k in available ]

        # Grab the currently existing cache for the current function, and use
        # it to tally up all of the reference counts for the tags.
        contents = {item for item in internal.tags.reference.contents.address(fn, target=fn)}
        for ci, (l, r) in enumerate(chunks):
            P.update(text=text(chunks=len(chunks), plural='' if len(chunks) == 1 else 's'), tooltip="Chunk #{:d} : {:#x} - {:#x}".format(ci, l, r))

            # Iterate through each address in the function, only updating the
            # references for tags that are not in our set of implicit ones. If
            # the address is a global, then we decrement out of the globals
            # because we're at a function entrypoint and want to make sure that
            # we only grab the contents address.
            for ea in interface.address.items(ui.navigation.analyze(l), r):
                available = {k for k in internal.tags.address.get(ea)}
                used_globally = internal.tags.reference.globals.get(ea)
                for k in available - implicit:
                    if ea in globals and k in used_globally: internal.tags.reference.globals.decrement(ea, k)
                    if ea not in contents: internal.tags.reference.contents.increment(ea, k, target=fn)
                    total += 1
                continue
            continue
        continue
    else:
        six.print_(u"Successfully seeded the tag cache with its index which was composed of {:d} tag{:s}.".format(total, '' if total == 1 else 's'))
    P.close()

def __execute_rcfile():
    '''Look in the current IDB directory for an rcfile that might need to be executed.'''
    ns, filename = sys.modules['__main__'].__dict__ if '__main__' in sys.modules else globals(), 'idapythonrc.py'
    path = database.information.path(filename)

    try:
        with open(path) as infile:
            logging.warning(u"{:s}.execute_rcfile() : Found a `{:s}` file to execute in the database directory at `{:s}`.".format(__name__, filename, path))
            exec(infile.read(), ns, ns)

    except IOError:
        logging.info(u"{:s}.execute_rcfile() : Skipping execution of `{:s}` file as it does not exist at `{:s}`.".format(__name__, filename, path))
    except Exception:
        logging.warning(u"{:s}.execute_rcfile() : Unexpected exception raised while trying to execute `{:s}`.".format(__name__, path), exc_info=True)
    return

def relocate(info):
    """This is for when the user relocates a number of segments in newer versions of IDA.

    We update the entire database in two parts. First we iterate through all
    the functions, and transform its cache to its new address. Next we iterate
    through all of the known global tags and then transform those. As we don't
    receive the "changed_netmap" parameter, we don't know whether IDA has actually
    relocated the netnodes or not.
    """
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name
    functions, globals = map(utils.fcompose(sorted, list), [database.functions(), internal.tags.reference.globals.iterate()])

    # First we need to sanity check what we've been asked to do and then we
    # disable the auto-analysis so that IDA doesn't change anything as we're
    # modifying the netnodes. We preserve this for restoration later.
    if info.size() == 0:
        return logging.warning(u"{:s}.relocate({!s}) : Ignoring request to relocate {:d} segments.".format(__name__, [], info.size()))

    # Output the amount of work (number of segments) that we'll need to perform.
    scount, segmap = info.size(), {info[si].to : info[si]._from for si in range(info.size())}
    listable = sorted(segmap)
    logging.info(u"{:s}.relocate({:#x}, {:#x}) : Relocating the tag cache and index for {:d} segment{:s}.".format(__name__, segmap[listable[0]], listable[0], scount, '' if scount == 1 else 's'))

    # Now we'll need to iterate through our functions and globals in order to filter
    # them and calculate the number of items we'll be expecting to process.
    count = sum(1 for ea in functions if any(info[si].to <= ea <= info[si].to + info[si].size for si in range(info.size())))
    count+= sum(1 for ea, _ in globals if any(info[si]._from <= ea <= info[si]._from + info[si].size for si in range(info.size())))

    # Create our progress bar that we'll continuously update using the number of
    # items that we just calculated from filtering our functions and globals.
    P = ui.Progress()
    P.update(current=0, min=0, max=count, title=u"Relocating the tag cache and index for {:d} segment{:s}...".format(scount, '' if scount == 1 else 's'))
    fcount = gcount = 0

    # Iterate through each work item (segment) in order to process them.
    P.open()
    for si in range(scount):
        seg = idaapi.getseg(info[si].to)

        # If the user canceled this process, then really confirm things. Because if they
        # abort this process, then the index will be desynchronized. Or really, it'll be
        # completely out-of-sync and should likely be removed since it's corrupt.
        if P.canceled:
            message = []
            message.append(u'If you abort this process, the tag cache and its index will become desynchronized (corrupt) which will result in spectacular failures when querying.')
            message.append(u"We are currently relocating segment {:d} of {:d} from {:#x} to {:#x}.".format(1 + si, scount, info[si]._from, info[si].to))
            message.append(u'Are you REALLY sure?')
            if ui.ask.yn('\n'.join(message), no=True):
                six.print_(u"User aborted relocating the tag cache and its index at segment {:d} of {:d} from {:#x} to {:#x}.".format(1 + si, scount, info[si]._from, info[si].to))
                break
            P.canceled = False

        # Format the description for the current work item (segment) that we're processing.
        description = "{:d} of {:d}{:s}".format(1 + si, scount, " ({:s})".format(get_segment_name(seg)) if seg else '') if scount > 1 else "{:s}".format(get_segment_name(seg) if seg else '')
        msg = u"Relocating the tag cache and index for segment{:s}: {:#x} ({:+#x}) -> {:#x}".format(" {:s}".format(description) if description else '', info[si]._from, info[si].size, info[si].to)
        P.update(title=msg), six.print_(msg)

        # Iterate through each function that was moved and relocate its contents. If we're
        # using a version of IDA prior to 7.3, then when our event has been dispatched
        # the netnodes have already been moved.
        listable = [ea for ea in functions if info[si].to <= ea < info[si].to + info[si].size]
        for i, offset in __relocate_function(info[si]._from, info[si].to, info[si].size, (item for item in listable), moved=True if idaapi.__version__ < 7.3 else False):
            name = interface.name.get(info[si].to + offset)
            text = u"Relocating function {:d} of {:d}{:s}: {:#x} -> {:#x}".format(1 + i, len(listable), " ({:s})".format(name) if name else '', info[si]._from + offset, info[si].to + offset)
            P.update(value=sum([fcount, gcount, i]), text=text)
            ui.navigation.procedure(info[si].to + offset)
        fcount += len(listable)

        # Iterate through all of the globals that were moved.
        listable = [(ea, count) for ea, count in globals if info[si]._from <= ea < info[si]._from + info[si].size]
        for i, offset in __relocate_globals(info[si]._from, info[si].to, info[si].size, (item for item in listable)):
            name = interface.name.get(info[si].to + offset)
            text = u"Relocating global {:d} of {:d}{:s}: {:#x} -> {:#x}".format(1 + i, len(listable), " ({:s})".format(name) if name else '', info[si]._from + offset, info[si].to + offset)
            P.update(value=sum([fcount, gcount, i]), text=text)
            ui.navigation.analyze(info[si].to + offset)
        gcount += len(listable)
    P.close()

def __relocate_function(old, new, size, iterable, moved=False):
    """Relocate the function addresses in `iterable` from address `old` to `new` adjusting them by the specified `size`.

    If `moved` is specified as true, then the netnodes are already at their target
    as per "Move Segment(s)". Otherwise they're still at their original address
    which happens when the database has been relocated via "Rebase Program".
    """
    failure, total, index = [], [item for item in iterable], {ea : keys for ea, keys in internal.tags.reference.contents.iterate() if old <= ea < old + size}

    for i, fn in enumerate(total):
        offset = fn - new
        source, target = offset + old, offset + new

        # Grab the contents tags from the former function's netnode. If the netnode has
        # already been moved, then use the function we were given. Otherwise we can just
        # use the old offset.
        try:
            state = internal.tagcache.contents.function(target if moved else source, offset + old)
            counts = internal.tagcache.contents.functiontags(target if moved else source, offset + old)

        except exceptions.FunctionNotFoundError:
            logging.fatal(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Unable to locate the original function address ({:#x}) while trying to transform to {:#x}.".format(__name__, old, new, size, iterable, offset + old, offset + new), exc_info=True)
            state = None

        # If there was no read state then there's nothing to do. So we just
        # continue to the next iteration (without yielding) for performance.
        if state is None:
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Skipping contents of function {:#x} due to no state being stored at {:#x}.".format(__name__, old, new, size, iterable, fn, fn if moved else (offset + old)))
            continue

        # Erase the old contents tags since we've already loaded its state.
        internal.tags.reference.contents.erase(source)
        logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cleared contents of function {:#x} at old address {:#x}.".format(__name__, old, new, size, iterable, fn, offset + old))

        # If there wasn't a value in our contents index, then warn the user
        # before we remove it. We use this later to figure out any strays.
        if not operator.contains(index, source):
            logging.warning(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Found contents for function {:#x} at old address {:#x} that wasn't in index.".format(__name__, old, new, size, iterable, fn, source))
        index.pop(source, None)

        # Update the state containing the old addresses with the newly transformed ones.
        res, newstate = state, {ea - old + new : ref for ea, ref in state.items()}

        # Copy the original counts into the new function, and write the modified
        # state with translated addresses back to the function's tagcache.
        copied = internal.tagcache.contents.setfunctiontags(fn, fn, counts)
        replaced = internal.tagcache.contents.setfunction(fn, fn, newstate)

        # If anything failed, then log it, stash it, and continue to the next one.
        if copied is None or replaced is None:
            logging.fatal(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Failure trying to write reference count for function {:#x} while trying to update old reference count ({!s}) to new one ({!s}).".format(__name__, old, new, size, iterable, fn, utils.string.repr(res), utils.string.repr(newstate)))
            failure.append((fn, res, newstate))

        # We successfully processed this function, so yield its index and offset.
        logging.debug(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Relocated {:d} content locations for function {:#x} using delta {:+#x}.".format(__name__, old, new, size, iterable, len(newstate), fn, new - old))
        yield i, offset

    # Now we need to gather all of our imports so that we can clean up any functions
    # that are runtime-linked addresses. This is because IDA seems to create a
    # func_t for certain imports.
    imports = {item for item in []}
    for idx in range(idaapi.get_import_module_qty()):
        idaapi.enum_import_names(idx, lambda address, name, ordinal: imports.add(address) or True)

    # Iterate through our index grabbing anything that's in our imports.
    items = {ea - old + new for ea in index}
    for ea in items & imports:
        offset = ea - new
        source, target = offset + old, offset + new
        logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Removing contents of runtime-linked function ({:#x}) from index at {:#x}.".format(__name__, old, new, size, iterable, target, source))
        internal.tags.reference.contents.erase(source)
        index.pop(source)

    # Last thing to do is to clean up the stray contents from the index that weren't
    # pointing to a function anyways.
    for ea, keys in index.items():
        offset = ea - old
        source, target = offset + old, offset + new
        fn, ch = idaapi.get_func(target), idaapi.get_fchunk(target)

        # Check that this stray isn't pointing to an actual function before we
        # continue to remove it from the netnode. If it is, then we skip processing.
        if fn is None:
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Discarding cache at {:#x} should've been relocated to {:#x} but is not part of a function anymore.".format(__name__, old, new, size, iterable, ea, target))
        elif interface.range.start(ch) == interface.range.start(fn) == target:
            logging.critical(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Refusing to clean up index for {:#x} as it has been relocated to {:#x} which is in use by function ({:#x}).".format(__name__, old, new, size, iterable, ea, offset + new, interface.range.start(ch)))
            continue
        elif ch.flags & idaapi.FUNC_TAIL:
            owners = [item for item in interface.function.owners(target)]
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cache at {:#x} should've been relocated to {:#x} but is a tail associated with more than one function ({:s}).".format(__name__, old, new, size, iterable, ea, target, ', '.join(map("{:#x}".format, owners))))
        else:
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cache at {:#x} should've been relocated to {:#x} but its boundaries ({:#x}<>{:#x}) do not correspond with a function ({:#x}).".format(__name__, old, new, size, iterable, ea, target, interface.range.start(ch), interface.range.end(ch), interface.range.start(fn)))

        # Now we know why this address is within our index, so all that
        # we really need to do is to remove it.
        internal.tags.reference.contents.erase(ea)
        logging.debug(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cleared stray contents for {:#x} at old address {:#x}.".format(__name__, old, new, size, iterable, offset + new, offset + old))
    return

def __relocate_globals(old, new, size, iterable):
    '''Relocate the global tuples (address, count) in `iterable` from address `old` to `new` adjusting them by the specified `size`.'''
    failure, total = [], [item for item in iterable]
    for i, (ea, count) in enumerate(total):
        offset = ea - old

        # Remove the old address from the netnode cache (altval) with our global.
        Fget_tags = internal.tags.function.get if idaapi.get_func(new + offset) else internal.tags.address.get
        tags = {tag for tag in Fget_tags(new + offset)}
        if not internal.tags.reference.globals.erase_address(ea):
            logging.fatal(u"{:s}.relocate_globals({:#x}, {:#x}, {:+#x}, {!r}) : Failure trying to remove reference count ({!r}) for global {:#x}.".format(__name__, old, new, size, iterable, count, ea))

        # Now we can re-add the new address to the netnode cache (altval).
        incremented = [internal.tags.reference.globals.increment(new + offset, tag) for tag in tags]
        if len(incremented) != len(tags):
            logging.fatal(u"{:s}.relocate_globals({:#x}, {:#x}, {:+#x}, {!r}) : Failure trying to store reference count ({!r}) from {:#x} to {:#x}.".format(__name__, old, new, size, iterable, count, ea, new + offset))
            failure.append((ea, new + offset, count))

        # Yield the offset to the global that we just processed.
        logging.debug(u"{:s}.relocate_globals({:#x}, {:#x}, {:+#x}, {!r}) : Relocated count ({:d}) for global {:#x} from {:#x} to {:#x}.".format(__name__, old, new, size, iterable, count, ea, old + offset, new + offset))
        yield i, offset
    return

def segm_start_changed(s, *oldstart):
    # XXX: since changing the segment boundaries shouldn't really modify the
    #      types of any tags, this doesn't need to do anything.
    return

def segm_end_changed(s, *oldend):
    # XXX: since changing the segment boundaries shouldn't really modify the
    #      types of any tags, this doesn't need to do anything.
    return

def segm_moved(source, destination, size, changed_netmap):
    """This is for when the user relocates an individual segment on older versions of IDA (6.9 and earlier).

    The segment is updated in two parts. First we itreate through the functions
    and relocate their cache to the destination address. Afterwards, we iterate
    through all the global tags and relocate those.
    """
    get_segment_name = idaapi.get_segm_name if hasattr(idaapi, 'get_segm_name') else idaapi.get_true_segm_name
    seg = idaapi.getseg(destination)

    # Pre-calculate our search boundaries, collect all of the functions and globals,
    # and then total the number of items that we expect to process.
    functions = sorted(ea for ea in database.functions() if destination <= ea < destination + size)
    globals = sorted((ea, count) for ea, count in internal.tags.reference.globals.iterate() if source <= ea < source + size)
    logging.info(u"{:s}.segm_moved({:#x}, {:#x}, {:+#x}) : Relocating tagcache for segment {:s}.".format(__name__, source, destination, size, get_segment_name(seg)))
    count = sum(map(len, [functions, globals]))

    # Create our progress bar that includes a title describing what's going on and
    # output it to the console so the user can see it.
    P, msg = ui.Progress(), u"Relocating tagcache for segment {:s}: {:#x} ({:+#x}) -> {:#x}".format(get_segment_name(seg), source, size, destination)
    P.update(current=0, min=0, max=count, title=msg), six.print_(msg)
    P.open()

    # Iterate through each function that we're moving and relocate its contents.
    for i, offset in __relocate_function(source, destination, size, (item for item in functions), moved=not changed_netmap):
        name = interface.name.get(destination + offset)
        text = u"Relocating function {:d} of {:d}{:s}: {:#x} -> {:#x}".format(1 + i, len(functions), " ({:s})".format(name) if name else '', source + offset, destination + offset)
        P.update(value=i, text=text)
        ui.navigation.procedure(destination + offset)

    # Iterate through each global that we're moving (we use the target address, because IDA moved everything already).
    for i, offset in __relocate_globals(source, destination, size, (item for item in globals)):
        name = interface.name.get(destination + offset)
        text = u"Relocating global {:d} of {:d}{:s}: {:#x} -> {:#x}".format(1 + i, len(globals), " ({:s})".format(name) if name else '', source + offset, destination + offset)
        P.update(value=len(functions) + i, text=text)
        ui.navigation.analyze(destination + offset)
    P.close()

# address naming
class naming(changingchanged):
    @classmethod
    def updater(cls):
        get_flags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags

        # We first just need to grab the address, the new name, and the old one.
        ea, expected = (yield)
        original = idaapi.get_ea_name(ea, idaapi.GN_LOCAL)

        # Now that we have the names, we need to figure out how
        # the name is going to change. For this we use the flags
        # to check if we're changing from a label to a custom name.
        flags = get_flags(ea)
        labelQ, customQ = (flags & item == item for item in [idaapi.FF_LABL, idaapi.FF_NAME])

        # Next we just need to grab the changes.
        try:
            new_ea, new_name, local_name = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while the name at {:#x} was being changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ea, original, expected))
            return

        # And then we double-check that everything matches. If expected is
        # cleared, but new_name holds some value then it's likely because
        # IDA chose some automatic name and so we have to make an assumption.
        if (ea, expected) != (new_ea, expected and new_name):
            prefix = expected.split('_', 1)

            # If the prefix is in one of our known names, then demote the loglevel.
            Flogging = logging.info if prefix[0] in {'sub', 'byte', 'loc'} else logging.fatal
            Flogging(u"{:s}.updater() : Rename is at address {:#x} has desynchronized. Target address at {:#x} should have been renamed from {!r} to {!r} but {!r} was received instead.".format('.'.join([__name__, cls.__name__]), ea, new_ea, original, expected, new_name))
            return

        # Now we use the address to figure out which context that we'll
        # need to update. If we're not in a function or the address is an
        # external segment, then we're in the global context.
        fn = idaapi.get_func(ea)
        if fn is None or idaapi.segtype(ea) in {idaapi.SEG_XTRN}:
            if local_name and fn is None:
                logging.warning(u"{:s}.updater() : Received rename for address {:#x} where \"{:s}\" is set ({!s}) but the address is not within a function.".format('.'.join([__name__, cls.__name__]), ea, 'local_name', local_name))
            context, target = internal.tags.reference.globals, None

        # If we're renaming the beginning of a function, then we're also
        # in the global context unless it's considered a "local_name".
        elif interface.range.start(fn) == ea and not local_name:
            context, target = internal.tags.reference.globals, None

        # Otherwise, we're inside a function and we should be good.
        else:
            context, target = internal.tags.reference.contents, interface.range.start(fn)

        # Next thing to do is to verify whether we're adding a new name,
        # removing one, or adding one. If the names are the same, then skip.
        if expected == original:
            pass

        # If our new_name is cleared, then we're removing it.
        elif not expected:
            context.decrement(new_ea, '__name__') if target is None else context.decrement(new_ea, '__name__', target=target)
            logging.info(u"{:s}.updater() : Decremented {:s} reference for rename at {:#x} due to removal of {!r}.".format('.'.join([__name__, cls.__name__]), 'global' if target is None else 'content', ea, original))

        # If our previous name nonexistent, or is a label (and not custom) then we add the reference.
        elif not original or (labelQ and not customQ):
            context.increment(new_ea, '__name__') if target is None else context.increment(new_ea, '__name__', target=target)
            logging.info(u"{:s}.updater() : Incremented {:s} reference for rename at {:#x} from original {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), 'global' if target is None else 'content', ea, original, expected))

        # If it was both a label and it was custom, then log a warning because we have no idea.
        elif labelQ and customQ:
            logging.debug(u"{:s}.updater() : Ignoring existing symbol rename ({:s}) received as a {:s} reference for at {:#x} from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ', '.join(itertools.chain(['FF_LABL'] if labelQ else [], ['FF_NAME'] if customQ else [])), 'global' if target is None else 'content', ea, original, expected))

        # Debug log showing that we didn't have to do anything.
        else:
            logging.debug(u"{:s}.updater() : Skipping rename at {:#x} from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ea, original, expected))
        return

    @classmethod
    def changing(cls, ea, new_name):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changing({:#x}, {!r}) : Ignoring naming.changing event (not an address) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, ea))

        # If we're not an identifier, then construct our new state.
        event = cls.new(ea)
        try:
            event.send((ea, new_name))
        except StopIteration:
            logging.fatal(u"{:s}.changing({:#x}, {!r}) : Abandoning rename at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), ea, new_name, ea), exc_info=True)
        return

    @classmethod
    def changed(cls, ea, new_name, local_name):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {!r}, {!s}) : Ignoring naming.changed event (not an address) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, local_name, ea))

        # If we're not changing an identifier, then resume where we left off.
        event = cls.resume(ea)
        try:
            event.send((ea, new_name, local_name))

        # If we get a StopIteration, then the coroutine has terminated unexpected
        # and we need to warn the user about what happened.
        except StopIteration:
            logging.fatal(u"{:s}.changed({:#x}, {!r}, {!s}) : Abandoning update of name at {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), ea, new_name, local_name, ea), exc_info=True)
        event.close()

    @classmethod
    def rename(cls, ea, new_name):
        """This hook is when a user adds a name or removes it from the database.

        We simply increase the reference count for the "__name__" key, or decrease it
        if the name is being removed.
        """
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.rename({:#x}, {!r}) : Ignoring rename event (not an address) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, ea))

        fl = idaapi.getFlags(ea) if idaapi.__version__ < 7.0 else idaapi.get_full_flags(ea)
        labelQ, customQ = (fl & item == item for item in [idaapi.FF_LABL, idaapi.FF_NAME])
        fn = idaapi.get_func(ea)

        # figure out whether a global or function name is being changed, otherwise it's the function's contents
        ctx = internal.tags.reference.globals if not fn or (interface.range.start(fn) == ea) else internal.tags.reference.contents

        # if a name is being removed
        if not new_name:
            # if it's a custom name
            if (not labelQ and customQ):
                ctx.decrement(ea, '__name__')
                logging.debug(u"{:s}.rename({:#x}, {!r}) : Decreasing reference count for tag {!r} at address due to an empty name.".format('.'.join([__name__, cls.__name__]), ea, new_name, '__name__'))
            return

        # if it's currently a label or is unnamed
        if (labelQ and not customQ) or all(not q for q in {labelQ, customQ}):
            ctx.increment(ea, '__name__')
            logging.debug(u"{:s}.rename({:#x}, {!r}) : Increasing reference count for tag {!r} at address due to a new name.".format('.'.join([__name__, cls.__name__]), ea, new_name, '__name__'))
        return

class extra_cmt(changingchanged):
    """
    This class is pretty much just a namespace for finding information about the
    extra comments in order to distinguish whether the comment is being added or
    removed.

    FIXME: This has an issue in that the tag cache is not properly cleaned up as
           we're unable to distinguish whether an extra comment is being created
           or just updated. Because of this, any update of an extra comment will
           result in its reference being increased more than once which then makes
           it impossible to remove without either completely removing and reapplying
           the tags for the address or keeping track of all the extra comments in
           a dictionary of some kind. If the latter is chosen, then we'd need to
           query the entire database for both types of extra comments. If the
           prior is chosen, then we'd need to implement the logic for all of the
           implicit tags in order to zero them entirely prior to re-applying them
           which would result in us losing track of the "__name__" tag.
    """
    MAX_ITEM_LINES = (idaapi.E_NEXT - idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV - idaapi.E_NEXT

    @classmethod
    def Fcount(cls, ea, base):
        sup = internal.netnode.sup
        for index in range(cls.MAX_ITEM_LINES):
            row = sup.get(ea, base + index, type=memoryview)
            if row is None: break
        return index or None

    @classmethod
    def is_prefix(cls, line_idx):
        return idaapi.E_PREV <= line_idx < idaapi.E_PREV + cls.MAX_ITEM_LINES

    @classmethod
    def is_suffix(cls, line_idx):
        return idaapi.E_NEXT <= line_idx < idaapi.E_NEXT + cls.MAX_ITEM_LINES

    @classmethod
    def changed(cls, ea, line_idx, cmt):
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Ignoring extra_cmt.changed event (not an address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except exceptions.OutOfBoundsError:
            return logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Ignoring extra_cmt.changed event (not a valid address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Determine whether we'll be updating the contents or a global.
        logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Processing event at address {:#x} for index {:d}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, utils.string.repr(cmt), ea, line_idx))
        ctx = internal.tags.reference.contents if idaapi.get_func(ea) else internal.tags.reference.globals

        # Figure out what the line_idx boundaries are so that we can use it to check
        # whether there's an "extra" comment at the given address, or not.
        if cls.is_prefix(line_idx):
            base_idx, tag = idaapi.E_PREV, '__extra_prefix__'
        elif cls.is_suffix(line_idx):
            base_idx, tag = idaapi.E_NEXT, '__extra_suffix__'
        else:
            return logging.fatal(u"{:s}.changed({:#x}, {:d}, {!r}) : Unable to determine type of extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Check if this is not the first line_idx. If it isn't, then we can simply leave
        # because all we care about is whether there's a comment here or not.
        if line_idx not in {base_idx}:
            return logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Exiting event for address {:#x} due to the index ({:d}) not pointing to the comment start ({:d}).".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, ea, line_idx, base_idx))

        # Now we need to figure out whether we've added an extra_cmt, or removed it.
        if cmt is None:
            return ctx.decrement(ea, tag)

        # XXX: If an "extra" comment is updated more than once, then we unfortunately
        #      lose track of the reference and it's permanently cached. There's nothing
        #      we can really do here except for keep a complete state of all of the
        #      extra comments that the user has created.
        return ctx.increment(ea, tag)

    @classmethod
    def changed_multiple(cls, ea, line_idx, cmt):
        """
        This implementation is deprecated, but is being preserved as the logic that
        it uses can be reused if the workaround methodology of zero'ing the refcount
        for the entire address is applied.
        """

        # First check that we're not an identifier, because we don't care about
        # caching these.
        if interface.node.identifier(ea):
            return logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}) : Ignoring extra_cmt.changed event (not an address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except exceptions.OutOfBoundsError:
            return logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}) : Ignoring extra_cmt.changed event (not a valid address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # XXX: this function is now busted in later versions of IDA because for some
        #      reason, Ilfak, is now updating the extra comment prior to dispatching
        #      this event. unfortunately, our tag cache doesn't allow us to identify
        #      the actual number of tags that are at an address, so there's no way
        #      to identify the actual change to the extra comment that the user made,
        #      which totally fucks up the reference count. with the current
        #      implementation, if we can't distinguish between the old and new extra
        #      comments, then it's simply a no-op. this is okay for now...

        oldcmt = internal.netnode.sup.get(ea, line_idx, type=memoryview)
        if oldcmt is not None: oldcmt = oldcmt.tobytes().rstrip(b'\0')
        logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}) : Processing event at address {:#x} for line {:d} with previous comment set to {!r}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, ea, line_idx, oldcmt))
        ctx = internal.tags.reference.contents if idaapi.get_func(ea) else internal.tags.reference.globals

        MAX_ITEM_LINES = (idaapi.E_NEXT - idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV - idaapi.E_NEXT
        prefix = (idaapi.E_PREV, idaapi.E_PREV + MAX_ITEM_LINES, '__extra_prefix__')
        suffix = (idaapi.E_NEXT, idaapi.E_NEXT + MAX_ITEM_LINES, '__extra_suffix__')

        for l, r, key in [prefix, suffix]:
            if l <= line_idx < r:
                if oldcmt is None and cmt is not None: ctx.increment(ea, key)
                elif oldcmt is not None and cmt is None: ctx.decrement(ea, key)
                logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}, oldcmt={!r}) : {:s} reference count at address for tag {!r}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, oldcmt, 'Increasing' if oldcmt is None and cmt is not None else 'Decreasing' if oldcmt is not None and cmt is None else 'Doing nothing to', key))
            continue
        return

### individual tags
def item_color_changed(ea, color):
    '''This hook is for when a color is applied to an address.'''
    DEFCOLOR = 0xffffffff

    # First make sure it's not an identifier, as if it is then we
    # need to terminate early because the tag cache doesn't care
    # about this stuff.
    if interface.node.identifier(ea):
        return

    # Now we need to distinguish between a content or global tag so
    # that we can look it up to see if we need to remove it or add it.
    ctx = internal.tags.reference.contents if idaapi.get_func(ea) else internal.tags.reference.globals

    # FIXME: we need to figure out if the color is being changed, updated or
    #        removed. unfortunately, the event we receive only happens after the
    #        color has been applied. this means that there's just no way to
    #        identify whether an already existing color is being changed to
    #        another color resulting in the reference count always being
    #        incremented. ideally, we could work around this if the tagging
    #        backend was actually updated to track more than just tag counts.

    # If the color was restored, then we need to decrease its ref.
    if color in {DEFCOLOR}:
        ctx.decrement(ea, '__color__')

    # The color is being applied, so we can just increase its reference.
    else:
        ctx.increment(ea, '__color__')
    return

### function scope
def thunk_func_created(pfn):
    # XXX: This might be interesting to track, but the disassembler generally
    #      removes them unless they're actually referenced by something.
    pass

def func_tail_appended(pfn, tail):
    """This hook is for when a chunk is appended to a function.

    If the tail we were given only has one owner, then that means we need to
    demote the tags for the tail from globals to contents tags. If there's more
    than one, then we simply add the references in the tail to the function.
    """
    bounds = interface.range.bounds(tail)
    referrers = [fn for fn in interface.function.owners(bounds.left)]

    # If the number of referrers is larger than just 1, then the tail is
    # owned by more than one function. We still doublecheck, though, to
    # ensure that our pfn is still in the list.
    if len(referrers) > 1:
        if not operator.contains(referrers, interface.range.start(pfn)):
            logging.warning(u"{:s}.func_tail_appended({:#x}, {!s}) : Adjusting contents of function ({:#x}) but function was not found in the owners ({:s}) of chunk {!s}.".format(__name__, interface.range.start(pfn), bounds, interface.range.start(pfn), ', '.join(map("{:#x}".format, referrers)), bounds))

        # Now we just need to iterate through the tail, and tally up
        # the tags for the function in pfn.
        for ea in interface.address.items(*bounds):
            for k in internal.tags.address.get(ea):
                internal.tags.reference.contents.increment(ea, k, target=interface.range.start(pfn))
                logging.debug(u"{:s}.func_tail_appended({:#x}, {!s}) : Adding reference for tag ({:s}) at {:#x} to cache for function {:#x}.".format(__name__, interface.range.start(pfn), bounds, utils.string.repr(k), ea, interface.range.start(pfn)))
            continue
        return

    # Otherwise if there was only one referrer, then that means this
    # tail is being demoted from globals tags to contents that are
    # owned by the function in pfn.
    if not operator.contains(referrers, interface.range.start(pfn)):
        logging.warning(u"{:s}.func_tail_appended({:#x}, {!s}) : Demoting globals in {!s} and adding them to the cache for function {:#x} but function was not found in the owners ({:s}) of chunk {!s}.".format(__name__, interface.range.start(pfn), bounds, bounds, interface.range.start(pfn), ', '.join(map("{:#x}".format, referrers)), bounds))

    # All we need to do is to iterate through the tail, and adjust
    # any references by exchanging them with the cache for pfn.
    for ea in interface.address.items(*bounds):
        for k in internal.tags.address.get(ea):
            internal.tags.reference.globals.decrement(ea, k)
            internal.tags.reference.contents.increment(ea, k, target=interface.range.start(pfn))
            logging.debug(u"{:s}.func_tail_appended({:#x}, {!s}) : Exchanging (decreasing) reference count for global tag ({:s}) at {:#x} and (increasing) reference count for contents tag in the cache for function {:#x}.".format(__name__, interface.range.start(pfn), bounds, utils.string.repr(k), ea, interface.range.start(pfn)))
        continue
    return

def removing_func_tail(pfn, tail):
    """This hook is for when a chunk is removed from a function.

    If the tail we were given only has one owner, then we promote the tags in
    the tail to globals tags. Otherwise, we just decrease the reference count
    in the cache for the function that the tail was removed from.
    """
    bounds = interface.range.bounds(tail)
    referrers = [fn for fn in function.chunk.owners(bounds.left)]

    # Before we do anything, we need to make sure we can iterate through the
    # boundaries in the database that we're supposed to act upon.
    try:
        iterable = interface.address.items(*bounds)

    # If the address is out of bounds, then IDA removed this tail completely from
    # the database and we need to manually delete the tail's contents. Since we
    # can't trust anything, we use the entire contents index filtered by bounds.
    except exceptions.OutOfBoundsError:
        iterable = (ea for ea, _ in internal.tags.reference.contents.iterate() if bounds.contains(ea))

        results = remove_contents(pfn, iterable)
        for tag, items in results.items():
            logging.debug(u"{:s}.removing_func_tail({:#x}, {!s}) : Removed {:d} instances of tag ({:s}) that were associated with a removed tail.".format(__name__, interface.range.start(pfn), bounds, len(items), utils.string.repr(tag)))
        return

    # If the number of referrers is larger than 1, then the tail was just removed
    # from the pfn function. We verify that the pfn is still in the list of
    # referrers and warn the user if it isn't.
    if len(referrers) > 1:
        if not operator.contains(referrers, interface.range.start(pfn)):
            logging.warning(u"{:s}.removing_func_tail({:#x}, {!s}) : Adjusting contents of function ({:#x}) but function was not found in the owners ({:s}) of chunk {!s}.".format(__name__, interface.range.start(pfn), bounds, interface.range.start(pfn), ', '.join(map("{:#x}".format, referrers)), bounds))

        # So there's no promotion from a contents tag to a global tag, but
        # there is a removal from the cache for pfn.
        for ea in iterable:
            for k in internal.tags.address.get(ea):
                internal.tags.reference.contents.decrement(ea, k, target=interface.range.start(pfn))
                logging.debug(u"{:s}.removing_func_tail({:#x}, {!s}) : Decreasing reference for tag ({:s}) at {:#x} in cache for function {:#x}.".format(__name__, interface.range.start(pfn), bounds, utils.string.repr(k), ea, interface.range.start(pfn)))
            continue
        return

    # Otherwise, there's just one referrer and it should be pointing to pfn.
    if not operator.contains(referrers, interface.range.start(pfn)):
        logging.warning(u"{:s}.removing_func_tail({:#x}, {!s}) : Promoting contents for function ({:#x}) but function was not found in the owners ({:s}) of chunk {!s}.".format(__name__, interface.range.start(pfn), bounds, interface.range.start(pfn), ', '.join(map("{:#x}".format, referrers)), bounds))

    # If there's just one referrer, then the referrer should be pfn and we should
    # be promoting the relevant addresses in the cache from contents to globals.
    for ea in iterable:
        for k in internal.tags.address.get(ea):
            internal.tags.reference.contents.decrement(ea, k, target=interface.range.start(pfn))
            internal.tags.reference.globals.increment(ea, k)
            logging.debug(u"{:s}.removing_func_tail({:#x}, {!s}) : Exchanging (increasing) reference count for global tag ({:s}) at {:#x} and (decreasing) reference count for contents tag in the cache for function {:#x}.".format(__name__, interface.range.start(pfn), bounds, utils.string.repr(k), ea, interface.range.start(pfn)))
        continue
    return

def func_tail_removed(pfn, ea):
    """This hook is for when a chunk is removed from a function in older versions of IDA.

    We simply iterate through the old chunk, decrease all of its tags in the
    function context, and increase their reference within the global context.
    """
    start, stop = interface.range.unpack(pfn)

    # first we'll grab the addresses from our refs
    listable = internal.tags.reference.contents.address(ea, target=start)

    # these should already be sorted, so our first step is to filter out what
    # doesn't belong. in order to work around one of the issues posed in the
    # issue arizvisa/ida-minsc#61, we need to explicitly check that each item is
    # not None prior to their comparison against `pfn`. this is needed in order
    # to work around a null-pointer exception raised by SWIG when it calls the
    # area_t.__ne__ method to do the comparison.
    tail, missing = ea, [ item for item in listable if not idaapi.get_func(item) or idaapi.get_func(item) != pfn ]

    # if there was nothing found, then we can simply exit the hook early
    if not missing:
        return

    logging.debug(u"{:s}.func_tail_removed({:#x}..{:#x}, {:#x}) : Updating the tags for the function tail being removed at address {:#x} to {:#x}.".format(__name__, start, stop, tail, start, stop))

    # now iterate through the min/max of the list as hopefully this is
    # our event.
    for ea in interface.address.items(min(missing), max(missing)):
        for k in internal.tags.address.get(ea):
            internal.tags.reference.contents.decrement(ea, k, target=start)
            internal.tags.reference.globals.increment(ea, k)
            logging.debug(u"{:s}.func_tail_removed({:#x}..{:#x}, {:#x}) : Exchanging (increasing) reference count at {:#x} for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, start, stop, tail, ea, utils.string.repr(k), utils.string.repr(k)))
        continue
    return

def tail_owner_changed(tail, owner_func):
    """This hook is for when a chunk is moved to another function and is for older versions of IDA.

    We simply iterate through the new chunk, decrease all of its tags in its
    previous function's context, and increase their reference within the new
    function's context.
    """
    # XXX: this is for older versions of IDA

    # this is easy as we just need to walk through tail and add it
    # to owner_func
    for ea in interface.address.items(interface.range.bounds(tail)):
        for k in internal.tags.address.get(ea):
            internal.tags.reference.contents.decrement(ea, k)
            internal.tags.reference.contents.increment(ea, k, target=owner_func)
            logging.debug(u"{:s}.tail_owner_changed({:#x}, {:#x}) : Exchanging (increasing) reference count for contents tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(tail), owner_func, utils.string.repr(k), utils.string.repr(k)))
        continue
    return

def add_func(pfn):
    """This is called when a new function is created.

    When a new function is created, its entire area needs its tags transformed
    from global tags to function tags. This iterates through each chunk belonging
    to the function and does exactly that.
    """
    start, stop = interface.range.unpack(pfn)

    # check that we're not adding an import as a function. if this happens,
    # then this is because IDA's ELF loader seems to be loading this.
    if idaapi.segtype(start) == idaapi.SEG_XTRN:
        return

    logging.debug(u"{:s}.add_func({:#x}..{:#x}) : Updating the tags for the new function being added at address {:#x} to {:#x}.".format(__name__, start, stop, start, stop))

    # if the database is ready then we can trust the changingchanged-based classes
    # to add all the implicit tags and thus we can exclude them here. otherwise,
    # we'll do it ourselves because the functions get post-processed after building
    # in order to deal with the events that we didn't receive.
    excluded = {'__typeinfo__', '__name__'}
    available = {k for k in internal.tags.function.get(start)}
    [ internal.tags.reference.globals.increment(start, k) for k in available - excluded ]

    # convert all globals into contents whilst making sure that we don't
    # add any of the implicit tags that are handled by other events.
    for l, r in map(interface.range.bounds, interface.function.chunks(pfn)):
        for ea in interface.address.items(l, r):
            available = {item for item in internal.tags.address.get(ea)}
            for k in available - excluded:
                internal.tags.reference.globals.decrement(ea, k)
                internal.tags.reference.contents.increment(ea, k, target=start)
                logging.debug(u"{:s}.add_func({:#x}..{:#x}) : Exchanging (decreasing) reference count at {:#x} for global tag {!s} and (increasing) reference count for contents tag {!s}.".format(__name__, start, stop, ea, utils.string.repr(k), utils.string.repr(k)))
            continue
        continue
    return

def remove_contents(fn, iterable):
    '''This is just a utility that manually removes the contents from a function using an iterator of addresses.'''
    func, results, DEFCOLOR = interface.range.start(fn), {}, 0xffffffff

    # Iterate through each address we were given and decode the contents tags directly
    # using IDAPython, since none of these addresses are accessible via our api.
    for index, ea in enumerate(iterable):
        items = idaapi.get_cmt(ea, True), idaapi.get_cmt(ea, False)
        repeatable, nonrepeatable = (internal.comment.decode(item) for item in items)

        logging.debug(u"{:s}.remove_contents({:#x}) : Removing both repeatable references ({:d}) and non-repeatable references ({:d}) from {:s} ({:#x}).".format(__name__, func, len(repeatable), len(nonrepeatable), 'contents', ea))

        # After decoding it, we can now decrease their refcount and remove them.
        [ internal.tags.reference.contents.decrement(ea, k, target=func) for k in repeatable ]
        [ internal.tags.reference.contents.decrement(ea, k, target=func) for k in nonrepeatable ]

        # Update our results with the keys at whatever address we just removed.
        [ results.setdefault(k, []).append(ea) for k in itertools.chain(repeatable, nonrepeatable) ]

        # Now we need to do a couple of the implicit tags which means we need to
        # check the name, type information, and color.
        if idaapi.get_item_color(ea) == DEFCOLOR:
            internal.tags.reference.contents.decrement(ea, '__color__', target=func)
        if internal.comment.extra.get_prefix(ea) is not None:
            internal.tags.reference.contents.decrement(ea, '__extra_prefix__', target=func)
        if internal.comment.extra.get_suffix(ea) is not None:
            internal.tags.reference.contents.decrement(ea, '__extra_suffix__', target=func)

        get_flags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        if get_flags(ea) & idaapi.FF_NAME:
            internal.tags.reference.contents.decrement(ea, '__name__', target=func)
        continue
    return results

def del_func(pfn):
    """This is called when a function is removed/deleted.

    When a function is removed, all of its tags get moved from the function back
    into the database as global tags. We iterate through the entire function and
    transform its tags by decreasing its reference count within the function,
    and then increasing it for the database. Afterwards we simply remove the
    reference count cache for the function.
    """
    start, stop = interface.range.unpack(pfn)

    try:
        rt, fn = interface.addressOfRuntimeOrStatic(pfn)

    # If IDA told us a function was there, but it actually isn't, then this
    # function was completely removed out from underneath us.
    except exceptions.FunctionNotFoundError:
        exc_info = sys.exc_info()

        # We sanity check what we're being told by checking if it's outside
        # the bounds of the db. If it isn't, then reraise the exception.
        bounds = interface.range.bounds(pfn)
        left, right = interface.address.bounds()
        if any(left <= ea < right for ea in bounds):
            six.reraise(*exc_info)

        # Okay, so our function bounds are not within the database whatsoever but
        # we know which function it's in and we know its boundaries. So at the
        # very least we can manually remove its contents from our storage.
        fn, _ = bounds
        iterable = (ea for ea in internal.tags.reference.contents.address(fn, target=fn) if bounds.contains(ea))

        results = remove_contents(pfn, iterable)
        for tag, items in results.items():
            logging.debug(u"{:s}.del_func({:#x}..{:#x}) : Removed {:d} instances of tag ({:s}) that were associated with a removed function.".format(__name__, start, stop, len(items), utils.string.repr(tag)))

        # Now we need to remove the global tags associated with this function.
        items = idaapi.get_func_cmt(pfn, True), idaapi.get_func_cmt(pfn, False)
        repeatable, nonrepeatable = (internal.comment.decode(item) for item in items)

        logging.debug(u"{:s}.del_func({:#x}..{:#x}) : Removing both repeatable references ({:d}) and non-repeatable references ({:d}) from {:s} ({:#x}).".format(__name__, start, stop, len(repeatable), len(nonrepeatable), 'globals', fn))

        # After decoding them, we can try to decrease our reference count.
        [ internal.tags.reference.globals.decrement(fn, k) for k in repeatable ]
        [ internal.tags.reference.globals.decrement(fn, k) for k in nonrepeatable ]

        # We also need to handle any implicit tags as well to be properly done.
        DEFCOLOR = 0xffffffff
        if pfn.color == DEFCOLOR:
            internal.tags.reference.globals.decrement(fn, '__color__')

        get_flags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        if get_flags(fn) & idaapi.FF_NAME:
            internal.tags.reference.globals.decrement(fn, '__name__')

        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        if get_tinfo(idaapi.tinfo_t(), fn):
            internal.tags.reference.globals.decrement(fn, '__typeinfo__')
        return

    # convert all contents into globals
    for ea in internal.tags.reference.contents.address(fn, target=fn):
        for k in internal.tags.address.get(ea):
            internal.tags.reference.contents.decrement(ea, k, target=fn)
            internal.tags.reference.globals.increment(ea, k)
            logging.debug(u"{:s}.del_func({:#x}..{:#x}) : Exchanging (increasing) reference count at {:#x} for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, start, stop, ea, utils.string.repr(k), utils.string.repr(k)))
        continue

    # remove all function tags depending on whether our address
    # is part of a function, runtime-linked, or neither.
    Ftags = internal.tags.address.get if rt else internal.tags.function.get
    for k in Ftags(fn):
        internal.tags.reference.globals.decrement(fn, k)
        logging.debug(u"{:s}.del_func({:#x}..{:#x}) : Removing (global) tag {!s} from function at {:#x}.".format(__name__, start, stop, utils.string.repr(k), fn))

    return

def set_func_start(pfn, new_start):
    """This is called when the user changes the beginning of the function to another address.

    If this happens, we simply walk from the new address to the old address of
    the function that was changed. Then we can update the reference count for
    any globals that were tagged by moving them into the function's tagcache.
    """
    start, stop = interface.range.unpack(pfn)

    # if new_start has removed addresses from function, then we need to transform
    # all contents tags into globals tags
    if start > new_start:
        for ea in interface.address.items(new_start, start):
            for k in internal.tags.address.get(ea):
                internal.tags.reference.contents.decrement(ea, k, target=start)
                internal.tags.reference.globals.increment(ea, k)
                logging.debug(u"{:s}.set_func_start({:#x}..{:#x}, {:#x}) : Exchanging (increasing) reference count at {:#x} for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, start, stop, new_start, ea, utils.string.repr(k), utils.string.repr(k)))
            continue
        return

    # if new_start has added addresses to function, then we need to transform all
    # its global tags into contents tags
    elif start < new_start:
        for ea in interface.address.items(start, new_start):
            for k in internal.tags.address.get(ea):
                internal.tags.reference.globals.decrement(ea, k)
                internal.tags.reference.contents.increment(ea, k, target=start)
                logging.debug(u"{:s}.set_func_start({:#x}..{:#x}, {:#x}) : Exchanging (decreasing) reference count at {:#x} for global tag {!s} and (increasing) reference count for contents tag {!s}.".format(__name__, start, stop, new_start, ea, utils.string.repr(k), utils.string.repr(k)))
            continue
        return
    return

def set_func_end(pfn, new_end):
    """This is called when the user changes the ending of the function to another address.

    If this happens, we simply walk from the old end of the function to the new
    end of the function that was changed. Then we can update the reference count
    for any globals that were tagged by moving them into the function's tagcache.
    """
    start, stop = interface.range.unpack(pfn)

    # if new_end has added addresses to function, then we need to transform
    # all globals tags into contents tags
    if new_end > stop:
        for ea in interface.address.items(stop, new_end):
            for k in internal.tags.address.get(ea):
                internal.tags.reference.globals.decrement(ea, k)
                internal.tags.reference.contents.increment(ea, k, target=start)
                logging.debug(u"{:s}.set_func_end({:#x}..{:#x}, {:#x}) : Exchanging (decreasing) reference count at {:#x} for global tag {!s} and (increasing) reference count for contents tag {!s}.".format(__name__, start, stop, new_end, ea, utils.string.repr(k), utils.string.repr(k)))
            continue
        return

    # if new_end has removed addresses from function, then we need to transform
    # all contents tags into globals tags
    elif new_end < stop:
        for ea in interface.address.items(new_end, stop):
            for k in internal.tags.address.get(ea):
                internal.tags.reference.contents.decrement(ea, k, target=start)
                internal.tags.reference.globals.increment(ea, k)
                logging.debug(u"{:s}.set_func_end({:#x}..{:#x}, {:#x}) : Exchanging (increasing) reference count at {:#x} for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, start, stop, new_end, ea, utils.string.repr(k), utils.string.repr(k)))
            continue
        return
    return

class structures(changingchanged):
    """
    This namespace handles the 2-part event that can be dispatched by the
    disassembler when a repeatable or non-repeatable comment has been applied to
    a structure. This is done by monitoring the "changing_struc_cmt" and the
    "struc_cmt_changed" event types, and verifying that the identifier given by
    each event corresponds to an actual structure (rather than a member).

    It is worth noting that on some later versions of the disassembler (8.4),
    when a repeatable comment gets applied to a structure it destroys the
    non-repeatable comment that is currently applied. The inverse of this holds
    true in that there can only be a single comment type applied to a structure.
    So, to deal with the differences between these versions we provide two flags
    to an implementer to allow specifying how tags should be tracked.

    The "combined" flag, when set, will result in combining the tags from both
    repeatable and non-repeatable comments (giving priority to what the user
    specified), and then encoding them as a single comment which is then
    re-applied to the structure. The other flag, "single", when set will
    configure the namespace so that any modifications to a repeatable or
    non-repeatable comment will result in deleting references to the other
    comment.
    """

    # These flags specify whether we destroy the other comment when a comment is
    # applied to a structure (single), or that we should combine both comment
    # types into the comment chosen by the user (combined).
    single, combined = False, False

    @classmethod
    def update_refs(cls, sid, old, new):
        '''Update the reference counts for the structure in `sid` by comparing the `old` tags with the ones in `new`.'''
        oldkeys, newkeys = ({item for item in content} for content in [old, new])

        # compare the original keys against the modified ones in order to figure
        # out whether we're removing a key or simply adding it.
        logging.debug(u"{:s}.update_refs({:#x}) : Updating old tags ({!s}) to new tags ({!s}) for structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(oldkeys), utils.string.repr(newkeys), sid))
        for key in oldkeys ^ newkeys:
            if key not in new:
                logging.debug(u"{:s}.update_refs({:#x}) : Decreasing reference count for tag {!s} in structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(key), sid))
                internal.tags.reference.structure.decrement(sid, key)
            if key not in old:
                logging.debug(u"{:s}.update_refs({:#x}) : Increasing reference count for tag {!s} in structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(key), sid))
                internal.tags.reference.structure.increment(sid, key)
            continue
        return

    @classmethod
    def create_refs(cls, sid, new):
        '''Create the references for the structure in `sid` using the tags in `new`.'''
        available = internal.tags.reference.structure.get(sid)
        contentkeys = {item for item in new}

        if available - contentkeys:
            logging.debug(u"{:s}.create_refs({:#x}) : Some of the tags ({!s}) in structure {:#x} already exist and do not need to be created.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(available - contentkeys), sid))

        logging.debug(u"{:s}.create_refs({:#x}) : Creating tags ({!s}) for structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(contentkeys), sid))
        for key in contentkeys - available:
            logging.debug(u"{:s}.create_refs({:#x}) : Increasing reference count for tag {!s} in structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(key), sid))
            internal.tags.reference.structure.increment(sid, key)
        return

    @classmethod
    def delete_refs(cls, sid, old):
        '''Delete the references from the structure in `sid` using the tags in `old`.'''
        available = internal.tags.reference.structure.get(sid)
        contentkeys = {item for item in old}
        logging.debug(u"{:s}.delete_refs({:#x}) : Deleting tags ({!s}) from structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(sorted(contentkeys)), sid))
        for key in (contentkeys & available):
            logging.debug(u"{:s}.delete_refs({:#x}) : Decreasing reference count for tag {!s} in structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(key), sid))
            internal.tags.reference.structure.decrement(sid, key)

        if contentkeys ^ available:
            logging.warning(u"{:s}.delete_refs({:#x}) : Due to a discrepancy for some of the tags ({!s}), not all keys may have been removed ({!s}.".format('.'.join([__name__, cls.__name__]), sid, utils.string.repr(contentkeys - available), utils.string.repr(available - contentkeys)))
        return

    @classmethod
    def updater(cls):
        sid, repeatable, newcmt = (yield)

        # First verify that the structure id actually points to a valid structure.
        if not internal.structure.has(sid):
            return logging.fatal(u"{:s}.updater() : Terminating state for {:s} \"{:s}\" due to the specified structure ({:#x}) not being found.".format('.'.join([__name__, cls.__name__]), 'repeatable comment' if repeatable else 'comment', utils.string.escape(newcmt, '"'), sid))
        sptr = internal.structure.by_identifier(sid)

        # Then we can use it to grab the right comment, and then attempt to
        # decode the tags out of both the old comment and the new one. We also
        # need to grab the "other" comment since later versions of the
        # disassembler will overwrite the other comment with the new one.
        oldcmt = internal.structure.comment.get(sptr, repeatable)
        othercmt = internal.structure.comment.get(sptr, not repeatable)
        old, new, other = (internal.comment.decode(cmt) for cmt in [oldcmt, newcmt, othercmt])

        # Wait until we receive the second "changed" event, and unpack the new
        # information that it gave us. If we were asked to exit, then honor it.
        try:
            newsid, newrepeatable, changedcmt = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while the {:s} for structure {:#x} was being changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), 'repeatable comment' if repeatable else 'comment', sptr.id, oldcmt, newcmt))
            return

        # now we can fix the comment that was typed by the user. we compare them
        # to make sure that we received the events in the correct order.
        if (newsid, newrepeatable) == (sid, repeatable):
            if changedcmt != newcmt:
                logging.debug(u"{:s}.updater() : {:s} from event for structure {:#x} is different from what was stored in the database. Expected comment ({!s}) is different from the changed comment ({!s})".format('.'.join([__name__, cls.__name__]), 'Repeatable comment' if repeatable else 'Comment', sid, newcmt, changedcmt))

            # If we've been configured to preserve both comment types when they
            # have been modified, then we need to combine both the "other" tags
            # with the "new" ones. We do this by merging both tags into the same
            # dictionary (giving priority to "new"), and then re-encoding them
            # back into whatever comment the user has modified.
            if cls.combined:
                fixed = other
                for key, value in new.items():
                    fixed[key] = value
                fixedcmt = internal.comment.encode(fixed)
                internal.structure.comment.set(sid, None, not repeatable)

            # If our configuration specifies that only one comment can be
            # applied to a structure at a given time, then we need to delete the
            # tag references for the other comment from the member.
            elif cls.single:
                cls.delete_refs(sid, other)
                fixed, fixedcmt = new, newcmt

            # Otherwise, we can leave everything alone as both comments have
            # nothing to do with each other.
            else:
                fixed, fixedcmt = new, newcmt

            # If the comment is of the correct format, then we can simply
            # update the refs, and write the comment to the given address.
            if internal.comment.check(fixedcmt):
                cls.update_refs(sid, old, fixed)
                internal.structure.comment.set(sid, fixedcmt, repeatable)

            # If the format was incorrect, but there's a comment to assign, then
            # we use the internal.structure api to set it correctly.
            elif fixedcmt:
                cls.update_refs(sid, old, fixed)
                internal.structure.comment.set(sid, fixedcmt, repeatable)

            # If there wasn't a new comment, then we need to delete all the
            # references to the keys from the old tag on the structure.
            else:
                cls.delete_refs(sid, old)
            return

        # If the changed and changing events didn't have comments that matched,
        # then they didn't happen in the right order. So, we fix it deleting all
        # the references, decoding the comment, and recreating them.
        logging.fatal(u"{:s}.updater() : {:s} events are out of sync for structure {:#x}, updating tags from previous comment. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), 'Repeatable comment' if newrepeatable else 'Comment', sid, utils.string.repr(oldcmt), utils.string.repr(newcmt)))

        # Now we can delete all the comments and their references.
        cls.delete_refs(sid, old), cls.delete_refs(sid, new)
        internal.structure.comment.remove(sid, newrepeatable)
        logging.warning(u"{:s}.updater() : Deleted {:s} from structure {:#x} which was originally {!s}.".format('.'.join([__name__, cls.__name__]), 'repeatable comment' if newrepeatable else 'comment', sid, utils.string.repr(oldcmt)))

        # Now we can recreate the references for the new comment.
        new = internal.comment.decode(changedcmt)
        cls.create_refs(sid, new)

    @classmethod
    def changing(cls, struc_id, repeatable, newcmt):
        '''changing_struc_cmt(struc_id, repeatable, newcmt)'''
        if not internal.structure.has(struc_id):
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Ignoring structures.changing event for a {:s} comment on structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), struc_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', struc_id))
        logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Received structures.changing event for a {:s} comment on structure {:#x}.".format('.'.join([__name__, cls.__name__]), struc_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', struc_id))

        # Now try and grab the structure using its identifier. This should not
        # fail due to the test we did at the beginning.
        # then log a warning and abort so that we don't interrupt the user.
        sptr = internal.structure.by_identifier(struc_id)

        # Create a new event using sid and repeatable as a unique key. We also
        # grab the old comment prior to renaming so that we can compare it.
        event, oldcmt = cls.new((sptr.id, repeatable)), internal.structure.comment.get(sptr, repeatable)

        # Disable the hooks to prevent re-entrancy issues that might occur.
        hooks = [name for name in ['changing_struc_cmt', 'struc_cmt_changed'] if name in ui.hook.idb.available]
        [ ui.hook.idb.disable(item) for item in hooks ]

        # Now we can send the data received to the coroutine that we allocated.
        try:
            event.send((sptr.id, True if repeatable else False, newcmt))

        # If the coroutine raised a StopIteration, then we let the user know.
        except StopIteration:
            logging.fatal(u"{:s}.changing({:#x}, {!s}, {!r}) : Abandoning structures.changing event for a {:s} comment on structure {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), struc_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', sptr.id))

        # Then, we restore the hooks that we disabled and wait for the next event.
        finally:
            [ ui.hook.idb.enable(item) for item in hooks ]
        return

    @classmethod
    def changed(cls, struc_id, repeatable):
        '''struc_cmt_changed(struc_id, repeatable_cmt)'''
        if not internal.structure.has(struc_id):
            return logging.debug(u"{:s}.changed({:#x}, {!s}) : Ignoring structures.changed event for a {:s} comment on structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), struc_id, repeatable, 'repeatable' if repeatable else 'non-repeatable', struc_id))
        logging.debug(u"{:s}.changed({:#x}, {!s}) : Received structures.changed event for a {:s} comment on structure {:#x}.".format('.'.join([__name__, cls.__name__]), struc_id, repeatable, 'repeatable' if repeatable else 'non-repeatable', struc_id))

        # Go ahead and grab the structure that had its comment changed. This
        # shouldn't fail if the test at the beginning passed.
        sptr = internal.structure.by_identifier(struc_id)

        # Now we'll use the parameters to try and resume the coroutine. We also
        # extract the comment since by now the new comment has been applied.
        event, newcmt = cls.resume((sptr.id, repeatable)), internal.structure.comment.get(sptr, repeatable)

        # Before submitting the changes to our coroutine, disable all the hooks
        # since the coroutine might write to the same comment which could cause
        # a recursion issue.
        hooks = [name for name in ['changing_struc_cmt', 'struc_cmt_changed'] if name in ui.hook.idb.available]
        [ ui.hook.idb.disable(item) for item in hooks ]

        # Send the parameters and our new comment to the coroutine so that it
        # could finish what it started.
        try:
            event.send((sptr.id, True if repeatable else False, newcmt))

        # If we received a StopIteration, then the coroutine has aborted for
        # some reason and we can't do anything else but whine about it.
        except StopIteration:
            logging.fatal(u"{:s}.changed({:#x}, {!s}) : Abandoning structures.changed event for a {:s} comment on structure {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), sptr.id, repeatable, 'repeatable' if repeatable else 'non-repeatable', sptr.id))

        # Restore the hooks that we disabled, and close the coroutine since this
        # event signals that the comment has been completely applied.
        finally:
            [ ui.hook.idb.enable(item) for item in hooks ]
        event.close()

class structures_84(structures):
    """
    This namespace is intended to support the updating of comments for
    structures in v8.4 of the disassembler. This version of the disassembler
    changes the way that comments can be applied to a structure or member by
    deleting the other comment that was previously applied. So, we set the
    correct flags here to mirror what we expect the disassembler will do.
    """
    single = True

class structurenaming(changingchanged):
    """
    This class handles the 2-part event that is dispatched by the disassembler
    when a structure is renamed. This is responsible for tracking the reference
    count for the "__name__" tag applied to a structure. The structure name is
    checked in order to distinguish a user-specified name from the default one
    that might be specified by the disassembler.

    We also implement the hooks for managing the structure scope. Although, the
    disassembler implements structure removal as a 2-part with the hook names
    "deleting_struc" and "struc_deleted", it turns out that only the
    "struc_deleted" hook appears to be called. So, on creation we check if the
    name is user-specified or general and adjust the "__name__" tag accordingly,
    and on deletion we remove all the tags associated with the structure.

    During creation of a structure, we try to detect whether it was created by
    the user or the disassembler. We distinguish this by making the assumption
    that anything pre-analysis belongs to the disassembler, and post-analysis
    belongs to the user. This is specifically to control the existence of the
    "__typeinfo__" tag for the structure.
    """

    # FIXME: this doesn't work in 8.4, but it does in 8.3

    @classmethod
    def is_general_name(cls, sid, name):
        '''Return true if the structure or union in `sid` has a given `name` that is generic and was decided by the disassembler.'''
        sptr = internal.structure.by_identifier(sid) if internal.structure.has(sid) else None
        prefixes = {'struc', 'union'}

        # If we couldn't get the structure, then we can only do a test for the
        # prefixes since we can't check if the structure if a frame or a union.
        if not sptr:
            prefix, suffix = name.split('_', 1) if name.startswith(('struc_', 'union_')) else ('', name)
            return prefix in prefixes and all(digit in '0123456789' for digit in suffix)

        # Otherwise, we need to check if we were given a frame. Normally, the
        # user shouldn't be able to rename a frame structure as the disassembler
        # won't really like it, but we support doing this anyways.
        if sptr.props & idaapi.SF_FRAME:
            prefix, suffix = name.split(' ', 1) if name.startswith('$ ') else ('', name)
            return prefix == '$' and all(digit in '0123456789ABCDEF' for digit in suffix.upper())

        # Now we have a regular structure. We can just test its prefix normally.
        prefix, suffix = name.split('_', 1) if name.startswith(('struc_', 'union_')) else ('', name)
        return prefix in prefixes and all(digit in '0123456789' for digit in suffix)

    @classmethod
    def is_tracked(cls, sid, name):
        '''Return true if the structure `sid` with specified `name` should not be tracked with tags.'''
        sptr = internal.structure.by_identifier(sid) if internal.structure.has(sid) else None

        # If we couldn't get the structure, then it doesn't exist and as such it
        # is untrackable.
        if not sptr:
            return False

        # If the flags for the structure suggest that it's unlisted, then we
        # treat it as untracked since the user wouldn't normally see it.
        elif sptr.props & idaapi.SF_NOLIST:
            return False

        # If it's a frame, then it is also unlisted and untracked.
        elif sptr.props & idaapi.SF_FRAME:
            return False

        # Next we need to check if the structure was copied from the type
        # library. If so, then it was created automatically, and so we avoid
        # tracking it since it is owned by the disassembler. We used to care
        # about SF_GHOST types, but since the disassembler is getting rid of
        # these in v9.0, we stick to only things from the type library.
        elif sptr.props & getattr(idaapi, 'SF_TYPLIB', 0):
            return False
        return True

    @classmethod
    def created(cls, struc_id):
        '''struc_created(struc_id)'''
        if not internal.structure.has(struc_id):
            return logging.warning(u"{:s}.created({:#x}) : Received structurenaming.created event for an unknown structure ({:#x}).".format('.'.join([__name__, cls.__name__]), struc_id, struc_id))

        # Grab the structure from the database using its id and then check if it
        # belongs to a frame. If it does, then we can ignore it entirely.
        sptr = internal.structure.by_identifier(struc_id)
        if sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.created({:#x}) : Ignoring structurenaming.created event for structure {:#x} (is a frame).".format('.'.join([__name__, cls.__name__]), struc_id, struc_id))
        logging.debug(u"{:s}.created({:#x}) : Received structurenaming.created event for structure {:#x}.".format('.'.join([__name__, cls.__name__]), struc_id, struc_id))

        # All we need to do is grab its name and check if it's a general name or
        # a user-specified one. We also check that the structure is listed,
        # since if it isn't then it's technically nameless. If we discover it is
        # listed and a user-specified name, then we can go ahead and increment
        # its reference count for the "__name__" tag.
        name = internal.structure.naming.get(sptr)
        if not cls.is_general_name(sptr.id, name) and not sptr.props & idaapi.SF_NOLIST:
            internal.tags.reference.structure.increment(sptr.id, '__name__')

        # Next we need to increment the "__typeinfo__" tag. We don't have a real
        # way of distinguishing whether a structure has been created by the user
        # or the disassembler, so we rely on whether the structure was created
        # at the same time as the database or after the analysis has completed.
        if cls.is_tracked(sptr.id, name):
            internal.tags.reference.structure.increment(sptr.id, '__typeinfo__')
        return

    # XXX: the following is not implemented because as it turns out, the event
    #      is never called by the disassembler (at least in 8.4).
    #@classmethod
    #def deleting(cls, sptr):
    #    '''deleting_struc(sptr)'''

    @classmethod
    def deleted(cls, struc_id):
        '''struc_deleted(struc_id)'''
        logging.debug(u"{:s}.deleted({:#x}) : Received structurenaming.deleted event for structure {:#x}.".format('.'.join([__name__, cls.__name__]), struc_id, struc_id))

        # The only thing we have to do is to remove all tags associated with the
        # structure. So we grab them, and decrement each one-by-one.
        tags = internal.tags.reference.structure.get(struc_id)
        logging.debug(u"{:s}.deleted({:#x}) : Found {:d} tag{:s} ({!s}) associated with structure {:#x} that will be removed.".format('.'.join([__name__, cls.__name__]), struc_id, len(tags), '' if len(tags) == 1 else 's', tags, struc_id))
        [ internal.tags.reference.structure.decrement(struc_id, tag) for tag in tags ]
        return

    @classmethod
    def updater(cls):
        '''This coroutine is responsible for accepting both "changed" and "changing" events in order to adjust the reference count for the "__name__" tag.'''

        # Start out by grabbing the names suggested by the "changing" event.
        sid, oldname, newname = (yield)

        # Next we can grab whatever is sent by the "changed" event. This
        # contains the actual name that was applied to the structure.
        try:
            newsid, applied = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while name for structure {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), sid, oldname, newname))
            return

        # Verify that both structure ids are correct, and that the new name
        # matches the applied name. If the former, then we log a warning and
        # assume that the new structure id is correct. If the latter, then log a
        # warning since the disassembler might have just filtered the name.
        if newsid != sid:
            logging.fatal(u"{:s}.updater() : Structure renaming events for structure {:#x} are out of sync. Expected structure {:#x}, but event gave us structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, sid, newsid))

        if applied != newname:
            logging.warning(u"{:s}.updater() : Structure renaming events for structure {:#x} are out of sync. Expected structure {:#x} to have name \"{:s\", but the name \"{:s}\" was applied.".format('.'.join([__name__, cls.__name__]), newsid, utils.string.escape(newname, '"'), utils.string.escape(applied, '"')))

        # Now we'll figure out whether we are renaming to a default-ish name, or
        # something that was user-specified. We use this to compare the names
        # and determine whether to remove it since the disassembler doesn't let
        # us apply an empty name to a structure anyways.
        renamed = cls.is_general_name(sid, oldname), cls.is_general_name(newsid, applied)

        # If we're switching from general to user-specified, then increment.
        if renamed == (True, False):
            internal.tags.reference.structure.increment(newsid, '__name__')

        # If we're going from user-specified to general, then decrement.
        elif renamed == (False, True):
            internal.tags.reference.structure.decrement(newsid, '__name__')

        # If the old name is user-specified, but the tag doesn't exist then we
        # need to add it since we must've missed it.
        elif not renamed[0] and '__name__' not in internal.tags.reference.structure.get(newsid):
            internal.tags.reference.structure.increment(newsid, '__name__')

        # If both are general or user-specified, then there's nothing to do
        # since it should already be tagged with "__name__" if the name has been
        # customized and not be tagged when it has a general name.
        else:
            logging.debug(u"{:s}.updater() : Structure renaming event for structure {:#x} from \"{!s}\" to \"{!s}\" did not need an adjustment.".format('.'.join([__name__, cls.__name__]), newsid, utils.string.escape(oldname, '"'), utils.string.escape(applied, '"')))
        return

    @classmethod
    def renaming(cls, sid, oldname, newname):
        '''renaming_struc(id, oldname, newname)'''
        logging.debug(u"{:s}.renaming({:#x}, {!s}, {!r}) : Received structurenaming.renaming event for structure {:#x}.".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(oldname), "{!r}".format(newname), sid))

        # First thing is to re-grab the structure and make sure it actually exists.
        if not internal.structure.has(sid):
            return logging.warning(u"{:s}.renaming({:#x}, {!s}, {!r}) : Received structurenaming.renaming event for an unknown structure ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(oldname), "{!r}".format(newname), sid))
        sptr = internal.structure.by_identifier(sid)

        # Now we need to create a new state for the structure, and then send it
        # our parameters so that we can track what the name has been changed to.
        event = cls.new(sptr.id)
        try:
            event.send((sptr.id, oldname, newname))
        except StopIteration:
            logging.fatal(u"{:s}.renaming({:#x}, {!s}, {!r}) : Abandoning rename for structure {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(oldname), "{!r}".format(newname), sid))
        return

    @classmethod
    def renamed(cls, sptr):
        '''struc_renamed(sptr, success)'''
        logging.debug(u"{:s}.renamed({:#x}) : Received structurenaming.renamed event for structure {:#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, sptr.id))

        # Unpack the structure id, and then use it to regrab the structure from
        # the database. If it doesn't exist, then abort and don't do anything.
        sid, sptr = sptr.id, internal.structure.by_identifier(sptr.id) if internal.structure.has(sptr.id) else None
        if not sptr:
            logging.warning(u"{:s}.renamed({:#x}) : Received structurenaming.renamed event for an unknown structure ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(oldname), "{!r}".format(newname), sid))
            return

        # Now we can use the id to resume our event state, get the current
        # name, and then send them both to the event before closing it.
        event, name = cls.resume(sptr.id), internal.structure.naming.get(sptr)
        try:
            event.send((sptr.id, name))

        except StopIteration:
            logging.fatal(u"{:s}.renamed({:#x}) : Abandoning rename for structure {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sptr.id, sptr.id))
        event.close()

class membertagscommon(changingchanged):
    """
    This namespace is responsible for tracking all of the tags that are applied
    to a structure or frame member. It does this by monitoring both commenting
    event types, "changing_struc_cmt" and "struc_cmt_changed", that are
    dispatched by the disassembler. The namespace is intended to be derived from
    so that subclasses can add specific details as required by the current
    version of the disassembler.f

    It is worth noting that on later versions of the disassembler, when a
    repeatable comment is applied to a member, it will result in destroying the
    other non-repeatable comment. This goes the same for the inverse. So, to
    accommodate this difference we support specifying two flags which can be
    used to configure how this namespace responds.

    The "combined" flag, when set to true, will result in taking both repeatable
    and non-repeatable comments and encoding them into a single comment before
    writing it back to the comment that was specified by the user. If the
    "single" flag is set to true, modifying one comment type will assume that
    the other comment type is properly destroyed. This will result in removing
    any of the tags that were stored in the other comment type.
    """

    # These flags specify whether modifying one comment via the disassembler
    # will destroy the other one (single), or that when modifying a comment both
    # comments should be combined into whatever was modified (combined).
    single, combined = False, False

    @classmethod
    def update_refs(cls, mid, old, new):
        '''Update the reference counts for the member in `mid` by comparing the `old` tags with the ones in `new`.'''
        oldkeys, newkeys = ({item for item in content} for content in [old, new])

        # compare the original keys against the modified ones in order to figure
        # out whether we're removing a key or simply adding it.
        logging.debug(u"{:s}.update_refs({:#x}) : Updating old tags ({!s}) to new tags ({!s}) for member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(oldkeys), utils.string.repr(newkeys), mid))
        for key in oldkeys ^ newkeys:
            if key not in new:
                logging.debug(u"{:s}.update_refs({:#x}) : Decreasing reference count for tag {!s} in member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(key), mid))
                internal.tags.reference.members.decrement(mid, key)
            if key not in old:
                logging.debug(u"{:s}.update_refs({:#x}) : Increasing reference count for tag {!s} in member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(key), mid))
                internal.tags.reference.members.increment(mid, key)
            continue
        return

    @classmethod
    def create_refs(cls, mid, new):
        '''Create the references for the member in `mid` using the tags in `new`.'''
        available = internal.tags.reference.members.get(mid)
        contentkeys = {item for item in new}

        if available - contentkeys:
            logging.debug(u"{:s}.create_refs({:#x}) : Some of the tags ({!s}) in member {:#x} already exist and do not need to be created.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(available - contentkeys), mid))

        logging.debug(u"{:s}.create_refs({:#x}) : Creating tags ({!s}) for member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(contentkeys), mid))
        for key in contentkeys - available:
            logging.debug(u"{:s}.create_refs({:#x}) : Increasing reference count for tag {!s} in member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(key), mid))
            internal.tags.reference.members.increment(mid, key)
        return

    @classmethod
    def delete_refs(cls, mid, old):
        '''Delete the references from the member in `mid` using the tags in `old`.'''
        available = internal.tags.reference.members.get(mid)
        contentkeys = {item for item in old}
        logging.debug(u"{:s}.delete_refs({:#x}) : Deleting tags ({!s}) from member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(sorted(contentkeys)), mid))
        for key in (contentkeys & available):
            logging.debug(u"{:s}.delete_refs({:#x}) : Decreasing reference count for tag {!s} in member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(key), mid))
            internal.tags.reference.members.decrement(mid, key)

        if contentkeys ^ available:
            logging.warning(u"{:s}.delete_refs({:#x}) : Due to a discrepancy for some of the tags ({!s}), not all keys may have been removed ({!s}.".format('.'.join([__name__, cls.__name__]), mid, utils.string.repr(contentkeys - available), utils.string.repr(available - contentkeys)))
        return

    @classmethod
    def updater(cls):
        mid, repeatable, newcmt = (yield)

        # First verify that the member id actually points to a valid member.
        if not internal.structure.member.has(mid):
            return logging.warning(u"{:s}.updater() : Terminating state for {:s} \"{:s}\" due to the specified member ({:#x}) not being found.".format('.'.join([__name__, cls.__name__]), 'repeatable comment' if repeatable else 'comment', utils.string.escape(newcmt, '"'), mid))

        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)

        # Then we can use it to grab the right comment, and then attempt to
        # decode the tags out of both the old comment and the new one. We also
        # capture the "other" comment since later versions of the disassembler
        # will overwrite the other comment with the new one.
        oldcmt = internal.structure.member.get_comment(mptr, repeatable)
        othercmt = internal.structure.member.get_comment(mptr, not repeatable)
        old, new, other = (internal.comment.decode(cmt) for cmt in [oldcmt, newcmt, othercmt])

        # Wait until we receive the second "changed" event, and unpack the new
        # information that it gave us. If we were asked to exit, then honor it.
        try:
            newmid, newrepeatable, changedcmt = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while the {:s} for member {:#x} was being changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), 'repeatable comment' if repeatable else 'comment', mid, oldcmt, newcmt))
            return

        # now we can fix the comment that was typed by the user. we compare them
        # to make sure that we received the events in the correct order.
        if (newmid, newrepeatable) == (mid, repeatable):
            if changedcmt != newcmt:
                logging.debug(u"{:s}.updater() : {:s} from event for member {:#x} is different from what was stored in the database. Expected comment ({!s}) is different from the changed comment ({!s})".format('.'.join([__name__, cls.__name__]), 'Repeatable comment' if repeatable else 'Comment', mid, newcmt, changedcmt))

            # If we've been configured to combine repeatable and non-repeatable
            # comments, then we overwrite the "other" decoded comment with any
            # of the new tags, and re-encode both of them into a new comment.
            if cls.combined:
                fixed = other
                for key, value in new.items():
                    fixed[key] = value
                fixedcmt = internal.comment.encode(fixed)
                internal.structure.member.set_comment(mptr, None, not newrepeatable)

            # If our configuration specifies that applying a comment results in
            # destroying the other comment, then we need to delete the refs for
            # the other tags since they won't actually exist anymore.
            elif cls.single:
                cls.delete_refs(mid, other)
                fixed, fixedcmt = new, newcmt

            # Otherwise, we can leave everything alone since things should work
            # as they're supposed to and getting the tag for the mebmer results
            # in decoding them from both comment types anyways.
            else:
                fixed, fixedcmt = new, newcmt

            # write the comment to the given address.
            if internal.comment.check(fixedcmt):
                cls.update_refs(mid, old, fixed)
                internal.structure.member.set_comment(mptr, fixedcmt, repeatable)

            # If the format wasn't right, but there's a comment to assign, then
            # use the internal.structure.member api to set it correctly.
            elif fixedcmt:
                cls.update_refs(mid, old, fixed)
                internal.structure.member.set_comment(mptr, fixedcmt, repeatable)

            # If there wasn't a new comment, then we need to delete all the
            # references to the keys from the old tag on the structure.
            else:
                cls.delete_refs(mid, old)
            return

        # If the changed and changing events didn't have comments that matched,
        # then they didn't happen in the right order. So, we fix it by deleting
        # all the references, decoding the comment, and then recreating them.
        logging.fatal(u"{:s}.updater() : {:s} events are out of sync for member {:#x}, updating tags from previous comment. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), 'Repeatable comment' if newrepeatable else 'Comment', mid, utils.string.repr(oldcmt), utils.string.repr(newcmt)))

        # Now we can delete the old and other comments with their references.
        cls.delete_refs(mid, old), cls.delete_refs(mid, other)
        internal.structure.member.set_comment(mptr, None, newrepeatable)
        logging.warning(u"{:s}.updater() : Deleted {:s} from member {:#x} which was originally {!s}.".format('.'.join([__name__, cls.__name__]), 'repeatable comment' if newrepeatable else 'comment', mid, utils.string.repr(oldcmt)))

        # Now we recreate the references for the new comment.
        new = internal.comment.decode(changedcmt)
        cls.create_refs(mid, new)

    @classmethod
    def changing(cls, mid, repeatable, newcmt):
        '''changing_struc_cmt(member_id, repeatable, newcmt)'''
        description = cls.__name__

        # Now we can go ahead and grab the struc_t and member_t using the
        # identifier we were given. This should always succeed because the
        # identifier should have already been checked by the caller.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Received {:s}.changing event for a {:s} comment on member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, repeatable, newcmt, description, 'repeatable' if repeatable else 'non-repeatable', mptr.id))

        # Create a new event using the owning structure, the member id, and the
        # repeatable value as the key. Grab its old comment so we can compare.
        event, oldcmt = cls.new((mowner.id, mptr.id, repeatable)), internal.structure.member.get_comment(mptr, repeatable)

        # Disable the hooks to prevent re-entrancy issues that might occur.
        hooks = [name for name in ['changing_struc_cmt', 'struc_cmt_changed'] if name in ui.hook.idb.available]
        [ ui.hook.idb.disable(item) for item in hooks ]

        # Now we can send the data received to the coroutine that we allocated.
        try:
            event.send((mptr.id, True if repeatable else False, newcmt))

        # If the coroutine raised a StopIteration, then we let the user know.
        except StopIteration:
            logging.fatal(u"{:s}.changing({:#x}, {!s}, {!r}) : Abandoning {:s}.changing event for a {:s} comment on member {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), member_id, repeatable, newcmt, description, 'repeatable' if repeatable else 'non-repeatable', mptr.id))

        # Then, we restore the hooks that we disabled and wait for the next event.
        finally:
            [ ui.hook.idb.enable(item) for item in hooks ]
        return

    @classmethod
    def changed(cls, mid, repeatable):
        '''struc_cmt_changed(member_id, repeatable_cmt)'''
        description = cls.__name__

        # First we'll need to get the struc_t and member_t using the identifier
        # that we given to us by the caller. This should never fail as the
        # caller should have already checked that these identifiers are valid.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        logging.debug(u"{:s}.changed({:#x}, {!s}) : Received {:s}.changed event for a {:s} comment on member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, repeatable, description, 'repeatable' if repeatable else 'non-repeatable', mptr.id))

        # Now we'll use the parameters to try and resume the coroutine. We also
        # extract the comment since by now the new comment has been applied.
        event, newcmt = cls.resume((mowner.id, mptr.id, repeatable)), internal.structure.member.get_comment(mptr, repeatable)

        # Before submitting the changes to our coroutine, disable all the hooks
        # since the coroutine might write to the same comment which could cause
        # a recursion issue.
        hooks = [name for name in ['changing_struc_cmt', 'struc_cmt_changed'] if name in ui.hook.idb.available]
        [ ui.hook.idb.disable(item) for item in hooks ]

        # Send the parameters and our new comment to the coroutine so that it
        # could finish what it started.
        try:
            event.send((mptr.id, True if repeatable else False, newcmt))

        # If we received a StopIteration, then the coroutine has aborted for
        # some reason and we can't do anything else but whine about it.
        except StopIteration:
            logging.fatal(u"{:s}.changed({:#x}, {!s}) : Abandoning {:s}.changed event for a {:s} comment on member {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), mptr.id, repeatable, description, 'repeatable' if repeatable else 'non-repeatable', mptr.id))

        # Restore the hooks that we disabled, and close the coroutine since this
        # event signals that the comment has been completely applied.
        finally:
            [ ui.hook.idb.enable(item) for item in hooks ]
        event.close()

class members(membertagscommon):
    """
    This class handles the 2-part event that is dispatched by the disassembler
    when a repeatable or non-repeatable comment is applied to a member inside a
    structure. It turns out that the disassembler dispatches to the same hooks,
    "changing_struc_cmt" and "struc_cmt_changed", in order to handle member
    comments. The only difference is that the id that we are given belongs to a
    structure member, rather than a structure. The resulting comment is also
    reformatted as a tag so that the tag names can be indexed as necessary.
    """

    @classmethod
    def changing(cls, member_id, repeatable, newcmt):
        '''changing_struc_cmt(member_id, repeatable, newcmt)'''
        if not internal.structure.member.has(member_id):
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Ignoring members.changing event for a {:s} comment on member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', member_id))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above. We use this to
        # determine whether the member belongs to a frame or a structure.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, member_id)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Ignoring members.changing event for a {:s} comment on member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', member_id))
        return super(members, cls).changing(mptr.id, repeatable, newcmt)

    @classmethod
    def changed(cls, member_id, repeatable):
        '''struc_cmt_changed(member_id, repeatable_cmt)'''
        if not internal.structure.member.has(member_id):
            return logging.debug(u"{:s}.changed({:#x}, {!s}) : Ignoring members.changed event for a {:s} comment on member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, 'repeatable' if repeatable else 'non-repeatable', member_id))

        # Now we can grab the member that had its comment changed and its parent
        # structure using the identifier that we had just verified.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, member_id)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changed({:#x}, {!s}) : Ignoring members.changed event for a {:s} comment on member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, 'repeatable' if repeatable else 'non-repeatable', member_id))
        return super(members, cls).changed(mptr.id, repeatable)

class framemembers(members):
    """
    This class handles the 2-part event that is dispatched by the disassembler
    when a repeatable or non-repeatable comment is applied to a member inside a
    frame. The disassembler dispatches to the exact same hooks that is used for
    structures, which includes "changing_struc_cmt" and "struc_cmt_changed".
    Thus, for us to support frame members we distinguish whether the id
    represents a member, and check its owning structure to see if it actually is
    a frame.

    We inherit from the `members` namespace, since the only thing that differs
    between this one and `members` is that we distinguish the owning structure.
    """

    @classmethod
    def changing(cls, member_id, repeatable, newcmt):
        '''changing_struc_cmt(member_id, repeatable, newcmt)'''
        if not internal.structure.member.has(member_id):
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Ignoring framemembers.changing event for a {:s} comment on member {:#x} (unknown frame member).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', member_id))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, member_id)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!r}) : Ignoring framemembers.changing event for a {:s} comment on member {:#x} (belongs to a structure).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, newcmt, 'repeatable' if repeatable else 'non-repeatable', member_id))
        return super(members, cls).changing(mptr.id, repeatable, newcmt)

    @classmethod
    def changed(cls, member_id, repeatable):
        '''struc_cmt_changed(member_id, repeatable_cmt)'''
        if not internal.structure.member.has(member_id):
            return logging.debug(u"{:s}.changed({:#x}, {!s}) : Ignoring framemembers.changed event for a {:s} comment on member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, 'repeatable' if repeatable else 'non-repeatable', member_id))

        # Now we can grab the member that had its comment changed and its parent
        # by using the identifier that we just verified.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, member_id)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changed({:#x}, {!s}) : Ignoring framemembers.changed event for a {:s} comment on member {:#x} (belongs to a structure).".format('.'.join([__name__, cls.__name__]), member_id, repeatable, 'repeatable' if repeatable else 'non-repeatable', member_id))
        return super(members, cls).changed(mptr.id, repeatable)

class members_84(members):
    """
    This namespace is used to support updating the comments in v8.4 of the
    disassembler. This specific version of the disassembler changes the way
    comments can be applied to a structure or a member by deleting the other
    comment that might be applied. So, we set the correct flags to mirror what
    we expect the disassembler will do.
    """
    single = True

class framemembers_84(framemembers):
    """
    This namespace is used to support updating the updating of comments for v8.4
    of the disassembler. This specific version changes the way comments can be
    applied to a structure or a member by deleting the other comment that might
    be applied. So, we set the correct flags to mirror what the disassembler
    will do.
    """
    single = True

class memberscopecommon(changingchanged):
    """
    This namespace handles the 2-part event that is dispatched by the
    disassembler when a structure or frame member has been deleted. Since the
    logic is similar, it also handles the event when the member has been
    created.
    """

    @classmethod
    def delete_refs(cls, sid, mid):
        '''Remove all the references from the member `mid` belonging to the structure in `sid`.'''
        if not internal.structure.member.has(mid):
            return internal.tags.reference.members.erase_member(sid, mid)

        used = internal.tags.reference.members.get(mid)
        [internal.tags.reference.members.decrement(mid, key) for key in used]

    @classmethod
    def updater(cls):
        '''This coroutine is responsible for accepting both "deleting" and "deleted" events in order to remove the reference counts for the member.'''
        sid, mid = (yield)
        try:
            oldsid, oldmid, offset = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while member {:#x} was being removed from structure {:#x}.".format('.'.join([__name__, cls.__name__]), mid, sid))
            return

        # The only thing we need to do is to grab all the tags for the member,
        # and remove them by decrementing each of them one-by-one.
        if (sid, mid) == (oldsid, oldmid):
            return cls.delete_refs(sid, mid)

        # If the ids didn't match, then we assume only the ones from the second
        # "deleted" event need to be removed.
        logging.fatal(u"{:s}.updater() : Events are out of sync for removal of member {:#x}, as member {:#x} was originally selected. Assuming that member {:#x} was deleted.".format('.'.join([__name__, cls.__name__]), oldmid, mid, oldmid))
        cls.delete_refs(oldsid, oldmid)

    @classmethod
    def created(cls, sid, mid):
        '''struc_member_created(sptr, mptr)'''
        description = cls.__name__
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)

        # There really isn't anything for us to do, so we can just return.
        logging.debug(u"{:s}.created({:#x}, {:#x}) : Received memberscope.created event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, mid))
        return

    @classmethod
    def deleting(cls, sid, mid):
        '''deleting_struc_member(sptr, mptr)'''
        description = cls.__name__

        # Grab the structure and the member using the identifiers we were given
        # by the caller. These should always succeed since the caller should've
        # already checked them before giving them to us.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)

        # Now we can create a new event using the ids from the parameters. After
        # it's been created, we can send both ids to the event updater coroutine.
        logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Received {:s}.deleting event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, description, mid))

        event = cls.new((sid, mid))
        try:
            event.send((sid, mid))
        except StopIteration:
            logging.fatal(u"{:s}.deleting({:#x}, {:#x}) : Abandoning {:s}.deleting event for member {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, description, mid))
        return

    @classmethod
    def deleted(cls, sid, mid, offset):
        '''struc_member_deleted(sptr, member_id, offset)'''
        description = cls.__name__
        logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Received {:s}.deleted event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, offset, description, mid))

        # Now we'll resume our event coroutine using the ids we received. We
        # don't need the struc_t or member_t since the member doesn't actually
        # exist anymore. So, all we need to do is send parameters to the event.
        event = cls.resume((sid, mid))

        try:
            event.send((sid, mid, offset))
        except StopIteration:
            logging.fatal(u"{:s}.deleting({:#x}, {:#x}, {:+#x}) : Abandoning {:s}.deleted event for member {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, offset, description, mid))
        finally:
            event.close()
        return

class memberscope(memberscopecommon):
    """
    This class handles the 2-part event that is dispatched by the disassembler
    when a structure member has been deleted. It also handles the event when a
    structure member is created (despite not doing anything). This is supported
    by the "struc_member_created" event, the "deleting_struc_member" event, and
    the "struc_member_deleted" event.

    These events (according to the documentation) are supposed to be dispatched
    when ever a structure member is created or deleted. However, on some
    versions of the disassembler (8.4) these events are only dispatched on frame
    members. Due to this constraint, this namespace is distinctly separate from
    the `framememberscope` namespace despite their functionality being the same.
    """

    @classmethod
    def created(cls, sptr, mptr):
        '''struc_member_created(sptr, mptr)'''
        if not internal.structure.has(sptr.id):
            return logging.debug(u"{:s}.created({:#x}, {:#x}) : Ignoring memberscope.created event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, sptr.id))
        elif not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.created({:#x}, {:#x}) : Ignoring memberscope.created event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))
        elif sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.created({:#x}, {:#x}) : Ignoring memberscope.created event for structure {:#x} (is a frame).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, sptr.id))
        return super(memberscope, cls).created(sptr.id, mptr.id)

    @classmethod
    def deleting(cls, sptr, mptr):
        '''deleting_struc_member(sptr, mptr)'''
        sid, mid = sptr.id, mptr.id
        if not internal.structure.has(sid):
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring memberscope.deleting event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sid, mid, sid))
        elif not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring memberscope.deleting event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sid, mid, mid))
        elif sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring memberscope.deleting event for structure {:#x} (is a frame).".format('.'.join([__name__, cls.__name__]), sid, mid, sid))
        return super(memberscope, cls).deleting(sid, mid)

    @classmethod
    def deleted(cls, sptr, member_id, offset):
        '''struc_member_deleted(sptr, member_id, offset)'''
        sid, mid = sptr.id, member_id
        if not internal.structure.has(sid):
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring memberscope.deleted event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, sid))
        elif internal.structure.member.has(mid):
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring memberscope.deleted event for member {:#x} (not actually deleted).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, mid))
        elif sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring memberscope.deleted event for structure {:#x} (is a frame).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, sid))
        return super(memberscope, cls).deleted(sid, mid, offset)

class memberscope_84(memberscopecommon):
    """
    It seems that v8.4 of the disassembler can fuck this up pretty bad in that
    during the "struc_member_deleted" eventk, it can give us the completely
    wrong member id. So, we reimplement the base class to use the offset as the
    member key, rather than just the id.
    """

    @classmethod
    def updater(cls):
        '''This coroutine is responsible for accepting both "deleting" and "deleted" events in order to remove the reference counts for the member.'''
        sid, mid, moffset = (yield)
        try:
            oldsid, wrongmid, offset = (yield)

        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while member {:#x} was being removed from structure {:#x}.".format('.'.join([__name__, cls.__name__]), mid, sid))
            return

        # The only thing we need to do is to grab all the tags for the member,
        # and remove them by decrementing each of them one-by-one.
        if (sid, moffset) == (oldsid, offset):
            return cls.delete_refs(sid, mid)

        # If the ids didn't match, then we assume only the ones from the second
        # "deleted" event need to be removed.
        logging.fatal(u"{:s}.updater() : Events are out of sync for removal of member {:#x}, as member {:#x} was originally selected. Assuming that member {:#x} was deleted.".format('.'.join([__name__, cls.__name__]), mid, mid, mid))
        cls.delete_refs(sid, mid)

    @classmethod
    def deleting(cls, sptr, mptr):
        '''deleting_struc_member(sptr, mptr)'''
        description, sid, mid = cls.__name__, sptr.id, mptr.id
        if not internal.structure.has(sid):
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring {:s}.deleting event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sid, mid, description, sid))
        elif not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring {:s}.deleting event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sid, mid, description, mid))
        elif sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring {:s}.deleting event for structure {:#x} (is a frame).".format('.'.join([__name__, cls.__name__]), sid, mid, description, sid))

        # Grab the structure and the member using the identifiers we were given
        # by the caller. These should always succeed since we just verified that
        # the they already exist and are correct.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)

        # Now we can create a new event using the structure id and the member
        # offset. Afterwards, we can send both ids to the event updater.
        logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Received {:s}.deleting event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, description, mid))

        event = cls.new((sid, mptr.soff))
        try:
            event.send((sid, mid, mptr.soff))
        except StopIteration:
            logging.fatal(u"{:s}.deleting({:#x}, {:#x}) : Abandoning {:s}.deleting event for member {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, description, mid))
        return

    @classmethod
    def deleted(cls, sptr, member_id, offset):
        description, sid, mid = cls.__name__, sptr.id, member_id
        if not internal.structure.has(sid):
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring {:s}.deleted event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, description, sid))
        elif sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring {:s}.deleted event for structure {:#x} (is a frame).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, description, sid))
        description = cls.__name__
        logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Received {:s}.deleted event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, offset, description, mid))

        # Now we'll resume our event coroutine using the offset we were given,
        # since the disassembler at least gets this one right.
        event = cls.resume((sid, offset))
        try:
            event.send((sid, mid, offset))
        except StopIteration:
            logging.fatal(u"{:s}.deleting({:#x}, {:#x}, {:+#x}) : Abandoning {:s}.deleted event for member {:#x} due to unexpected termination of event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, offset, description, mid))
        finally:
            event.close()
        return

class framememberscope(memberscopecommon):
    """
    This class handles the 2-part event that is dispatched by the disassembler
    when a frame member is deleted. It handles the event when a frame member
    is created. This is done by using the "struc_member_created" event, the
    "deleting_struc_member" event, and the "struc_member_deleted" event.

    These events (according to the documentation) are supposed to be dispatched
    when ever a structure member is created or deleted. However, on some
    versions of the disassembler (8.4) these events are only dispatched on frame
    members. Due to this constraint, this class will explicitly test the
    member id that is given to verify that it actually belongs to a frame.
    """

    @classmethod
    def created(cls, sptr, mptr):
        '''struc_member_created(sptr, mptr)'''
        if not internal.structure.has(sptr.id):
            return logging.debug(u"{:s}.created({:#x}, {:#x}) : Ignoring framememberscope.created event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, sptr.id))
        elif not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.created({:#x}, {:#x}) : Ignoring framememberscope.created event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))
        elif not sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.created({:#x}, {:#x}) : Ignoring framememberscope.created event for structure {:#x} (not a frame).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, sptr.id))
        return super(framememberscope, cls).created(sptr.id, mptr.id)

    @classmethod
    def deleting(cls, sptr, mptr):
        '''deleting_struc_member(sptr, mptr)'''
        sid, mid = sptr.id, mptr.id
        if not internal.structure.has(sid):
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring framememberscope.deleting event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sid, mid, sid))
        elif not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring framememberscope.deleting event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sid, mid, mid))
        elif not sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.deleting({:#x}, {:#x}) : Ignoring framememberscope.deleting event for structure {:#x} (not a frame).".format('.'.join([__name__, cls.__name__]), sid, mid, sid))
        return super(framememberscope, cls).deleting(sid, mid)

    @classmethod
    def deleted(cls, sptr, member_id, offset):
        '''struc_member_deleted(sptr, member_id, offset)'''
        sid, mid = sptr.id, member_id
        if not internal.structure.has(sid):
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring framememberscope.deleted event for structure {:#x} (unknown structure).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, sid))
        elif internal.structure.member.has(mid):
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring framememberscope.deleted event for member {:#x} (not actually deleted).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, mid))
        elif not sptr.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.deleted({:#x}, {:#x}, {:+#x}) : Ignoring framememberscope.deleted event for structure {:#x} (not a frame).".format('.'.join([__name__, cls.__name__]), sid, mid, offset, sid))
        return super(framememberscope, cls).deleted(sid, mid, offset)

class membernamingcommon(changingchanged):
    """
    This namespace is a base class that is used when renaming members or frame
    members. Member names for either are tracked via the private "__name__" tag.
    The existence of this tag is used for distinguishing members with a custom,
    user-specified name from members that were named by the disassembler.
    """

    @classmethod
    def is_general_field(cls, sid, mid, name):
        '''Return true if the specified `name` is the default field name that was chosen by the disassembler for the member `mid` of structure `sid`.'''
        ok = internal.structure.has(sid) and internal.structure.member.has(mid)

        # If our structure id or member id is unknown, then we assume the name
        # is default, since they don't actually exist in the database.
        if not ok:
            return True

        # First we use the identifiers to grab the struc_t and member_t from the
        # disassembler api. Then we can use them to grab the default name for
        # the member. Only thing left to do is to return the comparison result.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)
        expected = internal.structure.member.default_name(mowner, mptr)

        # FIXME: should we check for things like "anonymous" too?
        return name == expected

    @classmethod
    def updater(cls):
        oldsid, oldmid, newname = (yield)

        # Before doing anything, we need to grab the old name for the member
        # that we were given. This way we can check if the name has been changed
        # or stayed the same. Afterwards, we grab whatever the next "renamed"
        # event has sent to us.
        oldname = internal.structure.member.get_name(oldmid)

        try:
            newsid, newmid = (yield)
        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while name for member {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), oldmid, oldname, newname))
            return

        # Next we need to sanity-check that our ids are correct. Regardless, we
        # explicitly trust the "newsid" and "newmid" given to us by "renamed".
        if oldsid != newsid:
            logging.fatal(u"{:s}.updater() : Member renaming events for member {:#x} are out of sync. Expected structure {:#x}, but event gave us structure {:#x}.".format('.'.join([__name__, cls.__name__]), oldmid, oldsid, newsid))

        if oldmid != newmid:
            logging.fatal(u"{:s}.updater() : Member renaming events for member {:#x} are out of sync. Expected member {:#x}, but event gave us member {:#x}.".format('.'.join([__name__, cls.__name__]), oldmid, oldmid, newmid))

        # Now we'll check both the old name and new name to figure out which
        # ones are generalized, and which ones are user-specified.
        sid, mid = newsid, newmid
        gold, gnew = (cls.is_general_field(sid, mid, name) for name in [oldname, newname])
        renamed = gold, gnew

        # Only thing left is to figure out whether we increment our reference
        # count for "__name__" or decrement it. If the rename is from a general
        # name to a user-specified one, then we increment.
        if renamed == (True, False):
            internal.tags.reference.members.increment(mid, '__name__')

        # Otherwise, the name was cleared to a default, which we'll decrement.
        elif renamed == (False, True):
            internal.tags.reference.members.decrement(mid, '__name__') if '__name__' in internal.tags.reference.members.get(mid) else ()

        # If the old name is fancy but there's no name tag for the member, then
        # the user renamed a member that the disassembler had initialized with a
        # custom name. So, we increment to add the "__name__" tag to the member.
        elif not gold and '__name__' not in internal.tags.reference.members.get(mid):
            internal.tags.reference.members.increment(mid, '__name__')

        # If both are the same, the state of the "__name__" tag hasn't changed.
        else:
            logging.debug(u"{:s}.updater() : Member renaming event for member {:#x} from \"{!s}\" to \"{!s}\" did not need an adjustment.".format('.'.join([__name__, cls.__name__]), mid, oldname, newname))
        return

    @classmethod
    def renaming(cls, sid, mid, newname):
        '''renaming_struc_member(sptr, mptr, newname)'''
        description = cls.__name__

        # Now grab the member using its identifier. This should always succeed
        # since the identifiers should've already been checked by caller.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)

        # Next we need to create a new coroutine for the member so that we can
        # send our parameters to it for processing.
        logging.debug(u"{:s}.renaming({:#x}, {:#x}, {!r}) : Received {:s}.renaming event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, newname, description, mptr.id))
        event = cls.new((mowner.id, mptr.id))

        # All that's left to do is to send our parameters to it. The coroutine
        # is responsible for figuring out the previous name of the member.
        try:
            event.send((mowner.id, mptr.id, newname))
        except StopIteration:
            logging.fatal(u"{:s}.renaming({:#x}, {:#x}, {!r}) : Abandoning rename for member {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, newname, mptr.id))
        return

    @classmethod
    def renamed(cls, sid, mid):
        '''struc_member_renamed(sptr, mptr)'''
        description = cls.__name__

        # Now grab the member that was renamed using its identifier. Our caller
        # method should've checked the identifiers before giving them to us.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)

        # Then we need to grab our coroutine in order to resume its execution.
        # After grabbing it, we send out the parameters to complete the rename.
        logging.debug(u"{:s}.renamed({:#x}, {:#x}) : Received {:s}.renamed event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, description, mptr.id))
        event = cls.resume((mowner.id, mptr.id))
        try:
            event.send((mowner.id, mptr.id))
        except StopIteration:
            logging.fatal(u"{:s}.renamed({:#x}, {:#x}) : Abandoning rename for member {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, mptr.id))
        event.close()

class membernaming(membernamingcommon):
    """
    This class handles the 2-part event dispatched by the disassembler when a
    frame member has been renamed. It is primarily responsible for tracking the
    reference count for the "__name__" tags that are applied to members. The
    existence of the "__name__" tag is only for identifying members that have a
    customized or user-specified name.

    The implementation of this namespace is the same implementation as the
    `framemembernaming` namespace. The reason for the existence of two different
    namespaces are because later versions of the disassembler (8.4) are actually
    broken and do not dispatch any of the member hooks if the target is a
    regular structure. For some reason this still works on frames, though.
    """

    @classmethod
    def renaming(cls, sptr, mptr, newname):
        '''renaming_struc_member(sptr, mptr, newname)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.renaming({:#x}, {:#x}, {!r}) : Ignoring membernaming.renaming event for member {:#x} (unknown frame member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, newname, mptr.id))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.renaming({:#x}, {:#x}, {!r}) : Ignoring membernaming.renaming event for member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, newname, mptr.id))
        return super(membernaming, cls).renaming(mowner.id, mptr.id, newname)

    @classmethod
    def renamed(cls, sptr, mptr):
        '''struc_member_renamed(sptr, mptr)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.renamed({:#x}, {:#x}) : Ignoring membernaming.renamed event for member {:#x} (unknown frame member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))

        # Now try and grab the member that was renamed using its identifier.
        # This always succeeds since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.renamed({:#x}, {:#x}) : Ignoring membernaming.renamed event for member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))
        return super(membernaming, cls).renamed(mowner.id, mptr.id)

class framemembernaming(membernamingcommon):
    """
    This class handles the 2-part event dispatched by the disassembler when a
    frame member has been renamed. It is primarily responsible for tracking the
    reference count for the "__name__" tags that are applied to members. The
    existence of the "__name__" tag is only for identifying members that have a
    customized or user-specified name.

    The implementation of this namespace is the same implementation as the
    `membernaming` namespace. The reason for the existence of two different
    namespaces are because later versions of the disassembler (8.4) are actually
    broken and do not dispatch any of the member hooks if the target is a
    regular structure. For some reason this still works on frames, though.
    """

    @classmethod
    def renaming(cls, sptr, mptr, newname):
        '''renaming_struc_member(sptr, mptr, newname)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.renaming({:#x}, {:#x}, {!r}) : Ignoring framemembernaming.renaming event for member {:#x} (unknown frame member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, newname, mptr.id))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.renaming({:#x}, {:#x}, {!r}) : Ignoring framemembernaming.renaming event for member {:#x} (belongs to a structure).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, newname, mptr.id))
        return super(framemembernaming, cls).renaming(mowner.id, mptr.id, newname)

    @classmethod
    def renamed(cls, sptr, mptr):
        '''struc_member_renamed(sptr, mptr)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.renamed({:#x}, {:#x}) : Ignoring framemembernaming.renamed event for member {:#x} (unknown frame member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))

        # Now try and grab the member that was renamed using its identifier.
        # This always succeeds since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.renamed({:#x}, {:#x}) : Ignoring framemembernaming.renamed event for member {:#x} (belongs to a structure).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))
        return super(framemembernaming, cls).renamed(mowner.id, mptr.id)

class membertypeinfocommon(changingchanged):
    """
    This namespace is intended to be inherited from and is used to track the
    type information applied to a structure member. It supports the 2-part
    events that are dispatched by the disassembler using both the "changing_ti"
    and "ti_changed" events. The purpose of monitoring the application of a type
    is specifically for the "__typeinfo__" tag.
    """

    @classmethod
    def updater(cls):
        oldsid, oldmid, typedata, fnamesdata = (yield)

        # Now we use the identifiers we were given to get both the struc_t and
        # member_t. This way we can grab the old values before the change.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, oldmid)

        # So, it turns out that the parameters we receive for "changing_ti" and
        # the following "ti_changed" event are always the same. The disassembler
        # doesn't give us the original type and instead always give us the new
        # one. So at this point we fetch the old type from the member ourselves
        # and use the data we were given to deserialize the actual target type.
        oldtype = internal.structure.member.get_typeinfo(mptr) if internal.structure.member.has_typeinfo(mptr) else None
        newtype = interface.tinfo.get(None, typedata, fnamesdata) if typedata else None

        # Now we can just wait until we receive the next parameters since
        # they're really only needed to match the identifiers.
        try:
            newsid, newmid, newtypedata, newfnamesdata = (yield)
        except GeneratorExit:
            description = "\"{!s}\"".format(utils.string.escape("{!s}".format(newtype), '"')) if newtype else None
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while type for member {:#x} was being {!s}.".format('.'.join([__name__, cls.__name__]), oldmid, "changed to {!s}".format(description) if description else 'removed'))
            return

        # Verify that our identifiers are all the same. Once they're confirmed,
        # we can start comparing the types to figure out whether we need to
        # increment the reference count for the "__typeinfo__" tag.
        sid, mid = newsid, newmid
        if (oldsid, oldmid) == (newsid, newmid):
            oldtyped, newtyped = oldtype is not None, newtype is not None
            applied = oldtyped, newtyped

            # If the change added a type, then increment the reference.
            if applied == (False, True):
                internal.tags.reference.members.increment(mid, '__typeinfo__')

            # If the change removed the type, then decrement the reference.
            elif applied == (True, False):
                internal.tags.reference.members.decrement(mid, '__typeinfo__') if '__typeinfo__' in internal.tags.reference.members.get(mid) else ()

            # If the old type exists but the "__typeinfo__" tag is missing, then
            # we need to add a reference to "__typeinfo__" since we missed it.
            elif oldtyped and '__typeinfo__' not in internal.tags.reference.members.get(mid):
                internal.tags.reference.members.increment(mid, '__typeinfo__')

            # Otherwise there is nothing to do since the updating of the type
            # didn't actually affect the previous type.
            else:
                old = "\"{!s}\"".format(utils.string.escape("{!s}".format(oldtype), '"') if oldtype else '')
                new = "\"{!s}\"".format(utils.string.escape("{!s}".format(newtype), '"') if newtype else '')
                logging.debug(u"{:s}.updater() : Member type information update for member {:#x} from {!s} to {!s} did not need an adjustment.".format('.'.join([__name__, cls.__name__]), mid, old, new))
            return

        # If the events didn't match at all, then somehow the events didn't
        # arrive in the correct order. So, we fix it by deleting the reference
        # to the "__typeinfo__" tag, and then recreating if it exists.
        logging.fatal(u"{:s}.updater() : Member type events for member {:#x} are out of sync. Expected member {:#x}, but event gave us member {:#x}.".format('.'.join([__name__, cls.__name__]), oldmid, oldmid, newmid))

        if '__typeinfo__' in internal.tags.reference.members.get(mid):
            internal.tags.reference.members.decrement(mid, '__typeinfo__')

        if newtype is not None:
            internal.tags.reference.members.increment(mid, '__typeinfo__')
        return

    @classmethod
    def changing(cls, mid, new_type, new_fnames):
        '''changing_ti(ea, new_type, new_fnames)'''
        description = cls.__name__
        logging.debug(u"{:s}.changing({:#x}, {!r}, {!r}) : Received {:s}.changing event for member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, "{!s}".format(new_type), new_fnames, description, mid))

        # Grab the member using the member id we were given. This will always
        # succeeed since it should've already been checked by the caller.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)

        # Only thing to do is to create a new coroutine for managing this event,
        # and then sending all of our parameters to it until the next event.
        event = cls.new((mowner.id, mptr.id))

        try:
            event.send((mowner.id, mptr.id, new_type, new_fnames))
        except StopIteration:
            logging.fatal(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!r}, {:+#x}) : Abandoning the change of type information for member {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, flag, 2 + 8, "{!s}".format(ti) if ti else '', nbytes, mptr.id))
        return

    @classmethod
    def changed(cls, mid, type, fnames):
        '''ti_changed(ea, type, fnames)'''
        description = cls.__name__
        logging.debug(u"{:s}.changed({:#x}, {!r}, {!r}) : Received {:s}.changed event for member {:#x}.".format('.'.join([__name__, cls.__name__]), mid, type, fnames, description, mid))

        # Snag the member using the identifier given to us by the caller.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)

        # Now we need to grab the matching coroutine from our state, and then
        # send the completion parameters to complete the type modification.
        event = cls.resume((mowner.id, mptr.id))
        try:
            event.send((mowner.id, mptr.id, type, fnames))
        except StopIteration:
            logging.debug(u"{:s}.changed({:#x}, {!r}, {!r}) : Abandoning the change of type information for member {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), mid, type, fnames, mptr.id))
        event.close()

class membertypeinfo(membertypeinfocommon):
    """
    This namespace handles the 2-part event that is dispatched by the
    disassembler when a type has been applied to a structure member. Is is
    intended for tracking whether the "__typeinfo__" tag should be attached to
    the structure member.

    This namespace is the same implementation as the `framemembertypeinfo`
    namespace, with the only difference being that this one is used for tracking
    types applied to structure members, and the other one being used to track
    any of the types applied to frame members.
    """

    @classmethod
    def changing(cls, mid, new_type, new_fnames):
        '''changing_ti(ea, new_type, new_fnames)'''
        if not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.changing({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changing event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), mid, new_type, new_fnames, mid))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changing({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changing event for member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), mid, new_type, new_fnames, mptr.id))
        return super(membertypeinfo, cls).changing(mptr.id, new_type, new_fnames)

    @classmethod
    def changed(cls, mid, type, fnames):
        '''ti_changed(ea, type, fnames)'''
        if not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.changed({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changed event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), mid, type, fnames, mid))

        # We just need to grab our own versions of the structure and member, and
        # then check if it belongs to a frame. Afterwards just call our parent.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changed({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changed event for member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), mid, type, fnames, mptr.id))
        return super(membertypeinfo, cls).changed(mptr.id, type, fnames)

class framemembertypeinfo(membertypeinfocommon):
    """
    This namespace handles the 2-part event that is dispatched by the
    disassembler when a type has been applied to a frame member. Is is intended
    for tracking whether the "__typeinfo__" tag should be attached to the
    corresponding frame member or not.

    This namespace is the same implementation as the `membertypeinfo` namespace,
    with the only difference between the two being that this one is only used
    for frame members. The reason why we split these up are because later
    versions of the disassembler break some of the hooks that use for tracking,
    so this way we can split up the implementation depending on the version.
    """
    @classmethod
    def changing(cls, mid, new_type, new_fnames):
        '''changing_ti(ea, new_type, new_fnames)'''
        if not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.changing({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changing event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), mid, new_type, new_fnames, mid))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changing({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changing event for member {:#x} (does not belong to a frame).".format('.'.join([__name__, cls.__name__]), mid, new_type, new_fnames, mptr.id))
        return super(framemembertypeinfo, cls).changing(mptr.id, new_type, new_fnames)

    @classmethod
    def changed(cls, mid, type, fnames):
        '''ti_changed(ea, type, fnames)'''
        if not internal.structure.member.has(mid):
            return logging.debug(u"{:s}.changed({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changed event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), mid, type, fnames, mid))

        # We just need to grab our own versions of the structure and member, and
        # then check if it belongs to a frame. Afterwards just call our parent.
        mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changed({:#x}, {!r}, {!r}) : Ignoring membertypeinfo.changed event for member {:#x} (does not belong to a frame).".format('.'.join([__name__, cls.__name__]), mid, type, fnames, mptr.id))
        return super(framemembertypeinfo, cls).changed(mptr.id, type, fnames)

class memberchangecommon(changingchanged):
    """
    This namespace contains the common logic that is used when the "type" of a
    member has been changed. This type is different from the type information in
    that it is always guaranteed to exist on a frame member. Presently the
    implementation of this namespace doesn't actually do anything since this
    information really isn't worth tracking for any reason. Hence, the namespace
    exists strictly as a placeholder in case we decide we want to track member
    types for some reason.
    """

    @classmethod
    def updater(cls):
        oldsid, oldmid, newflags, newinfo, newsize = (yield)

        # We first need to verify that the member id actually points to a valid
        # member. Then we can grab the original attributes for the member so
        # that we can compare them to the new ones.
        mowner, mindex, mptr = internal.structure.members.by_identifier(oldsid, oldmid)
        oldflags, oldsize = idaapi.as_uint32(mptr.flag), internal.structure.member.size(mptr.id)

        oldinfo = idaapi.opinfo_t()
        ok = idaapi.retrieve_member_info(mptr, oldinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(oldinfo, mptr)
        if not ok:
            oldinfo = None

        # FIXME: if we're a frame, we should grab the function and use it to
        #        figure out the member offset so that we can get a proper type.

        try:
            newsid, newmid = (yield)
        except GeneratorExit:
            logging.debug(u"{:s}.updater() : Terminating state due to explicit request from owner while name for member {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), oldmid, oldname, newname))
            return

        # Verify that our identifiers are all the same. Once they're confirmed,
        # we can start comparing the types to figure out what we need to do.
        sid, mid = newsid, newmid
        if (oldsid, oldmid) == (newsid, newmid):
            oldpythonic = interface.typemap.dissolve(oldflags, oldinfo.tid if oldinfo is not None else idaapi.BADNODE, oldsize)
            newpythonic = interface.typemap.dissolve(newflags, newinfo.tid if newinfo is not None else idaapi.BADNODE, newsize)
            logging.debug(u"{:s}.updater() : Member type update for member {:#x} from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), mid, oldpythonic, newpythonic))
            return

        # If the events didn't match at all, then somehow the events didn't
        # arrive in the correct order. It's okay though, because we don't really
        # need to do anything as this implementation is just a placeholder.
        logging.fatal(u"{:s}.updater() : Member type events for member {:#x} are out of sync. Expected member {:#x}, but event gave us member {:#x}.".format('.'.join([__name__, cls.__name__]), oldmid, oldmid, newmid))

        oldpythonic = interface.typemap.dissolve(oldflags, oldinfo.tid if oldinfo is not None else idaapi.BADNODE, oldsize)
        newpythonic = interface.typemap.dissolve(newflags, newinfo.tid if newinfo is not None else idaapi.BADNODE, newsize)
        logging.debug(u"{:s}.updater() : Member type update for member {:#x} from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), mid, oldpythonic, newpythonic))

    @classmethod
    def changing(cls, sid, mid, flag, newinfo, newsize):
        '''changing_struc_member(sptr, mptr, flag, ti, nbytes)'''
        description = cls.__name__

        # Grab the member using the identifiers we were given. This will always
        # succeeed since they should've been checked by the caller.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)
        logging.debug(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!s}, {:+#x}) : Received {:s}.changing event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, flag, 2 + 8, newinfo, newsize, description, mptr.id))

        # Only thing to do is to create a new coroutine for managing this event,
        # and then sending all of our parameters to it until the next event.
        event = cls.new((mowner.id, mptr.id))

        try:
            event.send((mowner.id, mptr.id, flag, newinfo, newsize))
        except StopIteration:
            logging.fatal(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!s}, {:+#x}) : Abandoning the change of type for member {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, flag, 2 + 8, newinfo, newsize, mptr.id))
        return

    @classmethod
    def changed(cls, sid, mid):
        '''struc_member_changed(sptr, mptr)'''
        description = cls.__name__

        # Snag the member using the identifiers given to us by the caller.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sid, mid)
        logging.debug(u"{:s}.changed({:#x}, {:#x}) : Received {:s}.changed event for member {:#x}.".format('.'.join([__name__, cls.__name__]), sid, mid, description, mptr.id))

        # Now we need to grab the matching coroutine from our state, and then
        # send the completion parameters to complete the type modification.
        event = cls.resume((mowner.id, mptr.id))
        try:
            event.send((mowner.id, mptr.id))
        except StopIteration:
            logging.debug(u"{:s}.changed({:#x}, {:#x}) : Abandoning the change of type for member {:#x} due to an unexpected termination of the event handler.".format('.'.join([__name__, cls.__name__]), sid, mid, mptr.id))
        event.close()

class memberchange(memberchangecommon):
    """
    This namespace handles the 2-part event that is dispatched by the
    disassembler when the type of a structure member has been updated. The
    implementation is basically the same as the `framememberchange` namespace
    with the only difference being that this namespace is intended to be used on
    structure members, whereas the other one is only for frame members.

    The reason why we split up this namespace from `framememberchange` is that
    later versions of the disassembler do not correctly dispatch the initial
    "changing_struc_member" event on a non-frame member.

    Due to a member type being guaranteed to exist on a member, this namespace
    doesn't really do anything. Hence, this namespace only exists as a
    placeholder in case someone in the future finds something worth tracking.
    """

    @classmethod
    def changing(cls, sptr, mptr, flag, newinfo, nbytes):
        '''changing_struc_member(sptr, mptr, flag, newinfo, nbytes)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!s}, {:+#x}) : Ignoring memberchange.changing event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, flag, 2 + 8, newinfo, nbytes, mptr.id))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!s}, {:+#x}) : Ignoring memberchange.changing event for member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, flag, 2 + 8, newinfo, nbytes, mptr.id))
        return super(memberchange, cls).changing(mowner.id, mptr.id, flag, newinfo, nbytes)

    @classmethod
    def changed(cls, sptr, mptr):
        '''struc_member_changed(sptr, mptr)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.changed({:#x}, {:#x}) : Ignoring memberchange.changed event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))

        # We just need to grab our own versions of the structure and member, and
        # then check if it belongs to a frame. Afterwards just call our parent.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changed({:#x}, {:#x}) : Ignoring memberchange.changed event for member {:#x} (belongs to a frame).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))
        return super(memberchange, cls).changed(mowner.id, mptr.id)

class framememberchange(memberchangecommon):
    """
    This namespace handles the 2-part event that can be dispatched by the
    disassembler when the type of a frame member has been changed or updated.
    The implementation is the exact same as the `memberchange` namespace with
    the only difference being that the hooks in this namespace are intended to
    be used with only frame members.

    The reason why this namespace is split up from the `memberchange` namespace
    is that later verions of the disassembler actually break structure member
    events for members that do not belong to frames. So, we split up the
    implementation so that we can specially handle structure members that are
    broken.

    Due to the frame member type always being guaranteed to exist on a frame
    member, this namespace really doesn't do anything important. The namespace
    only exists in case someone in the future has something that they want to
    track about how a frame member changes.
    """
    @classmethod
    def changing(cls, sptr, mptr, flag, newinfo, nbytes):
        '''changing_struc_member(sptr, mptr, flag, newinfo, nbytes)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!s}, {:+#x}) : Ignoring framememberchange.changing event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, flag, 2 + 8, newinfo, nbytes, mptr.id))

        # Now try and grab the member using its identifier. This should always
        # succeed since we just checked the member id up above.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changing({:#x}, {:#x}, {:#0{:d}x}, {!s}, {:+#x}) : Ignoring framememberchange.changing event for member {:#x} (belongs to a structure).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, flag, 2 + 8, newinfo, nbytes, mptr.id))
        return super(framememberchange, cls).changing(mowner.id, mptr.id, flag, newinfo, nbytes)

    @classmethod
    def changed(cls, sptr, mptr):
        '''struc_member_changed(sptr, mptr)'''
        if not internal.structure.member.has(mptr.id):
            return logging.debug(u"{:s}.changed({:#x}, {:#x}) : Ignoring framememberchange.changed event for member {:#x} (unknown member).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))

        # We just need to grab our own versions of the structure and member, and
        # then check if it belongs to a frame. Afterwards just call our parent.
        mowner, mindex, mptr = internal.structure.members.by_identifier(sptr.id, mptr.id)
        if not mowner.props & idaapi.SF_FRAME:
            return logging.debug(u"{:s}.changed({:#x}, {:#x}) : Ignoring framememberchange.changed event for member {:#x} (belongs to a structure).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, mptr.id))
        return super(framememberchange, cls).changed(mowner.id, mptr.id)

class localtypesmonitor_state(object):
    """
    This class maintains the state of the local type library from the current
    database. It does this in order to extract information about the library
    from the parameters of the "local_types_changed". The data inside the class
    is not persisted. Instead, the class is instantiated and populated when the
    database is created.
    """

    def __init__(self):
        self.loaded = False

        # This is a cache of all the structures and unions in a local types
        # library. It is keyed by the ordinal of the structure/union type.
        self.structurecache = {}
        self.structureid = {}
        self.structurecomment = {}

        # This is a cache of all the members belonging to a structure in the
        # type library. It is keyed by the ordinal number, and stores a
        # dictionary that is keyed by index.
        self.memberoffsetcache = {}
        self.memberindexcache = {}

    def count(self):
        '''Return the number of types that are currently cached.'''
        return len(self.structurecache)

    def __repr__(self):
        if not self.loaded:
            return "{!s} // the local types library has not been loaded".format(self.__class__)
        header = "{!s} // {:d}/{:d} type{:s} cached".format(self.__class__, len(self.structurecache), interface.tinfo.quantity(), '' if len(self.structurecache) == 1 else 's')

        # Iterate through all of the structures we've cached and display any
        # information that might be relevant.
        rows = []
        for ordinal in sorted(self.structurecache):
            name = self.structurecache[ordinal]
            sid = self.structureid[ordinal]
            count = len(self.memberindexcache[ordinal])
            actual = sum(1 for item in self.get_members(ordinal))
            iterable = map(operator.itemgetter(0), self.memberindexcache[ordinal].values())
            rows.append("[{:d}] {!r} ({:#x}) : {:d} member{:s} cached{:s}{!s}".format(ordinal, name, sid, count, '' if count == 1 else 's', '' if count == actual else ", expected {:d} member{:s}".format(actual, '' if actual == 1 else 's'), " : {:s}".format(','.join(map("{:#x}".format, iterable))) if count else ''))
        return '\n'.join(itertools.chain([header], rows))

    @classmethod
    def get_type(cls, ordinal):
        '''Return the type that is specified by `ordinal` and has member identifiers directly attached to it.'''
        if isinstance(ordinal, internal.types.integer):
            tinfo, description = interface.tinfo.for_ordinal(ordinal), "{:d}".format(ordinal)
        elif isinstance(ordinal, internal.types.string):
            tinfo, description = interface.tinfo.for_name(ordinal), "{!r}".format("{!s}".format(ordinal))
        elif isinstance(ordinal, idaapi.tinfo_t):
            tinfo, description = interface.tinfo.copy(ordinal), "{!r}".format("{!s}".format(ordinal))
        else:
            raise internal.exceptions.InvalidParameterError(u"{:s}.get_type({!s}) : Unable to locate a type within the local types library using an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), description, ordinal.__class__))

        # If we couldn't get the type, then just raise an exception.
        if not tinfo:
            raise internal.exceptions.LocalTypeNotFoundError(u"{:s}.get_type({!s}) : Unable to locate the specified type in the local types library.".format('.'.join([__name__, cls.__name__]), description))

        # If our type is a type reference pointing to a type reference, then
        # we need to dereference it in order to find the actual local type
        # that will return the member ids that we are looking for.
        res = tinfo
        while tinfo and tinfo.present() and tinfo.is_typeref():
            res, name, ordinal = tinfo, tinfo.get_type_name(), interface.tinfo.ordinal(tinfo)
            tinfo = interface.tinfo.at_ordinal(ordinal) if ordinal else interface.tinfo.at_name(name)
        return res

    @classmethod
    def get_members(cls, ordinal):
        '''Iterate through all of the members in the structure or union specified by `ordinal`.'''
        tinfo = cls.get_type(ordinal)
        iterable = (itertools.chain([index], items) for index, items in enumerate(interface.tinfo.members(tinfo)))

        # Now we can iterate through all of the members that were found in 8.4.
        # Still, we have to filter the members being yielded due to the
        # existence of "gap" fields. The disassembler treats these as if the
        # member is deleted. So, if a member was replaced with a gap, then skip.
        for mindex, mname, moffset, msize, mtype, malign in map(tuple, iterable):
            udm = idaapi.udm_t()
            udm.offset = mindex

            # Populate the udm structure and double-check the index is valid. If
            # the `tinfo_t.find_udm` method returns a negative index, suggesting
            # that the member wasn't found, then we just skip it.
            newindex = tinfo.find_udm(udm, idaapi.STRMEM_INDEX)
            if newindex < 0:
                pass

            # If the udm structure tells us that this member is a gap, then we
            # skip over it since essentially the member was deleted.
            elif udm.is_gap():
                pass

            # Now we can yield the info for the current member being processed.
            else:
                mid = tinfo.get_udm_tid(mindex)
                mcomment = utils.string.of(udm.cmt)
                yield mindex, mid, mname, moffset, msize, mtype, malign, mcomment
            continue
        return

    @classmethod
    def get_member_by_udm(cls, ordinal, key, value):
        '''Return the member of the structure or union in `ordinal` using given `key` and matching `value`.'''
        udm = idaapi.udm_t()
        if key in {idaapi.STRMEM_OFFSET, idaapi.STRMEM_INDEX, idaapi.STRMEM_AUTO}:
            udm.offset = bitoffset
        elif key == idaapi.STRMEM_NAME:
            udm.name = utils.string.to(value)
        elif key == idaapi.STRMEM_TYPE:
            udm.type = value
        elif key == idaapi.STRMEM_SIZE:
            udm.size = value
        elif key in {idaapi.STRMEM_MINS, idaapi.STRMEM_MAXS}:
            pass
        else:
            raise internal.exceptions.InvalidParameterError(u"{:s}.get_member_by_udm({:d}, {:d}, {!s}) : Unable to find a member using an unsupported key type ({:d}) with the given key ({!s}).".format('.'.join([__name__, 'localtypesmonitor_84', cls.__name__]), ordinal, key, "{:d}".format(value) if isinstance(value, internal.types.integer) else "{!r}".format(value), key, "{:d}".format(value) if isinstance(value, internal.types.integer) else "{!r}".format(value)))

        # Grab the index for the member and verify that it is valid.
        tinfo = cls.get_type(ordinal)
        mindex = tinfo.find_udm(udm, key)
        if mindex < 0:
            raise internal.exceptions.MemberNotFoundError(u"{:s}.get_member_by_udm({:d}, {:d}, {!r}) : Unable to find a member matching the specified key type ({:d}) with the given key ({!s}).".format('.'.join([__name__, 'localtypesmonitor_84', cls.__name__]), ordinal, key, "{:d}".format(value) if isinstance(value, internal.types.integer) else "{!r}".format(value), key, "{:d}".format(value) if isinstance(value, internal.types.integer) else "{!r}".format(value)))

        mname = utils.string.of(udm.name)
        mid = tinfo.get_udm_tid(mindex)
        moffset, msize, malign = udm.offset, udm.size, udm.effalign
        mtype = interface.tinfo.concretize(udm.type)
        return mindex, mid, moffset, msize, mtype, malign

    @classmethod
    def get_member_by_bitoffset(cls, ordinal, bitoffset):
        return cls.get_member_by_udm(ordinal, idaapi.STRMEM_OFFSET, bitoffset)
    @classmethod
    def get_member_by_name(cls, ordinal, name):
        return cls.get_member_by_udm(ordinal, idaapi.STRMEM_NAME, name)
    @classmethod
    def get_member_by_index(cls, ordinal, index):
        return cls.get_member_by_udm(ordinal, idaapi.STRMEM_INDEX, index)
    @classmethod
    def get_member_by_offset(cls, ordinal, index_or_offset):
        return cls.get_member_by_udm(ordinal, idaapi.STRMEM_AUTO, index_or_offset)
    @classmethod
    def get_member_by_mid(cls, ordinal, mid):
        res, tinfo = idaapi.udm_t(), cls.get_type(ordinal)
        mindex = tinfo.get_udm_by_tid(mid)
        mname = utils.string.of(udm.name)
        mid = tinfo.get_udm_tid(mindex)
        moffset, msize, malign = udm.offset, udm.size, udm.effalign
        mtype = interface.tinfo.concretize(udm.type)
        return mindex, mid, moffset, msize, mtype, malign

    @classmethod
    @contextlib.contextmanager
    def ignore_changes(cls, *events):
        '''This context manager disables any type changes that might occur inside the managed code by disabling the specified `events`.'''
        iterable = itertools.chain(['local_types_changed'], events)

        # Import our hook module, accepting that we don't care about the
        # perform of the handler for the "local_types_changed" event.
        import hook

        # Start by disabling all of the required events and storing whether
        # they were successful for not. If they weren't disabled, then we
        # raise an exception and abort the context manager entirely.
        required = {event for event in iterable} - hook.idb.disabled
        disabled = [hook.idb.disable(event) for event in required]
        try:
            if not all(disabled):
                raise exceptions.DisassemblerError(u"{:s}.ignore_changes({!s}) : Unable to disable {:d} of {:d} requested event{:s}.".format('.'.join([__name__, cls.__name__]), sum(1 for ok in disabled if not ok), len(required), '' if len(required) == 1 else 's'))
            yield

        # Now that we're done, we can go ahead and re-enable all of the
        # events that we just disabled.
        finally:
            enabled = [hook.idb.enable(event) for event in required]

        if not all(enabled):
            raise exceptions.DisassemblerError(u"{:s}.ignore_changes({!s}) : Unable to enable {:d} of {:d} disabled event{:s}.".format('.'.join([__name__, cls.__name__]), sum(1 for ok in enabled if not ok), len(required), '' if len(required) == 1 else 's'))
        return

    def unload(self, *library):
        '''Clear all of the cached information from the current state.'''
        count = len(self.structurecache)
        self.structurecache = {}
        self.structureid = {}
        self.structurecomment = {}
        self.memberoffsetcache = {}
        self.memberindexcache = {}
        self.loaded = False
        return count

    def __load_unguarded(self, *library):
        '''Load information from the specified type `library` into the current state.'''
        cls = self.__class__
        structurecache, structureid, structurecomment = {}, {}, {}
        memberoffsetcache, memberindexcache = {}, {}

        # Iterate through all the types only looking for structures or
        # unions since they're the only thing that really counts.
        for ordinal, name, tinfo in interface.tinfo.iterate():
            if not(tinfo) or tinfo.empty():
                logging.debug(u"{:s}.load({:s}) : Skipping deleted or empty type \"{:s}\" at ordinal {:d} of the local types library.".format('.'.join([__name__, cls.__name__]), interface.tinfo.format_library(*library) if library else '', utils.string.escape(name, '"'), ordinal))
                continue

            elif not(tinfo.is_struct() or tinfo.is_union()):
                logging.debug(u"{:s}.load({:s}) : Ignoring type \"{:s}\" at ordinal {:d} that is not a structure or a union.".format('.'.join([__name__, cls.__name__]), interface.tinfo.format_library(*library) if library else '', utils.string.escape(name, '"'), ordinal))
                continue

            # Stash the original structure name so that we can know what the
            # previous name will be. We also create a dictionary for the
            # structure so that we can store information about its members.
            structurecache[ordinal] = name
            structureid[ordinal] = interface.tinfo.identifier(tinfo)
            structurecomment[ordinal] = utils.string.of(tinfo.get_type_cmt())
            memberoffsets = memberoffsetcache.setdefault(ordinal, {})
            memberindices = memberindexcache.setdefault(ordinal, {})

            # Now we'll need to go through and enumerate all the members of
            # the structure/union so that we can add their information to
            # our cache.
            iterable = self.get_members(ordinal)
            for mindex, mid, mname, moffset, msize, mtype, malign, mcomment in iterable:
                memberoffsets[moffset] = mindex
                memberindices[mindex] = mid, mname, moffset, msize, mtype, malign, mcomment
            continue

        # Now we can assign them as members of our class.
        self.structurecache = structurecache
        self.structureid = structureid
        self.structurecomment = structurecomment
        self.memberoffsetcache = memberoffsetcache
        self.memberindexcache = memberindexcache
        self.loaded = interface.tinfo.quantity() >= 0
        return len(structurecache)

    def load(self, *library):
        '''Disable any related events and load information from the specified type `library` into the current instance.'''
        with self.ignore_changes():
            res = self.__load_unguarded(*library)
        return res

    def cachedname(self, ordinal):
        '''Return the cached name of the type specified by `ordinal` or an empty string.'''
        return self.structurecache.get(ordinal, '')

    def cachedidentifier(self, ordinal):
        '''Return the cached identifier for the type specified by `ordinal`.'''
        return self.structureid.get(ordinal, idaapi.BADADDR)

    def cachedcomment(self, ordinal):
        '''Return the cached comment for the type specified by `ordinal` or an empty string.'''
        return self.structurecomment.get(ordinal, '')

    def name(self, ordinal):
        '''Return the current name of the type specified by `ordinal`.'''
        tinfo = self.get_type(ordinal)
        res = tinfo.get_type_name()
        return utils.string.of(res)

    def identifier(self, ordinal):
        '''Return the current identifier for the type specified by `ordinal`.'''
        with self.ignore_changes():
            tid = interface.tinfo.identifier(ordinal)
        return tid

    def comment(self, ordinal):
        '''Return the current comment for the type specified by `ordinal`.'''
        tinfo = self.get_type(ordinal)
        res = tinfo.get_type_cmt()
        return utils.string.of(res)

    def renamed(self, ordinal):
        '''Synchronize the cached name for the type specified by `ordinal` with the current name from the local types library.'''
        tinfo = self.get_type(ordinal)
        res, self.structurecache[ordinal] = self.structurecache[ordinal], utils.string.of(tinfo.get_type_name())
        return res

    def commented(self, ordinal):
        '''Synchronize the cached comment for the type specified by `ordinal` with the current comment from the local types library.'''
        tinfo = self.get_type(ordinal)
        res, self.structurecomment[ordinal] = self.structurecomment[ordinal], utils.string.of(tinfo.get_type_cmt())
        return res

    def added(self, ordinal, update=True):
        '''Update the cache with the addition of the type specified by `ordinal`.'''
        tinfo = self.get_type(ordinal)
        res, sid, comment = self.name(tinfo), self.identifier(tinfo), self.comment(tinfo)

        # Verify the identifier and whine if we couldn't find a valid one.
        if sid == idaapi.BADADDR:
            logging.warning(u"{:s}.added({:d}) : An invalid identifier ({:#x}) was found for the recently created type at ordinal {:d} named \"{:s}\" ({!r}).".format('.'.join([__name__, self.__class__.__name__]), ordinal, sid, ordinal, utils.string.escape(res or '', '"'), "{!s}".format(tinfo)))

        # Now we can go through all of its members and collect them.
        memberoffsets, memberindices = {}, {}
        iterable = self.get_members(ordinal)
        for mindex, mid, mname, moffset, msize, mtype, malign, mcomment in iterable:
            memberoffsets[moffset] = mindex
            memberindices[mindex] = mid, mname, moffset, msize, mtype, malign, mcomment

        # Then we can update the cache for the members if it was specified.
        if update:
            self.structurecache[ordinal] = res
            self.structureid[ordinal] = sid
            self.structurecomment[ordinal] = comment
            self.memberoffsetcache[ordinal] = memberoffsets
            self.memberindexcache[ordinal] = memberindices
        return sid, res, comment, memberindices

    def removed(self, ordinal, update=True):
        '''Update the cache with the removal of the type specified by `ordinal`.'''
        Fget_from_dict = operator.methodcaller('pop', ordinal) if update else operator.methodcaller('get', ordinal)
        if self.structureid[ordinal] == idaapi.BADADDR:
            logging.warning(u"{:s}.removed({:d}) : An invalid identifier ({:#x}) was found in the cache for the type at ordinal {:d}.".format('.'.join([__name__, self.__class__.__name__]), ordinal, self.structureid[ordinal], ordinal))

        # Clear the specified ordinal out of all of our dictionaries.
        res, sid, comment = (Fget_from_dict(structure) for structure in [self.structurecache, self.structureid, self.structurecomment])
        return sid, res, comment, Fget_from_dict(self.memberindexcache)

    def synchronize(self, ordinal):
        '''Update the cache for the members belonging to the type specified by `ordinal`.'''
        iterable = self.get_members(ordinal)

        # Iterate through all the members and collect their attributes.
        currentmemberoffsets, currentmemberindices = {}, {}
        for mindex, mid, mname, moffset, msize, mtype, malign, mcomment in iterable:
            currentmemberoffsets[moffset] = mindex
            currentmemberindices[mindex] = mid, mname, moffset, msize, mtype, malign, mcomment

        # All we need to do is to assign them into our cache and we're done.
        res = self.memberindexcache[ordinal]
        self.memberindexcache[ordinal] = currentmemberindices
        self.memberoffsetcache[ordinal] = currentmemberoffsets
        return res

    def changes(self, ordinal, update=True):
        '''Iterate through the members for type `ordinal`, and yield the index or offset of each one that has changed.'''
        memberoffsets, memberindices = (cache[ordinal] for cache in [self.memberoffsetcache, self.memberindexcache])
        currentmemberoffsets, currentmemberindices = {}, {}

        # First start by enumerating all of the members for the type with
        # the specified ordinal. This is so we can compare them later.
        iterable = self.get_members(ordinal)
        for mindex, mid, mname, moffset, msize, mtype, malign, mcomment in iterable:
            currentmemberoffsets[moffset] = mindex
            currentmemberindices[mindex] = mid, mname, moffset, msize, mtype, malign, mcomment

        # Then we'll combine all our dictionaries into a pair that can be
        # used as a parameter for the functions we'll use for comparing.
        cached = memberoffsets, memberindices
        current = currentmemberoffsets, currentmemberindices

        # Now we'll create a bunch of lists that we'll use to do our
        # comparisons and figure out what changed in the structure/union.
        currentbounds, bounds = ([(moffset, msize) for _, _, moffset, msize, _, _, _ in indices.values()] for indices in [currentmemberindices, memberindices])
        currentnames, names = ([mname for _, mname, _, _, _, _, _ in indices.values()] for indices in [currentmemberindices, memberindices])
        currenttypes, types = ([mtype for _, _, _, _, mtype, _, _ in indices.values()] for indices in [currentmemberindices, memberindices])
        currentcomments, comments = ([mcomment for _, _, _, _, _, _, mcomment in indices.values()] for indices in [currentmemberindices, memberindices])

        # After capturing the current state, if we were asked to update our
        # cache, then assign the current changes that we just grabbed.
        if update:
            self.memberindexcache[ordinal] = currentmemberindices
            self.memberoffsetcache[ordinal] = currentmemberoffsets

        # Check if the number of members have changed, because if so then a
        # member was added or deleted and we'll need to know which one.
        if len({mindex for mindex in memberindices}) != len({mindex for mindex in currentmemberindices}):
            return self.__changed_member_count(ordinal, cached, current)

        # Now we'll attempt to determine how the type was actually edited.
        # We start by comparing the boundaries (offset and size) of the
        # member to figure out if a member was moved.
        elif currentbounds != bounds and currentnames == names:
            return self.__changed_member_positions(ordinal, cached, current)

        # If the names are different, then a member was renamed.
        elif currentnames != names:
            return self.__changed_member_names(ordinal, cached, current)

        # If a type was changed, then we need to handle that too.
        elif any(not(interface.tinfo.same(currenttype, type)) for currenttype, type in zip(currenttypes, types)):
            return self.__changed_member_types(ordinal, cached, current)

        # If the comments were changed, then that needs to also be handled.
        elif currentcomments != comments:
            return self.__changed_member_comments(ordinal, cached, current)

        # Otherwise there weren't any changes that occurred, and we just
        # return nothing so that it looks like we actually did something.
        return []

    @classmethod
    def __changed_members(cls, cached, current):
        '''Compare the fields in `cached` to `current` and yield the number of changes, the old field, and the new field that was changed.'''
        cachedmemberoffsets, cachedmemberindices = ({key : value for key, value in dictionary.items()} for dictionary in cached)
        currentmemberoffsets, currentmemberindices = ({key : value for key, value in dictionary.items()} for dictionary in current)

        # Start by gathering all of the information we can use as a unique
        # key for matching the members.
        cached_byname = {mname : mindex for mindex, (_, mname, _, _, _, _, _) in cachedmemberindices.items()}
        current_byname = {mname : mindex for mindex, (_, mname, _, _, _, _, _) in currentmemberindices.items()}

        cached_bybitoffset = {moffset : mindex for mindex, (_, _, moffset, _, _, _, _) in cachedmemberindices.items()}
        current_bybitoffset = {moffset : mindex for mindex, (_, _, moffset, _, _, _, _) in currentmemberindices.items()}

        # Before doing anything, empty out all of the elements that haven't
        # changed from all of our dictionaries.
        matching = {mindex for mindex in cachedmemberindices} & {mindex for mindex in currentmemberindices}
        for mindex in matching:
            oldmid, oldname, oldoffset, oldsize, oldtype, oldalign, oldcomment = old = cachedmemberindices[mindex]
            newmid, newname, newoffset, newsize, newtype, newalign, newcomment = new = currentmemberindices[mindex]

            # Compare all the member attributes that we use to consider it
            # the same member. We ignore the member identifier since it
            # really is just a reference number that can change (despite the
            # disassembler not currently changing it).
            if (oldname, oldoffset, oldsize, oldcomment) == (newname, newoffset, newsize, newcomment) and interface.tinfo.same(oldtype, newtype):
                [memberindices.pop(mindex) for memberindices in [cachedmemberindices, currentmemberindices]]
            continue

        # The very first thing we need to do is to figure out which members
        # have been moved around and collect them so that we can match from
        # their old location to the new one. We grab a union of everything
        # and then iterate through them to check their names.
        pairs = []
        for mindex in {index for index in cachedmemberindices} | {index for index in currentmemberindices}:
            if not all(mindex in memberindices for memberindices in [cachedmemberindices, currentmemberindices]):
                continue

            old = cachedmemberindices[mindex]
            new = currentmemberindices[mindex]

            oldmid, oldname, oldoffset, oldsize, oldtype, oldalign, oldcomment = old
            newmid, newname, newoffset, newsize, newtype, newalign, newcomment = new

            # If the names and offsets are the same, then this member wasn't
            # moved and we can add its pair since they're already matching.
            if (oldname, oldoffset) == (newname, newoffset):
                oldindex, newindex = mindex, mindex

            # If the name doesn't exist in the current names, then skip it
            # as we treat it as removed and we'll be handling those later.
            elif oldname not in current_byname:
                continue

            # Now we can extract the index for the new member using the new
            # offset.
            else:
                oldindex, newindex = mindex, current_byname[oldname]

            # That should give us a pair that we can append for later.
            pairs.append((oldindex, newindex))

        # Iterate through both pairs and figure out what has changed between
        # the matching members. Every time we process a member, we remove it
        # from its corresponding dictionary of indices.
        for oldindex, newindex in pairs:
            old = cachedmemberindices.pop(oldindex)
            new = currentmemberindices.pop(newindex)

            oldmid, oldname, oldoffset, oldsize, oldtype, oldalign, oldcomment = old
            newmid, newname, newoffset, newsize, newtype, newalign, newcomment = new

            # Now we can just tally up the number of changes and yield them
            # back to the caller.
            count = 0 if oldname == newname else 1
            count+= 0 if oldoffset == newoffset else 1
            count+= 0 if oldsize == newsize else 1
            count+= 0 if interface.tinfo.same(oldtype, newtype) else 1
            count+= 0 if oldalign == newalign else 1
            count+= 0 if oldcomment == newcomment else 1

            # Prepend the indices that we processed, and then yield the
            # changes for the pair of members back to the caller.
            yield count, tuple(itertools.chain([oldindex], old)), tuple(itertools.chain([newindex], new))

        # Before figuring out removals, we go through all the ones with
        # matching offsets to see if the types and sizes are the same so
        # that we can treat this as a single change...really for renames.
        unmoved = {moffset for moffset in cached_bybitoffset} & {moffset for moffset in current_bybitoffset}
        for moffset in unmoved:
            oldindex, newindex = (cached[moffset] for cached in [cached_bybitoffset, current_bybitoffset])

            # Make sure we haven't processed these indices already.
            if not(oldindex in cachedmemberindices and newindex in currentmemberindices):
                continue

            old = cachedmemberindices.pop(oldindex)
            new = currentmemberindices.pop(newindex)

            oldmid, oldname, oldoffset, oldsize, oldtype, oldalign, oldcomment = old
            newmid, newname, newoffset, newsize, newtype, newalign, newcomment = new

            # Now we can tally up whatever the changes are. This should be
            # much lighter than what we did the first time since we know
            # that the offsets here match between both members.
            count = 0 if oldname == newname else 1
            count+= 0 if oldoffset == newoffset else 1
            count+= 0 if oldsize == newsize else 1
            count+= 0 if interface.tinfo.same(oldtype, newtype) else 1
            count+= 0 if oldalign == newalign else 1
            count+= 0 if oldcomment == newcomment else 1

            # If nothing changed, then we don't need to do anything.
            if count:
                yield count, tuple(itertools.chain([oldindex], old)), tuple(itertools.chain([newindex], new))
            continue

        # Now we'll figure out what members were removed by removing the
        # members that we already processed from the cached member indices.
        removed = {mindex for mindex in cachedmemberindices}
        for mindex in removed:
            old = cachedmemberindices.pop(mindex)
            yield -len(old[1:]), tuple(itertools.chain([mindex], old)), ()

        # Finally we can figure out what members were added by removing the
        # ones that were already processed from the current member indices.
        added = {mindex for mindex in currentmemberindices}
        for mindex in added:
            new = currentmemberindices.pop(mindex)
            yield +len(new[1:]), (), tuple(itertools.chain([mindex], new))
        return

    @classmethod
    def __changed_members_compare(cls, ordinal, cached, current):
        '''Compare the fields in `cached` from the given `ordinal` to the fields in `current` and log each field that is different.'''
        res, iterable = [], cls.__changed_members(cached, current)
        logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : Comparing the members for the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', ordinal))
        for changes, old, new in iterable:
            res.append((changes, old, new))

            # If both the old and new members exist, then the old member was
            # modified and we can just compare the values to figure it out.
            if old and new:
                _, oldmid, oldname, oldoffset, oldsize, oldtype, oldalign, oldcomment = old
                _, newmid, newname, newoffset, newsize, newtype, newalign, newcomment = new

                # First check the potential keys that we use for matching
                # members. At least one thing should match, if nothing
                # matches then it's an unexpected condition and we complain.
                if oldname != newname and oldoffset == newoffset:
                    moffset = newoffset
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The name for the member at offset {:+#x} has been changed from \"{!s}\" to \"{!s}\".".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', moffset, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))
                elif oldname == newname and oldoffset != newoffset:
                    mname = newname
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" has been moved from offset {:+#x} to {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, oldoffset, newoffset))
                elif (oldname, oldoffset) == (newname, newoffset):
                    mname, moffset = newname, newoffset
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has had {:d} change{:s} made to it.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, changes, '' if changes == 1 else 's'))
                else:
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has had {:d} change{:s} made and changed it to \"{!s}\" at offset {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', utils.string.escape(oldname, '"'), oldoffset, changes, '' if changes == 1 else 's', utils.string.escape(newname, '"'), newoffset))

                # Now we can figure out what changed from what we grabbed.
                mname, moffset = newname, newoffset
                if oldsize != newsize:
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has had its size changed from {:+#x} to {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, oldsize, newsize))
                if not(interface.tinfo.same(oldtype, newtype)):
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has had its type changed from \"{!s}\" to \"{!s}\".".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, utils.string.escape("{!s}".format(oldtype), '"'), utils.string.escape("{!s}".format(newtype), '"')))
                if oldalign != newalign:
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has had its alignment changed from {:+#x} to {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, oldalign, newalign))

                # Process any comments by decoding them into tags that we can
                # compare directly for changes.
                olddecoded, newdecoded = (internal.comment.decode(comment) for comment in [oldcomment, newcomment])
                oldtags, newtags = ({tag for tag in decoded} for decoded in [olddecoded, newdecoded])
                if oldtags != newtags:
                    logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has had its comment tags changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, oldtags, newtags))
                continue

            # Next we can check the details about what member was added.
            elif new:
                _, mid, mname, moffset, msize, mtype, malign, mcomment = new
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been added with {:d} change{:s} (including the offset).".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, changes, '' if abs(changes) == 1 else 's'))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been added with the identifier {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, mid))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been added with the size {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, msize))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been added with the type \"{!s}\".".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, utils.string.escape("{!s}".format(mtype), '"')))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been added with the alignment {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, malign))

                mtags = {tag for tag in internal.comment.decode(mcomment)}
                mtags and logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been added with the specified tags ({!s}).".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, mtags))

            # And finally information about the member that was just removed.
            elif old:
                _, mid, mname, moffset, msize, mtype, malign, mcomment = old
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been removed with {:d} change{:s} (including the offset).".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, changes, '' if abs(changes) == 1 else 's'))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been removed with the identifier {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, mid))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been removed with the size {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, msize))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been removed with the type \"{!s}\".".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, utils.string.escape("{!s}".format(mtype), '"')))
                logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been removed with the alignment {:+#x}.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, malign))

                mtags = {tag for tag in internal.comment.decode(mcomment)}
                mtags and logging.info(u"{:s}.__changed_members_compare({:d}, {!s}, {!s}) : The member with the name \"{!s}\" at offset {:+#x} has been removed with the specified tags ({!s}).".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', mname, moffset, mtags))
            continue
        return res

    def __changed_member_count(self, ordinal, cached, current):
        cls = self.__class__
        logging.info(u"{:s}.__changed_members_count({:d}, {!s}, {!s}) : The number of members for the type at ordinal {:d} have been changed.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', ordinal))
        return self.__changed_members_compare(ordinal, cached, current)

    def __changed_member_positions(self, ordinal, cached, current):
        cls = self.__class__
        logging.info(u"{:s}.__changed_members_positions({:d}, {!s}, {!s}) : The positions of the members for the type at ordinal {:d} have been moved.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', ordinal))
        return self.__changed_members_compare(ordinal, cached, current)

    def __changed_member_names(self, ordinal, cached, current):
        cls = self.__class__
        logging.info(u"{:s}.__changed_members_names({:d}, {!s}, {!s}) : The names of the members for the type at ordinal {:d} have been changed.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', ordinal))
        return self.__changed_members_compare(ordinal, cached, current)

    def __changed_member_types(self, ordinal, cached, current):
        cls = self.__class__
        logging.info(u"{:s}.__changed_members_types({:d}, {!s}, {!s}) : The types of the members for the type at ordinal {:d} have been changed.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', ordinal))
        return self.__changed_members_compare(ordinal, cached, current)

    def __changed_member_comments(self, ordinal, cached, current):
        cls = self.__class__
        logging.info(u"{:s}.__changed_members_comments({:d}, {!s}, {!s}) : The comments of the members from the type at ordinal {:d} have been changed.".format('.'.join([__name__, cls.__name__]), ordinal, '...', '...', ordinal))
        return self.__changed_members_compare(ordinal, cached, current)

class localtypesmonitor_84(object):
    """
    In v8.4 of the disassembler, a number of important hooks on structure
    members were broken due to the developers planing to get rid of the
    structures api for the next major version, v9.0. This is because of their
    choice to favor the type library instead. Unfortunately that means that all
    of the indexing we do for structure members don't actually work. So, to be
    able to still support structure members, this namespace monitors the changes
    applied to the local types library and stores updates to it in a class that
    can be used to track both the renaming of things in the local types library,
    and any changes made to the members defined in those types.

    The `changed` function in this namespace is the primary dispatcher and is
    responsible for figuring out the correct function to call in order to handle
    the event that was dispatched by the disassembler.
    """

    # Find all of the available local type changes events, and save a map for
    # converting between the integer value and their string name.
    table = {attribute : getattr(idaapi, attribute) for attribute in dir(idaapi) if attribute.startswith('LTC_')}
    table.update({value : attribute for attribute, value in table.items()})

    @classmethod
    def init_local_types_monitor(cls, *idp_modname):
        """Initialize the internal state for the local types monitor.

        This function is called when the database has been initialized and is
        used to create the state that is required for monitoring the local types
        library.
        """
        descriptions = [parameter for parameter in map("{!r}".format, idp_modname)]
        logging.info(u"{:s}.init_local_types_monitor({!s}) : Initializing the local type monitor for v{:.1f} and instantiating the class for tracking their changes.".format('.'.join([__name__, cls.__name__]), ', '.join(descriptions), idaapi.__version__))
        cls.state = localtypesmonitor_state()

    @classmethod
    def load_local_types_monitor(cls, *args):
        """Load the currently available types from the local types library into the monitor state.

        This is intended to create an initial state for all the types in the
        local types library so that changes can be tracked. It is intended to be
        called when the local types library is actually ready.
        """
        descriptions = [parameter for parameter in map("{!r}".format, args)]
        count = interface.tinfo.quantity()
        logging.info(u"{:s}.load_local_types_monitor({!s}) : Loading {:d} type{:s} from the local type library...".format('.'.join([__name__, cls.__name__]), ', '.join(descriptions), count, '' if count == 1 else 's'))
        count = cls.state.load()
        logging.info(u"{:s}.load_local_types_monitor({!s}) : Loaded {:d} type{:s} from the local type library that were structures or unions.".format('.'.join([__name__, cls.__name__]), ', '.join(descriptions), count, '' if count == 1 else 's'))

    @classmethod
    def unload_local_types_monitor(cls, *args):
        """Unload any types being monitored in the local types library from the monitor state.

        This function will clear all types from the current monitoring state.
        """
        descriptions = [parameter for parameter in map("{!r}".format, args)]
        logging.info(u"{:s}.unload_local_types_monitor({!s}) : Unloading types from the local type library...".format('.'.join([__name__, cls.__name__]), ', '.join(descriptions)))
        count = cls.state.unload()
        logging.info(u"{:s}.unload_local_types_monitor({!s}) : Unloaded {:d} type{:s} from the local type library.".format('.'.join([__name__, cls.__name__]), ', '.join(descriptions), count, '' if count == 1 else 's'))

    @classmethod
    def nw_init_local_types_monitor(cls, nw_code, is_old_database):
        '''Initialize the state for the local types monitor as a notification.'''
        idp_modname = idaapi.get_idp_name()
        return cls.init_local_types_monitor(idp_modname)

    @classmethod
    def changed(cls, ltc, ordinal, name):
        '''local_types_changed(ltc, ordinal, name)'''
        events_where_we_can_load = ['LTC_ADDED', 'LTC_DELETED', 'LTC_EDITED', 'LTC_TIL_LOADED']

        # First check if we've been initialized. If not, then we need to abort.
        if not hasattr(cls, 'state'):
            return logging.error(u"{:s}.changed({:#x}, {!s}, {!s}) : Unable to handle event {:s}({:d}) for {:s}.local_types_changed due to the monitor being uninitialized.".format('.'.join([__name__, cls.__name__]), ltc, "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), cls.table[ltc], ltc, cls.__name__))

        # Now we'll need to figure out which event was just dispatched.
        if ltc == cls.table['LTC_ADDED']:
            return cls.local_type_added(ordinal, name)
        elif ltc == cls.table['LTC_DELETED']:
            return cls.local_type_deleted(ordinal, name)
        elif ltc == cls.table['LTC_EDITED']:
            return cls.local_type_edited(ordinal, name)
        elif ltc == cls.table['LTC_ALIASED']:
            return cls.local_type_aliased(ordinal, name)
        elif ltc == cls.table['LTC_COMPILER']:
            return cls.local_type_compiler(ordinal, name)
        elif ltc == cls.table['LTC_TIL_LOADED']:
            return cls.local_type_til_loaded(ordinal, name)
        elif ltc == cls.table['LTC_TIL_UNLOADED']:
            return cls.local_type_til_unloaded(ordinal, name)
        elif ltc == cls.table['LTC_TIL_COMPACTED']:
            return cls.local_type_til_compacted(ordinal, name)
        return cls.local_type_unsupported(ltc, ordinal, name)

    @classmethod
    def local_type_unsupported(cls, ltc, ordinal, name):
        '''Handle an unknown event type that is unsupported.'''
        logging.error(u"{:s}.local_type_unsupported({:#x}, {!s}, {!s}) : The type of change that was dispatched ({:d}) by the disassembler is unsupported.".format('.'.join([__name__, cls.__name__]), ltc, "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), ltc))
    @classmethod
    def local_type_til_compacted(cls, ordinal, name):
        '''Handle the event when the type library is compacted.'''
        event = 'LTC_TIL_COMPACTED'
        logging.debug(u"{:s}.local_type_til_compacted({!s}, {!s}) : Ignoring local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))
    @classmethod
    def local_type_compiler(cls, ordinal, name):
        '''Handle the event when the compiler and calling convention was changed for the local type library.'''
        event = 'LTC_COMPILER'
        logging.debug(u"{:s}.local_type_compiler({!s}, {!s}) : Ignoring local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))

    @classmethod
    def local_type_aliased(cls, ordinal, name):
        '''Handle the event when an alias is added to the type library.'''
        event = 'LTC_ALIASED'
        logging.debug(u"{:s}.local_type_aliased({!s}, {!s}) : Ignoring local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))

    # These events are for actually loading and unloading our local types.
    # However, it turns out that in v8.4 these these events don't actually
    # inform us whether it's safe to access the local type library or not. Plus,
    # the "ev_setup_til" event is also worthless since you can't get the number
    # of ordinals in the type library when it's dispatched. Thanks IDA!

    @classmethod
    def local_type_til_loaded(cls, ordinal, name):
        '''Handle the event when a new type library has been loaded into the database.'''
        event = 'LTC_TIL_LOADED'
        logging.debug(u"{:s}.local_type_til_loaded({!s}, {!s}) : Received local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))

    @classmethod
    def local_type_til_unloaded(cls, ordinal, name):
        '''Handle the event when a type library has been unloaded from the database.'''
        event = 'LTC_TIL_UNLOADED'
        logging.debug(u"{:s}.local_type_til_unloaded({!s}, {!s}) : Received local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))

    # Now for the actual events that we track.
    @classmethod
    def local_type_added(cls, ordinal, name):
        '''Handle the event when a new type has been added to the type library.'''
        ltc, event = cls.table['LTC_ADDED'], 'LTC_ADDED'
        logging.debug(u"{:s}.local_type_added({!s}, {!s}) : Received local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))

        # Figure out the correct ordinal number for the type. If the ordinal
        # isn't set, then we figure it out by searching for the name.
        if not ordinal:
            newordinal, newname = interface.tinfo.by_name(name), name
        elif not name:
            type = interface.tinfo.for_ordinal(ordinal)
            newordinal, newname = ordinal, utils.string.of(type.get_type_name())
        else:
            newordinal, newname = ordinal, name

        # We need to create a callback to execute in the ui thread since this
        # hook gets dispatched before the local type actually gets created. This
        # callback is responsible for updating our state cache and its tags.
        def ui_async_callback(ordinal):
            newsid, newname, newcomment, newmembers = cls.state.added(newordinal, True)
            logging.debug(u"{:s}.local_type_added({!s}, {!s}) : Discovered a new type at ordinal {:d} of the local type library named \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), newordinal, newname, newsid))

            # Now we need to format our new members as a list of changes.
            iterable = ((mindex, mid, mname, moffset, msize, mtype, malign, mcomment) for mindex, (mid, mname, moffset, msize, mtype, malign, mcomment) in newmembers.items())
            changes = [(len(field[2:]), (), field) for field in iterable]

            # Then we can update the tags for the type and also the members that
            # were included alongside the addition of the type.
            cls.type_updater(ltc, ordinal)
            logging.debug(u"{:s}.local_type_added({!s}, {!s}) : Finished updating tags for the newly added type at ordinal {:d} named \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), newordinal, newname, newsid))
            cls.member_updater(ltc, ordinal, changes)
            logging.debug(u"{:s}.local_type_added({!s}, {!s}) : Finished updating tags for {:d} member{:s} belonging to the newly added type at ordinal {:d} named \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), len(changes), '' if len(changes) == 1 else 's', newordinal, newname, newsid))

        # Since our "local_types_changed" event gets dispatched before the
        # structure can have an identifier, we need to execute this passively as
        # a UI request so that we are able to grab and cache the identifier.
        Fupdate_identifier = functools.partial(ui_async_callback, newordinal)
        if not idaapi.execute_ui_requests([Fupdate_identifier]):
            logging.error(u"{:s}.local_type_added({!s}, {!s}) : Error dispatching a user interface request for the new type at ordinal {:d} of the local type library.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), newordinal))
        return

    @classmethod
    def local_type_deleted(cls, ordinal, name):
        '''Handle the event when a type has been removed from the type library.'''
        ltc, event = cls.table['LTC_DELETED'], 'LTC_DELETED'
        logging.debug(u"{:s}.local_type_deleted({!s}, {!s}) : Received local type change event of type {:s}({:d}) for the type at ordinal {:d} of the local type library.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event], ordinal))

        # Figure out the correct ordinal number for the type. If the ordinal
        # isn't set, then we figure it out by searching for the name.
        if not ordinal:
            oldordinal, oldname = interface.tinfo.by_name(name), name
        elif not name:
            type = interface.tinfo.for_ordinal(ordinal)
            oldordinal, oldname = ordinal, utils.string.of(type.get_type_name())
        else:
            oldordinal, oldname = ordinal, name

        # Now we can update our data cache, and log what just happened.
        oldsid, oldname, oldcomment, oldmembers = cls.state.removed(oldordinal, True)
        logging.debug(u"{:s}.local_type_deleted({!s}, {!s}) : Discovered a removed type at ordinal {:d} of the local type library named \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), oldordinal, oldname, oldsid))

        # Since we're removing a type from the local type library, we really
        # should be deleting its references if it's a supported type. But, since
        # the type doesn't really exist anymore we just delete the entire sid.
        removed, removedmembers = cls.delete_type(oldsid)
        logging.debug(u"{:s}.local_type_deleted({!s}, {!s}) : Removal of {:s} at ordinal {:d} named \"{:s}\" ({:#x}) resulted in erasing {:d} member{:s}.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), "{:d} type".format(len(removed)) if len(removed) == 1 else "{:d} types".format(len(removed)), oldordinal, oldname, oldsid, len(removedmembers), '' if len(removedmembers) == 1 else 's'))

    @classmethod
    def local_type_edited(cls, ordinal, name):
        '''Handle the event when a type in the type library has been modified.'''
        ltc, event = cls.table['LTC_EDITED'], 'LTC_EDITED'
        logging.debug(u"{:s}.local_type_edited({!s}, {!s}) : Received local type change event of type {:s}({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), event, cls.table[event]))

        # Figure out the correct ordinal number for the type. If the ordinal
        # isn't set, then we figure it out by searching for the name.
        if not ordinal:
            newordinal, newname = interface.tinfo.by_name(name), name
        elif not name:
            type = interface.tinfo.for_ordinal(ordinal)
            newordinal, newname = ordinal, utils.string.of(type.get_type_name())
        else:
            newordinal, newname = ordinal, name

        # We need to create a callback that executes in the ui thread since this
        # hook can be dispatched before the members for the local type actually
        # get a type id allocated to them. After getting the member changes and
        # then updating them, we then need to tally the tags used for the
        # members that were modified.
        def ui_async_callback(ordinal):
            changes = cls.state.changes(ordinal, True)
            logging.info(u"{:s}.local_type_edited({!s}, {!s}) : The type \"{!s}\" at ordinal {:d} has had {!s} changed.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), utils.string.escape(newname, '"'), newordinal, "{:d} member{:s}".format(len(changes), '' if len(changes) == 1 else 's') if changes else 'no members'))

            # Now we just need to update the tags for the members of the type.
            cls.member_updater(ltc, ordinal, changes)

        # Start out by processing the type in case it was renamed or changed.
        # Once we're done, we can go ahead and update its name and comment.
        cls.type_updater(ltc, newordinal)
        oldname, oldcomment = cls.state.renamed(ordinal), cls.state.commented(ordinal)

        # Afterwards we tell the disassembler to dispatch to our callback so
        # that it can check if any of its members have changed and safely grab
        # the identifier for all recently added members.
        Fget_changes = functools.partial(ui_async_callback, newordinal)
        if not idaapi.execute_ui_requests([Fget_changes]):
            logging.error(u"{:s}.local_type_edited({!s}, {!s}) : Error dispatching a user interface request for the changed type at ordinal {:d} of the local type library.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal), "{!s}".format(name) if name is None else "{!r}".format(name), ordinal))
        return

    @classmethod
    def is_name_general(cls, ordinal, tid, name):
        '''Return true if the `name` for the given `ordinal` and type `tid` is the default type name that was chosen by the disassembler.'''
        prefixes = {'struct', 'struc', 'union', 'enum'}

        # XXX: IDA uses both "struct" (in types) and "struc" (in structures)

        # Technically the default name chosen by the disassembler for a new type
        # is prefixed with either "struc_" or "enum_" and not "union_". Still,
        # we check for it just in case the user explicitly specified it.
        if not name.startswith(tuple(map("{:s}_".format, prefixes))):
            return False

        # Check if the type is anonymous. The disassembler assumes that a type
        # is anonymous if it begins with a '$', but we also verify the length
        # since in v8.4 the disassembler uses an MD5 hash for anonymous types.
        elif name.startswith('$') and len(name[1:]) == 0x20:
            return True

        # Split up the prefix from its suffix, then verify the prefix is valid
        # and that the suffix is numeric.
        prefix, suffix = name.split('_', 1)
        return prefix in prefixes and all(digit in '0123456789' for digit in suffix)

    @classmethod
    def is_field_general(cls, ordinal, mindex, name):
        '''Return true if the `name` for the member at `mindex` of the type in `ordinal` is a default field name that was chosen by the disassembler.'''
        prefixes, tinfo = {'field'}, cls.state.get_type(ordinal)

        # Start by populating the `idaapi.udm_t` with the information for the
        # given member. This way we can extract the offset and do a proper
        # comparison of what we expect the field name to actually be.
        udm = idaapi.udm_t()
        udm.offset = mindex

        # Now we can search for the member at the given index. If we couldn't
        # find it then we can't really check its name. So, log our failure and
        # return that the field is a general name (since it doesn't have one).
        newindex = tinfo.find_udm(udm, idaapi.STRMEM_INDEX)
        if newindex < 0:
            logging.warning(u"{:s}.is_field_general({:d}, {:d}, {!r}) : Unable to find a member at index {:d} of the type at ordinal {:d}.".format('.'.join([__name__, cls.__name__]), ordinal, mindex, name, mindex, ordinal))
            return True

        # Before doing anything, we need to check if the name of the member is
        # anonymous. Normally we explicitly check, but the disassembler gives us
        # the `udm_t.is_anonymous_udm` method which we can use.
        elif udm.is_anonymous_udm():
            return True

        # Next we'll figure out what the expected name should be. If our type is
        # a union, then the field is suffixed with the index. Otherwise, the
        # field is suffixed with the byte offset.
        elif tinfo.is_union():
            expected, suffix_integer = "field_{:d}".format(newindex), newindex

        elif tinfo.is_struct():
            bits = udm.offset
            bytes, _ = divmod(bits, 8)
            expected, suffix_integer = "field_{:X}".format(bytes), bytes

        else:
            logging.error(u"{:s}.is_field_general({:d}, {:d}, {!r}) : Unable to determine the default field name for the member at index {:d} of the unsupported type \"{:s}\" (ordinal {:d}).".format('.'.join([__name__, cls.__name__]), ordinal, mindex, name, mindex, utils.string.escape("{!s}".format(tinfo), '"'), ordinal))
            return True

        # The only default field name that exists in v8.4 of the type library
        # are names that begin with "field_". There are some defaults chosen
        # when using "Create struct from selection" (CreateStructFromData), but
        # since the default name for those is dependent on the type being used
        # for the field we don't bother trying to track figure it out.

        # FIXME: Is is worth attempting to distinguish the default field names
        #        from the "CreateStrucFromData" action?

        # So we now have a name that we expect to be used for the field. If we
        # have an exact match, then can be sure that it was not from the user.
        if name == expected:
            return True

        # Next in order to allow the user to specify a field name that will be
        # treated as a default one, we'll check if it uses the "field_" prefix.
        elif not name.startswith('field_'):
            return False

        # We now know that the member name is prefixed correctly, so we need
        # to split it and then check that the pieces meet our requirements. Our
        # requirements are that the suffix, containing the offset, is specified
        # as either decimal (the default) or hexadecimal.
        field, suffix = name.split('_', 1) if '_' in name else (name, '')
        expected_base10, expected_base16 = (string.format(suffix_integer) for string in ["{:x}", "{:d}"])

        # Finally we can do our tests against the field prefix and its suffix.
        return field in prefixes and suffix.lower() in {expected_base10, expected_base16}

    @classmethod
    def is_type_tracked(cls, ordinal, tid, name):
        '''Return true if the type at the specified `ordinal` and `name` should be tracked with tags.'''
        tinfo = cls.state.get_type(ordinal)

        # The local type library really doesn't have a way of distinguishing
        # whether a type was created by the user or the disassembler. So, we
        # verify that the type is not an anonymous struct or union.
        if tinfo.is_anonymous_udt():
            return False

        # If the type identifier we were given is invalid, then this is
        # definitely not a type we should track. However, our type monitor
        # is supposed to guarantee that the type id is valid. So, checking this
        # identifier likely doesn't make a difference.
        elif tid == idaapi.BADADDR:
            return False

        # For last, we check if the type actually belongs to a type library of
        # some kind. Really, since we're grabbing it from the local type
        # library, it will always come from one. This is what we have for now.
        til = tinfo.get_til()
        return til is not None

    @classmethod
    def is_field_tracked(cls, ordinal, mindex, type):
        '''Return true if the `type` for the member at `mindex` of the specified `ordinal` should be tracked with tags.'''
        basic = interface.tinfo.basic(type)

        # We only need to check if the type is considered a basic type or a
        # non-trivial type. This way we can track members with types that have
        # significantly more details than the others.
        if type and not basic:
            return True
        return False

    @classmethod
    def delete_member_refs(cls, sid, mid):
        '''Remove all of the tags associated with the member `mid` belonging to the type `sid`.'''
        return internal.tags.reference.members.erase_member(sid, mid)

    @classmethod
    def delete_type(cls, sid):
        '''Remove all of the tags associated with the type `sid` and its members.'''
        tinfo = idaapi.tinfo_t()

        # Try and get the type using the identifier in `sid`, and use it to grab
        # the ordinal for the type that is associated with it. If we can grab
        # it, then we can use it to enumerate all of the member identifiers in
        # order to remove them.
        if tinfo.get_type_by_tid(sid):
            erased = internal.tags.reference.members.erase(sid)
            erased and logging.debug(u"{:s}.delete_type({:#x}) : Deleted the tags for {:d} member{:s} from the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, len(erased), '' if len(erased) == 1 else 's', sid))

        # Otherwise, the only thing left to do is to erase the structure id.
        removed = internal.tags.reference.structure.erase(sid)
        if removed:
            logging.debug(u"{:s}.delete_type({:#x}) : Deleted the tags associated with the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, sid))
        return removed, erased

    @classmethod
    def update_member_comments(cls, sid, mid, old, new):
        '''Update the member `mid` for the type in `sid` using the tags from the comment in `old` that is modified to `new`.'''
        oldkeys, newkeys = ({item for item in tags} for tags in [old, new])

        # check the original keys against the modified ones and iterate through
        # them figuring out whether we're removing the key or just adding it.
        logging.debug(u"{:s}.update_member_comments({:#x}, {:#x}, {!s}, {!s}) : Updating old keys ({!s}) to new keys ({!s}) for member {:#x} of the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, mid, '...', '...', sorted(oldkeys), sorted(newkeys), mid, sid))
        for key in oldkeys ^ newkeys:
            if key not in newkeys:
                logging.debug(u"{:s}.update_member_comments({:#x}, {:#x}, {!s}, {!s}) : Decreasing reference count for {!s} in member {:#x} of the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, mid, '...', '...', utils.string.repr(key), mid, sid))
                internal.tags.reference.members.decrement(mid, key)
            if key not in oldkeys:
                logging.debug(u"{:s}.update_member_comments({:#x}, {:#x}, {!s}, {!s}) : Increasing reference count for {!s} in member {:#x} of the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, mid, '...', '...', utils.string.repr(key), mid, sid))
                internal.tags.reference.members.increment(mid, key)
            continue
        return

    @classmethod
    def update_type_comments(cls, sid, old, new):
        '''Update the type in `sid` using the tags in `old` that have been changed to `new`.'''
        oldkeys, newkeys = ({item for item in tags} for tags in [old, new])

        # check the original keys against the modified ones and iterate through
        # them figuring out whether we're removing the key or just adding it.
        logging.debug(u"{:s}.update_type_comments({:#x}, {!s}, {!s}) : Updating old keys ({!s}) to new keys ({!s}) for the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, '...', '...', utils.string.repr(oldkeys), utils.string.repr(newkeys), sid))
        for key in oldkeys ^ newkeys:
            if key not in newkeys:
                logging.debug(u"{:s}.update_type_comments({:#x}, {!s}, {!s}) : Decreasing reference count for {!s} from the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, '...', '...', utils.string.repr(key), sid))
                internal.tags.reference.structure.decrement(sid, key)
            if key not in oldkeys:
                logging.debug(u"{:s}.update_type_comments({:#x}, {!s}, {!s}) : Increasing reference count for {!s} in the specified type ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, '...', '...', utils.string.repr(key), sid))
                internal.tags.reference.structure.increment(sid, key)
            continue
        return

    @classmethod
    def type_updater(cls, ltc, ordinal):
        '''Check the changes for the type specified in `ordinal` and update any tags resulting from them.'''
        if not hasattr(cls, 'state'):
            return logging.error(u"{:s}.type_updater({:d}, {:d}) : Unable to handle an update for type at ordinal {:d} due to the monitor state being uninitialized.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal))

        # First thing to do is to grab the identifier for the type at the given
        # ordinal. We try the cached version first, and then fall back to to the
        # most recent identifier.
        oldsid = cls.state.cachedidentifier(ordinal)
        newsid = cls.state.identifier(ordinal) if oldsid == idaapi.BADADDR else oldsid
        if newsid == idaapi.BADADDR:
            return logging.warning(u"{:s}.type_updater({:d}, {:d}) : Refusing to update type at ordinal {:d} due to it having an invalid identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid))

        # Grab the current state of the tags so we can log something useful.
        else:
            original = internal.tags.reference.structure.get(newsid)

        # Then we'll need to snag the old and new names for the type that we'll
        # be comparing. Then we can do some basic checks to figure out whether
        # we should update its tags or not.
        oldname = cls.state.cachedname(ordinal)
        newname = cls.state.name(ordinal)

        # Next we can compare the names to see how exactly they were changed. If
        # we switched from a general name to user-specified, then increment it.
        renamed = not cls.is_name_general(ordinal, oldsid, oldname), not cls.is_name_general(ordinal, newsid, newname)
        if renamed == (False, True):
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Rename for type at ordinal {:d} ({:#x}) from \"{!s}\" to \"{!s}\" resulted in the addition of the tag.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))
            internal.tags.reference.structure.increment(newsid, '__name__')

        # If the name was from user-specified to a general name, then decrement.
        elif renamed == (True, False):
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Rename for type at ordinal {:d} ({:#x}) from \"{!s}\" to \"{!s}\" resulted in the removal of the tag.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))
            internal.tags.reference.structure.decrement(newsid, '__name__')

        # If the name was originally user-specified but the tag doesn't exist,
        # then our monitor didn't track this change and we need to adjust it.
        elif renamed[0] and '__name__' not in original:
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Rename for type at ordinal {:d} ({:#x}) from \"{!s}\" to \"{!s}\" required us to fix it.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))
            internal.tags.reference.structure.increment(newsid, '__name__')

        # If there was no change from general name to a user-specified name,
        # then we don't have to do anything since the current state is the same.
        elif oldname != newname:
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Rename for type at ordinal {:d} ({:#x}) from \"{!s}\" to \"{!s}\" did not need an adjustment.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))

        # The next thing we need to check is if the type being updated is
        # something that we're supposed to track or not. This is easy since if
        # it's tracked, we increment the tag. If it's not, we decrement the tag.
        tracked = cls.is_type_tracked(ordinal, newsid, newname)
        if tracked and '__typeinfo__' not in original:
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Change for type at ordinal {:d} ({:#x}) from \"{!s}\" to \"{!s}\" required us to track it.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))
            internal.tags.reference.structure.increment(newsid, '__typeinfo__')

        elif not tracked and '__typeinfo__' in original:
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Change for type at ordinal {:d} ({:#x}) from \"{!s}\" to \"{!s}\" required us to track it.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, utils.string.escape(oldname, '"'), utils.string.escape(newname, '"')))
            internal.tags.reference.structure.decrement(newsid, '__typeinfo__')

        else:
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Tracking for type at ordinal {:d} ({:#x}) did not need to be adjusted.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid))

        # Grab the comment that's been applied to the type, and update its refs.
        oldcomment, newcomment = cls.state.cachedcomment(ordinal), cls.state.comment(ordinal)
        oldtags, newtags = ({tag for tag in decoded} for decoded in map(internal.comment.decode, [oldcomment, newcomment]))
        if oldtags != newtags:
            logging.debug(u"{:s}.type_updater({:d}, {:d}) : Comment tags for type at ordinal {:d} ({:#x}) were changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, sorted(oldtags), sorted(newtags)))
            cls.update_type_comments(newsid, oldtags, newtags)

        # Grab the current tags that have been applied to the structure and log
        # exactly how they were modified during this update.
        modified = internal.tags.reference.structure.get(newsid)
        logging.debug(u"{:s}.type_updater({:d}, {:d}) : The tags for the type at ordinal {:d} ({:#x}) were changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), ltc, ordinal, ordinal, newsid, sorted(original), sorted(modified)))

    @classmethod
    def member_updater(cls, ltc, ordinal, changes):
        '''Iterate through the specified `changes` for the type in `ordinal` and update the tags for each of its members.'''
        if not hasattr(cls, 'state'):
            parameter = "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal)
            return logging.error(u"{:s}.member_updater({:d}, {:#x}, {!s}) : Unable to handle an update for the members of type {!s} due to the monitor state being uninitialized.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', parameter))

        # First we'll need to get the type identifier for our parameters. We try
        # the cached version first, and then use the noncached one if it fails.
        sid = cls.state.cachedidentifier(ordinal)
        sid = cls.state.identifier(ordinal) if sid == idaapi.BADADDR else sid
        parameter = "{!s}".format(ordinal) if ordinal is None else "{!r}".format(ordinal)

        if sid == idaapi.BADADDR:
            return logging.error(u"{:s}.member_updater({:d}, {:#x}, {!s}) : Unable to handle an update for the members of type {!s} due to its identifier ({:#x}) being invalid.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', parameter, sid))

        # Now we can iterate through the changes that were made to the members of
        # the ordinal. If we have an old state and a new state, then we be doing
        # a comparison of the changes to figure out what tags to apply.
        for count, old, new in changes:
            if old and new:
                oldindex, oldmid, oldname, oldoffset, oldsize, oldtype, oldalign, oldcomment = old
                newindex, newmid, newname, newoffset, newsize, newtype, newalign, newcomment = new

                # Now we'll assign the member index, and then figure out the
                # correct identifier that we should be using.
                mindex, mid = newindex, oldmid if newmid == idaapi.BADADDR else newmid
                if mid == idaapi.BADADDR:
                    logging.error(u"{:s}.member_updater({:d}, {!s}, {!s}) : Unable to adjust the tags for the changed member at index {:d} of type {!s} due to its identifier ({:#x}) being invalid.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, parameter, mid))
                    continue

                # Grab the tags that are currently applied to the member.
                else:
                    original = internal.tags.reference.members.get(mid)

                # Then we'll check the name change first. If we're switching
                # from a general name to a user-specified one, then increment.
                renamed = not cls.is_field_general(ordinal, oldindex, oldname), not cls.is_field_general(ordinal, newindex, newname)
                if renamed == (False, True):
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Rename for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" resulted in the addition of the tag.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, oldname, newname))
                    internal.tags.reference.members.increment(mid, '__name__')

                # If it's been switched the other way, then decrement the tag.
                elif renamed == (True, False):
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Rename for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" resulted in the removal of the tag.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, oldname, newname))
                    internal.tags.reference.members.decrement(mid, '__name__')

                # If the name was originally user-specified, but there's no
                # count for the tag attached to the member, then fix it.
                elif renamed[0] and '__name__' not in original:
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Rename for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" required us to fix it.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, oldname, newname))
                    internal.tags.reference.members.increment(mid, '__name__')

                # If the names aren't the same but the generality is, then we
                # just log that we didn't need to do anything for it.
                elif oldname != newname:
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Rename for the changed member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" did not need an adjustment.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, oldname, newname))

                # Last thing we need to do is to figure out whether the type was
                # changed between a trivial (basic) type to non-trivial one. If
                # it was switched to one that we track, then increment its tag.
                tracked = cls.is_field_tracked(ordinal, oldindex, oldtype), cls.is_field_tracked(ordinal, newindex, newtype)
                if tracked == (False, True):
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Changing the type for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" resulted in the addition of the tag.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, utils.string.escape("{!s}".format(oldtype), '"'), utils.string.escape("{!s}".format(newtype), '"')))
                    internal.tags.reference.members.increment(mid, '__typeinfo__')

                # If the new type was lowered to a trivial (basic) type, then go
                # ahead and decrement it.
                elif tracked == (True, False):
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Changing the type for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" resulted in the removal of the tag.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, utils.string.escape("{!s}".format(oldtype), '"'), utils.string.escape("{!s}".format(newtype), '"')))
                    internal.tags.reference.members.decrement(mid, '__typeinfo__')

                # If the original type was something for us to track, but it
                # doesn't include our tag, then we fix it by incrementing.
                elif tracked[0] and '__typeinfo__' not in original:
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Changing the type for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" required us to fix it.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, utils.string.escape("{!s}".format(oldtype), '"'), utils.string.escape("{!s}".format(newtype), '"')))
                    internal.tags.reference.members.increment(mid, '__typeinfo__')

                # Next we'll figure out whether we should log that no changes to
                # the reference counts for "__typeinfo__" were needed.
                elif not interface.tinfo.same(oldtype, newtype):
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Changing the type for the member at index {:d} ({:#x}) of type {!s} ({:#x}) from \"{!s}\" to \"{!s}\" did not need an adjustment.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, utils.string.escape("{!s}".format(oldtype), '"'), utils.string.escape("{!s}".format(newtype), '"')))

                # The very last thing we need to do is to check the tags that
                # have been encoded into the comments. We pretty much just hand
                # this off to the "update_member_comments" classmethod.
                oldtags, newtags = ({tag for tag in tags} for tags in map(internal.comment.decode, [oldcomment, newcomment]))
                if oldtags != newtags:
                    logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Changing the comment tags for the member at index {:d} ({:#x}) of type {!s} ({:#x}) resulted in modifying the tags from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, sorted(oldtags), sorted(newtags)))
                    cls.update_member_comments(sid, mid, oldtags, newtags)

                # Now we can output all of the tags that we changed.
                modified = internal.tags.reference.members.get(mid)
                logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : The tags for the member at index {:d} ({:#x}) of type {!s} ({:#x}) were changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid, sorted(original), sorted(modified)))

            # The member was removed, so we can just delete all the tag
            # information for the specified identifier.
            elif old:
                mindex, mid, mname, moffset, msize, mtype, malign, mcomment = old
                if mid == idaapi.BADADDR:
                    logging.error(u"{:s}.member_updater({:d}, {!s}, {!s}) : Unable to adjust the tags for the deleted member at index {:d} of type {!s} ({:#x}) due to its identifier ({:#x}) being invalid.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, parameter, sid, mid))
                    continue

                removed = cls.delete_member_refs(sid, mid)
                logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Removed the tags for the member at index {:d} ({:#x}) of type {!s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, mid, parameter, sid))

            # A member was added, so we need to check if the field uses a
            # non-general type or a user-specified name to update its tags.
            elif new:
                mindex, mid, mname, moffset, msize, mtype, malign, mcomment= new
                if mid == idaapi.BADADDR:
                    logging.error(u"{:s}.member_updater({:d}, {!s}, {!s}) : Unable to adjust the tags for the added member at index {:d} of type {!s} ({:#x}) due to its identifier ({:#x}) being invalid.".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', mindex, parameter, sid, mid))
                    continue

                # First we'll delete anything that exists at the identifier for
                # the member. This shouldn't do anything since there's really
                # isn't any reason for a new member to have any tag data
                # associated with it.
                removed = cls.delete_member_refs(sid, mid)

                # If the field name is not a general one, then increment the
                # reference count for its "__name__" tag.
                changed = []
                if not cls.is_field_general(ordinal, mindex, mname):
                    internal.tags.reference.members.increment(mid, '__name__'), changed.append('__name__')

                if cls.is_field_tracked(ordinal, mindex, mtype):
                    internal.tags.reference.members.increment(mid, '__typeinfo__'), changed.append('__typeinfo__')

                logging.debug(u"{:s}.member_updater({:d}, {!s}, {!s}) : Added the specified tags ({!s}) to the member at index {:d} ({:#x}) of type {!s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ltc, parameter, '...', ', '.join(map("{!r}".format, changed)), mindex, mid, parameter, sid))
            continue
        return

class supermethods(object):
    """
    Define all of the functions that will be used as supermethods for
    the situation when the original hook supermethod does not take the
    same parameters as listed in IDAPython's documentation. This is
    used when initializing the hooks module via the priorityhook class.
    """

    class IDP_Hooks(object):
        """
        This is just a namespace for the the list of supermethods that
        we need to override with when using the IDP_Hooks object.
        """
        mapping = {}

        # idaapi.__version__ >= 7.5
        def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
            '''This patch is needed as the supermethod wants a vector type for its value.'''
            cls = self.__class__
            if value_type == idaapi.IDPOPT_STR:     # string constant (char*)
                res = idaapi.uchar_array(1 + len(value))
                for index, item in enumerate(bytearray(value + b'\0')):
                    res[index] = item
                pvalue = res
            elif value_type == idaapi.IDPOPT_NUM:   # number (uval_t*)
                res = idaapi.uvalvec_t()
                res.push_back(value)
                pvalue = res
            elif value_type == idaapi.IDPOPT_BIT:   # bit, yes/no (int*)
                res = idaapi.intvec_t()
                res.push_back(value)
                pvalue = res
            elif value_type == idaapi.IDPOPT_FLT:   # float, yes/no (double*)
                # FIXME: is there a proper way to get a double* type?
                res = idaapi.uint64vec_t()
                res.push_back(internal.utils.float_to_integer(value, 52, 11, 1))
                pvalue = res
            elif value_type == idaapi.IDPOPT_I64:   # 64bit number (int64*)
                res = idaapi.int64vec_t()
                res.push_back(value)
                pvalue = res
            else:
                raise ValueError(u"ev_set_idp_options_hook({!r}, {:d}, {:d}, {!s}) : Unknown value_type ({:d}) passed to ev_set_idp_options hook".format(keyword, value_type, value, idb_loaded, value_type))

            # We need to figure out the original supermethod to call into
            # ourselves because we don't have the method name as a cellvar.
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'ev_set_idp_options')
            return supermethod(keyword, value_type, pvalue, idb_loaded)

        # Populate the dictionary with each of the supermethods that need
        # to be patched for the IDB_Hooks class by checking the version
        # in order to determine whether it should be assigned or not.
        idaapi.__version__ >= 7.5 and mapping.setdefault('ev_set_idp_options', ev_set_idp_options)

    class IDB_Hooks(object):
        """
        This is just a namespace for the the list of supermethods that
        we need to override with when using the IDB_Hooks object.
        """
        mapping = {}

        # idaapi.__version__ >= 7.6
        def compiler_changed(self, adjust_inf_fields):
            '''This patch is needed due to the supermethod not wanting *this as its first parameter.'''
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'compiler_changed')
            return supermethod(adjust_inf_fields)

        # idaapi.__version__ >= 7.6
        def renamed(self, ea, new_name, local_name):
            '''This patch is needed due to the supermethod wanting a different number of parameters.'''
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'renamed')
            return supermethod(ea, new_name, local_name or None, '')

        # idaapi.__version__ >= 7.6
        def bookmark_changed(self, index, pos, desc, operation):
            '''This patch is needed due to the supermethod not wanting *this as its first parameter.'''
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'bookmark_changed')
            return supermethod(index, pos, desc, operation)

        # idaapi.__version__ >= 7.7
        def segm_deleted(self, start_ea, end_ea, flags):
            '''This patch is needed due to the supermethod not wanting *this as its first parameter.'''
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'segm_deleted')
            return supermethod(start_ea, end_ea, flags)

        # idaapi.__version__ >= 8.0
        def struc_renamed(self, sptr):
            '''This patch is needed due to the supermethod wanting a boolean to control whether the rename was successful.'''
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'struc_renamed')
            return supermethod(sptr, True)

        # Populate the dictionary with each of the supermethods that need
        # to be patched for the IDB_Hooks class by checking the version
        # in order to determine whether it should be assigned or not.
        idaapi.__version__ >= 7.6 and mapping.setdefault('compiler_changed', compiler_changed)
        idaapi.__version__ >= 7.6 and mapping.setdefault('renamed', renamed)
        idaapi.__version__ >= 7.6 and mapping.setdefault('bookmark_changed', bookmark_changed)
        idaapi.__version__ >= 7.7 and mapping.setdefault('segm_deleted', segm_deleted)
        idaapi.__version__ >= 8.0 and mapping.setdefault('struc_renamed', struc_renamed)

    class UI_Hooks(object):
        """
        This is just a namespace for the the list of supermethods that
        we need to override with when using the UI_Hooks object.
        """
        mapping = {}

        # idaapi.__version__ >= 7.6
        def saved(self, path):
            '''This patch is needed due to the supermethod not wanting *this as its first parameter.'''
            cls = self.__class__
            supercls = super(cls, self)
            supermethod = getattr(supercls, 'saved')
            return supermethod(path)

        # Populate the dictionary with each of the supermethods that need
        # to be patched for the IDB_Hooks class by checking the version
        # in order to determine whether it should be assigned or not.
        idaapi.__version__ >= 7.6 and mapping.setdefault('saved', saved)

class entrymethods(object):
    """
    Define all of the functions that will be used as entrymethods for the
    situation when the code generated by SWIG for the original hook depends
    on the number of arguments defined for the method. These functions only
    apply to the priorityhook class from the hooks module.

    The way that IDAPython implemented it prevents us from using wildargs
    to capture everything that a hook may give us. So, this hack is necessary
    for tricking certain IDAPython hook types into thinking that we know what
    we're actually receiving.

    For the record, the functions defined within the classes from this
    namespace are never called. Instead, we use them to mirror the function
    prototype for the corresponding hook method.
    """

    class IDB_Hooks(object):
        """
        This is just a namespace for the the list of entrymethods that
        we need to use when receiving callbacks from the IDB_Hooks object.
        """
        mapping = {}

        # idaapi.__version__ >= 7.6
        def compiler_changed(self, adjust_inf_fields):
            '''introduced by commit c22e07185389adaef1698314071f2c6cd31dd08b to patch_codegen/idp.py.'''

        # idaapi.__version__ < 8.4
        def busted_local_types_changed(self):
            '''this variation is defined in v7.7 of the disassembler as having no parameters (making it useless).'''

        # idaapi.__version__ >= 8.4
        def local_types_changed(self, ltc, ordinal, name):
            '''introduced by commit ae62cd4df534f18c8c3dc47bd159d50c9822d82d to patch_codegen/idp.py.'''

        idaapi.__version__ >= 7.6 and mapping.setdefault('compiler_changed', compiler_changed)
        idaapi.__version__ < 8.4 and mapping.setdefault('local_types_changed', busted_local_types_changed)
        idaapi.__version__ >= 8.4 and mapping.setdefault('local_types_changed', local_types_changed)

    class IDP_Hooks(object):
        """
        This is just a namespace for the the list of entrymethods that
        we need to use when receiving callbacks from the IDP_Hooks object.
        """
        mapping = {}

    class UI_Hooks(object):
        """
        This is just a namespace for the the list of entrymethods that
        we need to use when receiving callbacks from the UI_Hooks object.
        """
        mapping = {}

def make_ida_not_suck_cocks(nw_code):
    '''Start hooking all of IDA's API.'''
    import hook

    # first we try to delete the leftover garbage from idapython's init.py script.
    if '__main__' in sys.modules:
        remove = ['signal', 'site', 'sp']
        [ sys.modules['__main__'].__dict__.pop(item, None) for item in remove ]

    # at this point, the hook classes should already have been instantiated by the
    # loader. so we just verify that the necessary attributes exist to be safe.
    for attribute in ['notification', 'idp', 'idb', 'ui']:
        if not hasattr(hook, attribute):
            logging.warning(u"{:s} : Unable to locate the \"{:s}\" hook type that should have been attached during load.".format(__name__, attribute))
        continue

    ## initialize the priorityhook api for all three of IDA's interfaces in the
    ## "ui" module for backwards compatibility with older versions of the plugin.
    ui.hook.__start_ida__()

    ## verify that the scheduler exists and if it doesn't, then create a fake one.
    fake_hook_method = lambda self, hook, *args, **kwargs: hook.add(*args, **kwargs)
    fake_modulate_method = lambda self, state: state
    scheduler = hook.scheduler if hasattr(hook, 'scheduler') else type('scheduler', (object,), {attribute : value for attribute, value in itertools.chain(zip(['default', 'initialized', 'loaded', 'ready'], 4 * [fake_hook_method]), [('modulate', fake_modulate_method)])})

    ## setup default integer types for the typemapper once the loader figures everything out
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_newprc', interface.typemap.__ev_newprc__, 0)

    elif idaapi.__version__ >= 6.9:
        scheduler.default(hook.idp, 'newprc', interface.typemap.__newprc__, 0)

    else:
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, interface.typemap.__nw_newprc__, -40)

    ## monitor when ida enters its various states so we can pre-build the tag cache
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_init', on_init, -100)
        scheduler.default(hook.idp, 'ev_newfile', on_newfile, -100)
        scheduler.default(hook.idp, 'ev_oldfile', on_oldfile, -100)
        scheduler.default(hook.idp, 'ev_auto_queue_empty', auto_queue_empty, -100)

    elif idaapi.__version__ >= 6.9:
        scheduler.default(hook.idp, 'init', on_init, -100)
        scheduler.default(hook.idp, 'newfile', on_newfile, -100)
        scheduler.default(hook.idp, 'oldfile', on_oldfile, -100)
        scheduler.default(hook.idp, 'auto_empty', on_ready, -100)

    else:
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, nw_on_init, -50)
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, nw_on_newfile, -20)
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, nw_on_oldfile, -20)
        scheduler.default(hook.idp, 'auto_empty', on_ready, 0)

    scheduler.default(hook.idb, 'closebase', on_close, 10000) if 'closebase' in hook.idb.available else scheduler.default(hook.idp, 'closebase', on_close, 10000)

    ## create the tagcache netnode when a database is created
    import internal.tagcache, internal.tagindex
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_init', internal.tagcache.tagging.__init_tagcache__, -1)
        scheduler.default(hook.idp, 'ev_init', internal.tagindex.init_tagindex, -1)

    elif idaapi.__version__ >= 6.9:
        scheduler.default(hook.idp, 'init', internal.tagcache.tagging.__init_tagcache__, -1)
        scheduler.default(hook.idp, 'init', internal.tagindex.init_tagindex, -1)

    else:
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, internal.tagcache.tagging.__nw_init_tagcache__, -40)
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, internal.tagindex.nw_init_tagcache, -40)

    ## hook any user-entered comments so that they will also update the tagcache
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_init', address.database_init, 0)
        scheduler.default(hook.idp, 'ev_init', globals.database_init, 0)
        scheduler.ready(hook.idb, 'changing_range_cmt', globals.changing, 0)
        scheduler.ready(hook.idb, 'range_cmt_changed', globals.changed, 0)

    elif idaapi.__version__ >= 6.9:
        scheduler.default(hook.idp, 'init', address.database_init, 0)
        scheduler.default(hook.idp, 'init', globals.database_init, 0)
        scheduler.ready(hook.idb, 'changing_area_cmt', globals.changing, 0)
        scheduler.ready(hook.idb, 'area_cmt_changed', globals.changed, 0)

    else:
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, address.nw_database_init, -30)
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, globals.nw_database_init, -30)
        scheduler.ready(hook.idb, 'area_cmt_changed', globals.old_changed, 0)

    # hook the changing of a comment
    if idaapi.__version__ >= 6.9:
        scheduler.ready(hook.idb, 'changing_cmt', address.changing, 0)
        scheduler.ready(hook.idb, 'cmt_changed', address.changed, 0)

    else:
        scheduler.ready(hook.idb, 'cmt_changed', address.old_changed, 0)

    ## hook renames to support updating the "__name__" implicit tag
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_init', naming.database_init, 0)
        scheduler.ready(hook.idp, 'ev_rename', naming.changing, 0)
        scheduler.ready(hook.idb, 'renamed', naming.changed, 0)

    else:
        scheduler.ready(hook.idp, 'rename', naming.rename, 0)

    ## hook function transformations so we can shuffle their tags between types
    if idaapi.__version__ >= 7.0:
        scheduler.ready(hook.idb, 'deleting_func_tail', removing_func_tail, 0)
        scheduler.ready(hook.idb, 'func_added', add_func, 0)
        scheduler.ready(hook.idb, 'deleting_func', del_func, 0)
        scheduler.ready(hook.idb, 'set_func_start', set_func_start, 0)
        scheduler.ready(hook.idb, 'set_func_end', set_func_end, 0)

    elif idaapi.__version__ >= 6.9:
        scheduler.ready(hook.idb, 'removing_func_tail', removing_func_tail, 0)
        [ scheduler.ready(hook.idp, item.__name__, item, 0) for item in [add_func, del_func, set_func_start, set_func_end] ]

    else:
        scheduler.ready(hook.idb, 'func_tail_removed', func_tail_removed, 0)
        scheduler.ready(hook.idp, 'add_func', add_func, 0)
        scheduler.ready(hook.idp, 'del_func', del_func, 0)
        scheduler.ready(hook.idb, 'tail_owner_changed', tail_owner_changed, 0)

    [ scheduler.ready(hook.idb, item.__name__, item, 0) for item in [thunk_func_created, func_tail_appended] ]

    ## Relocate the tagcache for an individual segment if that segment is moved.
    scheduler.ready(hook.idb, 'segm_start_changed', segm_start_changed, 0)
    scheduler.ready(hook.idb, 'segm_end_changed', segm_end_changed, 0)
    scheduler.ready(hook.idb, 'segm_moved', segm_moved, 0)

    # XXX: We could use the "allsegs_moved" event which gets called after everything is moved,
    #      but fortunately after talking to igorsk these hooks are really the best method here.

    ## switch the instruction set when the processor is switched
    import __catalog__ as catalog
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_newprc', catalog.ev_newprc, 0)

    elif idaapi.__version__ >= 6.9:
        scheduler.default(hook.idp, 'newprc', catalog.newprc, 0)

    else:
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, catalog.nw_newprc, -10)

    ## ensure the internal.interface.database namespace is initialized as it's
    ## necessary and used by the processor detection.
    if idaapi.__version__ >= 7.0:
        scheduler.default(hook.idp, 'ev_init', internal.interface.database.__init_info_structure__, -100)

    elif idaapi.__version__ >= 6.9:
        scheduler.default(hook.idp, 'init', internal.interface.database.__init_info_structure__, -100)

    else:
        scheduler.default(hook.notification, idaapi.NW_OPENIDB, internal.interface.database.__nw_init_info_structure__, -30)

    ## keep track of individual tags like colors and type info
    if idaapi.__version__ >= 7.2:
        scheduler.ready(hook.idb, 'item_color_changed', item_color_changed, 0)

    # anything earlier than v7.0 doesn't expose the "changing_ti" and "ti_changed"
    # hooks... plus, v7.1 doesn't pass us the correct type (idaapi.tinfo_t) as its
    # parameter, instead opting for an idaapi.comp_t (compiler type) which is
    # completely fucking useless to us. so if we're using 7.1 or earlier, then
    # we completely skip the addition of the typeinfo hooks.
    if idaapi.__version__ >= 7.2:
        scheduler.default(hook.idp, 'ev_init', typeinfo.database_init, 0)

        # XXX: we keep these hooks scheduled all the time because i personally
        #      care about types, and you probably should too.
        scheduler.default(hook.idb, 'changing_ti', typeinfo.changing, 0)
        scheduler.default(hook.idb, 'ti_changed', typeinfo.changed, 0)

    # earlier versions of IDAPython don't expose anything about "extra" comments
    # so we can't do anything here.
    if idaapi.__version__ >= 6.9:
        scheduler.default(hook.idb, 'extra_cmt_changed', extra_cmt.changed, 0)
        # XXX: we schedule extra comments by default because they give us segment boundaries.

    ## start by initializing the states for all our structure-related hooks.
    namespaces = []
    namespaces+= [structures, structurenaming]
    namespaces+= [members, memberscope, membernaming, memberchange, membertypeinfo]
    namespaces+= [framemembers, framememberscope, framemembernaming, framememberchange, framemembertypeinfo]

    # now for the 8.4 specific hooks...
    namespaces+= [structures_84, members_84, memberscope_84]

    if idaapi.__version__ >= 7.0:
        [scheduler.default(hook.idp, 'ev_init', namespace.database_init, -100) for namespace in namespaces]

    elif idaapi.__version__ >= 6.9:
        [scheduler.default(hook.idp, 'init', namespace.database_init, -100) for namespace in namespaces]

    else:
        [scheduler.default(hook.notification, idaapi.NW_OPENIDB, namespace.nw_database_init, -100) for namespace in namespaces]

    # now for structures if they are actually available. we support structure
    # comments (changing/changed), created/deleted, and renaming/renamed.
    if idaapi.__version__ >= 7.7:
        scheduler.default(hook.idb, 'struc_created', structurenaming.created, -75)
        scheduler.default(hook.idb, 'struc_deleted', structurenaming.deleted, +75)
        scheduler.default(hook.idb, 'renaming_struc', structurenaming.renaming, -75)
        scheduler.default(hook.idb, 'struc_renamed', structurenaming.renamed, -75)

    # v8.4 of the disassembler changes the way repeatable comments and
    # non-repeatable comments can be applied to a structure. So, because of this
    # we need to support both variations of applying comments to structures.
    if idaapi.__version__ < 8.4:
        scheduler.default(hook.idb, 'changing_struc_cmt', structures.changing, -50)
        scheduler.default(hook.idb, 'struc_cmt_changed', structures.changed, -50)

    else:
        scheduler.default(hook.idb, 'changing_struc_cmt', structures_84.changing, -50)
        scheduler.default(hook.idb, 'struc_cmt_changed', structures_84.changed, -50)

    # Next we have to do members and frame members. All of the member events
    # should work work until we hit 8.4 where the renaming/renamed events don't
    # work for regular structure members. To list the handled events, we handle
    # comments (changing/changed) and created/deleting/deleted for both members
    # and frame members. We also handle naming (renaming/renamed) for only frame
    # members since they aren't affected by 8.4.

    if idaapi.__version__ >= 7.7:
        scheduler.default(hook.idb, 'struc_member_created', memberscope.created, -75)

        # modification of member type information
        scheduler.default(hook.idb, 'changing_ti', membertypeinfo.changing, -75)
        scheduler.default(hook.idb, 'ti_changed', membertypeinfo.changed, -75)

    # Here are the events for supporting the tag index with frame members.
    if idaapi.__version__ >= 7.7:
        scheduler.default(hook.idb, 'struc_member_created', framememberscope.created, -75)

        # applying a comment to a frame member works in both 8.3 and 8.4.
        scheduler.default(hook.idb, 'changing_struc_cmt', framemembers.changing, -75)
        scheduler.default(hook.idb, 'struc_cmt_changed', framemembers.changed, -75)

        # deleting a frame member.
        scheduler.default(hook.idb, 'deleting_struc_member', framememberscope.deleting, +75)
        scheduler.default(hook.idb, 'struc_member_deleted', framememberscope.deleted, +75)

        # updating the name for a frame member.
        scheduler.default(hook.idb, 'renaming_struc_member', framemembernaming.renaming, -50)
        scheduler.default(hook.idb, 'struc_member_renamed', framemembernaming.renamed, -50)

        # modification of frame member types
        scheduler.default(hook.idb, 'changing_struc_member', framememberchange.changing, -75)
        scheduler.default(hook.idb, 'struc_member_changed', framememberchange.changed, -75)

        # modification of member type information
        scheduler.default(hook.idb, 'changing_ti', framemembertypeinfo.changing, -50)
        scheduler.default(hook.idb, 'ti_changed', framemembertypeinfo.changed, -50)

    # Similar to structures, v8.4 of the disassembler changes the way that
    # comments can be applied to a member. So, we support the variation where
    # repeatable and non-repeatable comments can be applied to a member at the
    # same time, or the variation where only one can exist at a given time.
    if idaapi.__version__ < 8.4:
        scheduler.default(hook.idb, 'changing_struc_cmt', members.changing, -75)
        scheduler.default(hook.idb, 'struc_cmt_changed', members.changed, -75)

        # deletion of members.
        scheduler.default(hook.idb, 'deleting_struc_member', memberscope.deleting, +75)
        scheduler.default(hook.idb, 'struc_member_deleted', memberscope.deleted, +75)

    else:
        scheduler.default(hook.idb, 'changing_struc_cmt', members_84.changing, -75)
        scheduler.default(hook.idb, 'struc_cmt_changed', members_84.changed, -75)

        # deletion of members.
        scheduler.default(hook.idb, 'deleting_struc_member', memberscope_84.deleting, +75)
        scheduler.default(hook.idb, 'struc_member_deleted', memberscope_84.deleted, +75)

    # If we're earlier than 8.4, then the structure renaming/renamed events
    # actually work and we can add them. However, if we're using 8.4 then we
    # have to do some trickery with a different event (local_types_changed) to
    # monitor the renaming of a structure member in v8.4.
    if 7.7 <= idaapi.__version__ < 8.4:
        scheduler.default(hook.idb, 'renaming_struc_member', membernaming.renaming, -50)
        scheduler.default(hook.idb, 'struc_member_renamed', membernaming.renamed, -50)

        scheduler.default(hook.idb, 'changing_struc_member', memberchange.changing, -75)
        scheduler.default(hook.idb, 'struc_member_changed', memberchange.changed, -75)

    # FIXME: This hasn't been implemented yet because the implementation will
    #        likely overlap with 9.0 due to the deprecation of the structure api
    #        in favor of the local types library.
    else:
        scheduler.default(hook.idp, 'ev_init', localtypesmonitor_84.init_local_types_monitor, -10000)
        scheduler.default(hook.idp, 'ev_oldfile', localtypesmonitor_84.load_local_types_monitor, -100)
        scheduler.default(hook.idp, 'ev_newfile', localtypesmonitor_84.load_local_types_monitor, -100)
        scheduler.default(hook.idb, 'closebase', localtypesmonitor_84.unload_local_types_monitor, +10000)
        scheduler.default(hook.idb, 'local_types_changed', localtypesmonitor_84.changed, 0)

        logging.warning(u"{:s} : Tags involving the renaming of structure members is currently unimplemented in v{:.1f}.".format(__name__, idaapi.__version__))
        logging.warning(u"{:s} : Tags involving the application of types to structure members is currently unimplemented in v{:.1f}.".format(__name__, idaapi.__version__))

    # add any hooks that are tied to the existence of any plugins.
    if hasattr(hook, 'hx'):
        hook.ui.add('plugin_loaded', hook.hx.__plugin_loaded__, -10000)
        hook.ui.add('plugin_unloading', hook.hx.__plugin_unloading__, +10000)

    # add any hooks that are required to automatically prepare the
    # microarchitecture module that is tied to the decompiler.
    if hasattr(hook, 'hx'):
        micro = catalog.microarchitecture

        # only enable the module if the decompiler is loaded and enabled.
        hook.ui.add('plugin_loaded', micro.__plugin_loaded__, -10000)
        hook.ui.add('plugin_unloading', micro.__plugin_unloading__, +10000)

        # update the microarchitecture module whenever the processor changes.
        if idaapi.__version__ >= 7.0:
            scheduler.default(hook.idp, 'ev_newprc', micro.ev_newprc, 0)
        elif idaapi.__version__ >= 6.9:
            scheduler.default(hook.idp, 'newprc', micro.newprc, 0)
        else:
            scheduler.default(hook.notification, idaapi.NW_OPENIDB, micro.nw_newprc, -10)
        del(micro)

    ## just some debugging notification hooks
    #[ hook.ui.add(item, notify(item), -100) for item in ['range','idcstop','idcstart','suspend','resume','term','ready_to_run'] ]
    #[ hook.idp.add(item, notify(item), -100) for item in ['ev_newfile','ev_oldfile','ev_init','ev_term','ev_newprc','ev_newasm','ev_auto_queue_empty'] ]
    #[ hook.idb.add(item, notify(item), -100) for item in ['closebase','savebase','loader_finished', 'auto_empty', 'thunk_func_created','func_tail_appended'] ]
    #[ hook.idp.add(item, notify(item), -100) for item in ['add_func','del_func','set_func_start','set_func_end'] ]
    #hook.idb.add('allsegs_moved', notify('allsegs_moved'), -100)
    #[ hook.idb.add(item, notify(item), -100) for item in ['cmt_changed', 'changing_cmt', 'range_cmt_changed', 'changing_range_cmt'] ]
    #[ hook.idb.add(item, notify(item), -100) for item in ['changing_ti', 'ti_changed', 'changing_op_type', 'op_type_changed'] ]
    #[ hook.idb.add(item, notify(item), -100) for item in ['changing_op_ti', 'op_ti_changed'] ]
    #hook.idb.add('item_color_changed', notify(item), -100)
    #hook.idb.add('extra_cmt_changed', notify(item), -100)

    ### ...and that's it for all the hooks, so give out our greeting
    return greeting()

def make_ida_suck_cocks(nw_code):
    '''Unhook all of IDA's API.'''
    __import__('hook').close()

def ida_is_busy_sucking_cocks(*args, **kwargs):
    import hook
    make_ida_not_suck_cocks(idaapi.NW_INITIDA)
    hook.notification.add(idaapi.NW_TERMIDA, make_ida_suck_cocks, +1000)
    return -1

### database state
class DatabaseState(object):
    '''This base class is used to represent the different states a disassembler database can be in.'''
    def __init__(self, name, documentation=None):
        self.__name__, self.__doc__ = name, documentation
    def __repr__(self):
        return "{:s} ({:s})".format(self.__name__, self.__doc__) if self.__doc__ else self.__name__

class Scheduler(object):
    """
    This class describes an object that is used to manage which hooks
    are enabled by correlating them with the current database state.
    The database can either be initialized, loaded, ready, or not
    available. Once an instance is created, the caller may use the
    object to attach callables of their choosing, or hooks that are
    to be enabled when transitioning to one of these states.

    After the hooks have been attached, the instance can be used to
    modulate the object to either of these states or to check the
    current state. When a new state is being transitioned to, the
    object will disable all of the hooks from the prior state before
    executing any of the attached callables and then enabling the
    hooks for the target state.
    """
    class database(object):
        """
        This namespace contains each of the states that are available
        for a database being used by the disassembler. Each of the
        states can be accessed by this class using their name. The
        default function for this namespace will yield each of them.
        """
        __slots__ = []

        def __new__(cls):
            '''Yield the name for each the states that are available for a database.'''
            used = {item for item in []}
            for name in sorted(cls.__dict__):
                object = cls.__dict__[name]
                if name.startswith('__'):
                    continue
                elif object not in used:
                    yield name
                used.add(object)
            return

        # the available states that the database could be in.
        unavailable = DatabaseState('database.unavailable')
        initialized = DatabaseState('database.initialized')
        loaded = DatabaseState('database.loaded')
        ready = DatabaseState('database.ready')

    def __init__(self):
        self.__state, states = self.database.unavailable, [getattr(self.database, name) for name in self.database()]
        self.__hooks = {state: {empty for empty in []} for state in states}
        self.__used = {empty for empty in []}
        self.__transitions, self.__tracebacks = {}, {}

    def list(self):
        '''List all of the available states that can be used by this class.'''
        six.print_(u"List of database states for {:s}:".format(self.__class__.__name__))
        for name in self.database():
            six.print_(name)
        return

    def add(self, state, callable, priority=0):
        '''Add the `callable` to the queue for execution at the given `priority` when the database transitions to the specified `state`.'''
        [source, target] = state if hasattr(state, '__iter__') and not isinstance(state, internal.types.string) else [None, state]

        # verify the parameters before we do anything hasty.
        if not builtins.callable(callable):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a non-callable ({!s}) for the requested target with the given priority ({!r}).".format('.'.join(['hook', 'scheduler']), state, callable, priority, callable, format(priority)))
        elif not isinstance(priority, internal.types.integer):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a callable ({:s}) for the requested transition with a non-integer priority ({!r}).".format('.'.join(['hook', 'scheduler']), state, callable, priority, internal.utils.pycompat.fullname(callable), format(priority)))
        elif not all(any([item is None, isinstance(item, DatabaseState), isinstance(item, internal.types.string)]) for item in [source, target]):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a callable to the for the requested transition due to the state{:s} being an unsupported type ({:s}).".format('.'.join(['hook', 'scheduler']), state, callable, priority, '' if isinstance(state, internal.types.string) else 's' if hasattr(state, '__iter__') and len(state) != 1 else '', state if isinstance(state, internal.types.string) else ', '.join(item.__class__.__name__ for item in [source, target]) if hasattr(state, '__iter__') else state.__class__.__name__))
        elif any(not isinstance(getattr(self.database, item, None), DatabaseState) for item in [source, target] if isinstance(item, internal.types.string)):
            cls, format, busted = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format, [item for item in [source, target] if isinstance(item, internal.types.string) and any([item.startswith('__'), not hasattr(self.database, item)])]
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a callable to the for the given unknown state{:s} ({:s}).".format('.'.join(['hook', 'scheduler']), state, callable, priority, '' if len(busted) == 1 else 's', ', '.join(busted)))

        # now we need to normalize the states that we were given since they should be valid.
        [source, target] = [(item if isinstance(item, (DatabaseState, internal.types.none)) else getattr(self.database, item)) for item in [source, target]]
        transition_description = [(lambda state: 'any' if state is None else state.__name__)(item) for item in [source, target]]

        # and then we can add an entry in our priority queue for the callable.
        queue = self.__transitions.setdefault((source, target), [])
        heapq.heappush(queue, internal.utils.priority_tuple(priority, callable))

        # save a traceback for this callable in case its execution fails.
        self.__tracebacks[source, target, callable] = traceback.extract_stack()[:-1]
        return True

    def discard(self, state, callable):
        '''Discard the `callable` from the queue for the specified `state` transition.'''
        [source, target] = state if hasattr(state, '__iter__') and not isinstance(state, internal.types.string) else [None, state]
        [source, target] = [(item if isinstance(item, (DatabaseState, internal.types.none)) else getattr(self.database, item) if isinstance(item, internal.types.string) and hasattr(self.database, item) else item) for item in [source, target]]

        # Search through the specified queue for whatever callable we were given.
        counter, retained = 0, []
        for index, (priority, F) in enumerate(self.__transitions[source, target]):
            if F == callable:
                counter += 1
            else:
                retained.append((priority, F))
            continue

        # If anything was collected, then replace our transitions with it (in-place).
        if retained:
            self.__transitions[source, target][:] = [internal.utils.priorty_tuple(priority, F) for priority, F in retained]

        # Otherwise we can just remove the entire queue from the specified transition.
        else:
            self.__transitions.pop((source, target))

        self.__tracebacks.pop((source, target, callable), None)
        return True if counter else False

    def pop(self, state, index=-1):
        '''Pop the item at the specified `index` from the given `state` transition.'''
        [source, target] = state if hasattr(state, '__iter__') and not isinstance(state, internal.types.string) else [None, state]
        [source, target] = [(item if isinstance(item, (DatabaseState, internal.types.none)) else getattr(self.database, item) if isinstance(item, internal.types.string) and hasattr(self.database, item) else item) for item in [source, target]]

        # Search through the specified queue for whatever elements match the given priority.
        retained = []
        for index, (priority, F) in enumerate(self.__transitions[source, target]):
            retained.append((priority, F))

        # Pop off whatever result the user asked for and then put everything
        # back into the transition queue without what they asked for.
        item = retained.pop(index)
        if retained:
            self.__transitions[source, target][:] = [internal.utils.priorty_tuple(priority, F) for priority, F in retained]

        # Otherwise the transition queue is empty and we can remove it entirely.
        else:
            self.__transitions.pop((source, target))

        # Unpack whatever we just removed, clear it from the traceback, and return it.
        priority, result = item
        self.__traceback__((source, target, result), None)
        return result

    def remove(self, state, priority):
        '''Remove the first callable from the specified `state` transition that has the given `priority`.'''
        [source, target] = state if hasattr(state, '__iter__') and not isinstance(state, internal.types.string) else [None, state]
        [source, target] = [(item if isinstance(item, (DatabaseState, internal.types.none)) else getattr(self.database, item) if isinstance(item, internal.types.string) and hasattr(self.database, item) else item) for item in [source, target]]
        transition_description = [(lambda state: 'any' if state is None else state.__name__)(item) for item in [source, target]]

        # Search through the specified queue for whatever elements match the given priority.
        retained, priority_table = [], {}
        for index, (priority, F) in enumerate(self.__transitions[source, target]):
            retained.append((priority, F))
            priority_table.setdefault(priority, []).append(index)

        # If the priority doesn't exist, then throw up an exception so they know what's up.
        if priority not in priority_table:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise internal.exceptions.ItemNotFoundError(u"{:s}.remove({:s}, {:s}) : Unable to locate a callable with the specified priority ({:s}).".format('.'.join([__name__, cls.__name__]), ' -> '.join(transition_description), format(priority), format(priority)))

        # Figure out the element that we're going to remove.
        index = priority_table[priority].pop(0)
        item = retained.pop(index)

        # Combine the items that we retained back into the transitions list.
        if retained:
            self.__transitions[source, target][:] = [internal.utils.priorty_tuple(priority, F) for priority, F in retained]

        # Otherwise it's empty and we can remove the transition entirely.
        else:
            self.__transitions.pop((source, target))

        # Now we can remove the item from our tracebacks.
        priority, result = item
        self.__tracebacks.pop((source, target, result), None)
        return result

    def __apply_transition(self, source, destination):
        '''Execute all of the registered callables when transitioning from the `source` state to the `destination` state.'''

        # Create a dictionary containing the parameter choices for any of the callables.
        parameter_choice = {0: [], 1: [destination], 2: [source, destination]}

        # Use our current state and our target state to execute the contents of each queue.
        # We need to merge 3 queues for each state to support the None (any) transition.
        for priority, callable in heapq.merge(*(self.__transitions.get(pair, []) for pair in [(source, destination), (None, destination), (source, None)])):
            is_method = isinstance(callable, internal.types.method) and not isinstance(callable, staticmethod)
            function = internal.utils.pycompat.method.function(callable) if is_method else callable

            # Count out the number of parameters the callable wants
            # so that we can figure out which parameters to use.
            code = internal.utils.pycompat.function.code(function)
            parameter_count = internal.utils.pycompat.code.argcount(code)
            _, _, (wild, _) = internal.utils.pycompat.function.arguments(function)
            real_count = 2 if wild else parameter_count - 1 if is_method else parameter_count

            # Finally we can dispatch to the callable with the correct number of parameters.
            logging.debug(u"{:s}.modulate({:s}) : Dispatching {:d} parameter{:s} to {:s} ({:s}) with priority {:+d}.".format('.'.join(['hook', 'scheduler']), destination.__name__, real_count, '' if real_count == 1 else 's', internal.utils.pycompat.fullname(callable), "{:s}:{:d}".format(*internal.utils.pycompat.file(callable)), priority))
            try:
                result = callable(*parameter_choice[real_count])
                if result is not None:
                    logging.debug(u"{:s}.modulate({:s}) : Discarding unused result {!r} returned from {:s} ({:s}) with priority {:+d}.".format('.'.join(['hook', 'scheduler']), destination.__name__, result, internal.utils.pycompat.fullname(callable), "{:s}:{:d}".format(*internal.utils.pycompat.file(callable)), priority))

            # If we caught an exception, then we need to complain about it. To
            # accomplish this, we'll first need the current backtrace.
            except:
                backtrace = u''.join(traceback.format_exception(*sys.exc_info()))

                # Then we'll need the callable's backtrace and a user-friendly description.
                if (source, destination, callable) in self.__tracebacks:
                    bt = traceback.format_list(self.__tracebacks[source, destination, callable])
                    transition_description = [item for item in itertools.chain([source.__name__, destination.__name__])]
                elif (None, destination, callable) in self.__tracebacks:
                    bt = traceback.format_list(self.__tracebacks[None, destination, callable])
                    transition_description = [item for item in itertools.chain(['any'], [destination.__name__])]
                elif (source, None, callable) in self.__tracebacks:
                    bt = traceback.format_list(self.__tracebacks[source, None, callable])
                    transition_description = [item for item in itertools.chain([source.__name__], ['any'])]
                else:
                    bt = []
                    transition_description = [item for item in itertools.chain([source.__name__, destination.__name__])]

                # Now we just need to output the exception that happened.
                format = functools.partial(u"{:s}.modulate({:s}) : {:s}".format, '.'.join(['hook', 'scheduler']), destination.__name__)
                logging.fatal(format(u"Transition {:s} using {:s} with priority {:+d} raised an exception while executing.".format(' -> '.join(transition_description), internal.utils.pycompat.fullname(callable), priority)))
                logging.warning(format(u"Traceback ({:s} was attached at):".format(' -> '.join(transition_description))))
                [ logging.warning(format(item)) for item in u''.join(bt).split('\n') ]
                [ logging.warning(format(item)) for item in backtrace.split('\n') ]
            continue
        return

    def __guard_closure(self, required_state, callable):
        '''Return a closure that only executes `callable` if the scheduler state matches `required_state`.'''
        if not isinstance(required_state, DatabaseState):
            raise internal.exceptions.InvalidParameterError(u"{:s}.__guard_closure({!r}, {:s}) : Unable to create a guarded closure for the given state due to it being of the wrong type ({!r}).".format('.'.join(['hook', 'scheduler']), required_state, utils.pycompat.fullname(callable), required_state.__class__))

        def closure(*parameters):
            if self.__state not in {required_state}:
                return
            return callable(*parameters)
        utils.pycompat.function.set_name(closure, utils.pycompat.function.name(callable))
        utils.pycompat.function.set_documentation(closure, utils.pycompat.function.documentation(callable))
        setattr(closure, '__qualname__', callable.__qualname__) if hasattr(callable, '__qualname__') else None
        return closure

    def default(self, hook, target, callable, priority):
        '''Assign the specified `hook` and `target` to always be enabled by default.'''
        self.__hooks.setdefault(None, {empty for empty in []}).add((hook, target))
        if not hook.add(target, callable, priority):
            hook_descr, target_descr, callable_descr = utils.pycompat.fullname(hook), hook.__formatter__(target), utils.pycompat.fullname(callable)
            logging.warning(u"{:s}.default({!r}, {:s}, {:s}, {!s}) : Unable to add the specified callable ({:s}) to {} for the given target ({:s}).".format('.'.join([__name__, cls.__name__]), hook_descr, target_descr, callable_descr, priority, callable_descr, hook_descr, target_descr))

        # If we've already added this hook and target before, then there's nothing to do.
        if (hook, target) in self.__used:
            return True

        # Add the current hook and target and then enable it since it should
        # be running all the time regardless of the current state.
        self.__used.add((hook, target))
        return True if target in hook.enabled else hook.enable(target)

    def initialized(self, hook, target, callable, priority):
        '''Assign the specified `hook` and `target` to only be enabled when the database has been initialized.'''
        self.__hooks.setdefault(self.database.initialized, {empty for empty in []}).add((hook, target))
        F = self.__guard_closure(self.database.initialized, callable)
        if not hook.add(target, F, priority):
            hook_descr, target_descr, callable_descr = utils.pycompat.fullname(hook), hook.__formatter__(target), utils.pycompat.fullname(callable)
            logging.warning(u"{:s}.initialized({!r}, {:s}, {:s}, {!s}) : Unable to add the specified callable ({:s}) to {} for the given target ({:s}).".format('.'.join([__name__, cls.__name__]), hook_descr, target_descr, callable_descr, priority, callable_descr, hook_descr, target_descr))

        # If we've already used this hook and target, we're free to leave.
        if (hook, target) in self.__used:
            return True

        # Add the hook and target to our list of already used targets, and then we
        # just need to check if we're in the correct state to enable or disable it.
        self.__used.add((hook, target))
        Fmodulate, required_state = (hook.enable, hook.disabled) if self.__state in {self.database.initialized} else (hook.disable, hook.enabled)
        return Fmodulate(target) if target in required_state else True

    def loaded(self, hook, target, callable, priority):
        '''Assign the specified `hook` and `target` to only be enabled when the database is being loaded.'''
        self.__hooks.setdefault(self.database.loaded, {empty for empty in []}).add((hook, target))
        F = self.__guard_closure(self.database.loaded, callable)
        if not hook.add(target, F, priority):
            hook_descr, target_descr, callable_descr = utils.pycompat.fullname(hook), hook.__formatter__(target), utils.pycompat.fullname(callable)
            logging.warning(u"{:s}.loaded({!r}, {:s}, {:s}, {!s}) : Unable to add the specified callable ({:s}) to {} for the given target ({:s}).".format('.'.join([__name__, cls.__name__]), hook_descr, target_descr, callable_descr, priority, callable_descr, hook_descr, target_descr))

        # If this hook and target has been added already, then return success.
        if (hook, target) in self.__used:
            return True

        # Mark the hook and target that was added as used, and then we check the
        # current state to determine if we should enable it or not.
        self.__used.add((hook, target))
        Fmodulate, required_state = (hook.enable, hook.disabled) if self.__state in {self.database.loaded} else (hook.disable, hook.enabled)
        return Fmodulate(target) if target in required_state else True

    def ready(self, hook, target, callable, priority):
        '''Assign the specified `hook` and `target` to only be enabled when the database is ready.'''
        self.__hooks.setdefault(self.database.ready, {empty for empty in []}).add((hook, target))
        F = self.__guard_closure(self.database.ready, callable)
        if not hook.add(target, F, priority):
            hook_descr, target_descr, callable_descr = utils.pycompat.fullname(hook), hook.__formatter__(target), utils.pycompat.fullname(callable)
            logging.warning(u"{:s}.ready({!r}, {:s}, {:s}, {!s}) : Unable to add the specified callable ({:s}) to {} for the given target ({:s}).".format('.'.join([__name__, cls.__name__]), hook_descr, target_descr, callable_descr, priority, callable_descr, hook_descr, target_descr))

        # If the current hook and target has been used already, then there's nothing to do.
        if (hook, target) in self.__used:
            return True

        # Add the current hook and target, and then enable it if we're currently
        # in the correct state or disable it if we're not.
        self.__used.add((hook, target))
        Fmodulate, required_state = (hook.enable, hook.disabled) if self.__state in {self.database.ready} else (hook.disable, hook.enabled)
        return Fmodulate(target) if target in required_state else True

    def unavailable(self, hook, target, callable, priority):
        '''Assign the specified `hook` and `target` to only be enabled when the database is unavailable or has been unloaded.'''
        self.__hooks.setdefault(self.database.unavailable, {empty for empty in []}).add((hook, target))
        F = self.__guard_closure(self.database.unavailable, callable)
        if not hook.add(target, F, priority):
            hook_descr, target_descr, callable_descr = utils.pycompat.fullname(hook), hook.__formatter__(target), utils.pycompat.fullname(callable)
            logging.warning(u"{:s}.unavailable({!r}, {:s}, {:s}, {!s}) : Unable to add the specified callable ({:s}) to {} for the given target ({:s}).".format('.'.join([__name__, cls.__name__]), hook_descr, target_descr, callable_descr, priority, callable_descr, hook_descr, target_descr))

        # If the current hook and target is used, then we can just leave.
        if (hook, target) in self.__used:
            return True

        # Set the current hook and target as used, and then enable it if we're
        # presently in the correct state. If we're not, then just disable it.
        self.__used.add((hook, target))
        Fmodulate, required_state = (hook.enable, hook.disabled) if self.__state in {self.database.unavailable} else (hook.disable, hook.enabled)
        return Fmodulate(target) if target in required_state else True

    def modulate(self, state):
        '''Modulate the current state of the database to `state` and enable the hooks associated with it.'''
        if not isinstance(state, DatabaseState):
            raise internal.exceptions.InvalidParameterError(u"{:s}.modulate({!r}) : Unable to modulate to the suggested state due to it being of the wrong type ({!r}).".format('.'.join(['hook', 'scheduler']), state, state.__class__))
        current, self.__state = self.__state, state
        [ hook.disable(target) for hook, target in self.__hooks[current] if target in hook.enabled ]
        self.__apply_transition(current, state)
        [ hook.enable(target) for hook, target in itertools.chain(self.__hooks.get(None, []), self.__hooks[state]) if target in hook.disabled ]
        return current

    def reset(self):
        '''Reset the current perceived state of the database and return the state that is being transitioned from.'''
        return self.modulate(self.database.unavailable)
    def is_initialized(self):
        '''Return true if the database is initialized.'''
        return self.__state in {self.database.initialized}
    def is_loaded(self):
        '''Return true if the database has been loaded.'''
        return self.__state in {self.database.loaded}
    def is_ready(self):
        '''Return true if the database is ready.'''
        return self.__state in {self.database.ready}
    def is_unavailable(self):
        '''Return true if the database is unavailable or unloaded.'''
        return self.__state in {self.database.unavailable}
    def get(self):
        '''Return the current monitored state for the purpose of debugging.'''
        return self.__state

    def __repr__(self):
        count = sum(len(queue) for transition, queue in self.__transitions.items())
        if not count:
            return "Events currently being monitored by {:s}: {:s}".format('.'.join(['hook', 'scheduler']), 'No transitions are being monitored.')

        # This logic is straight-up copied out of internal.interface.prioritybase. I should consolidate it
        # into internal.utils, but it'd be for any kind of callable. That's an issue because there really
        # isn't any other reusable functionality I can come up with, other then "describing" a callable.
        def ripped_parameters(func):
            args, defaults, (star, starstar) = internal.utils.pycompat.function.arguments(func)
            for item in args:
                yield "{:s}={!s}".format(item, defaults[item]) if item in defaults else item
            if star:
                yield "*{:s}".format(star)
            if starstar:
                yield "**{:s}".format(starstar)
            return

        def ripped_repr_callable(object, pycompat=internal.utils.pycompat, parameters=ripped_parameters):
            if isinstance(object, (internal.types.method, internal.types.descriptor)):
                cls = pycompat.method.type(object)
                func = pycompat.method.function(object)
                module, name = func.__module__, pycompat.function.name(func)
                iterable = parameters(func)
                None if isinstance(object, internal.types.staticmethod) else next(iterable)
                return '.'.join([module, cls.__name__, name]), tuple(iterable)
            elif isinstance(object, internal.types.function):
                module, name = object.__module__, pycompat.function.name(object)
                iterable = parameters(object)
                return '.'.join([module, name]), tuple(iterable)
            elif callable(object):
                symbols, module, name = object.__dict__, object.__module__, object.__name__
                cons = symbols.get('__init__', symbols.get('__new__', None))
                iterable = parameters(cons) if cons else []
                next(iterable)
                return '.'.join([module, name]), tuple(iterable)
            return "{!r}".format(object), None

        # We have a couple of transitions to go and collect. Each state has a triplet associated
        # with it in order to monitor wildcards. To collect, we just go through all of them.
        states = [ getattr(self.database, name) for name in self.database() ]

        # Our names should be sorted, so we just do them left-to-right, starting with "any".
        items, Fdescribe_state = [], lambda state: 'any' if state is None else state.__name__
        for source, destination in itertools.chain(itertools.permutations(states + [None], 2), [(state, state) for state in states], [(None, None)]):
            transition_description = ' -> '.join(map(Fdescribe_state, [source, destination]))

            # Collect the description of each callable that was added.
            descriptions = []
            for priority, F in self.__transitions.get((source, destination), []):
                name, args = ripped_repr_callable(F)
                descriptions.append("{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))))

            # Stash it in our list of items that we'll format at the end.
            descriptions and items.append((transition_description, descriptions))

        # Now we can calculate the max length of the transition description, and return our results.
        max_transition_length = max(len(transition) for transition, _ in items) if items else 0
        res = "Transitions currently being monitored by {:s}:".format('.'.join(['hook', 'scheduler']))
        return '\n'.join([res] + ["{:<{:d}s} {:s}".format("{:s}:".format(transition), max_transition_length + len(':'), ','.join(descriptions)) for transition, descriptions in items])

class singleton_descriptor(object):
    '''
    This object is a descriptor that simply wraps a callable and manages its scope.
    '''
    def __init__(self, callable, klass, *args, **attributes):
        self.__owner__ = {}
        self.__constructor__ = functools.partial(callable, klass, *args)
        self.__name__ = name = '.'.join(getattr(klass, attribute) for attribute in ['__module__', '__name__'] if hasattr(klass, attribute)) or '.'.join([__name__, self.__class__.__name__])

        # Use any attributes we were given so that we can return an object
        # displaying something useful whenever we're asked for help.
        documentation_t = type(name, (object,), attributes)
        self.__documentation__ = documentation_t()

    def __get__(self, obj, type=None):
        if self.__owner__.get(obj, None) is not None:
            return self.__owner__[obj]

        # If obj is not actually an object (None), then our attribute is being fetched
        # by help and we need to return our dummy object for the documentation.
        elif obj is None:
            return self.__documentation__

        # Pre-initialize some variables that we'll use to log information to the console.
        klass, count = obj.__class__, len(self.__owner__)
        owner = '.'.join(getattr(klass, attribute) for attribute in ['__module__', '__name__'] if hasattr(klass, attribute))

        # If we've already cached a value (but still got this far), then that's because the
        # property we're supposed to return has not been initialized yet. So remove it.
        item = self.__owner__.pop(obj, None)
        if item is not None:
            logging.warning(u"{:s} : Removed unexpected instance that was attached to the {:s} object at {:#x} ({:d} reference{:s} currently exist{:s}).".format(self.__name__, owner, id(obj), count, '' if count == 1 else 's', 's' if count == 1 else ''))

        # Now we can just create our instance and assign it into the cache of owners.
        logging.debug(u"{:s} : Creating a new instance to be attached to the {:s} object at {:#x} ({:d} reference{:s} currently exist{:s}).".format(self.__name__, owner, id(obj), count, '' if count == 1 else 's', 's' if count == 1 else ''))
        cons = self.__constructor__
        return self.__owner__.setdefault(obj, cons())

    def __delete__(self, obj):
        klass, count = obj.__class__, len(self.__owner__)
        owner = '.'.join(getattr(klass, attribute) for attribute in ['__module__', '__name__'] if hasattr(klass, attribute))
        if obj not in self.__owner__:
            logging.critical(u"{:s} : The instance being suggested for removal is not attached to the {:s} object at {:#x}{:s}.".format(self.__name__, owner, id(obj), " ({:d} references still exist)".format(count) if count != 1 else ''))
            return

        instance = self.__owner__.pop(obj)
        logging.debug(u"{:s} : Found an instance attached to the {:s} object at {:#x} that will be removed ({:d} reference{:s} currently exist{:s}).".format(self.__name__, owner, id(obj), count, '' if count == 1 else 's', 's' if count == 1 else ''))
        instance and instance.close()

class module(object):
    """
    This object exposes the ability to hook different parts of IDA.

    There are a number of event types in IDA that can be hooked. These
    are available under the ``hook.idp``, ``hook.idb``, ``hook.ui``,
    and ``hook.notification`` objects. If the Hex-Rays plugin (decompiler)
    is installed, then there is also a ``hook.hx`` object that may be used
    for decompiler callbacks and ``hook.hexrays`` for the hooking api.

    To add a hook for any of the available event types, one can use
    the `add(target, callable, priority)` method to associate a python
    callable with the desired event. After the callable has been
    attached, the `enable(target)` or `disable(target)` methods can be
    used to temporarily enable or disable the attached hook.

    Please refer to the documentation for the ``idaapi.IDP_Hooks``,
    ``idaapi.IDB_Hooks``, and ``idaapi.UI_Hooks`` classes for
    identifying what event targets are available to hook. Similarly,
    the documentation for ``idaapi.notify_when`` can be used to list
    the targets available for notification hooks and the documentation
    for ``idaapi.Hexrays_Hooks`` for the decompiler's hooks.
    """

    # Create a descriptor for the notifications which should always exist if we're loaded.
    notification = singleton_descriptor(lambda cons, *args: cons(*args), internal.interface.prioritynotification,   __repr__=staticmethod(lambda: 'Notifications currently attached to a callable.'))

    # Create some descriptors for each of the available hooks with the supermethods
    # that we'll need to patch for compatibility with older versions of the disassembler.
    idp = singleton_descriptor(internal.interface.priorityhook, idaapi.IDP_Hooks, supermethods.IDP_Hooks.mapping, entrymethods.IDP_Hooks.mapping,  __repr__=staticmethod(lambda item=idaapi.IDP_Hooks: "Events currently connected to {:s}.".format('.'.join(getattr(item, attribute) for attribute in ['__module__', '__name__'] if hasattr(item, attribute)))))
    idb = singleton_descriptor(internal.interface.priorityhook, idaapi.IDB_Hooks, supermethods.IDB_Hooks.mapping, entrymethods.IDB_Hooks.mapping,  __repr__=staticmethod(lambda item=idaapi.IDB_Hooks: "Events currently connected to {:s}.".format('.'.join(getattr(item, attribute) for attribute in ['__module__', '__name__'] if hasattr(item, attribute)))))
    ui  = singleton_descriptor(internal.interface.priorityhook, idaapi.UI_Hooks,  supermethods.UI_Hooks.mapping,  entrymethods.UI_Hooks.mapping,  __repr__=staticmethod(lambda item=idaapi.UI_Hooks:  "Events currently connected to {:s}.".format('.'.join(getattr(item, attribute) for attribute in ['__module__', '__name__'] if hasattr(item, attribute)))))

    # Can't forget to create a descriptor for events related to the Hex-Rays decompiler...
    hx = singleton_descriptor(lambda cons, *args: cons(*args), internal.interface.priorityhxevent, __repr__=staticmethod(lambda: 'Events currently connected to the Hex-Rays (decompiler) callbacks.'))
    if hasattr(idaapi, 'Hexrays_Hooks') and hasattr(idaapi, 'init_hexrays_plugin'):
        hexrays = singleton_descriptor(lambda *args: internal.interface.priorityhook(*args) if idaapi.init_hexrays_plugin() else None, idaapi.Hexrays_Hooks, {}, __repr__=staticmethod(lambda item=idaapi.Hexrays_Hooks:  "Events currently connected to {:s}.".format('.'.join(getattr(item, attribute) for attribute in ['__module__', '__name__'] if hasattr(item, attribute)))))

    # And a descriptor for managing any actions that we may want to register.
    action = singleton_descriptor(lambda cons, *args: cons(*args), internal.interface.priorityaction, __repr__=staticmethod(lambda item=idaapi.UI_Hooks:  'Actions currently being managed.'))

    def close(self):
        '''Disconnect all of the hook instances associated with this object.'''
        try: hasattr(self, 'hx')
        except Exception:
            logging.info(u"{:s} : Unable to close the \"{:s}\" hook type due to an exception raised while trying to access it.".format(__name__, 'hx'), exc_info=True)
        else: delattr(self, 'hx')

        # Disconnect the managed actions first.
        hasattr(self, 'action') and delattr(self, 'action')

        # Iterate through the other attributes and close those too.
        for phook in ['idp', 'idb', 'ui', 'hexrays']:
            if hasattr(self, phook):
                delattr(self, phook)
            continue

        # The very last one that gets closed is the "notification" attribute. Technically
        # there's no reason that one would need to close this, but our descriptor will
        # end up reinstantiating it if it ends up still being needed.
        delattr(self, 'notification')

    # Create a descriptor that maintains the scheduler that controls the enabling
    # and disabling of hooks depending on the current database state.
    scheduler = singleton_descriptor(lambda cons, *args: cons(*args), Scheduler, __repr__=staticmethod(lambda: 'Internal scheduler for managing hooks depending on database state.'))

# Now we just need to change the name of our class so that the documentation reads right.
module.__name__ = 'hook'
