"""
Internal module (hooks)

This is an internal module that contains implementations of all the hooks
that are used. Some of the things that are hooked are things such as
comment creation, function and segment scoping, etc. This is not intended
to be used by the average user.
"""

import six
import sys, logging
import functools, operator, itertools, types

import database, function, instruction, ui
import internal
from internal import comment, utils, interface, exceptions as E

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
    # while ignoring the hooks module because that it should really be internal.
    items = itertools.chain(*(items for name, items in loaders.items() if name is None))
    available = sorted(item for item in itertools.chain(*items) if item != 'hooks')

    # hide the internal module from our display.
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
        six.print_("The following modules are available and may also be imported:")
        [six.print_("    {:s}".format(submodule)) for submodule in submodules]
        six.print_("")

    useful_modules = [
        ('ida_hexrays', 'https://hex-rays.com/decompiler/', 'for a freaking decompiler'),
        ('networkx', 'https://pypi.org/project/networkx/', 'for a real graph api'),
        ('dill', 'https://pypi.org/project/dill/', 'to save (and load) your game'),
    ]

    results, find_loader = [], __import__('imp').find_module if sys.version_info.major < 3 else __import__('importlib').find_loader
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
    def is_ready(cls):
        '''This is just a utility method for determining if a database is ready or not.'''
        global State
        return State in {state.ready}

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
            logging.info(u"{:s}.init() : Removing {:d} incomplete states due to re-initialization of database.".format('.'.join([__name__, cls.__name__]), len(states)))
        cls.__states__ = {}

    @classmethod
    def new(cls, ea):
        '''This registers a new state for a given address that can later be fetched.'''
        states = cls.__states__

        # If we're being asked to recreate the state for an address that is still
        # incomplete, then warn the user about it. This will only happen when the
        # "changing" event is called for the same address more than once without
        # the "changed" event being used to complete it.
        if ea in states:
            res = states.pop(ea)
            logging.info(u"{:s}.new({:#x}) : Forcefully closing the state for address {:#x} by request.".format('.'.join([__name__, cls.__name__]), ea, ea))
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
        raise E.AddressNotFoundError(u"{:s}.resume({:#x}) : Unable to locate a currently available state for address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, ea))

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
        logging.debug(u"{:s}.update_refs({:#x}) : Updating old keys ({!s}) to new keys ({!s}){:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(oldkeys), utils.string.repr(newkeys), ' for runtime-linked function' if rt else ''))
        for key in oldkeys ^ newkeys:
            if key not in new:
                logging.debug(u"{:s}.update_refs({:#x}) : Decreasing reference count for {!s} at {:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
                if f and not rt: internal.comment.contents.dec(ea, key)
                else: internal.comment.globals.dec(ea, key)
            if key not in old:
                logging.debug(u"{:s}.update_refs({:#x}) : Increasing reference count for {!s} at {:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
                if f and not rt: internal.comment.contents.inc(ea, key)
                else: internal.comment.globals.inc(ea, key)
            continue
        return

    @classmethod
    def _create_refs(cls, ea, content):
        f, rt = cls.get_func_extern(ea)

        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.create_refs({:#x}) : Creating keys ({!s}){:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(contentkeys), ' for runtime-linked function' if rt else ''))
        for key in contentkeys:
            logging.debug(u"{:s}.create_refs({:#x}) : Increasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
            if f and not rt: internal.comment.contents.inc(ea, key)
            else: internal.comment.globals.inc(ea, key)
        return

    @classmethod
    def _delete_refs(cls, ea, content):
        f, rt = cls.get_func_extern(ea)

        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.delete_refs({:#x}) : Deleting keys ({!s}){:s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(contentkeys), ' from runtime-linked function' if rt else ''))
        for key in contentkeys:
            logging.debug(u"{:s}.delete_refs({:#x}) : Decreasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(key), 'address', ea))
            if f and not rt: internal.comment.contents.dec(ea, key)
            else: internal.comment.globals.dec(ea, key)
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
            logging.debug(u"{:s}.event() : Terminating state due to explicit request from owner while the {:s} comment at {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), 'repeatable' if rpt else 'non-repeatable', ea, utils.string.repr(old), utils.string.repr(new)))
            return

        # Now to fix the comment the user typed.
        if (newea, nrpt, none) == (ea, rpt, None):
            ncmt = utils.string.of(idaapi.get_cmt(ea, rpt))

            if (ncmt or '') != new:
                logging.warning(u"{:s}.event() : Comment from event at address {:#x} is different from database. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new), utils.string.repr(ncmt)))

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
                cls._delete_refs(ea, n)
            return

        # If the changed event doesn't happen in the right order.
        logging.fatal(u"{:s}.event() : Comment events are out of sync at address {:#x}, updating tags from previous comment. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o), utils.string.repr(n)))

        # Delete the old comment and its references.
        cls._delete_refs(ea, o)
        idaapi.set_cmt(ea, '', rpt)
        logging.warning(u"{:s}.event() : Deleted comment at address {:#x} was {!s}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o)))

        # Create the references for the new comment.
        new = utils.string.of(idaapi.get_cmt(newea, nrpt))
        n = internal.comment.decode(new)
        cls._create_refs(newea, n)

    @classmethod
    def changing(cls, ea, repeatable_cmt, newcmt):
        if not cls.is_ready():
            return logging.debug(u"{:s}.changing({:#x}, {:d}, {!s}) : Ignoring comment.changing event (database not ready) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, utils.string.repr(newcmt), 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.changing({:#x}, {:d}, {!s}) : Ignoring comment.changing event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, utils.string.repr(newcmt), 'repeatable' if repeatable_cmt else 'non-repeatable', ea))

        # Construct our new state, and then grab our old comment. This is because
        # we're going to submit this to the state that we've constructed after we've
        # disabled the necessary events.
        logging.debug(u"{:s}.changing({:#x}, {:d}, {!s}) : Received comment.changing event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, utils.string.repr(newcmt), 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.changed({:#x}, {:d}) : Ignoring comment.changed event (database not ready) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {:d}) : Ignoring comment.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))

        # Resume the state that was created by the changing event, and then grab
        # our new comment that we will later submit to it.
        logging.debug(u"{:s}.changed({:#x}, {:d}) : Received comment.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.old_changed({:#x}, {:d}) : Ignoring comment.changed event (database not ready) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.old_changed({:#x}, {:d}) : Ignoring comment.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))

        # first we'll grab our comment that the user updated
        logging.debug(u"{:s}.old_changed({:#x}, {:d}) : Received comment.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, repeatable_cmt, 'repeatable' if repeatable_cmt else 'non-repeatable', ea))
        cmt = utils.string.of(idaapi.get_cmt(ea, repeatable_cmt))
        fn, rt = cls.get_func_extern(ea)

        # if we're in a function but not a runtime-linked one, then we need to
        # to clear our contents here.
        if fn and not rt:
            internal.comment.contents.set_address(ea, 0)

        # otherwise, we can simply clear the tags globally
        else:
            internal.comment.globals.set_address(ea, 0)

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
                internal.comment.globals.dec(interface.range.start(fn), key)
            if key not in old:
                logging.debug(u"{:s}.update_refs({:#x}) : Increasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
                internal.comment.globals.inc(interface.range.start(fn), key)
            continue
        return

    @classmethod
    def _create_refs(cls, fn, content):
        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.create_refs({:#x}) : Creating keys ({!s}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(contentkeys)))
        for key in contentkeys:
            logging.debug(u"{:s}.create_refs({:#x}) : Increasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
            internal.comment.globals.inc(interface.range.start(fn), key)
        return

    @classmethod
    def _delete_refs(cls, fn, content):
        contentkeys = {item for item in content.keys()}
        logging.debug(u"{:s}.delete_refs({:#x}) : Deleting keys ({!s}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(contentkeys)))
        for key in contentkeys:
            logging.debug(u"{:s}.delete_refs({:#x}) : Decreasing reference count for {!s} at {:s} {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn) if fn else idaapi.BADADDR, utils.string.repr(key), 'function' if fn else 'global', interface.range.start(fn)))
            internal.comment.globals.dec(interface.range.start(fn), key)
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
            logging.debug(u"{:s}.event() : Terminating state due to explicit request from owner while the {:s} function comment at {:#x} was being changed from {!s} to {!s}.".format('.'.join([__name__, cls.__name__]), 'repeatable' if rpt else 'non-repeatable', ea, utils.string.repr(old), utils.string.repr(new)))
            return

        # Now we can fix the user's new comment.
        if (newea, nrpt, none) == (ea, rpt, None):
            ncmt = utils.string.of(idaapi.get_func_cmt(fn, rpt))

            if (ncmt or '') != new:
                logging.warning(u"{:s}.event() : Comment from event for function {:#x} is different from database. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new), utils.string.repr(ncmt)))

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
                cls._delete_refs(fn, n)
            return

        # If the changed event doesn't happen in the right order.
        logging.fatal(u"{:s}.event() : Comment events are out of sync for function {:#x}, updating tags from previous comment. Expected comment ({!s}) is different from current comment ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o), utils.string.repr(n)))

        # Delete the old function comment and its references.
        cls._delete_refs(fn, o)
        idaapi.set_func_cmt(fn, '', rpt)
        logging.warning(u"{:s}.event() : Deleted comment for function {:#x} was ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(o)))

        # Create the references for the new function comment.
        newfn = idaapi.get_func(newea)
        new = utils.string.of(idaapi.get_func_cmt(newfn, nrpt))
        n = internal.comment.decode(new)
        cls._create_refs(newfn, n)

    @classmethod
    def changing(cls, cb, a, cmt, repeatable):
        if not cls.is_ready():
            return logging.debug(u"{:s}.changing({!s}, {:#x}, {!s}, {:d}) : Ignoring comment.changing event (database not ready) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        if interface.node.is_identifier(interface.range.start(a)):
            return logging.debug(u"{:s}.changing({!s}, {:#x}, {!s}, {:d}) : Ignoring comment.changing event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))

        # First we'll check to see if this is an actual function comment by confirming
        # that we're in a function, and that our comment is not empty.
        logging.debug(u"{:s}.changing({!s}, {:#x}, {!s}, {:d}) : Received comment.changing event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.changed({!s}, {:#x}, {!s}, {:d}) : Ignoring comment.changed event (database not ready) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        if interface.node.is_identifier(interface.range.start(a)):
            return logging.debug(u"{:s}.changed({!s}, {:#x}, {!s}, {:d}) : Ignoring comment.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))

        # First we'll check to see if this is an actual function comment by confirming
        # that we're in a function, and that our comment is not empty.
        logging.debug(u"{:s}.changed({!s}, {:#x}, {!s}, {:d}) : Received comment.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.old_changed({!s}, {:#x}, {!s}, {:d}) : Ignoring comment.changed event (database not ready) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        if interface.node.is_identifier(interface.range.start(a)):
            return logging.debug(u"{:s}.old_changed({!s}, {:#x}, {!s}, {:d}) : Ignoring comment.changed event (not an address) for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))

        # first thing to do is to identify whether we're in a function or not,
        # so we first grab the address from the area_t...
        logging.debug(u"{:s}.old_changed({!s}, {:#x}, {!s}, {:d}) : Received comment.changed event for a {:s} comment at {:#x}.".format('.'.join([__name__, cls.__name__]), utils.string.repr(cb), interface.range.start(a), utils.string.repr(cmt), repeatable, 'repeatable' if repeatable else 'non-repeatable', interface.range.start(a)))
        ea = interface.range.start(a)

        # then we can use it to verify that we're in a function. if not, then
        # this is a false alarm and we can leave.
        fn = idaapi.get_func(ea)
        if fn is None:
            return

        # we're using an old version of ida here, so start out empty
        internal.comment.globals.set_address(ea, 0)

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
    @classmethod
    def updater(cls):
        # All typeinfo are global tags unless they're being applied to an
        # operand...which is never handled by this class.
        ctx = internal.comment.globals

        # Receive the changing_ti event...
        ea, original, expected = (yield)

        # First check if we need to remove the typeinfo that's stored at the
        # given address. Afterwards we can unpack our original values.
        if any(original):
            ctx.dec(ea, '__typeinfo__')
        old_type, old_fname = original

        # Wait until we get the ti_changed event...
        try:
            new_ea, tidata = (yield)

        # If we end up catching a GeneratorExit then that's because
        # this event is being violently closed due to receiving a
        # changing event more than once for the very same address.
        except GeneratorExit:
            logging.debug(u"{:s}.event() : Terminating state due to explicit request from owner while the type information at {:#x} was being changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ea, bytes().join(original), bytes().join(expected)))
            return

        # Verify that the typeinfo we're changing to is the exact same as given
        # to use by both events. If they're not the same, then we need to make
        # an assumption and that assumption is to take the values given to us
        # by the changing_ti event.
        if (ea, expected) != (new_ea, tidata):
            logging.warning(u"{:s}.event() : The {:s} event has a different address ({:#x} != {:#x}) and type information ({!r} != {!r}) than what was given by the {:s} event. Using the values from the {:s} event.".format('.'.join([__name__, cls.__name__]), 'ti_changed', ea, new_ea, bytes().join(expected), bytes().join(tidata), 'changing_ti', 'ti_changed'))
        elif ea != new_ea:
            logging.warning(u"{:s}.event() : The {:s} event has a different address ({:#x} != {:#x}) than what was given by the {:s} event. Using the address {:#x} from the {:s} event.".format('.'.join([__name__, cls.__name__]), 'changing_ti', ea, new_ea, 'ti_changed', ea, 'changing_ti'))
            new_ea = ea
        elif expected != tidata:
            logging.warning(u"{:s}.event() : The {:s} event for address {:#x} has different type information ({!r} != {!r}) than what was received by the {:s} event. Re-fetching the type information for the address at {:#x}.".format('.'.join([__name__, cls.__name__]), 'changing_ti', ea, bytes().join(expected), bytes().join(tidata), 'ti_changed', new_ea))
            tidata, _, _ = database.type(ea)

        # Okay, we now have the data that we need to compare in order to determine
        # if we're removing typeinfo, adding it, or updating it. Since we
        # already decremented the tag from the previous address, we really
        # only need to determine if we need to add its reference back.
        if any(tidata):
            ctx.inc(new_ea, '__typeinfo__')
            logging.debug(u"{:s}.event() : Updated the type information at address {:#x} and {:s} its reference ({!r} -> {!r}).".format('.'.join([__name__, cls.__name__]), new_ea, 'kept' if original == tidata else 'increased', bytes().join(original), bytes().join(tidata)))

        # For the sake of debugging, log that we just removed the typeinfo
        # from the current address. We don't need to decrease our reference
        # here because we did it already when we git our "changing" event.
        else:
            logging.debug(u"{:s}.event() : Removed the type information from address {:#x} and its reference ({!r} -> {!r}).".format('.'.join([__name__, cls.__name__]), new_ea, bytes().join(original), bytes().join(tidata)))
        return

    @classmethod
    def changing(cls, ea, new_type, new_fname):
        if not cls.is_ready():
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Ignoring typeinfo.changing event (database not ready) with new type ({!s}) and new name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname, ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Ignoring typeinfo.changing event (not an address) with new type ({!s}) and new name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except E.OutOfBoundsError:
            return logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Ignoring typeinfo.changing event (not a valid address) with new type ({!s}) and new name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname, ea))

        # Extract the previous type information from the given address. If none
        # was found, then just use empty strings because these are compared to the
        # new values by the event.
        logging.debug(u"{:s}.changing({:#x}, {!s}, {!s}) : Received typeinfo.changing for new_type ({!s}) and new_fname ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(new_type), utils.string.repr(new_fname), utils.string.repr(new_type), new_fname))

        ti = database.type(ea)
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.changed({:#x}, {!s}, {!s}) : Ignoring typeinfo.changed event (database not ready) with type ({!s}) and name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(type), utils.string.repr(fnames), utils.string.repr(type), fnames, ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {!s}, {!s}) : Ignoring typeinfo.changed event (not an address) with type ({!s}) and name ({!s}) at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(type), utils.string.repr(fnames), utils.string.repr(type), fnames, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except E.OutOfBoundsError:
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
class state(object):
    '''database notification state'''
    init = type('init', (object,), {})()
    loaded = type('loaded', (object,), {})()
    ready = type('ready', (object,), {})()

State = None

def on_close():
    '''IDB_Hooks.closebase'''

    # Database was closed, so we need to reset our state.
    global State
    if state:
        logging.debug(u"{:s}.on_close() : Received unexpected state transition from state ({!s}).".format(__name__, utils.string.repr(State)))
    State = None

def on_init(idp_modname):
    '''IDP_Hooks.init'''

    # Database has just been opened, setup the initial state.
    global State
    if State == None:
        State = state.init
    else:
        logging.debug(u"{:s}.on_init({!s}) : Received unexpected state transition from state ({!s}).".format(__name__, utils.string.repr(idp_modname), utils.string.repr(State)))

def nw_on_init(nw_code, is_old_database):
    idp_modname = idaapi.get_idp_name()
    return on_init(idp_modname)

def on_newfile(fname):
    '''IDP_Hooks.newfile'''

    # Database has been created, switch the state to loaded.
    global State
    if State == state.init:
        State = state.loaded
    else:
        logging.debug(u"{:s}.on_newfile({!s}) : Received unexpected state transition from state ({!s}).".format(__name__, utils.string.repr(fname), utils.string.repr(State)))

    # FIXME: save current state like base addresses and such
    __execute_rcfile()

def nw_on_newfile(nw_code, is_old_database):
    if is_old_database:
        return
    fname = idaapi.cvar.database_idb
    return on_newfile(fname)

def on_oldfile(fname):
    '''IDP_Hooks.oldfile'''

    # Database has been loaded, switch the state to ready.
    global State
    if State == state.init:
        State = state.ready

        __check_functions()
    else:
        logging.debug(u"{:s}.on_oldfile({!s}) : Received unexpected state transition from state ({!s}).".format(__name__, utils.string.repr(fname), utils.string.repr(State)))

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
    global State

    # Queues have just been emptied, so now we can transition
    if State == state.loaded:
        State = state.ready

        # update tagcache using function state
        __process_functions()

    elif State == state.ready:
        logging.debug(u"{:s}.on_ready() : Database is already ready ({!s}).".format(__name__, utils.string.repr(State)))

    else:
        logging.debug(u"{:s}.on_ready() : Received unexpected transition from state ({!s}).".format(__name__, utils.string.repr(State)))

def auto_queue_empty(type):
    """This waits for the analysis queue to be empty.

    If the database is ready to be tampered with, then we proceed by executing
    the `on_ready` function which will perform any tasks required to be done
    on the database at startup.
    """
    if type == idaapi.AU_FINAL:
        on_ready()

def __process_functions(percentage=0.10):
    """This prebuilds the tag cache and index for the entire database so that we can differentiate tags made by the user and the application.

    It's intended to be called once the database is ready to be tampered with.
    """
    implicit = {'__typeinfo__', '__name__'}
    P, globals = ui.Progress(), {ea : count for ea, count in internal.comment.globals.iterate()}

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
        chunks = [item for item in function.chunks(fn)]

        # Check to see if the progress bar was cancelled for "some reason". If
        # so, we double-check if that's what the user really wanted.
        if P.canceled:
            six.print_(u"User opted to cancel building the tag cache at function {:#x} ({:d} of {:d}) after having indexed {:d} tag{:s}.".format(fn, 1 + i, len(funcs), total, '' if total == 1 else 's'))

            # Confirm with the user that they really don't care for indexing.
            message = []
            start, stop = database.config.bounds()
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
        if fn not in globals and function.tag(fn):
            [ internal.comment.globals.inc(fn, k) for k in implicit if k in function.tag(fn) ]

        # Grab the currently existing cache for the current function, and use
        # it to tally up all of the reference counts for the tags.
        contents = {item for item in internal.comment.contents.address(fn, target=fn)}
        for ci, (l, r) in enumerate(chunks):
            P.update(text=text(chunks=len(chunks), plural='' if len(chunks) == 1 else 's'), tooltip="Chunk #{:d} : {:#x} - {:#x}".format(ci, l, r))

            # Iterate through each address in the function, only updating the
            # references for tags that are not in our set of implicit ones.
            for ea in database.address.iterate(ui.navigation.analyze(l), r):
                available = {k for k in database.tag(ea)}
                for k in available - implicit:
                    if ea in globals: internal.comment.globals.dec(ea, k)
                    if ea not in contents: internal.comment.contents.inc(ea, k, target=fn)
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
    path = database.config.path(filename)

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
    functions, globals = map(utils.fcompose(sorted, list), [database.functions(), internal.comment.globals.iterate()])

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
            name = database.name(info[si].to + offset)
            text = u"Relocating function {:d} of {:d}{:s}: {:#x} -> {:#x}".format(1 + i, len(listable), " ({:s})".format(name) if name else '', info[si]._from + offset, info[si].to + offset)
            P.update(value=sum([fcount, gcount, i]), text=text)
            ui.navigation.procedure(info[si].to + offset)
        fcount += len(listable)

        # Iterate through all of the globals that were moved.
        listable = [(ea, count) for ea, count in globals if info[si]._from <= ea < info[si]._from + info[si].size]
        for i, offset in __relocate_globals(info[si]._from, info[si].to, info[si].size, (item for item in listable)):
            name = database.name(info[si].to + offset)
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
    key = internal.comment.tagging.__address__
    failure, total, index = [], [item for item in iterable], {ea : keys for ea, keys in internal.comment.contents.iterate() if old <= ea < old + size}

    for i, fn in enumerate(total):
        offset = fn - new
        source, target = offset + old, offset + new

        # Grab the contents tags from the former function's netnode. If the netnode has
        # already been moved, then use the function we were given. Otherwise we can just
        # use the old offset.
        try:
            state = internal.comment.contents._read(target if moved else source, offset + old)

        except E.FunctionNotFoundError:
            logging.fatal(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Unable to locate the original function address ({:#x}) while trying to transform to {:#x}.".format(__name__, old, new, size, iterable, offset + old, offset + new), exc_info=True)
            state = None

        # If there was no read state then there's nothing to do. So we just
        # continue to the next iteration (without yielding) for performance.
        if state is None:
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Skipping contents of function {:#x} due to no state being stored at {:#x}.".format(__name__, old, new, size, iterable, fn, fn if moved else (offset + old)))
            continue

        # Erase the old contents tags since we've already loaded its state.
        internal.comment.contents._write(source, offset + old, None)
        logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cleared contents of function {:#x} at old address {:#x}.".format(__name__, old, new, size, iterable, fn, offset + old))

        # If there wasn't a value in our contents index, then warn the user
        # before we remove it. We use this later to figure out any strays.
        if not operator.contains(index, source):
            logging.warning(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Found contents for function {:#x} at old address {:#x} that wasn't in index.".format(__name__, old, new, size, iterable, fn, source))
        index.pop(source, None)

        # Ensure that the function key is available in the loaded state.
        if key not in state:
            state.setdefault(key, {})
            # FIXME: We should completely rebuild the contents here instead of
            #        logging a warning and initializing it with an empty dict.
            logging.warning(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Missing address cache while translating address {:#x} -> {:#x}.".format(__name__, old, new, size, iterable, offset + old, offset + new))

        # Update the state containing the old addresses with the newly transformed ones.
        res, state[key] = state[key], {ea - old + new : ref for ea, ref in state[key].items()}

        # And then we can write the modified state back to the function's netnode.
        ok = internal.comment.contents._write(fn, fn, state)
        if not ok:
            logging.fatal(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Failure trying to write reference count for function {:#x} while trying to update old reference count ({!s}) to new one ({!s}).".format(__name__, old, new, size, iterable, fn, utils.string.repr(res), utils.string.repr(state[key])))
            failure.append((fn, res, state[key]))

        # We successfully processed this function, so yield its index and offset.
        logging.debug(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Relocated {:d} content locations for function {:#x} using delta {:+#x}.".format(__name__, old, new, size, iterable, len(state[key]), fn, new - old))
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
        internal.comment.contents._write(source, offset + old, None)
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
            owners = [item for item in function.chunk.owners(target)]
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cache at {:#x} should've been relocated to {:#x} but is a tail associated with more than one function ({:s}).".format(__name__, old, new, size, iterable, ea, target, ', '.join(map("{:#x}".format, owners))))
        else:
            logging.info(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cache at {:#x} should've been relocated to {:#x} but its boundaries ({:#x}<>{:#x}) do not correspond with a function ({:#x}).".format(__name__, old, new, size, iterable, ea, target, interface.range.start(ch), interface.range.end(ch), interface.range.start(fn)))

        # Now we know why this address is within our index, so all that
        # we really need to do is to remove it.
        internal.comment.contents._write(ea, ea, None)
        logging.debug(u"{:s}.relocate_function({:#x}, {:#x}, {:+#x}, {!r}) : Cleared stray contents for {:#x} at old address {:#x}.".format(__name__, old, new, size, iterable, offset + new, offset + old))
    return

def __relocate_globals(old, new, size, iterable):
    '''Relocate the global tuples (address, count) in `iterable` from address `old` to `new` adjusting them by the specified `size`.'''
    node = internal.comment.tagging.node()
    failure, total = [], [item for item in iterable]
    for i, (ea, count) in enumerate(total):
        offset = ea - old

        # Remove the old address from the netnode cache (altval) with our global.
        ok = internal.netnode.alt.remove(node, ea)
        if not ok:
            logging.fatal(u"{:s}.relocate_globals({:#x}, {:#x}, {:+#x}, {!r}) : Failure trying to remove reference count ({!r}) for global {:#x}.".format(__name__, old, new, size, iterable, count, ea))

        # Now we can re-add the new address to the netnode cache (altval).
        ok = internal.netnode.alt.set(node, new + offset, count)
        if not ok:
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
    globals = sorted((ea, count) for ea, count in internal.comment.globals.iterate() if source <= ea < source + size)
    logging.info(u"{:s}.segm_moved({:#x}, {:#x}, {:+#x}) : Relocating tagcache for segment {:s}.".format(__name__, source, destination, size, get_segment_name(seg)))
    count = sum(map(len, [functions, globals]))

    # Create our progress bar that includes a title describing what's going on and
    # output it to the console so the user can see it.
    P, msg = ui.Progress(), u"Relocating tagcache for segment {:s}: {:#x} ({:+#x}) -> {:#x}".format(get_segment_name(seg), source, size, destination)
    P.update(current=0, min=0, max=count, title=msg), six.print_(msg)
    P.open()

    # Iterate through each function that we're moving and relocate its contents.
    for i, offset in __relocate_function(source, destination, size, (item for item in functions), moved=not changed_netmap):
        name = database.name(destination + offset)
        text = u"Relocating function {:d} of {:d}{:s}: {:#x} -> {:#x}".format(1 + i, len(functions), " ({:s})".format(name) if name else '', source + offset, destination + offset)
        P.update(value=i, text=text)
        ui.navigation.procedure(destination + offset)

    # Iterate through each global that we're moving (we use the target address, because IDA moved everything already).
    for i, offset in __relocate_globals(source, destination, size, (item for item in globals)):
        name = database.name(destination + offset)
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
            logging.debug(u"{:s}.event() : Terminating state due to explicit request from owner while the name at {:#x} was being changed from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ea, original, expected))
            return

        # And then we double-check that everything matches. If expected is
        # cleared, but new_name holds some value then it's likely because
        # IDA chose some automatic name and so we have to make an assumption.
        if (ea, expected) != (new_ea, expected and new_name):
            prefix = expected.split('_', 1)

            # If the prefix is in one of our known names, then demote the loglevel.
            Flogging = logging.info if prefix[0] in {'sub', 'byte', 'loc'} else logging.fatal
            Flogging(u"{:s}.event() : Rename is at address {:#x} has desynchronized. Target address at {:#x} should have been renamed from {!r} to {!r} but {!r} was received instead.".format('.'.join([__name__, cls.__name__]), ea, new_ea, original, expected, new_name))
            return

        # Now we use the address to figure out which context that we'll
        # need to update. If we're not in a function or the address is an
        # external segment, then we're in the global context.
        fn = idaapi.get_func(ea)
        if fn is None or idaapi.segtype(ea) in {idaapi.SEG_XTRN}:
            if local_name and fn is None:
                logging.warning(u"{:s}.event() : Received rename for address {:#x} where \"{:s}\" is set ({!s}) but the address is not within a function.".format('.'.join([__name__, cls.__name__]), ea, 'local_name', local_name))
            context, target = internal.comment.globals, None

        # If we're renaming the beginning of a function, then we're also
        # in the global context unless it's considered a "local_name".
        elif interface.range.start(fn) == ea and not local_name:
            context, target = internal.comment.globals, None

        # Otherwise, we're inside a function and we should be good.
        else:
            context, target = internal.comment.contents, interface.range.start(fn)

        # Next thing to do is to verify whether we're adding a new name,
        # removing one, or adding one. If the names are the same, then skip.
        if expected == original:
            pass

        # If our new_name is cleared, then we're removing it.
        elif not expected:
            context.dec(new_ea, '__name__') if target is None else context.dec(new_ea, '__name__', target=target)
            logging.info(u"{:s}.event() : Decremented {:s} reference for rename at {:#x} from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), 'global' if target is None else 'content', ea, original, expected))

        # If our previous name nonexistent, or is a label (and not custom) then we add the reference.
        elif not original or (labelQ and not customQ):
            context.inc(new_ea, '__name__') if target is None else context.inc(new_ea, '__name__', target=target)
            logging.info(u"{:s}.event() : Incremented {:s} reference for rename at {:#x} from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), 'global' if target is None else 'content', ea, original, expected))

        # If it was both a label and it was custom, then log a warning because we have no idea.
        elif labelQ and customQ:
            logging.debug(u"{:s}.event() : Ignoring existing symbol rename ({:s}) received as a {:s} reference for at {:#x} from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ', '.join(itertools.chain(['FF_LABL'] if labelQ else [], ['FF_NAME'] if customQ else [])), 'global' if target is None else 'content', ea, original, expected))

        # Debug log showing that we didn't have to do anything.
        else:
            logging.debug(u"{:s}.event() : Skipping rename at {:#x} from {!r} to {!r}.".format('.'.join([__name__, cls.__name__]), ea, original, expected))
        return

    @classmethod
    def changing(cls, ea, new_name):
        if not cls.is_ready():
            return logging.debug(u"{:s}.changing({:#x}, {!r}) : Ignoring naming.changing event (database not ready) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, ea))
        if interface.node.is_identifier(ea):
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.changed({:#x}, {!r}, {!s}) : Ignoring naming.changed event (database not ready) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, local_name, ea))
        if interface.node.is_identifier(ea):
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
    def rename(cls, ea, newname):
        """This hook is when a user adds a name or removes it from the database.

        We simply increase the reference count for the "__name__" key, or decrease it
        if the name is being removed.
        """
        if not cls.is_ready():
            return logging.debug(u"{:s}.rename({:#x}, {!r}) : Ignoring rename event (database not ready) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.rename({:#x}, {!r}) : Ignoring rename event (not an address) for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, new_name, ea))

        fl = idaapi.getFlags(ea) if idaapi.__version__ < 7.0 else idaapi.get_full_flags(ea)
        labelQ, customQ = (fl & item == item for item in [idaapi.FF_LABL, idaapi.FF_NAME])
        fn = idaapi.get_func(ea)

        # figure out whether a global or function name is being changed, otherwise it's the function's contents
        ctx = internal.comment.globals if not fn or (interface.range.start(fn) == ea) else internal.comment.contents

        # if a name is being removed
        if not newname:
            # if it's a custom name
            if (not labelQ and customQ):
                ctx.dec(ea, '__name__')
                logging.debug(u"{:s}.rename({:#x}, {!r}) : Decreasing reference count for tag {!r} at address due to an empty name.".format('.'.join([__name__, cls.__name__]), ea, newname, '__name__'))
            return

        # if it's currently a label or is unnamed
        if (labelQ and not customQ) or all(not q for q in {labelQ, customQ}):
            ctx.inc(ea, '__name__')
            logging.debug(u"{:s}.rename({:#x}, {!r}) : Increasing reference count for tag {!r} at address due to a new name.".format('.'.join([__name__, cls.__name__]), ea, newname, '__name__'))
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
        if not cls.is_ready():
            return logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Ignoring extra_cmt.changed event (database not ready) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Ignoring extra_cmt.changed event (not an address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except E.OutOfBoundsError:
            return logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Ignoring comment.changed event (not a valid address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Determine whether we'll be updating the contents or a global.
        logging.debug(u"{:s}.changed({:#x}, {:d}, {!r}) : Processing event at address {:#x} for index {:d}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, utils.string.repr(cmt), ea, line_idx))
        ctx = internal.comment.contents if idaapi.get_func(ea) else internal.comment.globals

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
            return ctx.dec(ea, tag)

        # XXX: If an "extra" comment is updated more than once, then we unfortunately
        #      lose track of the reference and it's permanently cached. There's nothing
        #      we can really do here except for keep a complete state of all of the
        #      extra comments that the user has created.
        return ctx.inc(ea, tag)

    @classmethod
    def changed_multiple(cls, ea, line_idx, cmt):
        """
        This implementation is deprecated, but is being preserved as the logic that
        it uses can be reused if the workaround methodology of zero'ing the refcount
        for the entire address is applied.
        """

        # First check that we're not an identifier, because we don't care about
        # caching these.
        if interface.node.is_identifier(ea):
            return logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}) : Ignoring comment.changed event (not an address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

        # Verify that the address is within our database boundaries because IDA
        # can actually create "extra" comments outside of the database.
        try:
            ea = interface.address.within(ea)
        except E.OutOfBoundsError:
            return logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}) : Ignoring comment.changed event (not a valid address) for extra comment at index {:d} for {:#x}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, line_idx, ea))

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
        ctx = internal.comment.contents if idaapi.get_func(ea) else internal.comment.globals

        MAX_ITEM_LINES = (idaapi.E_NEXT - idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV - idaapi.E_NEXT
        prefix = (idaapi.E_PREV, idaapi.E_PREV + MAX_ITEM_LINES, '__extra_prefix__')
        suffix = (idaapi.E_NEXT, idaapi.E_NEXT + MAX_ITEM_LINES, '__extra_suffix__')

        for l, r, key in [prefix, suffix]:
            if l <= line_idx < r:
                if oldcmt is None and cmt is not None: ctx.inc(ea, key)
                elif oldcmt is not None and cmt is None: ctx.dec(ea, key)
                logging.debug(u"{:s}.changed_multiple({:#x}, {:d}, {!r}, oldcmt={!r}) : {:s} reference count at address for tag {!r}.".format('.'.join([__name__, cls.__name__]), ea, line_idx, cmt, oldcmt, 'Increasing' if oldcmt is None and cmt is not None else 'Decreasing' if oldcmt is not None and cmt is None else 'Doing nothing to', key))
            continue
        return

### individual tags
def item_color_changed(ea, color):
    '''This hook is for when a color is applied to an address.'''

    # First make sure it's not an identifier, as if it is then we
    # need to terminate early because the tag cache doesn't care
    # about this stuff.
    if interface.node.is_identifier(ea):
        return

    # Now we need to distinguish between a content or global tag so
    # that we can look it up to see if we need to remove it or add it.
    ctx = internal.comment.contents if idaapi.get_func(ea) else internal.comment.globals

    # FIXME: we need to figure out if the color is being changed,
    #        updated, or removed. since there's no way to determine
    #        this accurately, we just assume that any color is going
    #        to increase the reference count.

    # If the color was restored, then we need to decrease its ref.
    if color in {idaapi.COLOR_DEFAULT}:
        ctx.dec(ea, '__color__')

    # The color is being applied, so we can just increase its reference.
    else:
        ctx.inc(ea, '__color__')
    return

### function scope
def thunk_func_created(pfn):
    pass

def func_tail_appended(pfn, tail):
    """This hook is for when a chunk is appended to a function.

    If the tail we were given only has one owner, then that means we need to
    demote the tags for the tail from globals to contents tags. If there's more
    than one, then we simply add the references in the tail to the function.
    """
    bounds = interface.range.bounds(tail)
    referrers = [fn for fn in function.chunk.owners(bounds.left)]

    # If the number of referrers is larger than just 1, then the tail is
    # owned by more than one function. We still doublecheck, though, to
    # ensure that our pfn is still in the list.
    if len(referrers) > 1:
        if not operator.contains(referrers, interface.range.start(pfn)):
            logging.warning(u"{:s}.func_tail_appended({:#x}, {!s}) : Adjusting contents of function ({:#x}) but function was not found in the owners ({:s}) of chunk {!s}.".format(__name__, interface.range.start(pfn), bounds, interface.range.start(pfn), ', '.join(map("{:#x}".format, referrers)), bounds))

        # Now we just need to iterate through the tail, and tally up
        # the tags for the function in pfn.
        for ea in database.address.iterate(bounds):
            for k in database.tag(ea):
                internal.comment.contents.inc(ea, k, target=interface.range.start(pfn))
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
    for ea in database.address.iterate(bounds):
        for k in database.tag(ea):
            internal.comment.globals.dec(ea, k)
            internal.comment.contents.inc(ea, k, target=interface.range.start(pfn))
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
        iterable = database.address.iterate(bounds)

    # If the address is out of bounds, then IDA removed this tail completely from
    # the database and we need to manually delete the tail's contents. Since we
    # can't trust anything, we use the entire contents index filtered by bounds.
    except E.OutOfBoundsError:
        iterable = (ea for ea, _ in internal.comment.contents.iterate() if bounds.contains(ea))

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
            for k in database.tag(ea):
                internal.comment.contents.dec(ea, k, target=interface.range.start(pfn))
                logging.debug(u"{:s}.removing_func_tail({:#x}, {!s}) : Decreasing reference for tag ({:s}) at {:#x} in cache for function {:#x}.".format(__name__, interface.range.start(pfn), bounds, utils.string.repr(k), ea, interface.range.start(pfn)))
            continue
        return

    # Otherwise, there's just one referrer and it should be pointing to pfn.
    if not operator.contains(referrers, interface.range.start(pfn)):
        logging.warning(u"{:s}.removing_func_tail({:#x}, {!s}) : Promoting contents for function ({:#x}) but function was not found in the owners ({:s}) of chunk {!s}.".format(__name__, interface.range.start(pfn), bounds, interface.range.start(pfn), ', '.join(map("{:#x}".format, referrers)), bounds))

    # If there's just one referrer, then the referrer should be pfn and we should
    # be promoting the relevant addresses in the cache from contents to globals.
    for ea in iterable:
        for k in database.tag(ea):
            internal.comment.contents.dec(ea, k, target=interface.range.start(pfn))
            internal.comment.globals.inc(ea, k)
            logging.debug(u"{:s}.removing_func_tail({:#x}, {!s}) : Exchanging (increasing) reference count for global tag ({:s}) at {:#x} and (decreasing) reference count for contents tag in the cache for function {:#x}.".format(__name__, interface.range.start(pfn), bounds, utils.string.repr(k), ea, interface.range.start(pfn)))
        continue
    return

def func_tail_removed(pfn, ea):
    """This hook is for when a chunk is removed from a function in older versions of IDA.

    We simply iterate through the old chunk, decrease all of its tags in the
    function context, and increase their reference within the global context.
    """

    # first we'll grab the addresses from our refs
    listable = internal.comment.contents.address(ea, target=interface.range.start(pfn))

    # these should already be sorted, so our first step is to filter out what
    # doesn't belong. in order to work around one of the issues posed in the
    # issue arizvisa/ida-minsc#61, we need to explicitly check that each item is
    # not None prior to their comparison against `pfn`. this is needed in order
    # to work around a null-pointer exception raised by SWIG when it calls the
    # area_t.__ne__ method to do the comparison.
    missing = [ item for item in listable if not idaapi.get_func(item) or idaapi.get_func(item) != pfn ]

    # if there was nothing found, then we can simply exit the hook early
    if not missing:
        return

    # now iterate through the min/max of the list as hopefully this is
    # our event.
    for ea in database.address.iterate(min(missing), max(missing)):
        for k in database.tag(ea):
            internal.comment.contents.dec(ea, k, target=interface.range.start(pfn))
            internal.comment.globals.inc(ea, k)
            logging.debug(u"{:s}.func_tail_removed({:#x}, {:#x}) : Exchanging (increasing) reference count for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), ea, utils.string.repr(k), utils.string.repr(k)))
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
    for ea in database.address.iterate(interface.range.bounds(tail)):
        for k in database.tag(ea):
            internal.comment.contents.dec(ea, k)
            internal.comment.contents.inc(ea, k, target=owner_func)
            logging.debug(u"{:s}.tail_owner_changed({:#x}, {:#x}) : Exchanging (increasing) reference count for contents tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(tail), owner_func, utils.string.repr(k), utils.string.repr(k)))
        continue
    return

def add_func(pfn):
    """This is called when a new function is created.

    When a new function is created, its entire area needs its tags transformed
    from global tags to function tags. This iterates through each chunk belonging
    to the function and does exactly that.
    """
    implicit = {'__typeinfo__', '__name__'}

    # figure out the newly added function's address, and gather all the imports.
    ea, imports = interface.range.start(pfn), {item for item in []}
    for idx in range(idaapi.get_import_module_qty()):
        idaapi.enum_import_names(idx, lambda address, name, ordinal: imports.add(address) or True)

    # check that we're not adding an import as a function. if this happens,
    # then this is because IDA's ELF loader seems to be loading this.
    if idaapi.segtype(ea) == idaapi.SEG_XTRN or ea in imports:
        return

    # if the database is ready then we can trust the changingchanged-based classes
    # to add all the implicit tags and thus we can exclude them here. otherwise,
    # we'll do it ourselves because the functions get post-processed after building
    # in order to deal with the events that we didn't receive.
    exclude = implicit if changingchanged.is_ready() else {item for item in []}
    available = {k for k in function.tag(ea)}
    [ internal.comment.globals.inc(ea, k) for k in available - exclude ]

    # convert all globals into contents whilst making sure that we don't
    # add any of the implicit tags that are handled by other events.
    for l, r in function.chunks(ea):
        for ea in database.address.iterate(l, r):
            available = {item for item in database.tag(ea)}
            for k in available - implicit:
                internal.comment.globals.dec(ea, k)
                internal.comment.contents.inc(ea, k, target=interface.range.start(pfn))
                logging.debug(u"{:s}.add_func({:#x}) : Exchanging (decreasing) reference count for global tag {!s} and (increasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), utils.string.repr(k), utils.string.repr(k)))
            continue
        continue
    return

def remove_contents(fn, iterable):
    '''This is just a utility that manually removes the contents from a function using an iterator of addresses.'''
    func, results = interface.range.start(fn), {}

    # Iterate through each address we were given and decode the contents tags directly
    # using IDAPython, since none of these addresses are accessible via our api.
    for index, ea in enumerate(iterable):
        items = idaapi.get_cmt(ea, True), idaapi.get_cmt(ea, False)
        repeatable, nonrepeatable = (internal.comment.decode(item) for item in items)

        logging.debug(u"{:s}.remove_contents({:#x}) : Removing both repeatable references ({:d}) and non-repeatable references ({:d}) from {:s} ({:#x}).".format(__name__, func, len(repeatable), len(nonrepeatable), 'contents', ea))

        # After decoding it, we can now decrease their refcount and remove them.
        [ internal.comment.contents.dec(ea, k, target=func) for k in repeatable ]
        [ internal.comment.contents.dec(ea, k, target=func) for k in nonrepeatable ]

        # Update our results with the keys at whatever address we just removed.
        [ results.setdefault(k, []).append(ea) for k in itertools.chain(repeatable, nonrepeatable) ]

        # Now we need to do a couple of the implicit tags which means we need to
        # check the name, type information, and color.
        if idaapi.get_item_color(ea) == idaapi.COLOR_DEFAULT:
            internal.comment.contents.dec(ea, '__color__', target=func)
        if database.extra.__get_prefix__(ea) is not None:
            internal.comment.contents.dec(ea, '__extra_prefix__', target=func)
        if database.extra.__get_suffix__(ea) is not None:
            internal.comment.contents.dec(ea, '__extra_suffix__', target=func)

        get_flags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        if get_flags(ea) & idaapi.FF_NAME:
            internal.comment.contents.dec(ea, '__name__', target=func)
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

    try:
        rt, fn = interface.addressOfRuntimeOrStatic(pfn)

    # If IDA told us a function was there, but it actually isn't, then this
    # function was completely removed out from underneath us.
    except E.FunctionNotFoundError:
        exc_info = sys.exc_info()

        # We sanity check what we're being told by checking if it's outside
        # the bounds of the db. If it isn't, then reraise the exception.
        bounds = interface.range.bounds(pfn)
        if any(map(database.within, bounds)):
            six.reraise(*exc_info)

        # Okay, so our function bounds are not within the database whatsoever but
        # we know which function it's in and we know it's boundaries. So at the
        # very least we can manually remove its contents from our storage.
        fn, _ = bounds
        iterable = (ea for ea in internal.comment.contents.address(fn, target=fn) if bounds.contains(ea))

        results = remove_contents(pfn, iterable)
        for tag, items in results.items():
            logging.debug(u"{:s}.del_func({:#x}) : Removed {:d} instances of tag ({:s}) that were associated with a removed function.".format(__name__, interface.range.start(pfn), len(items), utils.string.repr(tag)))

        # Now we need to remove the global tags associated with this function.
        items = idaapi.get_func_cmt(pfn, True), idaapi.get_func_cmt(pfn, False)
        repeatable, nonrepeatable = (internal.comment.decode(item) for item in items)

        logging.debug(u"{:s}.del_func({:#x}) : Removing both repeatable references ({:d}) and non-repeatable references ({:d}) from {:s} ({:#x}).".format(__name__, interface.range.start(pfn), len(repeatable), len(nonrepeatable), 'globals', fn))

        # After decoding them, we can try to decrease our reference count.
        [ internal.comment.globals.dec(fn, k) for k in repeatable ]
        [ internal.comment.globals.dec(fn, k) for k in nonrepeatable ]

        # We also need to handle any implicit tags as well to be properly done.
        if pfn.color == idaapi.COLOR_DEFAULT:
            internal.comment.globals.dec(fn, '__color__')

        get_flags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        if get_flags(fn) & idaapi.FF_NAME:
            internal.comment.globals.dec(fn, '__name__')

        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        if get_tinfo(idaapi.tinfo_t(), fn):
            internal.comment.globals.dec(fn, '__typeinfo__')
        return

    # convert all contents into globals
    for ea in internal.comment.contents.address(fn, target=fn):
        for k in database.tag(ea):
            internal.comment.contents.dec(ea, k, target=fn)
            internal.comment.globals.inc(ea, k)
            logging.debug(u"{:s}.del_func({:#x}) : Exchanging (increasing) reference count for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), utils.string.repr(k), utils.string.repr(k)))
        continue

    # remove all function tags depending on whether our address
    # is part of a function, runtime-linked, or neither.
    Ftags = database.tag if rt else function.tag
    for k in Ftags(fn):
        internal.comment.globals.dec(fn, k)
        logging.debug(u"{:s}.del_func({:#x}) : Removing (global) tag {!s} from function.".format(__name__, fn, utils.string.repr(k)))
    return

def set_func_start(pfn, new_start):
    """This is called when the user changes the beginning of the function to another address.

    If this happens, we simply walk from the new address to the old address of
    the function that was changed. Then we can update the reference count for
    any globals that were tagged by moving them into the function's tagcache.
    """

    # if new_start has removed addresses from function, then we need to transform
    # all contents tags into globals tags
    if interface.range.start(pfn) > new_start:
        for ea in database.address.iterate(new_start, interface.range.start(pfn)):
            for k in database.tag(ea):
                internal.comment.contents.dec(ea, k, target=interface.range.start(pfn))
                internal.comment.globals.inc(ea, k)
                logging.debug(u"{:s}.set_func_start({:#x}, {:#x}) : Exchanging (increasing) reference count for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), new_start, utils.string.repr(k), utils.string.repr(k)))
            continue
        return

    # if new_start has added addresses to function, then we need to transform all
    # its global tags into contents tags
    elif interface.range.start(pfn) < new_start:
        for ea in database.address.iterate(interface.range.start(pfn), new_start):
            for k in database.tag(ea):
                internal.comment.globals.dec(ea, k)
                internal.comment.contents.inc(ea, k, target=interface.range.start(pfn))
                logging.debug(u"{:s}.set_func_start({:#x}, {:#x}) : Exchanging (decreasing) reference count for global tag {!s} and (increasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), new_start, utils.string.repr(k), utils.string.repr(k)))
            continue
        return
    return

def set_func_end(pfn, new_end):
    """This is called when the user changes the ending of the function to another address.

    If this happens, we simply walk from the old end of the function to the new
    end of the function that was changed. Then we can update the reference count
    for any globals that were tagged by moving them into the function's tagcache.
    """

    # if new_end has added addresses to function, then we need to transform
    # all globals tags into contents tags
    if new_end > interface.range.end(pfn):
        for ea in database.address.iterate(interface.range.end(pfn), new_end):
            for k in database.tag(ea):
                internal.comment.globals.dec(ea, k)
                internal.comment.contents.inc(ea, k, target=interface.range.start(pfn))
                logging.debug(u"{:s}.set_func_end({:#x}, {:#x}) : Exchanging (decreasing) reference count for global tag {!s} and (increasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), new_end, utils.string.repr(k), utils.string.repr(k)))
            continue
        return

    # if new_end has removed addresses from function, then we need to transform
    # all contents tags into globals tags
    elif new_end < interface.range.end(pfn):
        for ea in database.address.iterate(new_end, interface.range.end(pfn)):
            for k in database.tag(ea):
                internal.comment.contents.dec(ea, k, target=interface.range.start(pfn))
                internal.comment.globals.inc(ea, k)
                logging.debug(u"{:s}.set_func_end({:#x}, {:#x}) : Exchanging (increasing) reference count for global tag {!s} and (decreasing) reference count for contents tag {!s}.".format(__name__, interface.range.start(pfn), new_end, utils.string.repr(k), utils.string.repr(k)))
            continue
        return
    return

class supermethods(object):
    """
    Define all of the functions that will be used as supermethods for
    the situation when the original hook supermethod does not take the
    same parameters as listed in IDAPython's documentation. This is
    used when setting up the hooks via the priorityhook class during
    the initialization of them by the ui.hook namepsace.
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

        # Populate the dictionary with each of the supermethods that need
        # to be patched for the IDB_Hooks class by checking the version
        # in order to determine whether it should be assigned or not.
        idaapi.__version__ >= 7.6 and mapping.setdefault('compiler_changed', compiler_changed)
        idaapi.__version__ >= 7.6 and mapping.setdefault('renamed', renamed)
        idaapi.__version__ >= 7.6 and mapping.setdefault('bookmark_changed', bookmark_changed)
        idaapi.__version__ >= 7.7 and mapping.setdefault('segm_deleted', segm_deleted)

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

def make_ida_not_suck_cocks(nw_code):
    '''Start hooking all of IDA's API.'''

    ## initialize the priorityhook api for all three of IDA's interfaces
    ui.hook.__start_ida__()

    ## setup default integer types for the typemapper once the loader figures everything out
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_newprc', interface.typemap.__ev_newprc__, 0)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idp.add('newprc', interface.typemap.__newprc__, 0)

    else:
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, interface.typemap.__nw_newprc__, -40)

    ## monitor when ida enters its various states so we can pre-build the tag cache
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_init', on_init, -100)
        ui.hook.idp.add('ev_newfile', on_newfile, -100)
        ui.hook.idp.add('ev_oldfile', on_oldfile, -100)
        ui.hook.idp.add('ev_auto_queue_empty', auto_queue_empty, -100)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idp.add('init', on_init, -100)
        ui.hook.idp.add('newfile', on_newfile, -100)
        ui.hook.idp.add('oldfile', on_oldfile, -100)
        ui.hook.idp.add('auto_empty', on_ready, -100)

    else:
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, nw_on_init, -50)
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, nw_on_newfile, -20)
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, nw_on_oldfile, -20)
        ui.hook.idp.add('auto_empty', on_ready, 0)

    ui.hook.idb.add('closebase', on_close, 10000)

    ## create the tagcache netnode when a database is created
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_init', comment.tagging.__init_tagcache__, -1)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idp.add('init', comment.tagging.__init_tagcache__, -1)

    else:
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, comment.tagging.__nw_init_tagcache__, -40)

    ## hook any user-entered comments so that they will also update the tagcache
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_init', address.database_init, 0)
        ui.hook.idp.add('ev_init', globals.database_init, 0)
        ui.hook.idb.add('changing_range_cmt', globals.changing, 0)
        ui.hook.idb.add('range_cmt_changed', globals.changed, 0)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idp.add('init', address.database_init, 0)
        ui.hook.idp.add('init', globals.database_init, 0)
        ui.hook.idb.add('changing_area_cmt', globals.changing, 0)
        ui.hook.idb.add('area_cmt_changed', globals.changed, 0)

    else:
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, address.nw_database_init, -30)
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, globals.nw_database_init, -30)
        ui.hook.idb.add('area_cmt_changed', globals.old_changed, 0)

    # hook the changing of a comment
    if idaapi.__version__ >= 6.9:
        ui.hook.idb.add('changing_cmt', address.changing, 0)
        ui.hook.idb.add('cmt_changed', address.changed, 0)

    else:
        ui.hook.idb.add('cmt_changed', address.old_changed, 0)

    ## hook renames to support updating the "__name__" implicit tag
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_init', naming.database_init, 0)
        ui.hook.idp.add('ev_rename', naming.changing, 0)
        ui.hook.idb.add('renamed', naming.changed, 0)

    else:
        ui.hook.idp.add('rename', naming.rename, 0)

    ## hook function transformations so we can shuffle their tags between types
    if idaapi.__version__ >= 7.0:
        ui.hook.idb.add('deleting_func_tail', removing_func_tail, 0)
        ui.hook.idb.add('func_added', add_func, 0)
        ui.hook.idb.add('deleting_func', del_func, 0)
        ui.hook.idb.add('set_func_start', set_func_start, 0)
        ui.hook.idb.add('set_func_end', set_func_end, 0)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idb.add('removing_func_tail', removing_func_tail, 0)
        [ ui.hook.idp.add(item.__name__, item, 0) for item in [add_func, del_func, set_func_start, set_func_end] ]

    else:
        ui.hook.idb.add('func_tail_removed', func_tail_removed, 0)
        ui.hook.idp.add('add_func', add_func, 0)
        ui.hook.idp.add('del_func', del_func, 0)
        ui.hook.idb.add('tail_owner_changed', tail_owner_changed, 0)

    [ ui.hook.idb.add(item.__name__, item, 0) for item in [thunk_func_created, func_tail_appended] ]

    ## Relocate the tagcache for an individual segment if that segment is moved.
    ui.hook.idb.add('segm_start_changed', segm_start_changed, 0)
    ui.hook.idb.add('segm_end_changed', segm_end_changed, 0)
    ui.hook.idb.add('segm_moved', segm_moved, 0)

    ## switch the instruction set when the processor is switched
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_newprc', instruction.__ev_newprc__, 0)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idp.add('newprc', instruction.__newprc__, 0)

    else:
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, instruction.__nw_newprc__, -10)

    ## ensure the database.config namespace is initialized as it's
    ## necessary and used by the processor detection.
    if idaapi.__version__ >= 7.0:
        ui.hook.idp.add('ev_init', database.config.__init_info_structure__, -100)

    elif idaapi.__version__ >= 6.9:
        ui.hook.idp.add('init', database.config.__init_info_structure__, -100)

    else:
        hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_OPENIDB, database.config.__nw_init_info_structure__, -30)

    ## keep track of individual tags like colors and type info
    if idaapi.__version__ >= 7.2:
        ui.hook.idb.add('item_color_changed', item_color_changed, 0)

    # anything earlier than v7.0 doesn't expose the "changing_ti" and "ti_changed"
    # hooks... plus, v7.1 doesn't pass us the correct type (idaapi.tinfo_t) as its
    # parameter, instead opting for an idaapi.comp_t (compiler type) which is
    # completely fucking useless to us. so if we're using 7.1 or earlier, then
    # we completely skip the addition of the typeinfo hooks.
    if idaapi.__version__ >= 7.2:
        ui.hook.idp.add('ev_init', typeinfo.database_init, 0)
        ui.hook.idb.add('changing_ti', typeinfo.changing, 0)
        ui.hook.idb.add('ti_changed', typeinfo.changed, 0)

    # earlier versions of IDAPython don't expose anything about "extra" comments
    # so we can't do anything here.
    if idaapi.__version__ >= 6.9:
        ui.hook.idb.add('extra_cmt_changed', extra_cmt.changed, 0)

    ## just some debugging notification hooks
    #[ ui.hook.ui.add(item, notify(item), -100) for item in ['range','idcstop','idcstart','suspend','resume','term','ready_to_run'] ]
    #[ ui.hook.idp.add(item, notify(item), -100) for item in ['ev_newfile','ev_oldfile','ev_init','ev_term','ev_newprc','ev_newasm','ev_auto_queue_empty'] ]
    #[ ui.hook.idb.add(item, notify(item), -100) for item in ['closebase','savebase','loader_finished', 'auto_empty', 'thunk_func_created','func_tail_appended'] ]
    #[ ui.hook.idp.add(item, notify(item), -100) for item in ['add_func','del_func','set_func_start','set_func_end'] ]
    #ui.hook.idb.add('allsegs_moved', notify('allsegs_moved'), -100)
    #[ ui.hook.idb.add(item, notify(item), -100) for item in ['cmt_changed', 'changing_cmt', 'range_cmt_changed', 'changing_range_cmt'] ]
    #[ ui.hook.idb.add(item, notify(item), -100) for item in ['changing_ti', 'ti_changed', 'changing_op_type', 'op_type_changed'] ]
    #[ ui.hook.idb.add(item, notify(item), -100) for item in ['changing_op_ti', 'op_ti_changed'] ]
    #ui.hook.idb.add('item_color_changed', notify(item), -100)
    #ui.hook.idb.add('extra_cmt_changed', notify(item), -100)

    ### ...and that's it for all the hooks, so give out our greeting
    return greeting()

def make_ida_suck_cocks(nw_code):
    '''Unhook all of IDA's API.'''
    hasattr(idaapi, '__notification__') and idaapi.__notification__.close()
    ui.hook.__stop_ida__()

def ida_is_busy_sucking_cocks(*args, **kwargs):
    make_ida_not_suck_cocks(idaapi.NW_INITIDA)
    hasattr(idaapi, '__notification__') and idaapi.__notification__.add(idaapi.NW_TERMIDA, make_ida_suck_cocks, +1000)
    return -1
