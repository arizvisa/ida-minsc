.. _tutorials:

Tutorials
=========

Each one of these tutorials are for the Intel platform.

.. _tutorials_easy:

---------------------------------
Disassembling the current address
---------------------------------

This is an introductory tutorial which will show an example
of a multicased function as well as exposing the user to
aliases.

1. Most multicased functions have a variation that takes no
   parameters in order to imply the current address. Another
   way to do this, however, is to use :py:func:`database.here`
   which is aliased as :py:func:`database.h<database.here>`. This
   function is called so often, however, that its been imported into
   the default namespace of this plugin. So we can literally just call
   :py:func:`h()<database.here>`.

.. code-block:: python

   > print hex(h())

2. To disassemble this instruction, we'll rely on the :py:func:`database.disassemble`
   function that is aliased as :py:func:`database.disasm<database.disassemble>`.

.. code-block:: python

   > print db.disasm(h())

3. As mentioned before, most multicased functions have a no-parameter
   variation which refers to the current address. Therefore another
   way of accomplishing this can be the following.

.. code-block:: python

   > print db.disasm()

--------------------------------------------------------
Setting breakpoints (WinDbg) on all labels in a function
--------------------------------------------------------

This is an easy tutorial that will discuss tagging. Tags will be
used to filtering functions for specific instruction types,
identifying operands, and eventually generating breakpoints that
can be imported into WinDbg.

1. We'll start with by navigating to a function in IDA. Let's just
   store its address for now.

.. code-block:: python

   > f = func.address()

2. We'll need to identify an address that has a label. We can use
   :py:func:`database.type.has_label` for that. Let's navigate to
   a label and make sure it works (of course it works).

.. code-block:: python

   > print db.t.has_label()
   True
   >

3. Now we can iterate through all of the function's chunks while
   looking for a label. Instead of using a list comprehension,
   (which are incomprehensible to most), let's just use a straight
   up for-loop.

.. code-block:: python

   > result = []
   > for ea in func.iterate(f):
         if db.t.has_label(ea):
             result.append(ea)
         continue
   >

4. This is easy enough, but there's a better way using tagging. By
   using tagging, we can keep navigating to functions that we want to
   collect labels in and then aggregate them for later. To grab the
   label, it's simply a name that we can grab with :py:func:`database.name`.
   So let's tag up each label with the key "labels_to_get".

.. code-block:: python

   > for ea in func.iterate(f):
         if db.t.has_label(ea):
             db.tag(ea, 'labels_to_get', db.name(ea))
         continue
   >

5. So now, we can do this to any function we want and you'll notice
   that each address with a label now includes a tag as its comment.
   Now we can output something to paste into WinDbg (or actually
   write to a file that we can then use `$$<` to execute).

.. code-block:: python

   > for res in db.selectcontents('labels_to_get'):
         for ea, res in func.select(*res):
             print r'bp %x ".printf \"Hit label %s\n\""'%( ea, res['labels_to_get'] )
         continue
   >

6. So now we've outputted a list of breakpoints to feed into our
   debugger. This will only work if the base address of our database
   matches our image base in our debugger. But...we can actually just
   feed an offset to our debugger instead. This will allow our
   breakpoint to be independent of our base address. To get our module
   name, we can use :py:func:`database.module()<database.config.module>`,
   and to convert our address to an offset, we can use
   :py:func:`database.offset`.

.. code-block:: python

   > for res in db.selectcontents('labels_to_get'):
         for ea, res in func.select(*res):
             print r'bp %s+%x ".printf \"Hit label %s\n\""'%( db.module(), db.offset(ea), res['labels_to_get'])
         continue
   >

7. And now we have some breakpoints that output the label they execute.

.. _tutorials_medium:

-----------------------------------------
Tagging all dynamic calls in the database
-----------------------------------------

Similar to above, we will use tags to mark all the dynamic calls in
the database. This is a medium difficulty tutorial that will also
touch on tag importing an exporting.

When we're done, we'll also remove the tags we've created to avoid
cluttering things up. Let's pretend we're looking at Delphi and we
want to identify all functions that allocate something and tag all
of the dynamic calls within them.

First we'll need to enumerate all the functions that we care
about. We can do that via :py:func:`database.functions.list`
and then use :py:func:`database.functions.iterate` to select
a subset of them, or we can just iterate through everything in the
database via :py:func:`database.functions`.

1. To start out, let's assume that we have most of the `System` package
   already named. So, let's look for functions within that package that
   do stuff related to memory.

.. code-block:: python

   > db.functions.list('System.*Memory*')
   ...
   >

2. We turned up some results, so let's assume that we like them. Now
   we can use :py:func:`database.functions.iterate` to iterate through
   our results and then use :py:func:`function.tag` to tag them for
   later.

.. code-block:: python

   > for ea in db.functions.iterate('System.*Memory*'):
         func.tag(ea, 'is-memory-function', 1)
   >

3. Let's expand our search a little bit by also tagging the callers of
   these functions. This can be done by using :py:func:`function.up`.
   Our tag name "is-memory-function" doesn't make sense, so we'll tag
   the callers with "calls-memory-function".

.. code-block:: python

   > for ea, res in db.select('is-memory-function'):
         for ea in func.up(ea):
             func.tag(ea, 'calls-memory-function', 1)
         continue
   >

4. Now that we have all of our functions tagged with "is-memory-function",
   or "calls-memory-function. These can both be queried :py:func:`database.select`
   to select them. Since we're searching for either tag (or), we'll use
   the :py:data:`Or` parameter to return any function that has either tag
   assigned.  We plan on iterating through these results, so we'll need
   to use :py:func:`function.chunks.iterate` (or really its alias
   :py:func:`function.iterate<function.chunks.iterate>`) to look for our
   instruction type. To test for an indirect call instruction (a call
   which branches to a register or a phrase), we can simply use the
   :py:func:`instruction.is_calli` function.

.. code-block:: python

   > for ea, res in db.select(Or=('is-memory-function', 'calls-memory-function')):
         for ea in func.iterate(ea):
             if ins.is_calli(ea):
                 db.tag(ea, 'indirect-call', 1)
             continue
         continue
   >

5. Just to keep our function comments clean, let's untag both the function
   tags that we applied. Since we tagged the contents of these functions
   with the tag "indirect-call", querying for this contents tag will end
   up giving us the subset of the results we care about.

.. code-block:: python

   > for ea, res in db.select(Or=('is-memory-function', 'calls-memory-function')):
         for tagname, value in res.iteritems():
             oldvalue = func.tag(ea, tagname, None)
             print "Removing tag %s from function %x: %s"% (tagname, ea, func.name(ea))
         continue
   >

6. After cleaning up, now we should have the actual dynamic call
   instructions tagged in the contents of our functions. So to continue,
   let's tag the operand type for each instruction. This way we can
   determine which registers the instructions' operands are composed
   of. We can do this using :py:func:`instruction.op_type()<instruction.opt>`
   which is aliased as :py:func:`instruction.opt<instruction.opt>`. Actually,
   in order to check our results, let's actually store *all* of the operand
   types using its plural, :py:func:`instruction.ops_type`. As usual, this
   has an abbreviated alias of :py:func:`instruction.opts<instruction.ops_type>`.
   We'll also keep things clean again, by removing the previous tag,
   "indirect-call".

.. code-block:: python

   > for ea, res in db.selectcontents('indirect-call'):
         for ea, res in func.select(ea, *res):
             print "Tagging address %x with %d operands"% (ea, ins.ops_count(ea))
             db.tag(ea, 'call-optypes', ins.opts(ea))
             print "Removing old \"%s\" tag from %x"% ('indirect-call', ea)
             db.tag(ea, 'indirect-call', None)
         continue
   >

6. Just to sanity check things, lets prove that all of the calls that we
   care about really only have one operand. To do this, we'll output their
   address using the :py:func:`database.disassemble` function which is
   aliased as :py:func:`database.disasm<database.disassemble>` and also
   tag them so we can refer to them later. We'll do this removal by
   passing the :py:obj:`None` parameter to :py:func:`database.tag`.

.. code-block:: python

   > for res in db.selectcontents('call-optypes'):
         for ea, res in func.select(*res):
             if len(res['call-optypes']) != 1:
                 print "Unknown operand count %d for instruction: %s"% (len(res['call-optypes']), db.disasm(ea))
                 db.tag(ea, 'calli-unknown', 1)
                 print "Removing old tag \"%s\" from %x"% ('call-optypes', ea)
                 db.tag(ea, 'calli-optypes', None)
             continue
         continue
   >

7. Now if we want, we can manually go through all of the "calli-unknown"
   contents tags and figure out what is odd about them. But, we're
   really only interested in the registers for the first operand. To
   decode the first operand, we can use :py:func:`instruction.op_value`
   which is aliased as :py:func:`instruction.op`. Now operands that are
   composed of registers (or symbols) inherit from the :py:obj:`symbol_t`
   type. This type has a :py:attr:`symbols` property which will allow
   one to enumerate the symbols (really registers) belonging to an
   operand. So, let's go ahead and identify our "call-optypes"
   instructions again, and create a new tag, "call-opregs". This new
   tag will contain all of the registers we need to resolve the target
   address of the branch instructions that we've selected.

.. code-block:: python

   > for res in db.selectcontents('call-optypes'):
         for ea, res in func.select(*res):
             op = ins.op(ea, 0)
             regnames = []
             for symbol in op.symbols:
                 regnames.append(symbol.name)
             print "Tagging %x with %s containing the regs %r"% (ea, 'call-opregs', regnames)
             db.tag(ea, 'call-opregs', regnames)
         continue
   >

8. Tagging these registers for each call instruction is actually going
   to be useful to pass along to a debugger. With this we know which
   register to dump for a call instruction in order to calculate its
   target. Instead of calculating them though, let's remain hacky and
   just output their results as a breakpoint. In the prior tutorial,
   we chose :py:func:`database.offset` in order to calculate the
   relative address. Instead of doing it that way, there's a class in
   the :py:mod:`tools` module that we can use to transform an address
   named :py:class:`tools.remote`. So let's use this instead. To
   construct this class, we'll need to pass our remote base address
   as a parameter.

.. code-block:: python

   > R = tools.remote(remote_base_address)
   > print hex( R.get(h()) )

9. Now that we have an instance of :py:class:`tools.remote`, we can
   select our instructions tagged with "call-opregs" and produce a
   breakpoint for each one. Let's do that.


.. code-block:: python

   > for res in db.selectcontents('call-opregs'):
         for ea, res in func.select(*res):
             emit_registers = ''
             for regname in res['call-opregs']:
                 emit_registers += "r @%s;"% regname

             # "put" our address into the debugger
             remote_ea = R.put(ea)
             print r'bp %x ".printf \"Hit call %s\n\";%s;g"'% (remote_ea, db.disasm(ea), emit_registers)
         continue
   >

10. And now we've just outputted some breakpoints that we can feed into
    WinDbg which will emit the values of any registers that are required
    to branch via a call instruction. Let's redo this because we might
    want to save these breakpoints for later. We'll take the breakpoint
    that we generated for each instruction, and then store is via the
    tag "break-calli".

.. code-block:: python

   > for res in db.selectcontents('call-opregs'):
         for ea, res in func.select(*res):
             emit_registers = ''
             for regname in res['call-opregs']:
                 emit_registers += "r @%s;"% regname
             bpstr = r'.printf "Hit call %s\n";%s;gc'% (db.disasm(ea), emit_registers)
             db.tag(ea, 'break-calli', bpstr)
         continue
   >

11. Now that we have the breakpoints stored, the next time we open this
    database we should be able to generate the breakpoints for WinDbg
    at time that we need them. This data can also be shared with other
    users so that they will also have the access to the same information.
    Just for fun, let's serialize this data so that we can transport this
    to another user. Rather than writing the queries to do this manually,
    we can utilise one of the functions provided by the :py:mod:`custom.tags<tags>`
    module. Namely the :py:func:`custom.tags.export<tags.export>`. We only want to give
    them the "break-calli" tags which can be exported via the following code.

.. code-block:: python

   > data = custom.tags.export('break-calli')
   >
   > import pickle, os.path
   > filename = os.path.join(db.path(), 'breakpoints.pickle')
   > with file(filename, 'wb') as output:
         pickle.dump(data, output)
   >
   > print "Dumped breakpoints to %s"% filename

12. If another user wants to import this pickled object, we can again use the
    :py:mod:`custom.tags<tags>` to help us.

.. code-block:: python

   > filename = os.path.join(db.path(), 'breakpoints.pickle')
   > with file(filename, 'rb') as input:
         data = pickle.load(input)
   >
   > custom.tags.apply(data)

13. Unfortunately, this will overwrite any tags in the current database with
    the name "break-calli". If the user wants to map these tags to a different
    name, however, they can provide a dictionary of tag mappings as a keyword
    parameter to :py:func:`custom.tags.apply<tags.apply>`.

.. code-block:: python

   > custom.tags.apply(data, **{'break-calli': 'username.break-calli'})
   >

.. _tutorials_hardcore:

---------------------------------------
Marking all functions that are "leaves"
---------------------------------------

This tutorial is somewhat "advanced". Other than using tags as
described in the prior tutorials, this will also discuss ways to use
the combinators provided by this plugin.

1. Knowing whether a function is a utility function that doesn't call anything
   might reduce the time it takes a reverser to determine the complexity of a
   function. This plugin makes it pretty easy to do this thanks to the help
   of functions like :py:func:`function.down` or the combination of
   :py:func:`function.chunks.iterate` and :py:func:`instruction.is_call`.
   So, let's use these tools to define a function that returns whether a
   function calls other functions or not.

.. code-block:: python

   > def has_children(ea):
         if len(func.down()) > 0:
             return True
         return False
   >
   > print has_children(h())
   13
   >

2. One issue with using :py:func:`function.down` is since it only returns
   addresses that a function is capable of calling, it will still return
   :py:obj:`False` if the function we apply it to makes an indirect call.
   Let's improve this by looking for any call via the following variation.

.. code-block:: python

   > def has_children(ea):
         res = []
         for ea in func.iterate(ea):
             if ins.is_call(ea):
                 res.append(ea)
             continue
         return True if len(res) > 0 else False
   >

3. Another way to do this is via the combination of an anonymous function
   (`lambda`) and a list comprehension. This would look like the
   following code.

.. code-block:: python

   > has_children = lambda ea: True if len([ea for ea in func.iterate(ea) if ins.is_call(ea)]) > 0 else False

4. Yet another way involves using the functional combinator component of
   this plugin (see :ref:`combinators-intro`). To assist with these types
   of one-liners, this plugin includes a number of combinators that can
   be combined to build the exact same function. If we combine the
   :py:func:`fpartial`, :py:func:`ifilter`, and some operators available
   via Python's :py:mod:`operator` module with the :py:func:`fcompose`
   combinator we can implement our prior 2 implementations of the
   :py:func:`has_children` function with the following code.

.. code-block:: python

   > print "first we need to iterate through all addresses in function"
   > func_iterator = func.iterate
   >
   > print "now we'll filter for all call instructions"
   > func_callFilter = fcompose(func_iterator, fpartial(ifilter, ins.is_call))
   >
   > print "now we'll convert our ifilter into a list so we can count them"
   > func_callLister = fcompose(func_callFilter, list)
   >
   > print "convert our list of call instructions into a count"
   > func_callCounter = fcompose(func_callLister, len)
   >
   > print "now we want to return true if operator.lt(0, len(list( call_instructions )))"
   > func_callComparison = fcompose(func_callCounter, fpartial(operator.lt, 0))
   >
   > print "this will now return true is the number of call instructions is > 0"
   > has_children = func_callComparison
   >
   > print 'combined we have'
   > has_children = fcompose(func.iterate, fpartial(ifilter, ins.is_call), list, len, fpartial(operator.lt, 0))

5. The combination of these primitives can provide some potentially very
   powerful tools if a user chooses to use this method. Nonetheless, it
   is up to the user and their own personal preference. This function that
   we've created, :py:func:`has_children`, will now be used to tag all
   of the functions that have no children. To start out, however, let's
   create another function that will tag a function with the tag "function-type"
   and the value "leaf" if :py:func:`has_children` returns :py:obj:`False`.

.. code-block:: python

   > def tag_if_leaf(ea):
         if has_children(ea):
             func.tag(ea, 'function-type', 'leaf')
         return
   >

6. In the prior tutorials we used the :py:class:`database.functions`
   namespace to enumerate each function. In this case we'll use another
   useful function in that is provided to us by the :py:mod:`tools`
   module. This functions is :py:func:`tools.map` and takes a callable
   as its first parameter. Normally, this callable will be passed an
   address for each function within the database. This callable will
   then be executed against every function similar to using
   :py:func:`database.functions`. One thing that is interesting about
   :py:func:`tools.map`, however, is that it has the ability to detect
   the type of callable that is passed to it. If the callable takes
   two parameters, it will assume that the user intended an index, and
   an address to be passed to it. This can be used to detect how far
   along :py:func:`tools.map` has processed. Let's redefine the above
   :py:func:`tag_if_leaf` function again.

.. code-block:: python

   > def tag_if_leaf(index, ea, **kwargs):
         total = kwargs['total']
         print "Percentage complete: %f"% (index / float(total))
         if not has_children(ea):
             func.tag(ea, 'function-type', 'leaf')
             return (ea, False)
         return (ea, True)
   >

7. Now that we have a callable to pass to :py:func:`tools.map`, we
   can simply hand it our callable and proceses the entire database.

.. code-block:: python

   > total = len(db.functions())
   > res = tools.map(tag_if_leaf, total=len(db.functions()))

8. Now, not only are all the "leaf" functions tagged, the variable
   :py:obj:`res` contains a list of tuples containing each function's
   address, and whether or not it has any children. Let's convert this
   to a Python :py:class:`dict` and tag any functions that contain
   only indirect calls. This way we can distinguish if any of these
   functions are wrappers that use virtual methods.

.. code-block:: python

   > children_lookup = dict(res)
   > for ea in children_lookup:
         if children_lookup[ea] and len(func.down(ea)) == 0:
             func.tag(ea, 'function-type', 'virtual-wrapper')
         continue
   >

9. Now each function containing a call is tagged with "function-type"
   being equivalent to "leaf" or "virtual-wrapper" depending on whether
   no functions are called, or only indirect calls are made.

.. _tutorials_conclusion:

----------
Conclusion
----------

There are a variety of different features available in this plugin that
can allow users to automate different aspects of their reverse-engineering
project. It is recommended by the author to explore the different modules
by using Python's :py:func:`help` function to see what is available.

This plugin was written with the intention of enabling a reverse-engineer
to automate many issues that one may encounter while reversing without
investing in too much development effort. The author hopes that these
examples help demonstrate the flexibility that is provided by this plugin.
