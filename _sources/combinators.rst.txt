.. _combinators-intro:

Functional combinators
======================

To simplify the generation of functions that can contain potentially
complex logic, a number of primitive functions are provided which can
be combined in arbitrary ways. This can facilitate the quick creation
of functions that can be used as one-liners.

This was primarily developed for :doc:`matching`, but is also exposed to the
user if they wish to use it in their endeavors. These can be used for
creating one-liner functions that transform an input into various types,
constructing a function that will consume or test its input, or really
just any number of things.

.. _combinators-examples:

Examples
--------

To create a closure that will return the type of the second element of
a structure::

   > f = fcompose( fgetitem(1), fattribute('type') )
   >
   > st = struc.by('MyStructName')
   > print f(st)

To create a closure which will try and call :py:func:`__repr__` whilst
falling back to formatting as a string if not possible::

   > test = fcondition(fhasattr('__repr__'))
   > tf = test(fgetattr('__repr__'), "{!s}".format)
   > f = fcompose(tf, fcurry())
   > print f(object)

To create a closure which will return a string when defined and an empty
string when undefined::

   > f = fcompose(fdefault(''), "{!s}".format)
   > print f('hi')
   > print f(None)

.. _combinators-list:

Combinators
-----------

.. py:function:: fbox(\*args)

   Given any number of ``args``, box them into a tuple.

   Aliases: ``fboxed``

   :param \*args: any number of objects to box as a tuple
   :return: a tuple containing the arguments that were boxed

.. py:function:: funbox(callable, \*initial_args, \*\*initial_kwargs)(\*boxed_args, \*\*boxed_kwargs)

   Given a ``callable``, return a closure that when called with arguments
   will expand (unbox) them before applying them to the ``callable``.

   :param callable: the function whose closure will call
   :type callable: `function`
   :param \*initial_args: any default arguments to initially pass to the ``callable``
   :param \*\*initial_kwargs: any default keyword arguments to initially pass to the ``callable``
   :param \*boxed_args: any number of arguments which are unboxed and concatenated together
   :param \*\*boxed_kwargs: any extra keyword arguments to apply to the callable

.. py:function:: finstance(type)(object)

   Given a ``type``, return a closure that will return true or false
   depending on whether ``object`` is an instance of that ``type``.

   :param type: any kind of python type
   :type type: `type`
   :param object: any kind of python object to test

.. py:function:: fhasitem(item)(object)

   Given an ``item``, return a closure that will return true or false
   based on whether or not ``object`` contains it.

   Aliases: ``fitemQ``

   :param item: any kind of python object
   :param object: any kind of python object to test membership with

.. py:function:: fgetitem(item, \*default)(object)

   Given an ``item``, return a closure which fetches item from
   ``object``. If ``default`` is specified, then if the
   item does not exist in ``object`` return it instead.

   Aliases: ``fitem``

   :param item: any kind of python object to pass to :py:func:`operator.getitem`.
   :param object: any kind of python object to return an item from
   :param \*default: an item returned by default if the ``object``
                     does not contain the specified ``item``

.. py:function:: fhasattr(attribute)(object)

   Given an ``attribute`` as a string, return a closure that will return
   true or false based on whether or not ``object`` has the specified
   ``attribute``.

   Aliases: ``fattributeQ``

   :param attribute: the attribute to check for
   :type attribute: `str`
   :param object: any kind of python object to test

.. py:function:: fgetattr(attribute, \*default)(object)

   Given an ``attribute``, return a closure which fetches the attribute
   from the ``object``. If ``default`` is specified, then if the
   attribute does not exist in ``object`` return it instead.

   Aliases: ``fattribute``

   :param attribute: an attribute to return from the ``object``
   :type attribute: `str`
   :param object: any kind of python object to return an attribute from
   :param \*default: an attribute returned by default if the ``object``
                     does not contain with specified ``attribute``

.. py:function:: fpassthru(object)

   Given an ``object``, return it. This is the identity function
   and is typically used to ignore transforming an object.

   Aliases: ``fpass``, ``fidentity``, ``fid``

   :param object: any kind of python object to return

.. py:function:: fdefault(default)(object)

   Given a ``default`` object, return a closure that will return it if
   ``object`` is not defined (false-y).

   :param default: the default object to return
   :param object: any kind of python object to check

.. py:function:: fcompose(\*callables)(object)

   Given a number of ``callables``, return a closure that executes them
   in succession whilst returning the result.

   :param \*callables: a number of callables that each take one parameter
   :param object: any kind of python object to transform

.. py:function:: fdiscard(callable)(\*args, \*\*kwargs)

   Given a ``callable``, return a closure that will call it with no
   parameters whilst discarding any that were passed to it.

   :param callable: a callable to execute
   :param \*args: any number of arguments that get discarded
   :param \*\*kwargs: any kind of keyword arguments that get discarded

.. py:function:: fcondition(crit)(true, false)(object)

   Given a critiquing function ``crit``, return a closure which takes
   parameters for ``true`` and ``false``. This will return
   another closure that when passed an ``object``, will check it via
   the critiquing function (``crit``) and return ``true`` if
   the function returns a truthy value, or return ``false`` if it
   returns a false-y value.

   Aliases: ``fcond``

   :param crit: a callable that takes an argument and returns true or false
   :type crit: `function`
   :param true: an object or a function to return (or execute) when value is true
   :type true: `object` or `function`
   :param false: an object or a function to return (or execute) when value is false
   :type false: `object` or `function`
   :param object: any kind of python object to pass to ``crit``

.. py:function:: fmap(\*callables)(object)

   Given a number of ``callables``, return a closure that executes them
   synchronously against ``object`` returning a tuple containing the
   result of each callable.

   :param \*callables: any number of callables to execute for each desired
                       result returned
   :param object: any kind of python object to use

.. py:function:: fmemo(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, and any ``initial_args`` and ``initial_kwargs``,
   return a closure that caches (memoizes) the result that is returned. The next
   time this closure is called with the same arguments, the cached version will
   be returned instead.

   Aliases: ``flazy``

   :param callable: any callable to memoize the results for
   :type callable: `function`
   :param \*initial_args: any initial arguments to prefix to the callable
   :param \*\*initial_kwargs: any initial keyword arguments to apply to the callable
   :param \*args: any arguments to apply to the callable
   :param \*\*kwargs: any keyword arguments to apply to the callable

.. py:function:: fpartial(callable, \*start_args, \*\*start_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, partially apply the arguments specified in both
   ``start_args`` and ``start_kwargs``. This will return a closure
   that can then be called with any other ``args`` or keyword arguments
   in ``kwargs``.

   :param callable: any callable to partially apply arguments to
   :type callable: `function`
   :param \*start_args: initial arguments to partially apply to the ``callable``
   :param \*\*start_kwargs: initial keyword arguments to partially apply to the ``callable``
   :param \*args: arguments to continue to apply to the callable
   :param \*\*kwargs: any keyword arguments to continue to apply to the callable

.. py:function:: fapply(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, return a closure that will apply both the arguments
   (``args``) and keyword arguments (``kwargs``) to it.

   :param callable: any callable to apply arguments to
   :type callable: `function`
   :param \*args: the arguments to apply to the ``callable``
   :param \*\*kwargs: the keyword arguments to apply to the ``callable``
   :param \*initial_args: any initial arguments to prefix the ``args`` with
   :param \*\*initial_kwargs: any initial keyword args to prefix the ``kwargs`` with

.. py:function:: fcurry(\*default_args, \*\*default_kwargs)(callable, \*args, \*\*kwargs)

   Given ``default_args`` and ``default_kwargs``, return a closure
   that will apply these arguments to its first parameter ``callable``.
   If ``args`` or ``kwargs`` is specified, the append these to the
   default arguments.

   :param \*default_args: the arguments to apply to the ``callable``
   :param \*\*default_kwargs: the keyword arguments to apply to the ``callable``
   :param callable: the callable to apply the arguments to
   :type callable: `function`
   :param \*args: any extra arguments to apply to the ``callable``
   :param \*\*kwargs: any extra keyword arguments to apply to the ``callable``

.. py:function:: frpartial(callable, \*reverse_args, \*\*reverse_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, the arguments ``reverse_args``, and
   the keyword arguments ``reverse_kwargs``, return a closure that
   will apply these to the ``callable`` backwards. If ``args``
   or ``kwargs`` is provided, then apply these to the front of
   the ``callable``.

   :param callable: the callable to apply the arguments to
   :type callable: `function`
   :param \*reverse_args: the arguments to apply to the end of the ``callable``
   :param \*\*reverse_kwargs: the keyword arguments to apply to the ``callable``
   :param \*args: the arguments to apply to the beginning of the ``callable``
   :param \*\*kwargs: any extra keyword arguments to apply to the ``callable``

.. py:function:: freversed(callable, \*reverse_args, \*\*reverse_kwargs)(\*extra_args, \*\*extra_kwargs)

   Given a ``callable``, the arguments ``reverse_args``, and the
   keyword arguments ``reverse_kwargs``, return a closure which applies
   these to the end of the ``callable``. If ``extra_args`` or
   ``extra_kwargs`` is provided, then continue to apply these to the
   ``callable`` but backwards.

   Aliases: ``freverse``

   :param callable: the callable to apply the arguments to
   :type callable: `function`
   :param \*reverse_args: the arguments to apply to the end of ``callable``
   :param \*\*reverse_kwargs: the keyword arguments to apply to ``callable``
   :param \*extra_args: extra arguments to continue to apply to ``kwargs``
   :param \*\*extra_kwargs: any extra keyword arguments to apply to ``callable``

.. py:function:: fcatch(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, return a closure that will call it with the
   arguments ``initial_args`` combined with ``args``, and the
   keyword arguments ``initial_kwargs`` combined with ``kwargs``.

   This closure will wrap the result of ``callable`` so that the
   second element of the tuple will be the result, and the first element will
   be the exception object if one was raised. If one wasn't raised, then the
   first element will be the value :py:obj:`None`.

   Aliases: ``fexc``, ``fexception``

   :param callable: the callable to catch an exception in
   :type callable: `function`
   :param \*initial_args: the initial arguments to apply to the ``callable``
   :param \*\*initial_kwargs: the initial keyword arguments to apply to the ``callable``
   :param \*args: the arguments to apply to the ``callable``
   :param \*\*kwargs: the keyword arguments to apply to the ``callable``

.. py:function:: fcomplement(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, the arguments ``initial_args``, and the
   keyword arguments ``initial_kwargs``, return a closure that will
   invert the result (`not`) returned from the ``callable``.

   Aliases: ``fnot``

   :param callable: the callable to invert the result for
   :type callable: `function`
   :param \*initial_args: the initial arguments to apply to the ``callable``
   :param \*\*initial_args: the initial keyword arguments to apply to the ``callable``
   :param \*args: the arguments to apply to the ``callable``
   :param \*\*kwargs: the keyword arguments to apply to the ``callable``

.. py:function:: first(listable)

   Given a ``listable`` python object, return its first element.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`

.. py:function:: second(iterable)

   Given a ``listable`` python object, return its second element.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`

.. py:function:: third(iterable)

   Given a ``listable`` python object, return the third element.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`

.. py:function:: last(iterable)

   Given a ``listable`` python object, return its last element.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`

.. py:function:: ilist(iterable)

   Given a ``iterable`` python object, return it as a list.

   :param iterable: any kind of iterable object

.. py:function:: liter(listable)

   Given a ``listable`` python object, return it as an iterable..

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`

.. py:function:: ituple(iterable)

   Given a ``iterable`` python object, return it as a tuple.

   :param iterable: any kind of iterable object

.. py:function:: titer(tuple)

   Given a ``tuple``, return it as an iterator.

   :param tuple: any kind of python tuple
   :type tuple: `tuple`

.. py:function:: itake(count)(iterable)

   Given an integer ``count``, return a closure that will consume
   that number of elements from the provided ``iterable`` and
   return them as a tuple.

   :param count: a number of elements to consume
   :type count: `int` or `long`
   :param iterable: an iterable to consume

.. py:function:: iget(count)(iterable)

   Given an integer ``count``, return a closure that will consume
   that number of elements from the provided ``iterable`` and
   return the last one.

   :param count: a number of elements to consume
   :type count: `int` or `long`
   :param iterable: an iterable to consume values from

.. py:function:: imap(callable, iterable)

   Execute the provided ``callable`` against all of the elements in
   ``iterable`` returning an iterator containing the transformed
   results. This is similar to :py:func:`map` but for iterables.

   :param callable: a callable python object that transforms its argument
   :type callable: `function`
   :param iterable: an iterable to transform results from

.. py:function:: ifilter(crit, iterable)

   Yield each value from ``iterable`` that the callable ``crit``
   returns true for. This is similar to :py:func:`filter` but for iterables.

   :param crit: a callable python object that returns true or false based on its
                argument
   :type crit: `function`
   :param iterable: an iterable to critique

.. py:function:: ichain(\*iterables)

   Given a variable number of ``iterables``, combine them all
   into a single iterator. This is the same as :py:func:`itertools.chain`.

   :param \*iterables: any number of iterators

.. py:function:: izip(\*iterables)

   Given any number of ``iterables``, return them as an iterator that
   yields a tuple for each element that an individual iterator would return.
   This is similar to :py:func:`zip`, and is the same as :py:func:`itertools.izip`.

   :param \*iterables: any number of iterators

.. py:function:: count(iterable)

   Given an ``iterable``, return the number of elements that it contains.

   Note: This is done by consuming values from ``iterable`` which will
   modify its state. If the state of the iterator wishes to be retained, one
   can either re-create it, or make a copy of it using :py:func:`itertools.tee`.

   :param iterable: an iterator to count the elements of
