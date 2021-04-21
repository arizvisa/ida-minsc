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

.. py:function:: fpack(callable, \*initial_args, \*\*initial_kwargs))(\*packed_args, \*\*packed_kwargs)

   Given a ``callable``, return a closure that when called with arguments
   will pack (box) them before applying them to the ``callable`` as its first
   parameter. Any keyword arguments will be merged together when executing
   the ``callable``.

   :param callable: the function which will be called by the returned closure
   :type callable: `function`
   :param \*initial_args: any default arguments to prefix the parameter that is passed to the ``callable`` with
   :param \*\*initial_kwargs: any default keyword arguments to pass to the ``callable``
   :param \*packed_args: any number of arguments which are packed and then concatenated together
   :param \*\*packed_kwargs: any extra keyword arguments to apply to the callable

.. py:function:: funpack(callable, \*initial_args, \*\*initial_kwargs)(\*packed_args, \*\*packed_kwargs)

   Given a ``callable``, return a closure that when called with arguments
   will unpack (unbox) them before applying them to the ``callable`` as
   its parameters. Any keyword arguments will be merged together when
   executing the ``callable``.

   :param callable: the function which will be called by the returned closure
   :type callable: `function`
   :param \*initial_args: any default arguments to initially pass to the ``callable``
   :param \*\*initial_kwargs: any default keyword arguments to initially pass to the ``callable``
   :param \*packed_args: any number of arguments which are unpacked and then concatenated together
   :param \*\*packed_kwargs: any extra keyword arguments to apply to the callable

.. py:function:: fcar(callable, \*initial_args, \*\*initial_kwargs))(\*args, \*\*kwargs)

   Given a ``callable``, return a closure that when called with arguments will
   only use the first element from ``args`` parameter appended to the provided
   ``initial_args``. Any keyword arguments will be merged together when executing
   the ``callable``. This is similar to the ``car`` function found in programming
   languages from the LISP family.

   :param callable: the function which will be called by the returned closure
   :type callable: `function`
   :param \*initial_args: any default arguments to prefix the parameter that is passed to the ``callable`` with
   :param \*\*initial_kwargs: any default keyword arguments to pass to the ``callable``
   :param \*args: any number of arguments from which to use only the first one
   :param \*\*kwargs: any extra keyword arguments to apply to the callable

.. py:function:: fcdr(callable, \*initial_args, \*\*initial_kwargs))(\*args, \*\*kwargs)

   Given a ``callable``, return a closure that when called with arguments will
   use all except the first element from ``args`` parameter and append it to
   the end of the provided ``initial_args``. Any keyword arguments will be merged
   together when executing the ``callable``. This is similar to the ``cdr`` function
   found in programming languages from the LISP family.

   :param callable: the function which will be called by the returned closure
   :type callable: `function`
   :param \*initial_args: any default arguments to prefix the parameter that is passed to the ``callable`` with
   :param \*\*initial_kwargs: any default keyword arguments to pass to the ``callable``
   :param \*args: any number of arguments from which to use only the first one
   :param \*\*kwargs: any extra keyword arguments to apply to the callable

.. py:function:: finstance(type)(object)

   Given a ``type``, return a closure that will return either :py:const`True`
   or :py:const:`False` based on whether ``object`` is an instance of the
   provided ``type``.

   :param type: any kind of python type
   :type type: `type`
   :param object: any kind of python object to test
   :return: whether the object is an instance of the requested type or not
   :rtype: :py:class:`bool`

.. py:function:: fhasitem(item)(object)

   Given an ``item``, return a closure that will return true or false
   based on whether or not ``object`` contains it via the "contains"
   operator.

   Aliases: ``fitemQ``

   :param item: any kind of python object
   :param object: any kind of python object to test membership with
   :return: whether the object has the requested item or not
   :rtype: :py:class:`bool`

.. py:function:: fgetitem(item, \*default)(object)

   Given an ``item``, return a closure which fetches item from
   ``object``. If ``default`` is specified, then if the
   item does not exist in ``object`` return it instead.

   Aliases: ``fitem``

   :param item: any kind of python object to pass as the key to the :py:func:`operator.getitem` function
   :param object: any kind of python object to return an item from
   :param \*default: an item returned by default if the ``object``
                     does not contain the specified ``item``
   :return: the item that was requested

.. py:function:: fsetitem(item)(value)(object)

   Assign the given ``value`` to the specified ``item`` of the provided
   ``object`` when called and then return the modified ``object``.

   :param item: any kind of python object to pass as the key to the :py:func:`operator.setitem` function
   :param value: the value to assign to the python object as used by :py:func:`operator.setitem`
   :param object: any kind of python object to assign the item into
   :return: the object that was modified

.. py:function:: fdelitem(\*items)(object)

   Return a closure that when called with a particular ``object``, will
   remove the designated ``items`` from it prior to returning the modified
   ``object``.

   :param \*items: any number of python objects to pass as keys to the :py:func:`operator.delitem` function
   :param object: any kind of python object to remove the items from
   :return: the object that was modified

.. py:function:: fhasattr(attribute)(object)

   Given an ``attribute`` as a string, return a closure that will return
   :py:const:`True` or :py:const:`False` based on whether or not ``object``
   has the specified ``attribute``.

   Aliases: ``fattributeQ``

   :param attribute: the attribute to check for
   :type attribute: `str`
   :param object: any kind of python object to test
   :return: whether the object has the requested attribute or not
   :rtype: :py:class:`bool`

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
   :return: the requested attribute

.. py:function:: fsetattr(attribute)(value)(object)

   Assign the given ``value`` to the specified ``attribute`` of the
   provided ``object`` when called and return the ``object``.

   Aliases: ``fsetattribute``

   :param attribute: an attribute on the ``object`` to assign.
   :param value: the value to assign to the python object as used by :py:func:`builtins.setattr`.
   :param object: any kind of python object to assign the attribute on.
   :return: the object that was modified

.. py:function:: fconstant(object)

   Return a closure that always returns the provided ``object``.

   Aliases: ``fconst``, ``falways``

   :param object: any kind of python object to return
   :return: a closure that returns the object

.. py:function:: fidentity(object)

   Given an ``object``, return it. This is the identity function
   and is typically used to ignore transforming an object.

   :param object: any kind of python object to return
   :return: the object

.. py:function:: fdefault(default)(object)

   Given a ``default`` object, return a closure that will return it if
   ``object`` is not defined (false-y).

   :param default: the default object to return
   :param object: any kind of python object to check
   :return: the object if it is defined, otherwise the value for default

.. py:function:: fcompose(\*callables)(object)

   Given a number of ``callables``, return a closure that executes them
   in succession whilst returning the result.

   :param \*callables: a number of callables that each take one parameter
   :param object: any kind of python object to transform

.. py:function:: fdiscard(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable`` and any ``initial_args`` or ``initial_kwargs``,
   return a closure that will call it with only those parameters whilst
   discarding any parameters that were passed to the returned closure.

   :param callable: a callable to execute
   :type callable: `function`
   :param \*initial_args: any default arguments to pass as parameters to the ``callable``
   :param \*\*initial_kwargs: any default keyword arguments to pass as parameters to the ``callable``
   :param \*args: any number of arguments that get discarded
   :param \*\*kwargs: any kind of keyword arguments that get discarded

.. py:function:: fcondition(crit)(true, false)(object)

   Given a critiquing function ``crit``, return a closure which takes
   parameters for ``true`` and ``false``. This will return
   another closure that when passed an ``object``, will check it via
   the critiquing function (``crit``) and return ``true`` if
   the function returns a truthy value, or return ``false`` if it
   returns a false-y value.

   :param crit: a callable that takes an argument and returns true or false
   :type crit: `function`
   :param true: an object or a function to return (or execute) when value is true
   :type true: `object` or `function`
   :param false: an object or a function to return (or execute) when value is false
   :type false: `object` or `function`
   :param object: any kind of python object to pass to ``crit``

.. py:function:: fmap(\*callables)(object)

   Given a number of ``callables``, return a closure that executes them
   synchronously against ``object`` returning a tuple composed of the
   results of each callable.

   :param \*callables: any number of callables to execute for each desired
                       result returned
   :param object: any kind of python object to use

.. py:function:: flazy(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, and any ``initial_args`` and ``initial_kwargs``,
   return a closure that caches (memoizes) the result that is returned. The next
   time this closure is called with the same arguments, the cached version will
   be returned instead.

   :param callable: any callable to execute lazily and memoize its result for
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
   will apply these to the ``callable`` in reverse. If ``args``
   or ``kwargs`` is provided, then apply these to the front of
   the ``callable``.

   :param callable: the callable to apply the arguments to
   :type callable: `function`
   :param \*reverse_args: the arguments to apply to the end of the ``callable``
   :param \*\*reverse_kwargs: the keyword arguments to apply to the ``callable``
   :param \*args: the arguments to apply to the beginning of the ``callable``
   :param \*\*kwargs: any extra keyword arguments to apply to the ``callable``

.. py:function:: freverse(callable, \*reverse_args, \*\*reverse_kwargs)(\*extra_args, \*\*extra_kwargs)

   Given a ``callable``, the arguments ``reverse_args``, and the
   keyword arguments ``reverse_kwargs``, return a closure which applies
   these to the end of the ``callable``. If ``extra_args`` or
   ``extra_kwargs`` is provided, then continue to apply these to the
   ``callable`` but in reverse.

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
   second element of the returned tuple will be the result, and the
   first element will be the exception object if one was raised. If
   an exception was not raised, then the first element will be the
   value :py:const:`None`, and the second will be the original result.

   :param callable: the callable to catch an exception in
   :type callable: `function`
   :param \*initial_args: the initial arguments to apply to the ``callable``
   :param \*\*initial_kwargs: the initial keyword arguments to apply to the ``callable``
   :param \*args: the arguments to apply to the ``callable``
   :param \*\*kwargs: the keyword arguments to apply to the ``callable``

.. py:function:: fcomplement(callable, \*initial_args, \*\*initial_kwargs)(\*args, \*\*kwargs)

   Given a ``callable``, the arguments ``initial_args``, and the
   keyword arguments ``initial_kwargs``, return a closure that will
   invert the result (`not`) prior to returning it.

   Aliases: ``fnot``

   :param callable: the callable to invert the result for
   :type callable: `function`
   :param \*initial_args: the initial arguments to apply to the ``callable``
   :param \*\*initial_args: the initial keyword arguments to apply to the ``callable``
   :param \*args: the arguments to apply to the ``callable``
   :param \*\*kwargs: the keyword arguments to apply to the ``callable``

.. py:function:: first(listable)

   Given a ``listable`` object, return the first element in its sequence.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`
   :return: the first element from the iterable

.. py:function:: second(iterable)

   Given a ``listable`` object, return the second element in its sequence.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`
   :return: the second element from the iterable

.. py:function:: third(iterable)

   Given a ``listable`` object, return the third element in its sequence.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`
   :return: the third element from the iterable

.. py:function:: last(iterable)

   Given a ``listable`` object, return the last element in its sequence.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`
   :return: the last element from the iterable

.. py:function:: ilist(iterable)

   Given an ``iterable`` object, return it as a :py:class:`list`.

   :param iterable: any kind of iterable object
   :return: the items from the iterator
   :rtype: :py:class:`list`

.. py:function:: liter(listable)

   Given a ``listable`` object, return it as an iterable.

   :param listable: any kind of list-like object
   :type listable: `list` or `tuple`
   :return: an iterator composed of the items from the list

.. py:function:: ituple(iterable)

   Given an ``iterable`` object, return it as a :py:class:`tuple`.

   :param iterable: any kind of iterable object
   :return: the items from the iterator
   :rtype: :py:class:`tuple`

.. py:function:: titer(tuple)

   Given a ``tuple``, return it as an iterator.

   :param tuple: any kind of python tuple
   :type tuple: `tuple`
   :return: an iterator composed of the items from the tuple

.. py:function:: itake(count)(iterable)

   Given an integer ``count``, return a closure that will consume
   that number of elements from the provided ``iterable`` and
   return them as a :py:class:`tuple`.

   :param count: a number of elements to consume
   :type count: :py:class:`int` or :py:class:`long`
   :param iterable: an iterable to consume
   :return: the items that were selected
   :rtype: :py:class:`tuple`

.. py:function:: iget(index)(iterable)

   Given an integer ``index``, return a closure that will consume
   the required number of elements from the provided ``iterable``
   in order to return the element at the requested index.

   :param count: a number of elements to consume
   :type count: :py:class:`int` or :py:class:`long`
   :param iterable: an iterable to consume values from
   :return: the item at the requested index

.. py:function:: islice(iterable, stop)
.. py:function:: islice(iterable, start, stop[, step])

   Given an ``iterable``, return an iterator which yields the
   selected values from ``start`` to ``stop``. If ``step`` is
   provided, then use its value as the number of values to skip
   when yielding values. This is similar to using the :py:func:`operator.getitem`
   function with the :py:class:`slice` class for iterators.

   :param iterable: an iterable to transform results from
   :param start: the index to start at
   :type start: :py:class:`int` or :py:class:`long`
   :param stop: the index to stop at
   :type stop: :py:class:`int` or :py:class:`long`
   :param step: the number of values to skip
   :type step: :py:class:`int` or :py:class:`long`
   :return: the selected items as an iterator

.. py:function:: imap(callable, iterable)

   Execute the provided ``callable`` against all of the elements in
   ``iterable`` returning an iterator containing the transformed
   results. This is similar to :py:func:`map` and is the same
   as the :py:func:`itertools.imap` function from Python 2.x, or the
   regular :py:func:`map` function from Python 3.x.

   :param callable: a callable python object that transforms its argument
   :type callable: `function`
   :param iterable: an iterable to transform results from
   :return: the transformed items as an iterator

.. py:function:: ifilter(crit, iterable)

   Yield each value from ``iterable`` that the callable ``crit``
   returns :py:const:`True` for. This is similar to :py:func:`filter`
   and is the same as the :py:func:`itertools.ifilter` function from
   Python 2.x, or the regular :py:func:`filter` function from Python 3.x.

   :param crit: a callable python object that returns :py:const:`True` or
                :py:const:`False` based on its argument
   :type crit: `function`
   :param iterable: an iterable to critique
   :return: the filtered items as an iterator

.. py:function:: ichain(\*iterables)

   Given a variable number of ``iterables``, concatenate all of them into
   a single iterator. This is the same as the :py:func:`itertools.chain`.
   function.

   :param \*iterables: any number of iterators
   :return: an iterator composed of all of the provided iterators executed in sequence

.. py:function:: izip(\*iterables)

   Given any number of ``iterables``, return them as an iterator that
   yields a tuple for each element passed as positional arguments to
   the function. This is similar to :py:func:`zip`, and is the same
   as the :py:func:`itertools.izip` function from Python 2.x, or the
   regular :py:func:`zip` function from Python 3.x.

   :param \*iterables: any number of iterators
   :return: the items from each iterator zipped together

.. py:function:: lslice(iterable, stop)
.. py:function:: lslice(iterable, start, stop[, step])

   Given an ``iterable``, return a :py:class:`list` containing the
   selected values from ``start`` to ``stop``. If ``step`` is
   provided, then use its value as the number of values to skip when
   returning values. This is similar to the :py:func:`operator.getitem`
   function being used on lists with the :py:class:`slice` class.

   :param iterable: an iterable to transform results from
   :param start: the index to start at
   :type start: :py:class:`int` or :py:class:`long`
   :param stop: the index to stop at
   :type stop: :py:class:`int` or :py:class:`long`
   :param step: the number of values to skip
   :type step: :py:class:`int` or :py:class:`long`
   :return: the selected list of items
   :rtype: :py:class:`list`

.. py:function:: lmap(callable, iterable)

   Execute the provided ``callable`` against all of the elements in
   ``iterable`` returning a :py:class:`list` containing the transformed
   results.  This is similar to :py:func:`map` function from Python 2.x,
   or using the :py:func:`map` function from Python 3.x and iterating
   through the result as a :py:class:`list`.

   :param callable: a callable python object that transforms its argument
   :type callable: `function`
   :param iterable: an iterable to transform results from
   :return: the transformed list of items
   :rtype: :py:class:`list`

.. py:function:: lfilter(crit, iterable)

   Return a :py:class:`list` containing each value from ``iterable`` that
   the callable ``crit`` returns :py:const:`True` for. This is similar to
   the :py:func:`filter` function from Python 2.x, or using the :py:func:`filter`
   function from Python 3.x and iterating through the result as a :py:class:`list`.

   :param crit: a callable python object that returns :py:const:`True` or
                :py:const:`False` based on its argument
   :type crit: `function`
   :param iterable: an iterable to critique
   :return: the filtered list of items
   :rtype: :py:class:`list`

.. py:function:: lzip(\*iterables)

   Given any number of ``iterables``, return them as a :py:class:`list`
   composed of :py:class:`tuple` objects for each element passed as
   positional arguments to the function. This is similar to the :py:func:`zip`
   function from Python 2.x, or the :py:func:`zip` function from Python 3.x and
   iterating through the reuslt as a :py:class:`list`.

   :param \*iterables: any number of iterators
   :return: the items from each iterator zipped together
   :rtype: :py:class:`list` of :py:class:`tuple`

.. py:function:: count(iterable)

   Given an ``iterable``, return the number of items that it contains.

   Note: This is done by consuming values from ``iterable`` which will
   modify its state. If the state of the iterator wishes to be retained, one
   can either re-create it, or make a copy of it using :py:func:`itertools.tee`.

   :param iterable: an iterator to count the elements of
   :return: the number of items that were found
   :rtype: :py:class:`int` or :py:class:`long`
