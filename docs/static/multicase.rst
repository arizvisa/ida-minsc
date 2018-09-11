.. _multicase-intro:

Functions and Objects
=====================

Python (:ref:`1<multicase-references>`) is a dynamically typed object-oriented language
which revolves around "duck-typing" (or lack of typing) to accomplish its
various needs. Despite this project being written in Python, it uses
functions and objects entirely different from the way Python is typically
used.  Taking some ideas from Perl (:ref:`2<multicase-references>`), this project
allows there to be multiple variations of a function depending on the types
that are provided to a function as parameters. These are referred to as
multi-cased functions. The author is gratious to Talos/Cisco (:ref:`3<multicase-references>`) 
for providing him the resources and time in order to develop this component.

Typically when calling a function or an object in Python, the parameters and
schema for the object must be known. Objects must be constructed and then
customized which will then allow a user to call into its methods or pass them
to other functions in order to act on them. Unfortunately this typically
requires a user to review documentation or otherwise become intimately familiar
with this information.

In order to simplify the usage of IDAPython modules, this project changes
the semantics of these two concepts in Python (Functions and Objects) into
forms that allow one to group similar function together in various ways.

The semantics of Python objects are changed so that they're instead used
to group functions that are similar whilst using the :py:func:`classmethod` and
:py:func:`staticmethod` decorators to make methods appear is simple functions.
In essence, this transforms an object definition into a namespace which can
contain functions that perform similar tasks. By grouping functions like this
it is hoped that this will greatly simplify the required knowledge in order
to utilise the components of this project. Please see :ref:`multicase-namespaces` for
more information.

Another concept is implemented to assist with simplifying the required knowledge
in order to utilise a Python library. These are reffered to as multi-cased
functions. Multi-cased functions allow for the semantics of a function to change
based on the types of the parameters are passed to it. This allows a user to
just need to recall what it is that they wish to do, and then feed which
parameters they currently have to it. A multi-cased function will then take
these parameters, identify which variation of the function to call based on the
types of the parameters passed, and then dispatch to the correct function. Please
refer to :ref:`multicase-functions` for more details.

.. _multicase-references:
.. rubric:: References

1. `The Python Programming Language <https://www.python.org/>`_
2. `The Perl Programming Language <https://www.perl.org/about.html/>`_
3. `Cisco Talos <https://www.talosintelligence.com/about>`_

.. _multicase-namespaces:

----------
Namespaces
----------

As was prior mentioned, this project heavily uses a concept known as namespaces
which changes the semantics of the way objects are used. Although this project
provides a number of objects for things such as structures or registers, the
majority of object definitions are actually treated as namespaces. This is done
by simply abusing the class definition in python to create an object, overwriting
the :py:attr:`__new__` method so that it may be treated as a function, and then
decorating any methods associated with the object with either :py:attr:`classmethod`
or :py:attr:`staticmethod`. An example of this follows::

   > class namespace(object):
         def __new__(cls, offset):
             return offset + idaapi.get_imagebase()
         @classmethod
         def translate(cls, address)
             return address - idaapi.get_imagebase()
   >

Defining an object in this manner allows for the different methods that are
available in an object to be treated simply as functions discarding the object
that is bound to the method during construction of the object. This changes
the semantics of objects and methods entirely. When calling :py:func:`help` on
these namespaces, the functions available can then be listed.

This style of object is used in a number of modules such as :py:mod:`database`,
:py:mod:`function`, or :py:mod:`enumeration`. Please review :ref:`multicase-examples-namespace`
for some examples of using namespaces.

.. _multicase-functions:

--------------------
Multicased functions
--------------------

Functions also have different semantics by implementing them in a form that the
author refers to as "multicased". What this means is that a function can have
numerous variations. The variation to actually call is determined by which types
a user chooses to pass to said function. This allows for one function to perform
more than one task depending on the user's intentions. This idea is heavily
borrowed from some Perl modules.

When defining a multi-cased function, each version must be registered with the
types required to call it. This is so the documentation for each function
variation can include the prototype in its autodoc. Multicased functions are
defined within all the modules in this project and within namespaces within each
module. An example of how one might be defined is::

   >@multicase(ea=(int, long))
   >def myfunc(ea):
   >    '''Takes an integer'''
   >    print 'received an integer', ea
   >
   >@multicase(name=str):
   >def myfunc(name):
   >    '''Takes a string'''
   >    print 'received a string', name
   >

This results in the documentation for the :py:func:`myfunc` function to appear
as::

   >help(myfunc)
   Help on function myfunc in module database:

   myfunc(*arguments, **keywords)
       myfunc(ea=int|long) -> Takes an integer
       myfunc(key=basestring) -> Takes a string
   >
   
Some examples of calling these types of functions are at :ref:`multicase-examples-functions`.

.. _multicase-examples-namespace:

---------------------
Examples -- Namespace
---------------------

As prior mentioned, the are numerous modules within this project that utilise
namespaces such as :py:mod:`database`, or :py:mod:`function`. In the following
examples, we will use the :py:class:`database.config` namespace to extract
information about the database::

   > print database.config.filename(), database.config.idb()
   ...
   > print database.config.path()
   ...

To get information about the functions in the database, we can use the
:py:class:`database.functions` namespace to list them::

   > print database.functions.list()
   ...
   > for ea in database.functions():
   ...

Within the :py:mod:`function` module are namespaces used to identify information
about basic blocks within a function, or identify the chunk that is at a particular
address::

    > for left, right in function.blocks(ea):
          print "Left: %x Right: %x"% (left, right)
    >
    > top = function.chunk.top(ea)

.. _multicase-examples-functions:

---------------------
Examples -- Functions
---------------------

Multi-cased functions are used heavily within this project, as described
previously, this simplifies usage of functions and allows for a user to
only have to think about what it is they're trying to do. At this point they'll
just need to identify the function they wish to call and then provide the
parameters that "make sense".

Calling a function used for naming, for example, could mean one of two things.
To set the name for an address, or to return the name for an address::

   > res = database.name(ea)
   > print 'Name for address %x is %s'% (ea, res)
   >
   > newname = 'mynewname'
   > print 'Setting name to %s'% newname
   > database.name(ea, mynewname)

If no address is provided to :py:func:`database.name`, then the current address
will be assumed. If :py:obj:`None` is specified as a name, then the name will
be removed::

   > res = database.name()
   > print 'Name for the current address is %s'% res
   >
   > oldname = database.name(None)
   > print 'Name at current address used to be: %s'% oldname 

If a user wants to fetch a function and they're not sure of the type of the
parameter they received, the :py:func:`function.by` multicased function supports
a variety of ways to receive the type for a parameter.

To return the current function::

   > f = func.by()

To return the function by address (integer)::

   > f = func.by(ea)

To return a function by name (string)::

   > f = func.by(name)

There are a number of these types of functions available. Please review the
:py:func:`help` of the particular function to see all of the variations of
a multicased function.
