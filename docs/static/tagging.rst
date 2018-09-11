.. _tagging-intro:

Tagging and the querying of the tag cache
=========================================

This project provides an interesting interface based on some research
[:ref:`1<tagging-references>`] that was done by one of the authors at the
Ekoparty conference in 2011. The author is gratious to TippingPoint/3com/HP
for providing him the resources and time in which to do this research.

Typically when recalling addresses in an IDA database, users will use one of the
already existing facilities for navigation. This includes things such as names or
marks. At this point, the user will utilize names or comments in order to recall
what present work was being done at a particular location. One of the unfortunate
attributes of this is that it is of variable difficulty to share this knowledge
with other users. This can be any number of reasons related to inconsistency, but
it's suggested that this is because each reverser has a different personality as
well as different intentions for each reversing project.

In order to improve this methodology that users of IDA Pro tend to gravitate
towards, a system based on the concept of treating IDA as a key-value store
was introduced. This system abuses IDA's comments in order to allow a user
to programatically categorize information that a user might have inferred
during their reversing endeavor in the hopes to improve the way that a user
navigates the database and shares information with other users.

This system allows for a user to store a primitive python object within a comment
which can then be decoded back into its original type thus allowing a user to
store and retrieve a python object associated with an address. This is described
in detail later at :ref:`tagging-encoding`. These values can then later be queried
in order to reference the addresses of the types that the user has marked. This
is also described in detail at :ref:`tagging-querying`.

Using a mechanism such as this facilitates a user to be able to quickly tag
a number of related functions or addresses, and perform some sort of
processing against them. The work required to perform tasks such as
tagging all the handlers related to some binary CGI, tagging various
instructions according to some attribute in order to later color them,
tagging an instruction address with a breakpoint command to later feed
to a debugger, or even simply tagging the results of a hit-tracer for later
review is greatly simplified.

.. _tagging-references:
.. rubric:: References

1. [Eko7-2011] -- `Portnoy, Aaron, and Ali Rizvi-Santiago. Experiments Using IDA Pro as a Data Store. Ekoparty, 21 Sep. 2011, www.youtube.com/watch?v=A4yXdir_59E <https://www.youtube.com/watch?v=A4yXdir_59E>`_

.. _tagging-types:

---------
Tag types
---------

Comments are hence split up into two parts that compose a dictionary, these are
the "key" and the "value". Each location or object that can be tagged, will
include a specially formatted comment that isolates these components so that
they can later be queried. These tags are then cached in a netnode so that they
be easily queried (see :ref:`tagging-querying`) to then later revisit or extract
information to process.

In essence, these tags are grouped into two different types. One of which
is the "global" tag. A "global" tag is used to store attributes about a
particular global such as a function, or an address outside of a function.
These tags can then be used to search the database for something of reference
which is a significant improvement to the way that marks work, and works around
the limitation that a database has on its limited number of marks.

The other type of tag is known as a "contents" tag. A "contents" tag is used to
store attributes about an address that is inside a function and is commonly
associated with the instructions that belong to a function. This allows one to
store attributes describing the semantics of what is being reversed at a given
address within a function.

When querying a tag, it is important to distinguish between which tag the user
wishes to search through. This is described in detail at :ref:`tagging-querying`.
Some examples of querying are described at :ref:`tagging-examples-querying`.

.. _tagging-format:

-----------
Tag formats
-----------

In order to facilitate support tags and still allow for a user to quickly
comprehend the intention of a tag. Tags are actually encoded within comments
at the address that is "tagged". This is done by encoding the tag using a
specific newline-delimited format.

This format represents the attributes commonly associated with a dictionary. If
a user chooses to not use this special format, then when utilizing the tag api
the entire comment is treated as an "empty" tag using an empty string as its key.
Please see :ref:`tagging-examples` for an example of this.

Due to a limitation of IDA with regards to the size of comments and this abuse
of using comments to store tag values, tags have a limited size. If the user
wishes to store a long tag at an address it is necessary for them to break it
down into smaller components that do not exceed the maximum number of characters
that IDA allots for each comment or to use another storage mechanism entirely.
It is recommended by the author to only store light information and if a large
value needs to be stored, that a user should really just use another storage
mechanism. Long (and hidden) tags may be supported in the future, however.

The format for a tag to an address within the database can look like the
following:

.. code-block:: tasm

    call    sub_58B674      ; [note] this calls some parser of some kind
                            ; [mark] (0x4, 'this is the 4th mark')
                            ; [break] .printf "calling sub_58b674!\\n"; dc @esp L4; p "r @eax"
                            ; [references] set([0x58b012, 0x581061, 0x501212])
                            ; [floating-value] float(0.500000)

When applying a tag to a function, this can look like the following:

.. code-block:: tasm

    ; [node-type] leaf
    ; [note] this seems to do something different based on the file type?
    ; [synopsis] returns an unmodified @eax if by(ap_0-9) is zero, otherwise it returns @edx
    ; [input] {'%eax' : 'p_bufferObject?', '%edx' : 'v_offset'}
    ; Attributes: bp-based frame

    sub_5801F4      proc near
    ...

If a user chooses to not explicitly use the tagging API and wishes to use IDA's
regular commenting interface instead, they will simply need to specify the key
name with brackets ("[" and "]") with the value for the key immediately following.
This should look similar to:

.. code-block:: none

    [synopsis] this is what i suspect this function is doing
    [note] this is some note or whatever
    [numbers] set([0x0, 0x1, 0x2, 0x3, 0x4, 0x5])
    [dict] {'key1' : 'value1', 'key2' : 0x2a}
    [float] float(2.71828182846)
    [linked] 0x51b2080

IDA supports two different types of comments within the database. A comment can
be either a "repeatable" comment, or a "non-repeatable" comment. By default when
tagging, this type of comment is automatically chosen based on whether the address
belongs to a function, or a global. When fetching a tag, however, both types
of comments are combined whilst giving priority to the automatically chosen
comment type.

When tagging an address belonging to a function's contents, the default comment
type of "non-repeatable" will be chosen. When tagging to a global, or an actual
function, the comment type that will be chosen will be "repeatable." This choice
is hidden behind the tagging API.

.. _tagging-encoding:

---------------------
Tag encoding/decoding
---------------------

In order to allow a user to store and retrieve a primitive python types
whilst still allowing for them to visually read the contents of the type,
different python types are encoded in particular ways.

Integral types, and strings are specially encoded. Integers are always stored
as hexadecimal numbers in order to facilitate a user double-clicking on it to
have IDA navigate to this address. (This assumes that the user is capable of
reading hexadecimal. This is an integral part of reversing and it is highly
recommended that the user familiarizes his or herself with this numerical
format).

Strings are escaped in a few ways, replacing characters that might
interfere with the :ref:`tagging-format` with their backslash-prefixed
equivalents. When retrieving a string encoded within a tag, these
characters will then be decoded into their original forms.

Types such as the :py:class:`list`, :py:class:`tuple`, or :py:class:`dict`,
are typically encoded as the :py:func:`repr` of their instance. This allows
the usage of :py:func:`eval` to decode it back into a type. The iterable
types such as :py:class:`list` and :py:class:`tuple`, however, are iterated
through in order to convert integers into their hexadecimal equivalents
similar to the way integers are encoded.

Custom python objects, iterators, or callables are unfortunately not supported
as tags. If the user really wishes to store these types, however, it is possible
for one to serialize a type, and then store it as a string inside a tag. As
previousy mentioned, however, this is not recommended and it is suggested by
the author that a user use an alternative storage mechanism.

If a user wishes to go against these recommendations, however, once can
store an arbitrary type by using either :py:func:`pickle` or :py:func:`marshal`
to serialize their object, applying some compression to the resulting data,
followed by encoding into a character set using "base64", encoding to hex,
or some similar mechanism.

.. _tagging-querying:

-------------
Querying tags
-------------

When initially creating a database, this project will hook IDA in order to
identify a good time to pre-build the tag cache. Once IDA has finished its
analysis, the tag cache will begin to be built. This consists of iterating
through the different places that can be tagged and reference counting whats
available. By default all comments that do not fit the correct format
(see :ref:`tagging-format`) will be internally treated as the "empty" tag.

Once the creation of this cache has been completed, this project will keep
track of any comments and tags that are created by the user and automatically
update the cache. This will then allow a user to quickly query the tags that
they have marked up in a database. If this cache gets corrupted in some way,
one can repair the cache by using the module :py:mod:`tagfix`. Please see
:ref:`tagging-modules-tagfix` for more information.

When querying a tag, as mentioned before, the tag's type is of significant
importance. This is due to there being two different ways of querying them
based on the type.

Within the :py:mod:`database` namespace are the functions :py:func:`database.select`,
and :py:func:`database.selectcontents`. The :py:func:`database.select` function is
used for querying all of the global tags as well as any tags made explicitly to a
function.

The :py:func:`database.selectcontents` function, however, is used to return the
functions that contain the desired tags within the function's contents. Once the
functions in the database have been identified, the user can then use
:py:func:`function.select` function to query the contents of a function for
specific tags.

When calling either :py:func:`database.select`, or :py:func:`function.select`,
an iterator is returned. This iterator yields a tuple containing the address the
tag was found at, as well as a dictionary containing the values of the tags that
were queried. This then allows a user to act on the tags such as emitting them
to the console, or storing them in another data structure. See
:ref:`tagging-examples-querying-globals`
for such an example.

When calling :py:func:`database.selectcontents`, however, an iterator that returns
the function and the tag membership is returned. Each iteration of this iterator
will yield the address of the function, followed by a :py:class:`set` of the
contents tags that were found in the function. This tuple can then be immediately
passed to :py:func:`function.select` in order to iterate through all the contents
tags matched within the database. See :ref:`tagging-examples-querying-content`
for how a user can use this.

Each of these functions takes a variable number of parameters as well as boolean
types that specify whether to require specific tags in order to return a result,
or optionally include tags if they're defined for an address. If the keyword
:py:data:`And` is specified as an argument, then any of the tags specified are
required in order to yield an address. If the keyword :py:data:`Or` is specified
then this informs the function to optionally include any tags that were requested
if they are defined for the address that is returned.

.. _tagging-usage:

-------------------------
Storage/Retrieval of tags
-------------------------

The other aspect of the tag api is the programmatic storage and retrieval
of tags defined at a particular address. This functionality is performed
by either the :py:func:`database.tag` or the :py:func:`function.tag`
functions. It's important to distinguish that the namespace these functions
are contained in, do not distinguish whether a tag is a "global" or a
"contents" tag. As described in the documentation for the :py:mod:`database`,
the primary type for functions declared therein is considered the address
where for :py:mod:`function`, the primary type is the considered the function.

This implies that :py:func:`database.tag` is used to tag a specific address
belonging to a function's contents or a global, whereas :py:func:`function.tag`
is used to tag the function itself. This is demonstrated at :ref:`tagging-examples`.

When executing either of these tag functions, there are 4 variations of each
of them. The first variations is when only a tag name is provided. This
variation will return the value of the tag at a given address and is thus used
for reading a particular tag from an address. This looks like the following
for :py:func:`database.tag`::

   > value = database.tag(ea, 'mytagname')
   > print type(value)

The next variation takes a tag name and its value and is thus used to write
a value with the specified tag name at an address within the database. If a
tag is being overwritten, this variation will return the original value
of the tag that was overwritten. Some examples of how this can look like for
for the :py:func:`function.tag` function::

   > oldvalue = function.tag(ea, 'synopsis', 'this function is recursive')
   > print oldvalue
   >
   > oldvalue = function.tag('object', 'TList')
   >
   > oldvalue = function.tag('marks', [0x51b0102, 0x51b0208, 0x51b021f])

The third variation is responsible for removing a tag at a given address.
This is done by providing a tag name along with the python type :py:obj:`None`.
When removing a tag name, the value of the tag name is always returned. This
allows a user to save the tag name in case they wish to re-apply it elsewhere.
Here's how this can look like for the :py:func:`database.tag` function::

   > oldvalue = database.tag(ea, 'removethis', None)
   >
   > oldvalue = database.tag('object-type', None)
   >
   > res = {}
   > for ea in function.iterate():
         res[ea] = database.tag(ea, 'note', None)
   > print repr(res)

The final variation is responsible for returning all of the tags at a given
address. This is done by only providing a location without including any
specific tag name or anything. At this point, a dictionary will be returned
which a user can use to enumerate all of the tags for an address or to even
check for membership of a tag. Using :py:func:`function.tag`, this can look
like::

   > res = function.tag()
   > print "Current function's tags: %r"% res
   >
   > res = function.tag(ea)
   >
   > res = {}
   > for ea in database.functions():
         res[ea] = function.tag(ea)
   > print "All the tags in the world: %r"% res

.. _tagging-modules:

-----------
Tag modules
-----------

There are a few modules that are provided within this project that allows one
to interact with all of the tags defined in a database. This can be used to
perform various tasks such as exporting all the tags within a database to
serialize for later importing, translating tags within the database in order
to match up to another database, etc. These modules are available via the
:py:mod:`custom` namespace.

.. _tagging-modules-tags:

Tag modules -- tags
*******************

The custom :py:mod:`tags` module allows for one to export or import all of the
tags within a database. Please review the documentation for :py:mod:`tags` for
more about the capabilities of this module.

.. _tagging-modules-tagfix:

Tag modules -- tagfix
*********************

The custom :py:mod:`tagfix` module allows for one to rebuild the tag cache if
the cache somehow gets corrupted in some way (due to IDA crashing whilst trying
to write a netnode) or if a database did not complete it's initial creation of
the tag cache.

This module exposes a number of functions that can be used to rebuild the tag
cache entirely. Please review the documentation for :py:mod:`tagfix` for more
information on how to do this.

.. _tagging-examples-querying:

--------------------
Examples -- Querying
--------------------

As described in the previous sections, tags have 2 different types and thus have
2 different ways of querying them. "Global" tags can represent a tag associated
with a given function or a global address, whereas "Contents" tags are associated
with an address belonging to a function.

(In the following examples, format strings are used. Although format-specifiers
are a lot more flexible and poweful, they might not be familiar to the average
user. Apologies in advance.)

.. _tagging-examples-querying-globals:

Examples -- Querying "Global" tags
**********************************

Return all of the global addresses and functions that have the tag "note" applied
to it and output them to the IDAPython console::

   > for ea, tags in database.select('note'):
         print hex(ea), "note: %s"% (tags['note'])
   >

Return all of the global functions that have the tag "synopsis", with the
optional tag "note" applied to it::

   > for ea, tags in database.select('synopsis', Or=('note',)):
         print "Function: %x -- %s (note: %r)"% (ea, tags['synopsis'], tags.get('note', 'no notes found!'))
   >

Return all addresses that have both the required tags "object-name", and "object-size",
and include any tags that have "object-note" defined::

   > for ea, tags in database.select(And=('object-name', 'object-size'), Or=('object-note',)):
         print "Address: %x"% ea
         print "Name/Size: %s/%d"% (tags['object-name'], tags['object-size'])
         if 'object-note' in tags:
             print "Comment: %s"% tags['object-note']
         continue
   >

Return all the comments defined globally within the database that are not specially formatted,
by querying the "empty" tag::

   > for ea, tags in database.select(''):
         print "Address: %x"% ea
         print "Comment: %s"% tags['']
   >

.. _tagging-examples-querying-content:

Examples -- Querying "Contents" tags
************************************

Return all of the contents tags defined within the current function::

   > for ea, tags in func.select():
         print "Ea: %x Tags: %r".format(ea, tags)
   >

Return any instances of the "note" tag defined with a particular function at :py:data:`ea`::

   > for ea, tags in func.select(ea, 'note'):
         print "Ea: %x Note: %s"% (ea, tags['note'])
   >

Iterate through the contents tags defined within the database looking for the
tag "mark"::

   > for ea, result in db.selectcontents('mark'):
         for ea, tags in func.select(ea, *result):
             print "Mark found at %x: %s"% (ea, tags['mark'])
         continue
   >

Another way to perform the above due to the result returned from :py:func:`database.selectcontents`
being the same as the input to :py:func:`function.select`::

   > for res in db.selectcontents('mark'):
         for ea, res in func.select(*res):
             print "Mark found at %x: %s"% (ea, tags['mark'])
         continue
   >

Iterate through all the addresses in the function :py:data:`ea` tagged with "mark" and also
include any "note" tags::

   > for ea, res in func.select(ea, And=('mark',), Or=('note',)):
         if 'note' in res:
             print "Noted mark found at %x -> %s"% (ea, res['note'])
         else:
             print "Mark found at %x"% (ea)
         continue
   >

To list all of the contents tags that have been used in the database::

    > for ea, res in db.selectcontents():
          print "Function %x has the tags: %r"% (res)
    >

This same functionality is also provided within the :py:mod:`tags` module
within the :py:mod:`custom` namespace::

    > import custom
    > res = custom.tags.list()
    > print repr(res)

.. _tagging-examples:

------------------------------------
Examples -- Application or Retrieval
------------------------------------

The other aspect of the tag api is the application and retrieval of tags at
a particular address. As was explained bit in :ref:`tagging-usage`, this
functionality is performed by either :py:func:`database.tag` or :py:func:`function.tag`.

To tag all of the marks inside the database::

   > for ea, descr in db.marks():
         db.tag(ea, 'mark', descr)
   >

To fetch the empty tag at the current address and then print it::

    > res = db.tag('')
    > print repr(res)

To export all of the tags for anything tagged "synopsis" in the database::

   > res = {}
   > for ea, tags in db.select('synopsis'):
         res[ea] = db.tag(ea)
   >

To rename all of the "empty" tags in a function to "comment"::

   > for ea in func.iterate(f):
         if '' in db.tag(ea):
             old = db.tag(ea, '', None)
             db.tag(ea, 'comment', old)
         continue
   >

To obnoxiously tag every function with an index::

   > for i, ea in enumerate(db.functions()):
         func.tag(ea, 'index', i)
   >

To prefix all tags with the current username using the cache::

   > import getpass
   > username = getpass.getuser()
   >
   > print "transforming global tags"
   > for ea, res in db.select():
         for k, v in res.iteritems():
             db.tag(ea, k, None)
             db.tag(ea, "%s.%s"% (username, k), res[k])
         continue
   >
   > print "transforming contents tags"
   > for res in db.selectcontents():
         for ea, res in func.select(*res):
             for k, v in func.select(*res):
                 db.tag(ea, k, None)
                 db.tag(ea, "%s.%s"% (username, k), res[k])
             continue
         continue
   >

-------------------
Suggested tag names
-------------------

When using tag names within a database, any tag name can be used. Tags that
are wrapped with double-underscores ("__") may also have additional useful
side effects. Although any tag names can be used, it's recommended by the
author to choose consistent names to simplify exchanging knowledge with
other users. Some recommended names can be:

    - ``synopsis`` -- The potential semantics of a reversed function
    - ``__color__`` -- The RGB color of an item at a particular address
    - ``__name__`` -- The name associated with an address
    - ``note`` -- Any general notes about an address determined the the user
    - ``marks`` -- A set containing any marks contained within a function
    - ``mark`` -- A string containing the description for a mark at an address
    - ``object`` -- The name or address(es) of a related vtable applied to a function that is used to call a method.
    - ``input`` -- A dictionary mapping register arguments to a function
    - ``return`` -- A list containing the registers that a result is composed of
