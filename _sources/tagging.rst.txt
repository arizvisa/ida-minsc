.. _tagging-intro:

Tagging and the querying of the tag cache
=========================================

This project provides a unique interface that is based on some research
[:ref:`1<tagging-references>`] that was done by the authors at the Ekoparty
conference in 2011. The authors are grateful to TippingPoint/3com/HP for
providing them the resources and time in which to do this research.

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

------------------------------------
What is tagging and why is it useful
------------------------------------

Tagging basically allows for a user to store a primitive python object within a
comment, which can then be decoded back into its original pythonic type thus
allowing a user to store and retrieve a python object associated with an address.
This is described in detail later at :ref:`tagging-encoding`, but these values
can then be queried later in order to assist referencing the address of some
locations that the user has marked. This is also described in detail at
:ref:`tagging-querying`.

The existence of such a mechanism should enable a user to be able to quickly tag
and group related artifacts within the database in order to serialize or perform
some kind of collective processing against them. The visibility of these tags
also allows a user to quickly edit or modify special cases that their initial
query did not annotate correctly. Since the contents of these tags are native
Python types, these may also be serialized or translated in order to migrate
them between databases or into another Python interpreter.

This should greatly reduce the amount of work that is required in order to perform
a variety of tasks such as labelling all of the handlers within a CGI binary,
highlighting the basic blocks of a path through a control-flow-graph or later using
them to generate breakpoints that should be consumed by a debugger, enumerating
the 3rd parameter of some logging function in order to annotate a list of functions
with their correct name, or tagging arbitrary instructions or their operands
using a particular attribute. Thus later the user can either color them or annotate
them in a different way for improved visibility.

.. _tagging-references:
.. rubric:: References

1. [Eko7-2011] -- `Portnoy, Aaron, and Ali Rizvi-Santiago. Experiments Using IDA Pro as a Data Store. Ekoparty, 21 Sep. 2011, www.youtube.com/watch?v=A4yXdir_59E <https://www.youtube.com/watch?v=A4yXdir_59E>`_

.. _tagging-build:

----------------------
Building the tag-cache
----------------------

When creating an IDA database, the plugin will hook IDA in order to determine
when the auto-analysis queue is empty. When this happens, this plugin will
proceed to build the tag cache and its index. When building the tag cache,
the plugin will output the number of functions completed relative to the total
number of defined functions so that the user may see how much work is left
for the progress to complete. This process may be interrupted by the user, bu
it is recommended by the author that the user lets this process complete if
they wish to query the tags in any way. The current progress of this process
will be in the form of a progress bar which looks like the following.

.. image:: _images/tagging-progress.png
   :alt: image of progress bar
   :align: center

Once the tag cache and its index has been generated, the database is ready to
be modified and queried. If the user wants to rebuild the tag cache, or to
build a cache for a database that has been previously analyzed. Please see
:ref:`tagging-modules-tagfix` for more information.

.. _tagging-types:

---------
Tag types
---------

Tags split up comments into the two parts that compose a dictionary, these are
the "key" which is always referenced as a string and the "value" which can be
any one of the basic Python types. These tags will be displayed as a comment
alongside their target so that the user may review them or change them as needed.
These comments are specially formatted in a way that is easy for the user to
edit as a multi-line comment. The key of each created tag is also cached and
indexed in order to allow the user to quickly query it (see :ref:`tagging-querying`).
This allows the user to later revisit or extract reversing artifacts that they
wish to further process or display later.

In essence, tags are used to reference information that is associated with an
address. Thus, these tags are grouped into two different types. One of which
is the "global" tag. A "global" tag is used to store attributes about an address
such as a function, or an address that is **outside** of a function. These tags
can be used to perform a global search of the database for something of reference
which is a significant improvement to the way that marks work. This has the added
effect of working around the limitation of a database in which it has a limited
number of marks.

The other type of tag is known as a "contents" tag. A "contents" tag is used to
store attributes about an address that is **inside** a function and is commonly
associated with the instructions that belong to a function. This allows one to
store attributes describing the semantics of what is being reversed at a given
address within a function.

There are other places that tags may be applied in order to select certain parts
of the database that the user may wish to query. As such, there is also support
for tagging structures (that are explicitly defined or part of a function frame)
or their individual members. This can be useful if the user wishes to remember
specific structures or fields for scripting later.

When querying a tag, it is important to distinguish between whether the user
wishes to query a "global" tag or a "contents" tag when searching. The difference
in methodology or searching between these is described in detail at :ref:`tagging-querying`.
Some examples of querying the different types are also described at :ref:`tagging-examples-querying`
and :ref:`tagging-examples-querying-structures` with regards to structures.

.. _tagging-format:

-----------
Tag formats
-----------

In order to facilitate support for tags and still allow for a user to quickly
review the intention of a particular tag. Tags are actually encoded within
comments at the address that is "tagged". This is done by encoding the tag using a
specific newline-delimited format that is reminiscent of a Python dictionary.

If the user chooses to not use this format or is using a database that does not
follow this format, the comments within the database will then be treated as an
"empty" tag. If the user wishes to still query these tags, the user will need to
use the empty string as their key. Please see :ref:`tagging-examples` for an
example of this of how to use this.

Due to a limitation of IDA with regards to the size of comments and this abuse
of using comments to display the values of a tag to the user, tags have a limited
size. If the user wishes to store a long tag at an address it is necessary for them
to break it down into smaller components that do not exceed the maximum number of
characters that IDA allows when displaying each comment. There is also the other
option of using another storage mechanism entirely as tags are intended for
allowing the user to visibly see contextual information alongside the things that
they are reversing. Hence, it is recommended by the author to only store light
information that is easy to read and quick to edit. If a larger value needs to
be stored, then the user should really just use another storage mechanism.
Tags of a large length may eventually be supported in the future, but will likely
remain hidden due to the constraints of IDA's ability to display them.

The format for a tag associated with an address within the database should look
like the following:

.. code-block:: tasm

    call    sub_58B674      ; [note] this calls some parser of some kind
                            ; [mark] (0x4, 'this is the 4th mark')
                            ; [break] .printf "calling sub_58b674!\\n"; dc @esp L4; p "r @eax"
                            ; [references] set([0x58b012, 0x581061, 0x501212])
                            ; [floating-value] float(0.500000)

Similarly, when applying a tag to a function the same format should be followed.

.. code-block:: tasm

    ; [node-type] leaf
    ; [note] this seems to do something different based on the file type?
    ; [synopsis] returns an unmodified @eax if by(ap_0-9) is zero, otherwise it returns @edx
    ; [input] {'%eax' : 'p_bufferObject?', '%edx' : 'v_offset'}
    ; Attributes: bp-based frame

    sub_5801F4      proc near
    ...

If a user chooses to not explicitly use the tagging API and wishes to use IDA's
regular comment interface instead, they will simply need to specify the name of
the tag with brackets ("[" and "]") immediately followed by the value that they
wish to associate with the tag. This should look fairly similar to the following:

.. code-block:: none

    [synopsis] this is what i suspect this function is doing
    [note] this is some note or whatever
    [numbers] set([0x0, 0x1, 0x2, 0x3, 0x4, 0x5])
    [dict] {'key1' : 'value1', 'key2' : 0x2a}
    [float] float(2.71828182846)
    [linked] 0x51b2080

IDA supports two different types of comments within the database. These are a
"repeatable" or a non-repeatable" comment. By default when tagging, the type of
comment is automatically chosen based on whether the address belongs to a
function, or a global. When fetching a tag, however, both types of comments are
combined whilst giving priority to the automatically chosen comment type.

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
previously mentioned, however, this is not recommended and it is suggested by
the author that a user uses an alternative storage mechanism.

If a user wishes to go against these recommendations, however, one can
store an arbitrary type by using either :py:func:`pickle` or :py:func:`marshal`
to serialize their object, applying some compression to the resulting data,
followed by encoding into a character set using "base64", encoding to hex,
or some similar mechanism.

.. _tagging-querying:

-------------
Querying tags
-------------

When initially creating a database, this project will hook IDA in order to
identify the correct time to pre-build the tag index. Once IDA has finished its
analysis, the tag cache will begin to be built. This consists of iterating
through the different places that can be tagged and distinguishing what IDA
has done. This way when the location is later modified or queried, the plugin
will be able to distinguish a user annotation from an annotation caused by
IDA's initial analysis. By default all comments that do not fit the correct 
format (see :ref:`tagging-format`) will be treated as the "empty" tag.

Once the creation of this index has been completed, the plugin will keep
track of any comments and tags that are created by the user and automatically
update the index as needed. This will then allow a user to quickly query the
tags that they have marked up in a database. If the index gets corrupted in some
way, one may repair it by using the module :py:mod:`tagfix`. If this situation
happens to the user, please refer to :ref:`tagging-modules-tagfix` for more
information or contact the author for assistance.

When querying a tag associated with an address, as mentioned before, the tag's
type is of significant importance. This is due to there being two different
ways of querying them based on the type due to the address being either associated
with a function or a global address that is not associated with a function.

Within the :py:mod:`database` namespace are the functions :py:func:`database.select`,
and :py:func:`database.selectcontents`. The :py:func:`database.select` function is
used for querying all of the global tags as well as any tags made explicitly to a
function. The :py:func:`database.selectcontents` function, however, is used to
return the functions that contain the desired tags within the function's contents.
Once the functions in the database have been identified, the user can then use
:py:func:`function.select` function to query the contents of a function for
specific tags.

Similarly, if the user wishes to query any structures or members they may have
defined within their database, the :py:mod:`structure` namespace includes the
:py:func:`structure.select` function and :py:func:`structure.members_t.select`
method. These can be used to select a specific structure for serialization
or a member that they would like to extract information from to use outside
of their database.

When calling either :py:func:`database.select`, :py:func:`function.select`,
:py:func:`structure.select`, or :py:meth:`structure.members_t.select` an iterator
is returned. This iterator yields a tuple containing the address, structure, or
member that the chosen tag was found at, as well as a dictionary containing the
values of the tags that were queried. This then allows a user to act on the tags
such as emitting them to the console, or storing them within a serializeable data
structure. See :ref:`tagging-examples-querying-globals` for such an example.

When calling :py:func:`database.selectcontents`, however, its iterator will return
a tuple composed of the function address and the discovered tags as a :py:class:`set`.
This allows the user to identify the functions that which contain a particular set of
tags and can be directly passed to :py:func:`function.select` in order to iterate
through all of the contents tags that were matched. Please review the example at
:ref:`tagging-examples-querying-content` for how a user may use this.

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

The other aspect of the tagging api is the programmatic storage and retrieval
of tags defined at a particular address. This functionality is performed
by either the :py:func:`database.tag` or the :py:func:`function.tag`
functions. It's important to distinguish that the namespace these functions
are contained in, do not distinguish whether a tag is a "global" or a
"contents" tag.

As specified in :py:mod:`database`, the primary type that is typically passed
to its functions is an address. This implies that :py:func:`database.tag` can
be used to tag an address. This address may belong to a function's contents
or a global address. :py:func:`function.tag`, however, is used to tag the
function itself. This is demonstrated at :ref:`tagging-examples`.

This implies that :py:func:`database.tag` is used to tag a specific address
belonging to a function's contents or a global, whereas :py:func:`function.tag`
is used to tag the function itself. This is demonstrated at :ref:`tagging-examples`.

When executing either of these tag functions, there are 4 variations of each
of them that depend on the number and types of arguments that one passes to
them. The first variation takes a tag name and a value and is thus used for
writing a particular tag to the database. If a tag is being overwritten, this
variation will return the original value. Some examples of what this can
look like for :py:func:`function.tag`::

    > oldvalue = function.tag(ea, 'synopsis', 'this function is recursive')
    > print oldvalue
    >
    > oldvalue = function.tag('object', 'TList')
    >
    > oldvalue = function.tag('marks', [0x51b0102, 0x51b0208, 0x51b021f])

The next variation occurs when only the tag name is provided. This variation
will return the value of the tag at a given address and is thus used for
reading a particular tag from the database. This looks like the following for
:py:func:`database.tag`::

    > value = database.tag(ea, 'mytagname')
    > print type(value)

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

-----------------------------------
"Explicit" and "Implicit" Tag Names
-----------------------------------

When using tag names within a database, any tag name can be used. Tags that are
wrapped with double-underscores ("__") may also have additional useful side
effects and are referred to as "implicit" tags. In most cases, these "implicit"
tags are **only** indexed after IDA has finished processing the database. Thus
these can be queried in order to identify changes to the database that have been
made by the user or through further analysis by IDA Pro. Some of the implicit
tags that are currently available are as follows:

+------------------+-----------------------------------------------------------+
| ``__color__``    | The RGB color of an item at a particular address          |
+------------------+-----------------------------------------------------------+
| ``__name__``     | The name associated with an address, structure/frame, or  |
|                  | member. It also has the additional effect of only being   |
|                  | indexed if the location has been explicitly named after   |
|                  | the database has been processed by IDA                    |
+------------------+-----------------------------------------------------------+
| ``__typeinfo__`` | The type information that was applied to an address,      |
|                  | structure, or member. It has the added effect of only     |
|                  | being indexed if it was explicitly created or applied to  |
|                  | an address, structure, or member through type propagation |
+------------------+-----------------------------------------------------------+

Although any string may be used as a tag name, it's recommended by the author
that the user standardize upon a consistent naming scheme in order to simplify
the exchange of artifacts with other users. Some examples of tag names that one
may use as inspiration for other names are as follows.

+------------------+-----------------------------------------------------------+
| ``synopsis``     | The potential semantics of a fully-reversed function      |
+------------------+-----------------------------------------------------------+
| ``note``         | Any general notes about an address that the user may wish |
|                  | to inform others or that may need to be referenced later  |
+------------------+-----------------------------------------------------------+
| ``marks``        | A set of addresses containing marks used by the function  |
+------------------+-----------------------------------------------------------+
| ``mark``         | A string containing the description of a mark that the    |
|                  | user may have assigned to the address                     |
+------------------+-----------------------------------------------------------+
| ``object``       | The name of a structure or address(es) containing the     |
|                  | vtable that is used to reference a particular method.     |
+------------------+-----------------------------------------------------------+
| ``object.size``  | The size of an object that might be stored at a pointer   |
+------------------+-----------------------------------------------------------+
| ``input``        | A dictionary mapping register parameters for a function   |
+------------------+-----------------------------------------------------------+
| ``return``       | A list containing the registers that may compose a result |
|                  | that is returned by the called function                   |
+------------------+-----------------------------------------------------------+
| ``break``        | The contents of a conditional breakpoint or code that the |
|                  | user may wish to execute at a given address               |
+------------------+-----------------------------------------------------------+
| ``string``       | The address of a string that is referenced as a parameter |
+------------------+-----------------------------------------------------------+

.. _tagging-modules:

-----------
Tag modules
-----------

There are a few modules that are provided within this project that allows one
to interact with all of the tags defined in a database. These can be used to
perform various tasks such as exporting all the tags within a database to
later import into a difference database, translating tags within the database
in order to match them up to another database, etc. These modules are available
via the :py:mod:`tools` namespace.

.. _tagging-modules-tags:

Tag modules -- tags
*******************

The :py:mod:`tools.tags<tags>` module allows for one to export or import all of the
tags within a database. Please review the documentation for :py:mod:`tools.tags<tags>` for
more about the capabilities of this module.

.. _tagging-modules-tagfix:

Tag modules -- tagfix
*********************

The :py:mod:`tools.tagfix<tagfix>` module allows for one to rebuild the tag cache if
the cache somehow gets corrupted in some way (due to IDA crashing whilst trying
to write a netnode) or if a database did not complete its initial creation of
the tag cache.

This module exposes a number of functions that can be used to rebuild the tag
cache entirely. Please review the documentation for :py:mod:`tools.tagfix<tagfix>` for more
information on how to do this.

.. _tagging-examples-querying:

--------------------
Examples -- Querying
--------------------

As described in the previous sections, tags have 2 different types and thus have
2 different ways of querying them. "Global" tags can represent a tag associated
with a given function or a global address, whereas "Contents" tags are associated
with an address belonging to a function.

There are also 2 different types for tagging structures and their members. These
are similar to both "Global" and "Contents" tags in functionality, but are different
in that they can only be applied to structures, frames, and their members.

(In the following examples, format strings are used. Although format-specifiers
are a lot more flexible and powerful, they might not be familiar to the average
user and thus these are chosen for simplicity. Apologies in advance.)

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
         synopsis = tags['synopsis']
         note = tags.get('note', 'no notes found!')
         print "Function: %x -- %s (note: %r)"% (ea, synopsis, note)
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
         print "Ea: %x Tags: %r"% (ea, tags)
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
         for ea, tags in func.select(*res):
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
          print "Function %x has the tags: %r"% (ea, res)
    >

This same functionality is also provided within the :py:mod:`tags` module
within the :py:mod:`tools` namespace::

    > import tools
    > res = tools.tags.list()
    > print repr(res)

.. _tagging-examples-querying-structures:

Examples -- Querying "Structure" tags
*************************************

Create a temporary structure for this example and add some members to it::

    > st = structure.new('example')
    > f1 = st.add('my_dword_field', (int, 4))
    > f2 = st.add('my_ptr', type)
    > f3 = st.add('my_byte', (int, 1))

Set some attributes of the individual fields::

    > f2.tag('a pointer', 'this is a pointer that i need to track')
    > f3.typeinfo = 'bool'

Add a tag to the structure to query it later::

    > st.tag('selected', 1)

Select the previously tagged structure::

    > for st, res in struc.select('selected'):
          print('Found', st, 'with', res)
    >

Select the members of the structure containing user-defined type information::

    > for m, t in st.select('__typeinfo__'):
          print('Found member', m, 'with explicit type information', t)
    >

Select all of the members of within the database that are tagged with "a pointer"::

    > for st in structure.iterate():
          for m, t in st.select('a pointer'):
              print('Found a pointer', m, 'with note', t['a pointer'])
          continue
    >

Create a couple of structures to represent a path::

    > st1 = structure.new('struc_1')
    > m1 = st1.add(('field', st1.size))
    > st2 = structure.new('struc_2')
    > m2 = st2.add('field_0', st1)
    > st3 = structure.new('struc_3')
    > m3 = st3.add(('field', st3.size), st2)

Tag the members the order that you wish to traverse them::

    > m1.tag('order', 0)
    > m2.tag('order', 1)
    > m3.tag('order', 2)

Select all of the structures that you have created and store them in a list::

    > myitems = [st for st, tags in structure.select('__typeinfo__')]

Select the tagged members from the structures and store them into a dictionary::

    > myresults = {}
    > for st in myitems:
          for m, tags in st.select('order'):
              index = tags['order']
              myresults[index] = m
          continue
    >

Iterate through the sorted dictionary and display each member::

    > for index in sorted(myresults):
          m = myresults[index]
          print(hex(m.offset), m)
    >

Collect each of these entries into a structure path that may be explicitly applied to an operand::

    > path = [ myresults[index] for index in sorted(myresults) ]
    > instruction.op_structure(ea, opnum, *path)

.. _tagging-examples:

---------------------------------------------------
Examples -- Application of Tags and Retrieving them
---------------------------------------------------

The other aspect of the tagging API is the application and retrieval of tags at
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
         res[ea] = func.tag(ea)
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
             if func.within(ea):
                 func.tag(ea, k, None)
                 func.tag(ea, "%s.%s"% (username, k), res[k])
             else:
                 db.tag(ea, k, None)
                 db.tag(ea, "%s.%s"% (username, k), res[k])
             continue
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
