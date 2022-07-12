.. _install-intro:

=========================
Installation of IDA-Minsc
=========================

To install IDA-Minsc on whichever platform that you may have installed IDA
in, it simply requires you to clone the repository into a directory of your
choosing. After the repository has been cloned, you will then need to copy
the ``plugins/minsc.py`` file into their IDA user directory and then modify
its contents in order to assign the path that you have cloned the repository
into. After it has been modified, when starting up IDA you should then notice
that the "About Minsc" menu item is listed under your currently installed plugins.

If using an **older** version of IDA Pro, one may need to use the previous
installation methodology at section :ref:`1.6<install-older>` to ensure that
IDA-Minsc is loaded immediately after IDA has been started. To install it in
this manner, the idea is that the "``idapythonrc.py``" file from the IDA-Minsc
repository is executed by IDAPython when the user starts up IDA. This is done
by cloning the IDA-Minsc repository **directly** into the IDA user directory.
This way when IDA starts, IDA-Minsc will then empty out the default namespace
and replace it with its own.

---------------------
Software Requirements
---------------------

This plugin requires IDA Pro disassembler [:ref:`1<software-references>`] to be
installed along with the IDAPython plugin. To update the IDA-Minsc plugin, the
Git [:ref:`2<software-references>`] software is also required. This makes you
responsible for updating with regards to any newer features and avoids using
the many auto-updating systems that are pervasive throughout software. You may
download Git at [:ref:`3<software-references>`] and then run it in order to get
it installed. This should put "``git``" within your ``PATH`` and allow you to
run it from the command line. This is necessary as it will be used for cloning
the repository [:ref:`4<software-references>`] containing the actual plugin.

Currently, IDA versions 6.8 up to 7.7.220125 [:ref:`5<software-references>`] are
supported along with ``both`` versions of the Python interpreter [:ref:`6<software-references>`].
This includes the Python 3.x series and the older Python 2.x series. The installation
steps described within this document assume that you have Python 3.9 installed
[:ref:`7<software-references>`] and that it is also accessible via the command
line. If this is not the case, you may need to follow additional steps in order
to install Python and get it working within your instance of IDA Pro.

If you have installed IDA and realized that another plugin in which you are
interested in requires a different version of Python, please review the
`Downgrading the IDAPython version to Python 2.x for other plugins`_ section
for your platform in order to switch between them. To be clear, none of this
is required for the IDA-Minsc plugin and is instead only described in order
to support older versions of other plugins that you may need.

Cloning the repository
----------------------

To install the plugin, the contents of the repository will need to be cloned with
Git into a directory of your choosing. After you have downloaded Git [:ref:`3<software-references>`]
and installed it, you should then be able to clone the repository containing the
plugin [:ref:`4<software-references>`] into your desired installation directory.
If you're using the command line to clone the plugin repository, you will first
need to navigate to your desired installation directory and then you can run the
following if "``git``" is within your ``PATH``.

.. code-block:: sh

    $ cd /path/to/installation/directory/
    $ git clone https://github.com/arizvisa/ida-minsc

This should result in the repository being cloned underneath the current directory.
Afterwards, you can proceed with installing any of the required Python dependencies.

.. _install-dependencies:

Required Python dependencies
----------------------------

This project depends on a small number of Python modules that you will need to
install into Python's "``site-packages``" directory. These modules are mostly
used to provide a reasonable graph implementation. But there are other modules
which are used for compatibility with both Python3 and Python2.

To install these required modules you can use the "``pip``" tool which comes
with Python to install them. In the root of the repository, there's a file
"``requirements.txt``" that you can use. This file contains the required
dependencies and can be installed by executing the following while in the
directory that you cloned the repository into.

.. code-block:: sh

    $ pip install -r requirements.txt

This should install all of the required Python dependencies, and then you can
proceed with installing the actual plugin. There are two ways to install the
plugin. The new way which requires you to modify a file and manually deploy
it within the plugin directory, and then the old way which is only necessary
if you're using an older version of IDA Pro.

.. _software-references:
.. rubric:: References

1. `Hex Rays: IDA Disassembler — https://hex-rays.com/ida-pro/ida-disassembler/ <https://hex-rays.com/ida-pro/ida-disassembler/>`_
2. `Git: Local branching on the cheap — https://git-scm.com <https://git-scm.com>`_
3. `Git: Downloads — https://git-scm.com/downloads <https://git-scm.com/downloads>`_
4. `IDA-Minsc repository — https://github.com/arizvisa/ida-minsc <https://github.com/arizvisa/ida-minsc>`_
5. `Hex Rays: IDA 7.7 released — https://hex-rays.com/blog/ida-7-7-released/ <https://hex-rays.com/blog/ida-7-7-released/>`_
6. `Python: Welcome to Python.org — https://www.python.org/ <https://www.python.org/>`_
7. `Python: Downloading Python 3.9.13 — https://wiki.python.org/moin/BeginnersGuide/Download <https://www.python.org/downloads/release/python-3913>`_

----------------------------
Installing the actual plugin
----------------------------

Once the repository has been cloned into a directory of your choice, you will
need to modify the "``./plugins/minsc.py``" file from the repository to point it
to whichever directory you cloned the repository into. After it's been properly
modified, you can then deploy it into the IDA user directory.

Near the very top of this file, you should see the following text which is referencing
a variable which tells the plugin where its repository is actually located. By default
it uses the current IDA user directory for the prior installation method, but it
can actually be changed to reference any directory that you prefer.

.. code-block:: python

    # :: Point this variable at the directory containing the repository of the plugin ::
    root = idaapi.get_user_idadir()

It is this variable that you will need to modify to point it at the directory
that you cloned the repository into. As this is Python, you will need to keep in
mind that the directory will need to be specified as a string and will require any
escaping as is necessary for whatever path you specify.

As an example, if you have cloned the repository into "``C:\Users\Guest\IDA-Minsc``",
you would modify the variable in the file as so:

.. code-block:: python

    # :: Point this variable at the directory containing the repository of the plugin ::
    #root = idaapi.get_user_idadir()
    root = 'C:/Users/Guest/ida-minsc'

    # If you prefer backslashes, make sure you escape them.
    root = 'C:\\Users\\Guest\\ida-minsc'

After the file has been modified, you can then deploy this file into your IDA user
directory under the sub-directory labeled "``plugins``". On the Windows platform,
IDA Pro's user directory is typically found at "``%APPDATA%/Roaming/Hex-Rays/IDA Pro``"
whereas on Linux or MacOS the path to this directory can be found under
"``$HOME/.idapro``" [:ref:`1<install-references>`]. If you're not sure of the path that
IDA's user directory is located at, you can simply execute the following at the IDAPython
prompt to print out the correct path.

.. code-block:: python

    > print(idaapi.get_user_idadir())

After you have modified the file and identified your IDA user directory that you
will be deploying the modified file into, you can then copy the "``./plugins/minsc.py``" file
to it. To ensure this directory exists, you can execute the following at the IDAPython
prompt to first create the directory (which could raise an exception if it already
exists), and then print out the location that you will need to copy the "``./plugins/minsc.py``"
file into.

.. code-block:: python

    > plugins = idaapi.get_user_idadir() + '/plugins'
    > import os
    > os.makedirs(plugins)
    > print(plugins + '/')

Once the modified "``plugins/minsc.py``" file has been copied to this location, the
plugin should be installed. Whenever you startup IDA, the "About Minsc" menu item
will be visible in the plugins list. The plugins list can be found within the menu
system of IDA under "Edit" 🠞 "Plugins".

.. _install-sanity-check:

Sanity checking the installation
--------------------------------

To check that IDA-Minsc has been installed properly, you should be able to just
startup your instance of IDA and check your Plugins menu under "Edit" 🠞 "Plugins".
As if the plugin has been successfully loaded, the "About Minsc" menu item should be
listed. However, a programmatic method can be also used to check if the plugin
has been installed. To do this, ensure that the IDAPython prompt is selected as
"Python" (not "IDC") and then execute the following::

    > database.config.version()

This should return a number (typically ``0`` due to there being no database loaded).
If this is successful, then you should now have access to the modules that compose
IDA-Minsc. If you have problems with this process, please feel free to open up an
issue under GitHub's issue tracker for the project.

.. _install-references:
.. rubric:: References

1. `IDA Help: Environment variables (%IDAUSR%) — https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml <https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml>`_
2. `IDA-Minsc: Installation issues — https://github.com/arizvisa/ida-minsc/issues <https://github.com/arizvisa/ida-minsc/issues/new?title=Your+installation+process+sucks+and+here+is+how+to+improve+it...>`_

-----------------------
Using the actual plugin
-----------------------

The plugin cleans up the default namespace so that a number of Python's
features can be used in order to see what is currently available. This
allows you to use a function such as :py:func:`help` for identifying what
parameters are best or :py:func:`dir` to list all the functions that you
have created during a reversing session. The aim of this is to allow you
to automate simple things, or to do more advanced things such as pickling
your entire session to disk so that you can resume it later between
distinctly separate instances of IDA.

To get access to help, it is recommended by the author to use either the
Python :py:func:`help` function, or to use the ``?`` shortcut that is
provided the IDAPython command line ("``?database.functions``"). This
avoids the need of having to use any external documentation when hacking
together a script that is needed to import or export information from the
database. Some examples of using the :py:func:`help` function are as follows::

    > help(database)
    > help(function)

Similarly, to list the functions that you have defined within your
current namespace, you can use the :py:func:`dir` function to list
both the functions and variables. Likewise, you can access the contents
of the namespace using the :py:func:`globals` function in various ways
to filter things that you've already defined. Some basic examples of doing
this are as follows::

    > dir()
    > [name for name, item in globals().items() if not isinstance(item, type(sys))]
    > [name for name, item in globals().items() if not isinstance(item, type(sys)) and not hasattr(v, '__module__')]

Another aspect that the user may find useful as they get more accustomed to
using the features provided by the plugin is the ability to query the tags
that they have assigned within their database. For the sake of brevity,
this can be used to query the various parts of your database such as global
addresses (via :py:func:`database.select`), function contents (via :py:func:`function.select`),
types (via :py:func:`structure.select`), or their members (via :py:meth:`structure.members_t.select`).
Tagging is described in detail at section :ref:`2.2<tagging-intro>`, but one of
the most common things that you may want to query will be within the contents of
your functions. Thus, another utility you may find useful would be the following::

    > def selectall(*args, **kwargs):
    >     for fn, tags in database.selectcontents(*args, **kwargs):
    >         for ea, results in func.select(fn, *tags):
    >             yield ea, results
    >         continue
    >     return

It is recommended by the author that you include some of these example utility
functions, or import modules that can be used for serialization or deserialization of
Python objects (such as `pickle <https://docs.python.org/3/library/pickle.html>`_
or `dill <https://pypi.org/project/dill/>`_) within your default namespace.
Customization of your default namespace is described in the next section.

Customizing the default namespace
---------------------------------

If you wish to import your own modules, or define custom functionality using
the tooling that is provided by IDA-Minsc, you can simply add them to a file in
your home directory using the "``$HOME/.idapythonrc.py``" path or the equivalent
path, "``$USERPROFILE/.idapythonrc.py``", used by the Windows platform.

By default when IDA-Minsc starts up, the standard Python interpreter logic
is executed followed by the loading process for the plugin which will try to locate
the "``.idapythonrc.py``" file within your home (or user profile) directory.
Once this is located, it will then evaluated at startup. Similarly, when a
specific database is opened up, the plugin will also look for a file alongside
the database with the name, "``idapythonrc.py``", and execute it when the database
has been loaded.

As mentioned, these files can allow you to define functions that you may find useful
or to add aliases for the more common ones that you may use. If you wish to attach custom
hooks or key bindings using the :py:mod:`ui` module, this would be the place to add them.
By default the following functions are available in the default namespace:

+-----------------+----+-----------------------------------------------------------------+
| alias name      |    | description of alias                                            |
+=================+====+=================================================================+
| :py:func:`h`    | -- | Aliased from :py:func:`database.here` which will return the     |
|                 |    | current address                                                 |
+-----------------+----+-----------------------------------------------------------------+
| :py:func:`top`  | -- | Aliased from :py:func:`function.top` which will return the      |
|                 |    | top address of the current function chunk                       |
+-----------------+----+-----------------------------------------------------------------+
| :py:func:`go`   | -- | Aliased from :py:func:`database.go` which will navigate to      |
|                 |    | the provided address                                            |
+-----------------+----+-----------------------------------------------------------------+
| :py:func:`goof` | -- | Aliased from :py:func:`database.go_offset` which will navigate  |
|                 |    | to the specified offset from the lowest address in the database |
+-----------------+----+-----------------------------------------------------------------+

There are also a number of combinators that are exposed to the user via the
default namespace if the user is familiar with that style of programming.
Please see :doc:`combinators` for more information on how these can be used.

Some of the base types that can be used for checking their types with :py:func:`isinstance`
are also included in the default namespace. For more information on these types, it
is recommended to use an instance of the type with the :py:func:`help` function.

+------------------------+----+------------------------------------------------------+
| class or type          |    | description                                          |
+========================+====+======================================================+
| :py:class:`register_t` | -- | The base type that registers are inherited from      |
+------------------------+----+------------------------------------------------------+
| :py:class:`symbol_t`   | -- | A type that is used to represent objects that are    |
|                        |    | composed of some number of symbols. This can be used |
|                        |    | to enumerate through all the registers returned from |
|                        |    | an operand such as :py:func:`instruction.op`, or any |
|                        |    | object that may contain an unresolvable symbol.      |
+------------------------+----+------------------------------------------------------+
| :py:class:`bounds_t`   | -- | A tuple describing a range of memory addresses       |
+------------------------+----+------------------------------------------------------+
| :py:class:`location_t` | -- | A tuple describing a location by address and size    |
+------------------------+----+------------------------------------------------------+
| :py:class:`ref_t`      | -- | A tuple describing a reference to a memory address   |
|                        |    | that is read from, written to, or executed.          |
+------------------------+----+------------------------------------------------------+
| :py:class:`opref_t`    | -- | A tuple describing a reference for an instruction    |
|                        |    | operand that is either reading from, writing to, or  |
+                        |    | executing the contained address.                     |
+------------------------+----+------------------------------------------------------+

In order to shorten the typing required to access the more commonly used parts of the
API, most of the available modules are aliased as shorter and thus easier to remember
names. Thus to access these parts of the API, one can use these aliases instead of the
full module name to get access to them.

+-----------------------+----+----------------------+
| module name           |    | alias name           |
+=======================+====+======================+
| :py:mod:`database`    | -- | Aliased as ``db``    |
+-----------------------+----+----------------------+
| :py:mod:`function`    | -- | Aliased as ``func``  |
+-----------------------+----+----------------------+
| :py:mod:`instruction` | -- | Aliased as ``ins``   |
+-----------------------+----+----------------------+
| :py:mod:`structure`   | -- | Aliased as ``struc`` |
+-----------------------+----+----------------------+
| :py:mod:`enumeration` | -- | Aliased as ``enum``  |
+-----------------------+----+----------------------+
| :py:mod:`segment`     | -- | Aliased as ``seg``   |
+-----------------------+----+----------------------+
| :py:mod:`ui`          | -- | Is not aliased       |
+-----------------------+----+----------------------+

It is recommended by the author that the user use :py:func:`help` to explore these modules
when trying to identify certain aspects of functionality that the user may want to use when
querying their database or scripting different parts of IDA. The names of these modules
and the functions within try to group functionality within the context that they're used
and attempt to use names that can be referenced in proper english. The namining of these
functions are of course debatable, and if you believe something should be named differently
or another alias should be included, please contact the author.

---------------------------------------
Help with scripting or reporting issues
---------------------------------------

There is a wiki that is hosted at the plugin's repository page [:ref:`1<usage-references>`]
which may contain more information that might be worth reading. If you have any questions
about scripting parts of your reverse-engineering session [:ref:`2<usage-references>`] or
issues that may need to be reported [:ref:`3<usage-references>`], please do not hesitate
to ask.

.. _usage-references:
.. rubric:: References

1. `IDA-Minsc: Wiki — https://github.com/arizvisa/ida-minsc/wiki/ <https://github.com/arizvisa/ida-minsc/wiki/>`_
2. `IDA-Minsc: Issues — https://github.com/arizvisa/ida-minsc/issues <https://github.com/arizvisa/ida-minsc/issues/new?title=This+thing+appears+to+be+broken>`_
3. `IDA-Minsc: Questions — https://github.com/arizvisa/ida-minsc/issues <https://github.com/arizvisa/ida-minsc/issues/new?title=How+do+I+do+this+random+thing>`_
4. `IDA-Minsc: Plugin issues — https://github.com/arizvisa/ida-minsc/issues <https://github.com/arizvisa/ida-minsc/issues/new?title=This+other+plugin+seems+to+be+much+cooler+because+of+its+user+interface>`_

--------------------------------
Compatibility with other plugins
--------------------------------

This plugin "aims" to be friendly with a number of other plugins that a user may
use to script themself out of a job. Some plugins that the author has found useful
or interesting and may be worth checking out are listed below.

    1. :ref:`IPyIDA<competitors>`: https://github.com/eset/ipyida 

       This plugin provides an IPython (Jupyter) interface for editing IDAPython scripts. IPython/Jupyter is
       a "notebook interface" as popularized by Stephen Wolfram's Mathematica which combines some aspects of
       Knuth's ideas from "Literate Programming" into an elegant interface for writing code.

    2. :ref:`PyKd<competitors>`: https://githomelab.ru/pykd/pykd 

       This is not an IDA plugin, but is rather a combination of Windbg extension and Python module. It exposes
       the WinDbg API via Python and allows one to interact with all of the various aspects of WinDbg using
       its general API. The author of IDA-Minsc used to maintain a different project, PyDbgEng, but decided
       against it once the author of PyKd released this particular project.

    3. :ref:`BinSync<competitors>`: https://github.com/angr/binsync 

       A collaboration environment that also aims to serialize and deserialize information out of all
       of the disassemblers and decompilers so that reverse-engineering artifacts can be shared with
       other users. What makes it unique is that it also includes support for the different debuggers
       allowing one to exchange information between both static and runtime reverse-engineering tools.

    4. :ref:`Sark<competitors>`: https://sark.readthedocs.io/

       A well-documented object-oriented wrapper around the IDAPython API with the aim of simplifying
       some of the more tedious parts of IDAPython. This plugin also includes wrappers to ease the
       writing and distribution of user-written plugins that utilize this library.

    5. :ref:`Bip<competitors>`: https://synacktiv.github.io/bip/build/html/index.html 

       Another well-documented object-oriented wrapper around the IDAPython API. This plugin seems to provide
       more interaction with the lower-level parts of IDAPython and includes support for Hex-Rays.

If you find any other plugins that may be useful to combine with IDA-Minsc or a plugin
that may "compete" with any of its capabilities, feel free to contact the author [:ref:`4<usage-references>`]
about getting it added to this list.

.. _competitors:
.. rubric:: References

1. `IPyIDA: IPython console integration for IDA Pro — https://github.com/eset/ipyida <https://github.com/eset/ipyida>`_
2. `PyKD: DbgEng (windbg) wrappers for Python — https://githomelab.ru/pykd/pykd <https://githomelab.ru/pykd/pykd>`_
3. `BinSync: Collaborative Reversing — https://github.com/angr/binsync <https://github.com/angr/binsync>`_
4. `Sark: IDAPython plugin and scripting library — https://sark.readthedocs.io <https://sark.readthedocs.io>`_
5. `BIP: Object-oriented IDAPython library — https://synacktiv.github.io/bip/build/html/index.html <https://synacktiv.github.io/bip/build/html/index.html>`_

-------------------------------------------
Previous installation method for the plugin
-------------------------------------------

The following section describes other ways that the plugin may be
installed or how to customize which version of the Python
interpreter that the IDAPython plugin will use in order for
it to work on older versions of IDA Pro.

Installing the plugin "directly" into the IDA user directory
------------------------------------------------------------

To install the plugin in this manner, the contents of the repository must be
cloned or extracted into the IDA user directory. The repository to be cloned
can be located at the referenced URL  on GitHub [:ref:`1<install-clone-references>`].
On the Windows platform, IDA Pro's user directory can be typically found at the
"``%APPDATA%/Roaming/Hex-Rays/IDA Pro``" directory whereas on Linux or MacOS the
path to this directory can be found at "``$HOME/.idapro``" [:ref:`2<install-clone-references>`].
If the user is not sure where the path of the IDA user directory is located at,
they can simply execute the following at the IDAPython prompt to output the correct path:

.. code-block:: python

    > print idaapi.get_user_idadir()

To then clone the repository, one can use Git [:ref:`3<install-clone-references>`].
When cloning, the directory containing the plugin's repository should replace the
contents of the IDA user directory. If there are any existing files that the user
currently has in their IDA user directory, the user can simply move these files
into the repository's directory after cloning. This is done so that IDAPython
will execute the "``idapythonrc.py``" file that is in the root of the IDA-Minsc
repository upon startup. The following can be typed at the command line in order
to clone the repository of the plugin [:ref:`1<install-clone-references>`] directly
into the IDA user directory:

.. code-block:: sh

    $ git clone https://github.com/arizvisa/ida-minsc $IDA_USERDIR/./

Once this has been correctly done and the Python dependencies are installed,
then when IDA starts up, the "``idapythonrc.py``" file in the repository should be
executed resulting in the IDAPython namespace being replaced with the namespace
belonging to the plugin.

After the repository has been cloned, you will then need to install any of the
:ref:`Required Python dependencies<install-dependencies>` and then you can proceed
to :ref:`Sanity checking the installation<install-sanity-check>`.

.. _install-clone-references:
.. rubric:: References

1. `IDA-Minsc — https://github.com/arizvisa/ida-minsc <https://github.com/arizvisa/ida-minsc>`_
2. `IDA Help: Environment variables (%IDAUSR%) — https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml <https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml>`_
3. `Git: Local branching on the cheap — https://git-scm.com <https://git-scm.com>`_

.. _install-downgrade:

Downgrading the IDAPython version to Python 2.x for other plugins
-----------------------------------------------------------------

The Python 2.x series has since been deprecated due to the compatibility-breaking
changes that have been introduced with the Python 3.x series [:ref:`1<downgrading-references>`].
However, the user may still wish to use plugins or modules that only exist within
the Python 2.x series. As a result of this deprecation, when installing later
versions of IDAPython, the installer will let you choose which version of Python
to use [:ref:`2<downgrading-references>`]. After choosing your version of Python
and completing the installation process, IDAPython will appear to be locked to
that particular version without doing a complete re-install.

If you have chosen Python 3.x, then some desired third-party plugins might not work
with your setup, or some modules might not be available until you switch your Python
interpreter. This however does not affect any part of the IDA-Minsc plugin, and
the choice of choosing a Python version is left completely up to the user. To
temporary switch the interpreter that IDAPython uses, IDA provides a couple of
avenues that a user can take [:ref:`3<downgrading-references>`]. 

.. _install-older:

Earlier versions of IDAPython
*****************************

When installing IDA Pro, all of the available plugins that are currently installed
can be found under the "``plugins``" subdirectory [:ref:`4<downgrading-references>`].
On Windows, this directory is commonly found at a path that is similar to 
"``C:\Program Files\IDA 7.x\plugins``". Whereas on Linux, the plugins can be found
under the "``$HOME/idapro/plugins``" directory. On the MacOS platform, this directory
is likely "``/Applications/IDA Pro/ida.app/Contents/MacOS/plugins``".

+------------+------------------------------------------------------+
| Platform   | Path to the IDA Pro plugins directory                |
+============+======================================================+
| Windows    | C:\\Program Files\\IDA 7.x\\plugins                  |
+------------+------------------------------------------------------+
| Linux      | $HOME/idapro-7.x/plugins                             |
+------------+------------------------------------------------------+
| MacOS      | /Applications/IDA Pro/ida.app/Contents/MacOS/plugins |
+------------+------------------------------------------------------+

This "``plugins``" directory contains a number of shared objects or dynamic
libraries belonging to each individual plugin for both 32-bit and 64-bit
versions of the IDA Pro application [:ref:`4<downgrading-references>`].
Thus this path is where either the user or the IDA Pro installer would've
installed the IDAPython plugin. Regardless of what the user specified
during the install (Python 2.x or Python 3.x), the IDA Pro installer
installs both versions of the IDAPython plugin into this directory.

To accommodate the version of the IDAPython plugin that was chosen by the user,
the installer will use the filename suffix of the plugin to disable the version
that was not desirable by the user. Thus in order to enable a plugin, one will
simply need to rename the filename to include whichever suffix that corresponds
to the platform's shared library. This way when IDA Pro loads, it will see the
shared object or dynamic library and initialize it as a plugin.

+------------+---------------------+-----------------------+------------------------------------+
| Platform   | Shared library name | Shared library suffix | Reference                          |
+============+=====================+=======================+====================================+
| Windows    | plugin/python.dll   | .dll                  | [:ref:`5<downgrading-references>`] |
+------------+---------------------+-----------------------+------------------------------------+
| Linux      | plugin/python.so    | .so                   | [:ref:`6<downgrading-references>`] |
+------------+---------------------+-----------------------+------------------------------------+
| MacOS      | plugin/python.dylib | .dylib                | [:ref:`7<downgrading-references>`] |
+------------+---------------------+-----------------------+------------------------------------+

The following table shows the filenames that are used by IDA for some of the
known platforms. Thus in order to enable Python 2.x and be able to use this
plugin, the user must rename the filename suffix of the currently enabled
IDAPython plugin (which would be Python 3.x if explicitly chosen during the
install process) to its disabled version effectively disabling it.

Once the Python 3.x version of the IDAPython plugin has been disabled, then
the Python 2.x version can be enabled by doing the opposite and renaming the
file from its disabled version to its enabled version.

+-----------------------+---------------------------+---------------------------+--------------------+
| Platform              | Python2 (disabled)        | Python3 (disabled)        | Filename (enabled) |
+=======================+===========================+===========================+====================+
| Windows (32-bit)      | idapython2.disabled       | idapython3.disabled       | idapython.dll      |
+-----------------------+---------------------------+---------------------------+--------------------+
| Windows (64-bit)      | idapython642.disabled     | idapython643.disabled     | idapython64.dll    |
+-----------------------+---------------------------+---------------------------+--------------------+
| Linux (32-bit)        | idapython2.so.disabled    | idapython3.so.disabled    | idapython.so       |
+-----------------------+---------------------------+---------------------------+--------------------+
| Linux (64-bit)        | idapython2_64.so.disabled | idapython3_64.so.disabled | idapython64.so     |
+-----------------------+---------------------------+---------------------------+--------------------+
| MacOS (32-bit)        | idapython.2.disabled      | idapython.3.disabled      | idapython.dylib    |
+-----------------------+---------------------------+---------------------------+--------------------+
| MacOS (64-bit)        | idapython64.2.disabled    | idapython64.3.disabled    | idapython64.dylib  |
+-----------------------+---------------------------+---------------------------+--------------------+

For more information on troubleshooting issues related to the Python interpreter, please review the
article at [:ref:`8<downgrading-references>`].

Later versions of IDAPython
***************************

Within the directory that IDA Pro was installed, are a number of directories
containing the necessary components and assets for the application to run. Under
this same directory is all the necessary files required for IDAPython to work.
These files can be found under the "``python``" subdirectory of IDA Pro's user
directory [:ref:`4<downgrading-references>`]. On Windows, this path in the user
directory is found at "``C:\Program Files\Hex-Rays\IDA Pro\python``". On Linux,
the path can be "``$HOME/idapro/python``" depending on the location of the user
directory, and then lastly on the MacOS platform the directory at "``/Applications/IDA Pro/ida.app/Contents/MacOS/python``"
will contain the necessary Python components.

+------------+-----------------------------------------------------+
| Platform   | Path to the IDA Pro python directory                |
+============+=====================================================+
| Windows    | C:\\Program Files\\IDA 7.x\\python                  |
+------------+-----------------------------------------------------+
| Linux      | $HOME/idapro-7.x/python                             |
+------------+-----------------------------------------------------+
| MacOS      | /Applications/IDA Pro/ida.app/Contents/MacOS/python |
+------------+-----------------------------------------------------+

Within this directory contains the Python code for the IDAPython API. Due to the
variations between both Python 2.x and Python 3.x, IDAPython splits its implementation
and necessary files under the "``python/2``" directory for Python 2.x, and the
"``python/3``" directory for Python 3.x. These subdirectories will contain the
files for the familiar `idc`, `idautils`, and `idaapi` modules.

What's important about the "``python``" subdirectory, however, is that the
IDAPython plugin actually includes support for a conditional file (or a "kill file")
in order to determine whether a particular IDAPython plugin should be loaded or not.
This is relevant in that the necessary file that's used to determine whether the
Python 2.x version of the IDAPython plugin should be loaded is located under this
particular "``python``" subdirectory.

The name of this conditional file is "``use_python``". If a file with this name
is found by IDAPython under the "``python``" subdirectory as "``python/use_python2``",
the Python 3.x version of the IDAPython plugin will refuse to load thus resulting
in only the Python 2.x version of the IDAPython plugin loading.

The following table loosely describes the path where IDA Pro may be installed on
the platform, and the filename that must be created in order to prevent the Python
3.x version of the IDAPython plugin from loading.

+------------+--------------------------------------+----------------------------+
| Platform   | Path to file that needs to exist in order to load only Python 2.x |
+============+======================================+============================+
| Windows    | C:\\Program Files\\IDA 7.x\\python\\use_python2                   |
+------------+--------------------------------------+----------------------------+
| Linux      | $HOME/idapro-7.x/python/use_python                                |
+------------+--------------------------------------+----------------------------+
| MacOS      | /Applications/IDA Pro/ida.app/Contents/MacOS/python/use_python    |
+------------+--------------------------------------+----------------------------+

The `idapyswitch` utility
*************************

On some platforms, this utility comes installed with the IDA Pro application. It
is believed that by running this utility, one can explicitly specify which Python
version that IDAPython should use. This is done by scanning for already installed
instances of Python in the system's standard location and then allowing you to
choose one of them. For more information on this utility and how to use it,
please review the article at [:ref:`9<downgrading-references>`].

Verifying the Python version used by IDAPython
----------------------------------------------

Once the IDAPython plugin has been enabled, simply running the IDA Pro application
will result in the plugin being loaded. At the bottom of the application's user-interface
is an input box that the user may use in order to execute Python code. This input box
is the primary interface to Python's REPL (Read-Eval-Print-Loop). To verify that
the correct version of Python is in use by the plugin, one can execute the following
code by typing it into the input box::

    > import sys
    > sys.version_info
    sys.version_info(major=3, minor=9, micro=13, releaselevel='final', serial=0)

Examining the major version of the named tuple that has been returned shows that
the Python 3.x version of the IDAPython plugin is currently being used. At this
point, the user may continue to use the IDA-Minsc plugin with whatever other
plugins or modules that are now available.

.. _downgrading-references:
.. rubric:: References

1. `Deprecations between Python 2.7 and 3.x — https://blog.python.org/2011/03/recent-discussion-on-python-dev.html <https://blog.python.org/2011/03/recent-discussion-on-python-dev.html>`_
2. `Choosing Python version during installation — https://www.hex-rays.com/blog/ida-7-4-idapython-and-python-3/ <https://www.hex-rays.com/blog/ida-7-4-idapython-and-python-3/>`_
3. `IDAPython and Python3 — https://www.hex-rays.com/products/ida/support/ida74_idapython_python3.shtml <https://www.hex-rays.com/products/ida/support/ida74_idapython_python3.shtml>`_
4. `IDA Help: Plugin modules — https://www.hex-rays.com/products/ida/support/idadoc/536.shtml <https://www.hex-rays.com/products/ida/support/idadoc/536.shtml>`_
5. `Dynamic linker (Windows) — https://en.wikipedia.org/wiki/Dynamic_linker#Microsoft_Windows <https://en.wikipedia.org/wiki/Dynamic_linker#Microsoft_Windows>`_
6. `Dynamic linker (Linux) — https://en.wikipedia.org/wiki/Dynamic_linker#Systems_using_ELF <https://en.wikipedia.org/wiki/Dynamic_linker#Systems_using_ELF>`_
7. `Dynamic linker (MacOS) — https://en.wikipedia.org/wiki/Dynamic_linker#macOS_and_iOS <https://en.wikipedia.org/wiki/Dynamic_linker#macOS_and_iOS>`_
8. `IDA and common Python issues — https://www.hex-rays.com/blog/ida-and-common-python-issues/ <https://www.hex-rays.com/blog/ida-and-common-python-issues/>`_
9. `idapyswitch — https://www.hex-rays.com/blog/tag/idapyswitch/ <https://www.hex-rays.com/blog/tag/idapyswitch/>`_
