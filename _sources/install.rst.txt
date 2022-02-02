.. _install-intro:

Installation of IDA-Minsc
=========================

To install IDA-Minsc on the various platforms that a user has installed
IDA in, it simply requires a user to clone the repository into their
IDA user directory. The idea is that IDA-Minsc's ``idapythonrc.py`` file
is executed by IDAPython when the user starts up IDA. At this point,
IDA-Minsc will then empty out the default namespace and replace it with
the contents of ``__root__.py``. This allows a user to use a function
such as :py:func:`dir` or :py:func:`help` to list all the functions that
they have created during their reversing project.

---------------------
Software Requirements
---------------------

This plugin requires IDA Pro to be installed along with the IDAPython plugin.
IDA versions 6.9 up to 7.1.180227 are supported. The installation steps
described within this document assume that you're not using the bundled Python
instance and have instead installed a Python interpreter separately.

----------------------------
Installing the actual plugin
----------------------------

To install the directory, the contents of the repository must be either cloned
or extracted into IDA's user directory. The repository is located at the
referenced github url [:ref:`1<install-clone-references>`]. On the windows
platform, IDA's user directory is located at ``%APPDATA%/Roaming/Hex-Rays/IDA Pro``
whereas on Linux or MacOS it can be found at ``$HOME/.idapro``. If the user is
not sure of the path that IDA's user directory is located at, they can simply
execute the following at the IDAPython prompt to output the correct path:

.. code-block:: python

    > print idaapi.get_user_idadir()

To then clone the repository, one can use Git [:ref:`2<install-clone-references>`].
When cloning, the directory containing the plugin's repository should replace the
contents of the IDA user directory. If there are any files that the user
currently has in their IDA user directory, the user can simply move these files
into the repository's directory. This is done so that IDAPython will execute the
``idapythonrc.py`` file belonging to IDA-minsc. To clone the repository, one can
use Git [:ref:`2<install-clone-references>`] at their shell's command line:

.. code-block:: sh

    $ git clone https://github.com/arizvisa/ida-minsc $IDA_USERDIR

Once this has been correctly done and the Python dependencies are installed,
then when IDA starts up, the ``idapythonrc.py`` file in the repository should be
executed and IDAPython's namespace replaced with the namespace belonging to the
plugin.

.. _install-clone-references:
.. rubric:: References

1. `IDA-Minsc repository -- https://github.com/arizvisa/ida-minsc <https://github.com/arizvisa/ida-minsc>`_
2. `Git -- Local branching on the cheap -- https://git-scm.com <https://git-scm.com>`_

Required Python dependencies
****************************

This project depends on a small number of required Python modules that the
user will need to install into their ``site-packages`` directory. These modules
do things such as provide an implementation of a graph or to assist with Python2
and Python3 incompatbilities. To install these required packages one can use
the ``pip`` tool which comes with Python to install them. In the root of the
repository, there's a file ``requirements.txt``. This file contains the
required dependencies and can be installed by executing the following while
in the root of the user directory:

.. code-block:: sh

    $ pip install -r requirements.txt

Sanity checking the installation
********************************

To check that IDA-Minsc has been installed properly, one can simply start
up their instance of IDA. Once IDAPython has been successfully loaded,
ensure that the prompt is selected as "Python" and then execute the
following::

    > database.config.version()

This should return a number (typically ``0`` due to no database being loaded).
If this is successful, then the user should now have access to the modules
that compose IDA-Minsc.

------------------------------
Customizing the root namespace
------------------------------

If the user wishes to import their own modules, or define custom functions
that are available with IDA-Minsc has properly loaded they can add them to
a file in the in their home directory named ``$HOME/.idapythonrc.py``.

By default when IDA-Minsc starts up, the :py:mod:`user` module is first
imported (which will execute ``$HOME/.pythonrc.py``). This module is then
used to locate the user's ``.idapythonrc.py`` file which is then evaluated
within the current namespace.

As mentioned, this can allow a user to define functions that they use often
or add aliases to some of the longer ones. By default the following functions
are aliased in the root namespace:

+-----------------+----+-----------------------------------------------------------------+
| :py:func:`h`    | -- | Aliased from :py:func:`database.here` which will return the     |
|                 |    | current address                                                 |
+-----------------+----+-----------------------------------------------------------------+
| :py:func:`top`  | -- | Aliased from :py:func:`function.top` which will return the      |
|                 |    | top address of the current function chunk                       |
+-----------------+----+-----------------------------------------------------------------+
| :py:func:`go`   | -- | Aliased from :py:func:`database.go` which will navigate to      |
|                 |    | the provided address                                            |
+-----------------+----+-----------------------------------------------------------------+
| :py:func:`goof` | -- | Aliased from :py:func:`datbase.go_offset` which will navigate   |
|                 |    | to the specified offset from the lowest address in the database |
+-----------------+----+-----------------------------------------------------------------+

There are also a number of combinators that are exposed to the user via the
default namespace. Please see :doc:`combinators` for more information on
how these can be used.

Some of the base types that can be used for checking inheritance is also
included in the root namespace:

+------------------------+----+------------------------------------------------------+
| :py:class:`register_t` | -- | The base type that registers are inherited from      +
+------------------------+----+------------------------------------------------------+
| :py:class:`symbol_t`   | -- | A type that is used to represent objects that are    |
|                        |    | composed of some number of symbols. This can be used |
|                        |    | to enumerate through all the registers returned from |
|                        |    | an operand such as :py:func:`instruction.op_value`,  |
|                        |    | or any object that contains an unresolvable symbol.  |
+------------------------+----+------------------------------------------------------+

There are a number of modules that are aliased to shorten the typing required
to access their members. Some of these are:

+-----------------------+----+----------------------+
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

Through these aliases, it is hoped for by the author that the user is enabled
to write very quick and hacky code that will assist them to get the work they
need done.
