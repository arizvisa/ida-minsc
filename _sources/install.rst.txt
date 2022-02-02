.. _install-intro:

Installation of IDA-Minsc
=========================

To install IDA-Minsc on the various platforms that a user has installed
IDA in, it simply requires a user to clone the repository into their
IDA user directory. The idea is that IDA-Minsc's "``idapythonrc.py``" file
is executed by IDAPython when the user starts up IDA. At this point,
IDA-Minsc will then empty out the default namespace and replace it with
the contents of "``__root__.py``". This allows a user to use a function
such as :py:func:`dir` or :py:func:`help` to list all the functions that
they have created during their reversing project.

---------------------
Software Requirements
---------------------

This plugin requires IDA Pro to be installed along with the IDAPython plugin
IDA versions 6.8 up to 7.7.220125 are supported. Both versions of the Python
interpreter, the Python 2.x series, and the Python 3.x series are supported.
The installation steps described within this document assume that you're not
using the bundled Python instance and have instead installed a Python interpreter
separately. Despite the support for both Python 2.x and Python 3.x series, if you
have specified the usage of the Python 3.x for the IDAPython plugin and want
to change it, please review the `Downgrading the IDAPython version to Python 2.x`_
section for your platform.

----------------------------
Installing the actual plugin
----------------------------

To install the plugin, the contents of the repository must be either cloned
or extracted into IDA's user directory. The repository is located at the
referenced github url [:ref:`1<install-clone-references>`]. On the Windows
platform, IDA Pro's user directory can be typically found at the "``%APPDATA%/Roaming/Hex-Rays/IDA Pro``"
directory whereas on Linux or MacOS the path to this directory can be found at
"``$HOME/.idapro``" [:ref:`2<install-clone-references>`]. If the user is not
sure of the path that IDA's user directory is located at, they can simply
execute the following at the IDAPython prompt to output the correct path:

.. code-block:: python

    > print idaapi.get_user_idadir()

To then clone the repository, one can use Git [:ref:`3<install-clone-references>`].
When cloning, the directory containing the plugin's repository should replace the
contents of the IDA user directory. If there are any existing files that the user
currently has in their IDA user directory, the user can simply move these files
into the repository's directory after cloning. This is done so that IDAPython
will execute the "``idapythonrc.py``" file that is in the root of the IDA-minsc
repository upon startup. The following can be typed at the command line in order
to clone [:ref:`3<install-clone-references>`] the repository of the plugin directly
into IDA's user directory:

.. code-block:: sh

    $ git clone https://github.com/arizvisa/ida-minsc $IDA_USERDIR/./

Once this has been correctly done and the Python dependencies are installed,
then when IDA starts up, the "``idapythonrc.py``" file in the repository should be
executed and IDAPython's namespace replaced with the namespace belonging to the
plugin.

.. _install-clone-references:
.. rubric:: References

1. `IDA-Minsc repository -- https://github.com/arizvisa/ida-minsc <https://github.com/arizvisa/ida-minsc>`_
2. `IDA Help: Environment variables (%IDAUSR%) -- https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml <https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml>`_
3. `Git -- Local branching on the cheap -- https://git-scm.com <https://git-scm.com>`_

Required Python dependencies
****************************

This project depends on a small number of required Python modules that the
user will need to install into their "``site-packages``" directory. These modules
do things such as provide an implementation of a graph or to assist with Python2
and Python3 incompatbilities. To install these required packages one can use
the "``pip``" tool which comes with Python to install them. In the root of the
repository, there's a file "``requirements.txt``". This file contains the
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
a file in the in their home directory named "``$HOME/.idapythonrc.py``".

By default when IDA-Minsc starts up, the :py:mod:`user` module is first
imported (which will execute "``$HOME/.pythonrc.py``"). This module is then
used to locate the user's "``.idapythonrc.py``" file which is then evaluated
within the current namespace.

As mentioned, this can allow a user to define functions that they use often
or add aliases to some of the longer ones. By default the following functions
are aliased in the root namespace:

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
default namespace. Please see :doc:`combinators` for more information on
how these can be used.

Some of the base types that can be used for checking the type of an
instance are also included in the root namespace:

+------------------------+----+------------------------------------------------------+
| class or type          |    | description                                          |
+========================+====+======================================================+
| :py:class:`register_t` | -- | The base type that registers are inherited from      |
+------------------------+----+------------------------------------------------------+
| :py:class:`symbol_t`   | -- | A type that is used to represent objects that are    |
|                        |    | composed of some number of symbols. This can be used |
|                        |    | to enumerate through all the registers returned from |
|                        |    | an operand such as :py:func:`instruction.op_value`,  |
|                        |    | or any object that contains an unresolvable symbol.  |
+------------------------+----+------------------------------------------------------+

In order to shorten the typing required to access commonly used parts of the api,
there are a number of modules that are aliased. Thus to access these parts of the
api, one can use their aliases which include:

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

Through use of these aliases and some of the other features provided by
the IDA-minsc plugin, it is hoped for by the author that the user is able
to very quickly write terse code that will assist them to get the work
they need done whilst reversing their target.

.. _install-downgrade:

-----------------------------------------------
Downgrading the IDAPython version to Python 2.x
-----------------------------------------------

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
interpreter. This however does not affect any part of the IDA-minsc plugin, and
the choice of choosing a Python version is left completely up to the user. To
temporary switch the interpreter that IDAPython uses, IDA provides a couple of
avenues that a user can take [:ref:`3<downgrading-references>`]. 

Earlier versions of IDAPython
*****************************

When installing IDA Pro, all of the available plugins that are currently installed
can be found under the "``plugins``" subdirectory [:ref:`4<downgrading-references>`].
On Windows, this directory is commonly found at a path that is similar to 
"``C:\Program Files\IDA 7.x\plugins``". Whereas on Linux, the plugins can be found
under the "``$HOME/idapro/plugins``" directory. On the MacOS platform, this directory
is likely "``/Applications/IDA Pro/ida.app/Contents/MacOS/plugins``".

+------------+-----------------------------------------------------+
| Platform   | Path to the IDA Pro plugins directory               |
+============+=====================================================+
| Windows    | C:\\Program Files\\IDA 7.x\\plugin                  |
+------------+-----------------------------------------------------+
| Linux      | $HOME/idapro-7.x/plugin                             |
+------------+-----------------------------------------------------+
| MacOS      | /Applications/IDA Pro/ida.app/Contents/MacOS/plugin |
+------------+-----------------------------------------------------+

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

Within this directory contains the Python code for the IDAPython api. Due to the
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
**********************************************

Once the IDAPython plugin has been enabled, simply running the IDA Pro application
will result in the plugin being loaded. At the bottom of the application's user-interface
is an input box that the user may use in order to execute Python code. This input box
is the primary interface to Python's REPL (Read-Eval-Print-Loop). To verify that
the correct version of Python is in use by the plugin, one can execute the following
code by typing it into the input box::

    > import sys
    > sys.version_info
    sys.version_info(major=2, minor=7, micro=18, releaselevel='final', serial=0)

Examining the major version of the named tuple that has been returned shows that
the Python 2.x version of the IDAPython plugin is currently being used. At this
point, the user may continue to use the IDA-minsc plugin with whatever other
plugins or modules that are now available.

.. _downgrading-references:
.. rubric:: References

1. `Deprecations between Python 2.7 and 3.x -- https://blog.python.org/2011/03/recent-discussion-on-python-dev.html <https://blog.python.org/2011/03/recent-discussion-on-python-dev.html>`_
2. `Choosing Python version during installation -- https://www.hex-rays.com/blog/ida-7-4-idapython-and-python-3/ <https://www.hex-rays.com/blog/ida-7-4-idapython-and-python-3/>`_
3. `IDAPython and Python3 -- https://www.hex-rays.com/products/ida/support/ida74_idapython_python3.shtml <https://www.hex-rays.com/products/ida/support/ida74_idapython_python3.shtml>`_
4. `IDA Help: Plugin modules -- https://www.hex-rays.com/products/ida/support/idadoc/536.shtml <https://www.hex-rays.com/products/ida/support/idadoc/536.shtml>`_
5. `Dynamic linker (Windows) -- https://en.wikipedia.org/wiki/Dynamic_linker#Microsoft_Windows <https://en.wikipedia.org/wiki/Dynamic_linker#Microsoft_Windows>`_
6. `Dynamic linker (Linux) -- https://en.wikipedia.org/wiki/Dynamic_linker#Systems_using_ELF <https://en.wikipedia.org/wiki/Dynamic_linker#Systems_using_ELF>`_
7. `Dynamic linker (MacOS) -- https://en.wikipedia.org/wiki/Dynamic_linker#macOS_and_iOS <https://en.wikipedia.org/wiki/Dynamic_linker#macOS_and_iOS>`_
8. `IDA and common Python issues -- https://www.hex-rays.com/blog/ida-and-common-python-issues/ <https://www.hex-rays.com/blog/ida-and-common-python-issues/>`_
9. `idapyswitch -- https://www.hex-rays.com/blog/tag/idapyswitch/ <https://www.hex-rays.com/blog/tag/idapyswitch/>`_
