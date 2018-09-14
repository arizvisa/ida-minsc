# IDA-minsc

<table>
    <tr>
        <td width="10%">
            <img src="http://arizvisa.github.io/ida-minsc/_images/hamster.svg" height="10%" />
        </td>
        <td>
            <ul>
                <li>Website: https://github.com/arizisa/ida-minsc</li>
                <li>Documentation: https://arizvisa.github.io/ida-minsc</li>
                <li>IRC: <code>#eof</code> on EFnet</li>
            </ul>
        </td>
    </tr>
</table>

## General

IDA-minsc is a plugin for IDA Pro that assists a user with scripting the
IDAPython plugin that is bundled with the disassembler. This plugin groups the
different aspects of the IDAPython API into a simpler format which allows a
reverse engineer to script different aspects of their work with very little
investment.

A number of concepts are introduced such as a tagging system, support for
multicased functions, and filtering with the intention that most search
and annotation issues can be performed with just a few lines of code. This
should enable a user to write quick, hacky, throwaway code that can be used
to augment their reversing endeavors.

## Installation

Installation should be pretty simple and requires simply cloning the repository
directly into the user's IDA user directory. On the Windows platform, this is
typically located at `$APPDATA/Roaming/Hex-Rays/IDA Pro`. Whereas on the Linux
platform this can be found at `$HOME/.idapro`. This contents of this repository
should actually replace that directory. If you have any files that presently
reside there, simply move them into the repository's directory. After
installation, IDA Pro should load its IDAPython plugin which should result in
the `idapythonrc.py` belonging to IDA-minsc being executed which will then
replace IDAPython's default namespace with the one belonging to the plugin's.

To clone the repository in a directory `$TARGET`, one can simply do:

    $ git clone https://github.com/arizvisa/ida-minsc "$TARGET"

After cloning the repository, the user will need to install its required Python
dependencies into their site-packages. This can be done using `pip` which is a
tool that is bundled with Python. The file that contains the user's requirements
is in the root of the repository as `requirements.txt`.

To install the required Python dependencies, one can run `pip` as so:

    $ pip install -r 'requirements.txt'

At this point when the user starts IDA Pro, IDA-minsc will replace IDAPython's
namespace with its own at which point can be used immediately. To verify that
IDA-minsc was installed properly, one can simply type in the following at the
IDAPython prompt:

    > database.config.version()

This should then return the number `0` since no database has been loaded.

## Quick Start

After installing the python dependencies, you can do something like the
following to list all the functions in your database:

    > database.functions.list()

Or to iterate through all the functions in the database, you can try:

    > for ea in database.functions():
          print hex(ea)

Please refer to the documentation for more details on what this plugin
makes available to you.

## Documentation

Comprehensive documentation is available at [Github](https://arizvisa.github.io/ida-minsc).
or can be built locally via the "docs" branch.

If the user wishes to build documentation for local use, they will
first need the [Sphinx](http://www.sphinx-doc.org/en/master/usage/installation.html)
package to be installed. Afterwards, the entirety of the documentation
resides in the "docs" branch. Simply check out the "docs" branch,
change the directory to "docs", and then run GNU make as:

    $ make html

This will result in the generated documentation being built in the
current directory under the `_build` path. Documentation can be
generated for a number of different formats. To list the available
formats, type in `make help` at your command prompt.

## Contributing

See [CONTRIBUTING.md](https://github.com/arizvisa/ida-minsc/blob/master/CONTRIBUTING.md)
for best practices on adding functionality to IDA-minsc.

## Thanks

Thanks to a number of anonymous people have helped the development of
this plugin throughout the years.

[logo]: http://arizvisa.github.io/ida-minsc/_images/hamster.svg
