"""
Windbg module

This module exposes some basic tools for assistance when interacting with
windbg. This can be things that help with importing/exporting data from/to
windbg, or tools for generating quotes strings to paste into windbg.

One utility within this module will allow one to escape all the quotes
in a string of a particular depth. This can be used to help generating
string that can be pasted into a conditional breakpoint, or to pass a
properly quoted format-string as an argument to the `.printf` token.
"""

import functools, itertools, types, builtins, operator, six
import database as db, function as func, instruction as ins, structure as struc

import logging, string
from internal import utils

def reference(ea, **module):
    """Return a reference containing the module and offset of the address `ea`.

    If the string `module` is specified, then use it as the module name instead of the database filename.
    """
    module = module.get('module', db.filename())
    return '{:s}+{:x}'.format(module, db.offset(ea))

def label(ea):
    '''Return a label for the given address `ea`.'''
    try: res = '{:s}{{+{:x}}}'.format(func.name(ea), db.offset(ea))
    except: res = '+{:x}'.format(db.offset(ea))
    return '{:s}!{:s}'.format(db.module(), res)

def tokenize(input, escapables={"'", '"', '\\'} | {item for item in string.whitespace} - {' '}):
    """Yield each token belonging to the windbg format in `input` that would need to be escaped using the specified `escapables`.

    If the set `escapables` is defined, then use it as the list of characters to tokenize.
    """
    result, iterable = '', iter(input)
    try:
        while True:
            char = six.next(iterable)
            if operator.contains(escapables, char):
                if result:
                    yield result
                yield char
                result = ''

            else:
                result += char
            continue

    except StopIteration:
        if result:
            yield result
        return
    return

def escape(input, depth=0, **extra):
    """
    Given the windbg format string in `input`, escape each of its characters as if it was within `depth` level of quoting.

    If any other keyword parameters are provided, then escape those keywords with their value.
    """

    # Define the generator form of ourself as we're just going to aggregate its
    # result into a string anyways.
    def closure(input, depth, extra):
        bs = '\\'
        ws = { six.int2byte(i) : item for i, item in enumerate('0123456abtnvfr') }
        escaped = {bs, '"'}

        # Now we can tokenize our input and figure out what it's supposed to yield
        for token in tokenize(input):

            # Check if the token is a windbg quote that needs to be explicitly
            # escaped
            if operator.contains(escaped, token):
                yield bs * depth + token

            # Did the token match one of our whitespace characters?
            elif operator.contains(ws, token):
                yield bs + (bs * depth) + ws[token]

            # If nothing matched, then we can just yield the current character
            # as it was unprocessed.
            else:
                # Add any characters that were explicitly specified in the
                # "extra" dictionary, and replace our current token with it
                if any(operator.contains(token, item) for item in extra):
                    k = six.next(item for item in extra if operator.contains(token, item))
                    token = token.replace(k, extra[k] * depth + k)

                # Now we can yield our token
                yield token
            continue
        return
    return str().join(closure(input, depth, extra))

def breakpoints(f=None, **kwargs):
    """Query the function `f` for the "break" tag, and use it to emit a list of breakpoints for windbg.

    If the string `module` is specified, then use it instead of the current filename when emitting the location.
    If the string `tagname` is provided, then use it to query instead of "break".
    """
    tagname = kwargs.get('tagname', 'break')

    # if no function was provided, then recurse into ourself for all of them
    if f is None:
        for f, _ in db.selectcontents(tagname):
            breakpoints(f, **kwargs)
        return

    #entry, exit = func.top(f), func.bottom(f)
    #funcname = func.name(f)
    #[(entry,{tagname:'.printf "Entering {:s} %x,%x\\n",poi(@esp),@esp'.format(funcname)})], [(x,{tagname:'.printf "Exiting {:s} %x,%x\\n",poi(@esp),@esp'.format(funcname)}) for x in exit],

    # query the given function for the requested tagname
    tags, select = {}, itertools.chain(func.select(f, And=(tagname,), Or=('',)))
    for ea, t in select:
        h = tags.setdefault(ea, {})
        for k in six.iterkeys(t):
            if k == tagname:
                h.setdefault(k, []).extend(t[k] if isinstance(t[k], builtins.list) else t[k].split(';'))

            elif operator.contains(h, k):
                logging.warning(u"{:s}.breakpoints({:#x}{:s}) : The specified key \"{:s}\" already exists in dictionary for address {:#x}.".format(__name__, func.addr(f), u", {:s}".format(utils.strings.kwargs(kwargs)) if kwargs else '', utils.string.escape(k, '"'), ea))

            else:
                h[k] = t[k]
            continue
        continue

    # aggregate all of the discovered tags into a list of breakpoints
    for ea, t in six.iteritems(tags):
        ofs, commands = db.offset(ea), []

        # create the command that emits the current label
        label_t = string.Template(r'.printf "$label -- $note\n"' if t.has_key('') else r'.printf "$label\n"')
        commands.append(label_t.safe_substitute(label=label(ea), note=t.get('', '')))

        # append the commands to execute when encountering the given breakpoint
        res = t.get(tagname, ['g'])
        if isinstance(res, builtins.list):
            commands.extend(res)
        else:
            commands.append(res)

        # escape all of the commands since we're going to join them together
        commands = map(escape, commands)

        print 'bp {:s} "{:s}"'.format(reference(ea, **kwargs), escape(';'.join(commands), depth=1))
    return
