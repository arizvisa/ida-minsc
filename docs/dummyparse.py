from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import functools, operator, itertools, types

import argparse
import ast
import contextlib

### Namespace of types that should get evaluated to a string
class evaluate(object):
    def __new__(cls, path):
        res = cls
        for name in path.split('.'):
            res = getattr(res, name)
        return res

    import six
    from six.moves import builtins
    class instruction:
        register_t = 'register_t'
    _instruction = instruction
    class structure:
        structure_t = 'structure_t'
    _structure = structure

class stringify(object):
    def __new__(cls, object):
        if isinstance(object, basestring):
            return object
        lookup = {
            None: 'None',
            int: 'int',
            long: 'long',
            str: 'str',
            basestring: 'basestring',
            unicode: 'unicode',
            chr: 'chr',
            callable: 'callable',
        }
        if not isinstance(object, tuple):
            return lookup[object]
        return tuple(cls(res) for res in object)

### Types used for parsed tree
class Reference(object):
    def __init__(self, **attrs):
        self.__children__ = []
        self.set(**attrs)
    def add(self, object):
        if not isinstance(object, Reference):
            raise TypeError(object)
        self.__children__.append(object)
    def get(self, name):
        if not isinstance(name, basestring):
            raise TypeError(name)
        return getattr(self, "_{:s}".format(name))
    def set(self, **attrs):
        for name, _ in attrs.iteritems():
            if not isinstance(name, basestring):
                raise TypeError(name)
            continue
        [setattr(self, "_{:s}".format(key), value) for key, value in attrs.iteritems()]
    def has(self, name):
        if not isinstance(name, basestring):
            raise TypeError(name)
        return hasattr(self, "_{:s}".format(name))
    name = property(fget=operator.attrgetter('_name'))
    node = property(fget=operator.attrgetter('_node'))
    def __repr__(self):
        cls = self.__class__
        return "{:s}({:s})".format(cls.__name__, self.name)
    children = property(fget=operator.attrgetter('__children__'))
    def __iter__(self):
        for child in self.__children__:
            yield child
        return
    def __getitem__(self, index):
        return self.__children__[index]

class Commentable(Reference):
    comment = property(fget=operator.attrgetter('_docstring'))
class Module(Commentable): pass
class Namespace(Commentable):
    namespace = property(fget=operator.attrgetter('_namespace'))
class Function(Commentable):
    ns = namespace = property(fget=operator.attrgetter('_namespace'))
    args = property(fget=operator.attrgetter('_arguments'))
    argtypes = mc = property(fget=operator.attrgetter('_multicase'))
    argdefaults = defaults = property(fget=operator.attrgetter('_defaults'))
    def __repr__(self):
        return "{:s}({:s})".format(super(Function, self).__repr__(), ', '.join(map("{!r}".format, self._arguments)))
class StaticFunction(Function): pass
class ClassFunction(Function): pass
class Param(Reference):
    owner = property(fget=operator.attrgetter('_owner'))
class ParamVariableList(Param): pass
class ParamVariableKeyword(Param): pass

### reduce parts of the ast into a tuple of strings
class grammar(object):
    def reduce_call(call):
        res = ()
        res += grammar.reduce(call.func)
        res += map(grammar.reduce, call.keywords),
        return res

    def reduce_keyword(keyword):
        res = ()
        res += (keyword.arg,)
        if hasattr(keyword, 'value'):
            res += grammar.reduce(keyword.value)
        return res

    def reduce_attribute(attr):
        res = ()
        if hasattr(attr, 'value'):
            res += grammar.reduce(attr.value)
        res += (attr.attr,)
        return ('.'.join(res),)

    def reduce_name(name):
        return (name.id,)

    def reduce_tuple(T):
        return tuple(map(grammar.reduce, T.elts)),


    @staticmethod
    def resolve(value):
        global evaluate
        if isinstance(value, basestring):
            try:
                res = evaluate(value)
            except AttributeError:
                res = value
            return res
        return value
    @staticmethod
    def reduce(type):
        for t, f in grammar.reduction.iteritems():
            if isinstance(type, t):
                return f(type)
            continue
        raise TypeError(type)

    reduction = {
        ast.Attribute : reduce_attribute,
        ast.Name : reduce_name,
        ast.keyword : reduce_keyword,
        ast.Call : reduce_call,
        ast.Tuple : reduce_tuple,
    }

### parsing code using ast visitor
class NSVisitor(ast.NodeVisitor):
    def __init__(self, ref):
        if not isinstance(ref, Reference):
            raise TypeError(ref)
        self._ref = ref

    def visit_ClassDef(self, node):
        if node.name.startswith('_'): return

        name = node.name
        try:
            docstring = ast.get_docstring(node) or ''
        except TypeError:
            docstring = ''

        # construct the namespace
        res = Namespace(node=node, name=name, namespace=self._ref, docstring=docstring)
        self._ref.add(res)

        # continue parsing its children
        nv = NSVisitor(res)
        map(nv.visit, ast.iter_child_nodes(node))

    def visit_FunctionDef(self, node):
        if node.name.startswith('_'): return

        # capture fields
        name = '.'.join((self._ref.name, node.name))
        try:
            docstring = ast.get_docstring(node) or ''
        except TypeError:
            docstring = ''
        arguments, defaults = node.args, node.args.defaults

        # figure out the defaults
        defs = { a.id : grammar.resolve(grammar.reduce(df)[0]) for df, a in zip(defaults, reversed(arguments.args)) }

        # figure out the attributes
        decorator_attributes = [d for d in node.decorator_list if isinstance(d, ast.Name)]
        methodtypes = {n for n, in map(grammar.reduce, decorator_attributes)}

        # figure out the decorators
        decorator_functions = [d for d in node.decorator_list if isinstance(d, ast.Call)]
        multicase = (dict(args) for n, args in map(grammar.reduce, decorator_functions) if n == u'utils.multicase')

        # figure out which type
        if 'classmethod' in methodtypes:
            F, args = ClassFunction, arguments.args[1:]
        elif 'staticmethod' in methodtypes:
            F, args = StaticFunction, arguments.args[:]
        else:
            F, args = Function, arguments.args[:]

        # capture the method
        res = F(node=node, name=node.name, namespace=self._ref, multicase=next(multicase, {}), docstring=docstring, arguments=[], defaults=defs)
        self._ref.add(res)

        # add its arguments
        res.args.extend((Param(name=a.id, owner=res) for a in args))
        if arguments.vararg:
            res.args.append(ParamVariableList(name=arguments.vararg, owner=res))
        if arguments.kwarg:
            res.args.append(ParamVariableKeyword(name=arguments.kwarg, owner=res))
        return

class RootVisitor(ast.NodeVisitor):
    def __init__(self, ref):
        if not isinstance(ref, Reference):
            raise TypeError(ref)
        self._ref = ref

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Str):
            self._ref.set(docstring=node.value.s)
        return

    def visit_ClassDef(self, node):
        if node.name.startswith('_'): return

        name = node.name
        try:
            docstring = ast.get_docstring(node)
        except TypeError:
            docstring = ''

        # construct the namespace
        res = Namespace(node=node, name=name, namespace=self._ref, docstring=docstring or '')
        self._ref.add(res)

        # continue parsing its children
        nv = NSVisitor(res)
        map(nv.visit, ast.iter_child_nodes(node))

    def visit_FunctionDef(self, node):
        if node.name.startswith('_'): return

        # capture fields
        name = node.name
        try:
            docstring = ast.get_docstring(node)
        except TypeError:
            docstring = ''
        arguments, defaults = node.args, node.args.defaults

        # figure out the defaults
        defs = { a.id : grammar.resolve(grammar.reduce(df)[0]) for df, a in zip(defaults, reversed(arguments.args)) }

        # figure out the attributes
        decorator_attributes = [d for d in node.decorator_list if isinstance(d, ast.Name)]
        methodtypes = {name for name, in map(grammar.reduce, decorator_attributes)}

        # figure out the decorators
        decorator_functions = [d for d in node.decorator_list if isinstance(d, ast.Call)]
        multicase = (dict(args) for name, args in map(grammar.reduce, decorator_functions) if name == u'utils.multicase')

        # figure out which type
        if 'classmethod' in methodtypes:
            F, args = ClassFunction, arguments.args[1:]
        elif 'staticmethod' in methodtypes:
            F, args = StaticFunction, arguments.args[:]
        else:
            F, args = Function, arguments.args[:]

        # capture the function
        res = F(node=node, name=node.name, namespace=self._ref, multicase=next(multicase, {}), docstring=docstring or '', arguments=[], defaults=defs)
        self._ref.add(res)

        # add its arguments
        res.args.extend((Param(name=a.id, owner=res) for a in args))
        if arguments.vararg:
            res.args.append(ParamVariableList(name=arguments.vararg, owner=res))
        if arguments.kwarg:
            res.args.append(ParamVariableKeyword(name=arguments.kwarg, owner=res))
        return

class restructure(object):
    @classmethod
    def escape(cls, string):
        def escape_chars(iterable, characters=u'*\\'):
            characters = set(characters)
            for ch in iterable:
                if ch in characters:
                    yield '\\'
                yield ch
            return
        return str().join(escape_chars(string))
    @classmethod
    def escapelist(cls, strings):
        return map(cls.escape, strings)
    @classmethod
    def indent(cls, string, prefix):
        res = string.split('\n') if isinstance(string, basestring) else string
        return '\n'.join(cls.indentlist(res, prefix))
    @classmethod
    def indentlist(cls, strings, prefix):
        return [prefix + line for line in strings]
    @classmethod
    def walk(cls, ref, field):
        while ref.has(field):
            yield ref
            ref = ref.get(field)
        yield ref
    @classmethod
    def docstringToList(cls, cmt):
        res = cls.escape(cmt)
        res = cmt.replace('``', '**')
        res = cmt.replace('`', '*')
        return res.strip().split('\n')
    @classmethod
    def Module(cls, ref):
        definition = ".. py:module:: {name:s}".format(name=ref.name)
        res = []
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])

        for child in ref.children:
            if isinstance(child, Function):
                res.extend(cls.Function(child).split('\n'))
            elif isinstance(child, Namespace):
                res.extend(cls.Namespace(child).split('\n'))
            else:
                raise TypeError(child)
            continue
        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

    @classmethod
    def Namespace(cls, ref):
        ns = [r.name for r in cls.walk(ref, 'namespace')]
        name = '.'.join(reversed(ns))

        definition = ".. namespace {name:s}".format(name=name)

        res = []
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])
        for child in ref.children:
            if isinstance(child, Function):
                res.extend(cls.Function(child).split('\n'))
            elif isinstance(child, Namespace):
                res.extend(cls.Namespace(child).split('\n'))
            else:
                raise TypeError(child)
            continue
        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)
    @classmethod
    def Function(cls, ref):
        ns = [r.name for r in cls.walk(ref, 'namespace')]
        name = '.'.join(reversed(ns))
        adefs, atypes = ref.defaults or {}, ref.mc

        #gargs = dict(itertools.groupby(ref.args, type))
        gargs = {}
        for a in ref.args:
            gargs.setdefault(type(a), []).append(a)

        args = []
        if Param in gargs:
            args.extend( (a.name, a.name, adefs.get(a.name, None), atypes.get(a.name, None)) for a in gargs[Param])
        if ParamVariableList in gargs:
            args.extend( (a.name, '*{:s}'.format(a.name), None, None) for a in gargs[ParamVariableList] )
        if ParamVariableKeyword in gargs:
            args.extend( (a.name, '**{:s}'.format(a.name), None, None) for a in gargs[ParamVariableKeyword] )
        args = [(n, cls.escape(fn), df, t) for n, fn, df, t in args]

        definition = ".. py:function:: {name:s}({arguments:s})".format(name=name, arguments=', '.join('{:s}={:s}'.format(fn, df) if df is not None else fn for _, fn, df, _ in args))

        res = []
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])
        for n, fn, _, ty in args:
            t = ()
            if isinstance(ty, basestring):
                try: t = evaluate(ty)
                except AttributeError: t = ty
            t = stringify(t)
            fmt = ": param {type:s} {name:s}" if t else ": param {name:s}"
            #if any('``{name:s}``'.format(name=n) in line for line in ref.comment.split('\n')):
            #    iterable = (line for line in ref.comment.split('\n') if '``{name:s}``'.format(name=n) in line)
            #    cmt = next(iterable, '')
            #    fmt += ' '+cmt if cmt else ''
            res.append(fmt.format(type=t if isinstance(t, basestring) else '|'.join(t), name=fn))

        if args: res.append('')

        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

if __name__ == '__main__':
    import sys, os.path

    # extract the module name
    _, path = sys.argv[:]
    filename = os.path.basename(path)
    name, _ = os.path.splitext(filename)

    # create our root module object
    M = Module(name=name, docstring='')

    # parse everything into our module object
    with file(path, 'rt') as f:
        data = ast.parse(f.read(), filename)

    V = RootVisitor(M)
    V.visit(data)

    # now we should have some structures
    print(restructure.Module(M))
