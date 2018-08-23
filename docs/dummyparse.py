from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import functools, operator, itertools, types
import argparse, logging
import ast, contextlib

### Namespace of idascripts-specific types that get evaluated to an internal type or a string
class evaluate(object):
    def __new__(cls, path):
        res = cls
        for name in path.split('.'):
            res = getattr(res, name)
        return res

    ## Miscellaneous internal types
    import six, types
    from six.moves import builtins
    class instruction:
        register_t = 'register_t'

    _instruction = instruction
    class structure:
        structure_t = 'structure.structure_t'
        member_t = 'structure.member_t'
    _structure = structure

### Namespace of internal python types and how to convert them into a string
class stringify(object):
    definitions = {
        None: 'None',
        int: 'int',
        long: 'long',
        list: 'list',
        str: 'str',
        basestring: 'basestring',
        unicode: 'unicode',
        chr: 'chr',
        callable: 'callable',
        types.NoneType: 'None',
    }
    stringmap = {
        'types.NoneType' : 'None',
        'types.TupleType' : 'tuple',
    }
    def __new__(cls, object):
        if isinstance(object, basestring):
            try:
                res = cls.stringmap[object] if object in cls.stringmap else evaluate(object)
            except AttributeError:
                res = object
            return cls(res) if isinstance(res, type) else res
        if not isinstance(object, tuple):
            return cls.definitions[object]
        return tuple(cls(res) for res in object)

### Reference types which represent the parsed tree
class Reference(object):
    def __init__(self, **attrs):
        self.__children__ = []
        self.set(**attrs)
    def add(self, object):
        if not isinstance(object, Reference):
            raise TypeError(object)
        self.__children__.append(object)
    def get(self, name, *default):
        if not isinstance(name, basestring):
            raise TypeError(name)
        return getattr(self, "_{:s}".format(name), *default) if default else getattr(self, "_{:s}".format(name))
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
class Class(Commentable):
    ns = namespace = property(fget=operator.attrgetter('_namespace'))
class Function(Commentable):
    ns = namespace = property(fget=operator.attrgetter('_namespace'))
    args = property(fget=operator.attrgetter('_arguments'))
    argtypes = mc = property(fget=operator.attrgetter('_multicase'))
    argdefaults = defaults = property(fget=operator.attrgetter('_defaults'))
    def __repr__(self):
        return "{:s}({:s})".format(super(Function, self).__repr__(), ', '.join(map("{!r}".format, self._arguments)))
class PropertyFunction(Function):
    ns = namespace = property(fget=operator.attrgetter('_namespace'))
    owner = property(fget=operator.attrgetter('_owner'))
class StaticFunction(Function): pass
class ClassFunction(Function): pass
class Param(Reference):
    owner = property(fget=operator.attrgetter('_owner'))
class ParamTuple(Reference):
    owner = property(fget=operator.attrgetter('_owner'))
    params = property(fget=operator.attrgetter('_params'))
class ParamVariableList(Param): pass
class ParamVariableKeyword(Param): pass

### reduce parts of the ast as a tuple of strings
class grammar(object):
    def reduce_call(call):
        res = ()
        res += grammar.reduce(call.func)
        res += [arg for arg, in map(grammar.reduce, call.args)],
        res += map(grammar.reduce, call.keywords),
        res += grammar.reduce(call.starargs) if call.starargs else None,
        res += grammar.reduce(call.kwargs) if call.kwargs else None,
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
        return '.'.join(res),

    def reduce_name(name):
        return name.id,

    def reduce_number(num):
        return num.n,

    def reduce_tuple(T):
        return tuple(map(grammar.reduce, T.elts)),

    def reduce_string(str):
        def escape(string, chars):
            for ch in string:
                if ch in chars:
                    yield '\\'
                yield ch
            return
        res = ''.join(escape(str.s, r'\"'))
        return res,

    def reduce_binop(op):
        l, op, r = op.left, op.op, op.right
        operation = grammar.operation[type(op)]
        global evaluate
        l, r = (n[0] for n in map(grammar.reduce, (l, r)))
        if isinstance(l, tuple): l = reduce(operation, l)
        if isinstance(r, tuple): r = reduce(operation, r)
        if isinstance(l, basestring): l = evaluate(l)
        if isinstance(r, basestring): r = evaluate(r)
        return operation(l, r),

    def reduce_dictionary(dict):
        keys = map(grammar.reduce, dict.keys)
        values = map(grammar.reduce, dict.values)
        res = ["{:s}={:s}".format(k[0], v[0]) for k, v in zip(keys, values)]
        return "{{{:s}}}".format(', '.join(res)),

    def return_empty(yy):
        return '',

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
        # check if it's a reduction that requires a transform
        for t, f in grammar.reduction.iteritems():
            if isinstance(type, t):
                return f(type)
            continue
        # its not, so try and map it directly to the operation
        if type.__class__ in grammar.operation:
            return grammar.operation[type.__class__]
        raise TypeError(type)

    reduction = {
        ast.Attribute : reduce_attribute,
        ast.Name : reduce_name,
        ast.keyword : reduce_keyword,
        ast.Call : reduce_call,
        ast.Tuple : reduce_tuple,
        ast.Str : reduce_string,
        ast.Num : reduce_number,
        ast.Dict : reduce_dictionary,
        ast.BinOp : reduce_binop,
        ast.Load : return_empty,
    }

    operation = {
        ast.Add : operator.add,
        ast.And : lambda a, b: a and b,
        ast.BitAnd : operator.and_,
        ast.BitOr : operator.or_,
        ast.Compare : cmp,
        ast.Div : operator.div,
        ast.Eq : operator.eq,
        ast.Gt : operator.gt,
        ast.GtE : operator.ge,
        ast.In : lambda a, b: a in b,
        ast.Is : operator.is_,
        ast.IsNot : operator.is_not,
        ast.LShift : operator.lshift,
        ast.Lt : operator.lt,
        ast.LtE : operator.le,
        ast.Mod : operator.mod,
        ast.Mult : operator.mul,
        ast.NotEq : operator.ne,
        ast.NotIn : lambda a, b: a not in b,
        ast.Or : lambda a, b: a or b,
        ast.Pow : operator.pow,
        ast.RShift : operator.rshift,
        ast.Sub : operator.sub,
        ast.UAdd : operator.iadd,
        ast.USub : operator.isub,
    }

### Converting Reference types into reStructuredText
class restructure(object):
    ## small utility functions
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
        return res.strip().split('\n')

    ## Reference type converters
    @classmethod
    def Module(cls, ref):
        definition = ".. py:module:: {name:s}".format(name=ref.name)
        res = []
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])

        for ch in ref.children:
            if isinstance(ch, Function):
                res.extend(cls.Function(ch).split('\n'))
            elif isinstance(ch, Namespace):
                res.extend(cls.Namespace(ch).split('\n'))
            elif isinstance(ch, Class):
                res.extend(cls.Class(ch).split('\n'))
            else:
                raise TypeError(ch)
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
        if ref.has('details'): res.extend(cls.escape(ref.get('details')).strip().split('\n') + [''])
        for ch in ref.children:
            if isinstance(ch, Function):
                res.extend(cls.Function(ch).split('\n'))
            elif isinstance(ch, Namespace):
                res.extend(cls.Namespace(ch).split('\n'))
            else:
                raise TypeError(ch)
            continue
        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

    @classmethod
    def Class(cls, ref):
        ns = [r.name for r in cls.walk(ref, 'namespace')]
        name = '.'.join(reversed(ns))

        res, definition = [], ".. py:class:: {name:s}".format(name=name)

        # class documentation
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])
        if ref.has('details'): res.extend(['details:'] + cls.escape(ref.get('details')).split('\n') + [''])

        # split up the properties from the methods
        global types
        props, children = [], []
        for t, iterable in itertools.groupby(ref.children, lambda ch: isinstance(ch, PropertyFunction)):
            if t: props.extend(iterable)
            else: children.extend(iterable)

        # group related properties together
        grouped = []
        for ch in props:
            if ch.owner == ch:
                grouped.append(ch)
            elif ch.get('property') == 'getter':
                ch.owner.set(getter=ch)
            elif ch.get('property') == 'setter':
                ch.owner.set(setter=ch)
            continue

        # process properties
        for ch in grouped:
            if not isinstance(ch, PropertyFunction):
                raise TypeError(ch)
            res.append(cls.Property(ch))

        # process functions
        for ch in children:
            if isinstance(ch, Function):
                res.extend(cls.Method(ch).split('\n'))
            elif isinstance(ch, Namespace):
                res.extend(cls.Namespace(ch).split('\n'))
            else:
                raise TypeError(ch)
            continue
        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

    @classmethod
    def Property(cls, ref):
        ns = [r.name for r in cls.walk(ref, 'namespace')]
        ns = ns[1:] if ref.name == '__new__' else ns[:]
        name = '.'.join(reversed(ns)) if ref.name == '__new__' else ref.name

        definition = ".. py:attribute:: {name:s}".format(name=name)

        res = []
        res.append('')

        attrs = []
        if ref.has('getter'): attrs.append(('getter', ref.get('getter')))
        else: attrs.append(('getter', ref))
        if ref.has('setter'): attrs.append(('setter', ref.get('setter')))

        params = []
        for n, r in attrs:
            adefs, atypes, aparams = r.get('defaults') or {}, r.mc, r.get('parameters')

            # ensure that all default arguments are stringified ahead of time so they're always there
            adefs = {a : stringify(v) if not v and v not in {0, None} else v for a, v in adefs.iteritems()}

            fmt = ": param {name:s} {comment:s}"
            params.append(fmt.format(name=n, comment=' '.join(cls.docstringToList(r.comment))))

            #gargs = dict(itertools.groupby(ref.args, type))
            gargs = {}
            for a in r.args:
                gargs.setdefault(type(a), []).append(a)

            args = []
            if Param in gargs:
                args.extend( (a.name, a.name, adefs.get(a.name, None), atypes.get(a.name, None)) for a in gargs[Param])
            if ParamVariableList in gargs:
                args.extend( (a.name, '*{:s}'.format(a.name), None, None) for a in gargs[ParamVariableList] )
            if ParamVariableKeyword in gargs:
                args.extend( (a.name, '**{:s}'.format(a.name), None, None) for a in gargs[ParamVariableKeyword] )
            args = [(n, cls.escape(fn), df, t) for n, fn, df, t in args][1:]

            for n, fn, _, ty in args:
                if isinstance(ty, basestring): t = grammar.resolve(ty)
                elif ty is None: t = ()
                elif isinstance(ty, types.TupleType):
                    t = tuple(ty)
                    if all(isinstance(n, tuple) for n in t): t = tuple(map(operator.itemgetter(0), t))
                else: raise TypeError(name, n, ty)
                t = stringify(t)

                fmt = ": param {type:s} {name:s}" if t else ": param {name:s}"
                fmt += ' '+cls.escape(aparams[n]) if n in aparams else ''
                params.append(fmt.format(type=t if isinstance(t, basestring) else '|'.join(t), name=fn))
            continue
        res.extend(cls.indentlist(params, '   '))

        if attrs: res.append('')

        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

    @classmethod
    def Method(cls, ref):
        ns = [r.name for r in cls.walk(ref, 'namespace')]
        ns = ns[1:] if ref.name == '__new__' else ns[:]
        name = '.'.join(reversed(ns)) if ref.name == '__new__' else ref.name

        aliases = ref.get('aliases') or {}
        adefs, atypes, aparams = ref.get('defaults') or {}, ref.mc, ref.get('parameters')

        # ensure that all default arguments are stringified ahead of time so they're always there
        adefs = {a : stringify(v) if not v and v not in {0, None} else v for a, v in adefs.iteritems()}

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
        args = [(n, cls.escape(fn), df, t) for n, fn, df, t in args][1:]

        definition = ".. py:method:: {name:s}({arguments:s})".format(name=name, arguments=', '.join('{:s}={:s}'.format(fn, "''" if df == '' else df) if df is not None else fn for _, fn, df, _ in args))

        res = []
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])
        if aliases: res.extend(["Aliases: {:s}".format(', '.join(aliases))] + [''])

        for n, fn, _, ty in args:
            if isinstance(ty, basestring): t = grammar.resolve(ty)
            elif ty is None: t = ()
            elif isinstance(ty, types.TupleType):
                t = tuple(ty)
                if all(isinstance(n, tuple) for n in t): t = tuple(map(operator.itemgetter(0), t))
            else: raise TypeError(name, n, ty)
            t = stringify(t)

            fmt = ": param {type:s} {name:s}" if t else ": param {name:s}"
            fmt += ' '+cls.escape(aparams[n]) if n in aparams else ''
            res.append(fmt.format(type=t if isinstance(t, basestring) else '|'.join(t), name=fn))

        if args: res.append('')

        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

    @classmethod
    def Function(cls, ref):
        ns = [r.name for r in cls.walk(ref, 'namespace')]
        ns = ns[1:] if ref.name == '__new__' else ns[:]
        name = '.'.join(reversed(ns))

        aliases = ref.get('aliases') or {}
        adefs, atypes, aparams = ref.get('defaults') or {}, ref.mc, ref.get('parameters')

        # ensure that all default arguments are stringified ahead of time so they're always there
        adefs = {a : stringify(v) if not v and v not in {0, None} else v for a, v in adefs.iteritems()}

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

        definition = ".. py:function:: {name:s}({arguments:s})".format(name=name, arguments=', '.join('{:s}={!s}'.format(fn, "''" if df == '' else df) if df is not None else fn for _, fn, df, _ in args))

        res = []
        res.append('')
        if ref.comment: res.extend(cls.docstringToList(ref.comment) + [''])
        if aliases: res.extend(["Aliases: {:s}".format(', '.join(aliases))] + [''])

        for n, fn, _, ty in args:
            if isinstance(ty, basestring): t = grammar.resolve(ty)
            elif ty is None: t = ()
            elif isinstance(ty, types.TupleType):
                t = tuple(ty)
                if all(isinstance(n, tuple) for n in t): t = tuple(map(operator.itemgetter(0), t))
            else: raise TypeError(name, n, ty)
            t = stringify(t)

            fmt = ": param {type:s} {name:s}" if t else ": param {name:s}"
            fmt += ' '+cls.escape(aparams[n]) if n in aparams else ''
            res.append(fmt.format(type=t if isinstance(t, basestring) else '|'.join(t), name=fn))

        if args: res.append('')

        res = cls.indentlist(res, '   ')
        res[0:0] = (definition,)
        return '\n'.join(res)

### Visitor Node decorator_list extraction
class decorators(object):
    @classmethod
    def attributes(cls, node):
        global grammar
        res = (d for d in node.decorator_list if isinstance(d, (ast.Attribute,ast.Name)))
        return [n for n, in map(grammar.reduce, res)]
    @classmethod
    def functions(cls, node):
        global grammar
        res = (d for d in node.decorator_list if isinstance(d, ast.Call))
        return [(n, a, k, sa, sk) for n, a, k, sa, sk in map(grammar.reduce, res)]

### Visitor parser mix-ins
class ConditionalVisitor(ast.NodeVisitor):
    def visit_If(self, node):
        ok = None
        if isinstance(node.test, ast.Attribute):
            idaapiversion, = grammar.reduce(node.test.left)
            ops = [grammar.reduce(o)[0] for o in node.test.ops]
            versions = [grammar.reduce(v)[0] for v in node.test.comparators]
            if idaapiversion != 'idaapi.__version__':
                raise NotImplementedError(idaapiversion, ops, versions)
            ok = True
        elif isinstance(node.test, ast.Name):
            expr = grammar.reduce(node.test)[0]
            ok = eval(expr)

        if ok is None: return

        if ok:
            map(self.visit, node.body)
        else:
            map(self.visit, node.orelse)
        return

class FunctionVisitor(ast.NodeVisitor):
    def visit_FunctionDef(self, node):
        if node.name != '__new__' and node.name.startswith('_'): return

        # capture fields
        name = node.name
        try:
            docstring = ast.get_docstring(node)
        except TypeError:
            docstring = ''
        arguments, defaults = node.args, node.args.defaults

        # figure out the defaults
        defs = { a.id : grammar.resolve(grammar.reduce(df)[0]) for df, a in zip(reversed(defaults), reversed(arguments.args)) }

        # figure things out about which decorators were applied
        methodtypes = {m for m in decorators.attributes(node)}
        multicase = (dict(kw) for n, _, kw, _, _ in decorators.functions(node) if n == u'utils.multicase')
        aliases = (a for n, a, _, _, _ in decorators.functions(node) if n == 'document.aliases')
        params = (dict(kw) for n, _, kw, _, _ in decorators.functions(node) if n == 'document.parameters')

        # if it's hidden, then don't bother adding it
        if 'document.hidden' in methodtypes: return

        # figure out which type
        if node.name == '__new__' or 'classmethod' in methodtypes:
            F, args = ClassFunction, arguments.args[1:]
        elif 'staticmethod' in methodtypes:
            F, args = StaticFunction, arguments.args[:]
        elif 'property' in methodtypes or any(mt.endswith(t) for mt in methodtypes for t in {'.getter','.setter'}):
            F, args = PropertyFunction, arguments.args[:]
        else:
            F, args = Function, arguments.args[:]

        # construct the function
        res = F(node=node, name=node.name, namespace=self._ref, multicase=next(multicase, {}), docstring=docstring or '', arguments=[], defaults=defs, parameters=next(params, {}), aliases=set(next(aliases, {})))
        self._ref.add(res)

        # determine what type of attribute it is
        if F is PropertyFunction:
            owner = None
            if 'property' in methodtypes:
                owner = res
                res.set(property='define')
            elif any(mt.endswith('.getter') for mt in methodtypes):
                name = next(mt for mt in methodtypes if mt.endswith('.getter'))
                name, _ = name.rsplit('.', 1)
                owner = next(n for n in self._ref.children if isinstance(n, PropertyFunction) and n.name == name and n.owner == n)
                res.set(property='getter')
            elif any(mt.endswith('.setter') for mt in methodtypes):
                name = next(mt for mt in methodtypes if mt.endswith('.setter'))
                name, _ = name.rsplit('.', 1)
                owner = next(n for n in self._ref.children if isinstance(n, PropertyFunction) and n.name == name and n.owner == n)
                res.set(property='setter')
            if owner is not None:
                res.set(owner=owner)

        # add its arguments
        res.args.extend((ParamTuple(owner=res, params=a) if isinstance(a, ast.Tuple) else Param(name=a.id, owner=res) for a in args))
        if arguments.vararg:
            res.args.append(ParamVariableList(name=arguments.vararg, owner=res))
        if arguments.kwarg:
            res.args.append(ParamVariableKeyword(name=arguments.kwarg, owner=res))
        return

class NamespaceVisitor(ast.NodeVisitor):
    def visit_ClassDef(self, node):
        '''Anything that's a class is considered a namespace'''
        if node.name.startswith('_'): return

        # figure out which type it is according to the decorators
        attributes = decorators.attributes(node)
        if 'document.classdef' in attributes:
            return self.append_classdef(node)
        elif 'document.namespace' in attributes:
            return self.append_namespace(node)

        # no decorator was found, so assume it's a namespace
        return self.append_namespace(node)

    def append_classdef(self, node):
        attributes = decorators.attributes(node)
        details = [details for n, (details,), _, _, _ in decorators.functions(node) if n == 'document.details']

        try:
            docstring = ast.get_docstring(node) or ''
        except TypeError:
            docstring = ''

        # construct the namespace
        res = Class(node=node, name=node.name, namespace=self._ref, docstring=docstring)
        if attributes: res.set(attributes=attributes)
        if details: res.set(details=details)
        self._ref.add(res)

        # continue parsing its children
        nv = NSVisitor(res)
        map(nv.visit, ast.iter_child_nodes(node))

    def append_namespace(self, node):
        attributes = decorators.attributes(node)
        details = [details for n, (details,), _, _, _ in decorators.functions(node) if n == 'document.details']

        try:
            docstring = ast.get_docstring(node) or ''
        except TypeError:
            docstring = ''

        # construct the namespace
        res = Namespace(node=node, name=node.name, namespace=self._ref, docstring=docstring)
        if attributes: res.set(attributes=attributes)
        if details: res.set(details=details)
        self._ref.add(res)

        # continue parsing its children
        nv = NSVisitor(res)
        map(nv.visit, ast.iter_child_nodes(node))

### Visitor entrypoints
class NSVisitor(FunctionVisitor, NamespaceVisitor, ConditionalVisitor):
    def __init__(self, ref):
        if not isinstance(ref, Reference):
            raise TypeError(ref)
        self._ref = ref

class RootVisitor(FunctionVisitor, NamespaceVisitor, ConditionalVisitor):
    def __init__(self, ref):
        if not isinstance(ref, Reference):
            raise TypeError(ref)
        self._ref = ref
        self._ref.set(docstring='')

    def visit_Expr(self, node):
        '''Grab the first module docstring.'''
        if isinstance(node.value, ast.Str) and not self._ref.has('docstring'):
            docstring, = grammar.reduce(node.value)
            self._ref.set(docstring=docstring)
        return

if __name__ == '__main__':
    ### Output a module into reStructuredText
    import sys, os.path

    # extract the module name
    _, path = sys.argv[:]
    filename = os.path.basename(path)
    name, _ = os.path.splitext(filename)

    # create our root module object
    M = Module(name=name)

    # read the file and parse everything into our root module object
    with file(path, 'rt') as f:
        data = ast.parse(f.read(), filename)

    V = RootVisitor(M)
    V.visit(data)

    # now we should have some data to format as rst
    print(restructure.Module(M))
