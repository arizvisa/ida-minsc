from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import functools, operator, itertools, types

import argparse
import ast
import contextlib

### 
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
        if not isinstance(object, basestring):
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
    namespace = property(fget=operator.attrgetter('_namespace'))
    args = property(fget=operator.attrgetter('_arguments'))
    mc = property(fget=operator.attrgetter('_multicase'))
    def __repr__(self):
        return "{:s}({:s})".format(super(Function, self).__repr__(), ', '.join(map("{!r}".format, self._arguments)))
class StaticFunction(Function): pass
class ClassFunction(Function): pass
class Param(Reference):
    owner = property(fget=operator.attrgetter('_owner'))
class ParamVariableList(Param):
    owner = property(fget=operator.attrgetter('_owner'))
class ParamVariableKeyword(Param):
    owner = property(fget=operator.attrgetter('_owner'))

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
def _is_sub_node(node):
    return isinstance(node, ast.AST) and not isinstance(node, ast.expr_context)

def _is_leaf(node):
    for field in node._fields:
        attr = getattr(node, field)
        if _is_sub_node(attr):
            return False
        elif isinstance(attr, (list, tuple)):
            for val in attr:
                if _is_sub_node(val):
                    return False
                continue
            pass
        continue
    else:
        return True

def pformat(node, indent='    ', _indent=0):
    if node is None:  # pragma: no cover (py35+ unpacking in literals)
        return repr(node)
    elif _is_leaf(node):
        if hasattr(node, 'lineno'):
            ret = ast.dump(node)
            # For nodes like Pass() which have information but no data
            if ret.endswith('()'):
                info = '(lineno={:d}, col_offset={:d}'.format(node.lineno, node.col_offset)
            else:
                info = '(lineno={:d}, col_offset={:d}, '.format(node.lineno, node.col_offset)
            return ret.replace('(', info, 1)
        else:
            return ast.dump(node)
    else:
        class state:
            indent = _indent

        @contextlib.contextmanager
        def indented():
            state.indent += 1
            yield
            state.indent -= 1

        def indentstr():
            return state.indent * indent

        def _pformat(el, _indent=0):
            return pformat(el, indent=indent, _indent=_indent)

        out = type(node).__name__ + '(\n'
        with indented():
            fields = (('lineno', 'col_offset') + node._fields) if hasattr(node, 'lineno') else node._fields

            for field in fields:
                attr = getattr(node, field)
                if attr == []:
                    representation = '[]'
                elif isinstance(attr, list) and len(attr) == 1 and isinstance(attr[0], ast.AST) and _is_leaf(attr[0]):
                    representation = '[{:s}]'.format(_pformat(attr[0]))
                elif isinstance(attr, list):
                    representation = '[\n'
                    with indented():
                        for el in attr:
                            representation += '{:s}{:s},\n'.format(indentstr(), _pformat(el, state.indent))
                    representation += indentstr() + ']'
                elif isinstance(attr, ast.AST):
                    representation = _pformat(attr, state.indent)
                else:
                    representation = repr(attr)
                out += '{:s}{:s}={:s},\n'.format(indentstr(), field, representation)
        out += indentstr() + ')'
        return out

def pprint(*args, **kwargs):
    print(pformat(*args, **kwargs))

def is_multicased(fdef):
    res = (d for d in getattr(fdef, 'decorator_list', []))
    res = (d for d in res if isinstance(d, ast.Call))
    res = (d.func for d in res)
    res = (getattr(f, 'attr', None) for f in res)
    return any(a == 'multicase' for a in res)

class NSVisitor(ast.NodeVisitor):
    def __init__(self, ref):
        if not isinstance(ref, Reference):
            raise TypeError(ref)
        self._ref = ref

    def visit_ClassDef(self, node):
        if node.name.startswith('_'): return

        name = '.'.join((self._ref.name, node.name))
        try:
            docstring = ast.get_docstring(node)
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
            docstring = ast.get_docstring(node)
        except TypeError:
            docstring = ''
        arguments, defaults = node.args, node.args.defaults

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

        # capture the method
        res = F(node=node, name=node.name, namespace=self._ref, multicase=next(multicase, {}), docstring=docstring, arguments=[])
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

    def visit_ClassDef(self, node):
        if node.name.startswith('_'): return

        name = node.name
        try:
            docstring = ast.get_docstring(node)
        except TypeError:
            docstring = ''

        # construct the namespace
        res = Namespace(node=node, name=name, namespace=None, docstring=docstring)
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
        res = F(name=node.name, namespace=self._ref, multicase=next(multicase, {}), docstring=docstring, arguments=[])
        self._ref.add(res)

        # add its arguments
        res.args.extend((Param(name=a.id, owner=res) for a in args))
        if arguments.vararg:
            res.args.append(ParamVariableList(name=arguments.vararg, owner=res))
        if arguments.kwarg:
            res.args.append(ParamVariableKeyword(name=arguments.kwarg, owner=res))
        return

if __name__ == '__main__':
    import sys, os.path

    # extract the module name
    _, path = sys.argv[:]
    filename = os.path.basename(path)
    name, _ = os.path.splitext(filename)

    # create our root module object
    M = Module(name=name)

    # parse everything into our module object
    with file(path, 'rt') as f:
        data = ast.parse(f.read(), filename)

    V = RootVisitor(M)
    V.visit(data)

    # now we should have some structures
