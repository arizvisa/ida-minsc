import idc
import database,function,segment,structure,store
import ia32,pecoff,ndk
import ptypes,ctypes
import logging
from ptypes import *
pint.setbyteorder(pint.littleendian)

class Ida(object):
    offset = 0xffffffff

    @classmethod
    def seek(cls, offset):
        '''Seek to a particular offset'''
        cls.offset = offset

    @classmethod
    def consume(cls, amount):
        '''Read some number of bytes'''
        left,right = cls.offset,cls.offset+amount
        cls.offset = right
        return database.getblock(left,right)

    @classmethod
    def store(cls, data):
        '''Write some number of bytes'''
        for count,x in enumerate(data):
            idc.PatchByte(cls.offset, x)
            cls.offset += 1
        return count

    @classmethod
    def baseaddress(cls):
        return database.baseaddress()

    @classmethod
    def producer(cls, ea):
        while True:
            v = idc.Byte(ea)
            yield chr(v)
            ea += 1
        return

from database import log
kernel32 = ctypes.WinDLL('kernel32.dll')
ntdll = ctypes.WinDLL('ntdll.dll')

import ia32.decoder
def isdynamiccall(instruction):
    p,i,m,s,d,imm = instruction   #heh
    if i == '\xff':
        mod,r,rm = ia32.decoder.extractmodrm(ord(m))
        if (mod == 0) and (rm == 5):
            return False
        if (r == 2) or (r == 3):
            return True
    return False

def isregularcall(instruction):
    p,i,m,s,d,imm = instruction   #heh
    if i == '\xe8':
        return True
    return False

def iscmpconstant(instruction):
    m = ia32.modrm.extract(instruction)
    if m:
        mod,reg,rm = m
        return reg == 7 and ia32.getOpcode(instruction) == '\x81'
    return False

def isacall(instruction):
    return isdynamiccall(instruction) or isregularcall(instruction)
def isaminorbranch(instruction):
    return ia32.isRelativeBranch(instruction)
def isamajorbranch(instruction):
    return ia32.isRegisterBranch(instruction) or ia32.isAbsoluteBranch(instruction) or ia32.isMemoryBranch(instruction)

def iscallinblock(block):
    '''Given a string, check to see if there's a call instruction'''
    producer = iter(block)

    # XXX: might be useful to check if block is a forward to a real sub
    #      like a single jmp instruction..
    while True:
        if isacall(ia32.consume(producer)):
            return True
        continue
    return False
    
def iscallinfunction(ea):
    '''go through all of a function's chunks and check to see if there's a call in there'''
    result = []

    for start,end in function.chunks(ea):
        block = database.getblock(start,end)
        try:
            if iscallinblock(block):
                return True
        except StopIteration:
            pass
        continue

    return False

if False:
    # XXX: to convert from this, we can also just use idc.GetLocByName

    #QuickTimeImage!FPX_GraphicsImportComponentDispatch+0x65f6   
    #
    module,_location = string.split('!')
    symbol,offset = _location.split('+')     #FIXME: we should use rindex for this

    # XXX: to convert back, we'll need to find the nearest export symbol we know about
    #      and then calculate the offset

if False:
    # would be nice to identify if an address is contained inside a loop
    # that way we can apply it to a backtrace in order to prioritize the
    # list somehow
    pass

def detruncate():
    for x in database.functions():
        name = function.getName(x)
        if name.startswith('trunc_'):
            print '%x: [ali.detruncate] found truncated function name %s'% (x, name)
            name = name[ name.index('__') :]
            name = '%s_%x'% (name[:128], x - idc.GetSegmentAttr(x, idc.SEGATTR_START) + 0x400)
            function.setName(x, name)
        continue
    return

def getProcessBasicInformation(handle):
    class ProcessBasicInformation(ctypes.Structure):
        _fields_ = [('Reserved1', ctypes.c_uint32),
                    ('PebBaseAddress', ctypes.c_uint32),
                    ('Reserved2', ctypes.c_uint32 * 2),
                    ('UniqueProcessId', ctypes.c_uint32),
                    ('Reserved3', ctypes.c_uint32)]

    pbi = ProcessBasicInformation()
    res = ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
    # XXX: we should check res, but this is aaron's code
    return pbi

if False:
    # if we want to do name demangling, we can start with code here
    # http://code.google.com/p/ctypes-stuff/source/detail?r=122
    # i think idautils also provides an api
    pass

def readaddresses(filename):
    '''return a list of addresses from a formatted file where the first field is a hex number'''
    f = file(filename, 'rt')
    data = f.read().strip()
    
    result = []
    for x in data.split('\n'):
        x = x.lstrip()

        if ' ' in x:    # FIXME: this is not the way to do this
            x = x[:x.find(' ')]

        x = int(x,16)
        result.append(x)

    return result

def writeaddresses(list, filename):
    '''Write the specified list to the file represented by filename'''
    f = file(filename, 'wt')
    f.write('\n'.join(map(hex, list)))
    f.close()

if False:
    # need to figure out some fast way of identifying functions
    # that have a block that terminates with a jmp esp
    # or at least some way of identifying functions that might
    # branch to code outside of the function's boundaries
    pass

def checkmarks():
    res = []
    for a,m in database.marks():
        try:
            res.append((function.top(a), a , m))
        except ValueError:
            pass
        continue

    d = list(res)
    d.sort( lambda a,b: cmp(a[0], b[0]) )

    flookup = {}
    for fn,a,m in d:
        try:
            flookup[fn].append((a,m))
        except:
            flookup[fn] = [(a,m)]
        continue

    functions = [ (k,v) for k,v in flookup.items() if len(v) > 1 ]
    if not functions:
        print 'no dupes found or something'
        return

    for k,v in functions:
        print '%x function %s'% (k,function.getName(k))
        print '\n'.join( ('%x - %s'%(a,m) for a,m in v) )
    return
checkMarkLocality = checkmarks

def colormarks():
    # tag and color
    f = set()
    for ea,m in database.marks():
        database.tag(ea, 'mark', m)
        database.color(ea, 0x7f007f)
        try:
            f.add(function.top(ea))
        except ValueError:
            pass
        continue

    # tag the functions too
    for ea in list(f):
        m = function.marks(ea)
        database.tag(ea, 'marks', ','.join([hex(a) for a,b in m]))
    return
colorAllMarks = colormarks

def writebreakpoints(list, filename, command="r;g"):
    '''Write the specified list to the file represented by filename'''
    f = file(filename, 'wt')
    f.write('\n'.join( ('bp %x "%s"'% (ea,command) for ea in list) ))
    f.close()

class remote(object):
    '''For poor folk without a dbgeng'''
    def __init__(self, localbaseaddress, remotebaseaddress):
        if localbaseaddress is None:
            localbaseaddress = database.baseaddress()
        self.lbase = localbaseaddress
        self.rbase = remotebaseaddress

    def get(self, addr):
        offset = addr - self.rbase
        return offset + self.lbase

    def put(self, ea):
        offset = ea - self.lbase
        return offset + self.rbase

    def go(self, ea):
        database.go( self.get(ea) )

def markhits(addresses, prefix='ht-', color=0x004000):
    sourcetag = '%ssource'% prefix
    destinationtag = '%sdestination'% prefix
    counttag = '%scount'% prefix
    for i,ea in enumerate(addresses):
        print '%x: %d of %d'%(ea,i+1,len(addresses))
        target = database.cxdown(ea)[-1]
        database.tag(target, sourcetag, ea)
        database.tag(ea, destinationtag, target)
        database.color(ea, color)

        result = database.tag(ea, counttag)
        if result is None:
            count = 0
        else:
            count = result+1
        database.tag(ea, counttag, count)

        result = database.tag(target,counttag)
        if result is None:
            count = 0
        else:
            count = result+1
        database.tag(target, counttag, count)
    return

### vtable type stuff that only grabs addresses that point to code
class vtable(parray.terminated):
    _object_ = pint.uint32_t
    source = Ida
    def isTerminator(self, value):
        offset = value.getoffset()
        if len(self) <= 1:
            return False

        # if the value of the currently read object doesn't point to code, then bail.
        ea = int(value)
        if not database.isCode(ea):
            del(self.value[-1])
            return True

        # if the offset of the read object contains a reference to it, then also bail
        if database.up(offset):
            del(self.value[-1])
            return True

        return False

    def shortname(self):
        return 'vt_%x'% (self.getoffset()-self.source.baseaddress())

def makevtable(ea):
    a = database.prevdata(ea)   # assume we'll hit the dataref that ida has figured out for us
    a = vtable(offset=a)
    return a.l

def markvtable(ea):
    a = makevtable(ea)
    name = a.shortname()
    res = map(int, list(a))
    for x in res:
        function.tag(x, 'vtable', name)
        
    fnmap(process, res)

### standard table of some kind
class table(parray.terminated):
    _object_ = pint.uint32_t
    source = Ida
    def isTerminator(self, value):
        offset = value.getoffset()
        if len(self) <= 1:
            return False

        # if the offset of the read object contains a reference to it, then also bail
        if database.up(offset):
            del(self.value[-1])
            return True

        return False

    def shortname(self):
        return 'v_table_%x'% (self.getoffset()-self.source.baseaddress())

def maketable(ea):
    a = database.prevdata(ea)   # assume we'll hit the dataref that ida has figured out for us
    a = table(offset=a)
    return a.l

### structure <-> ptype stuff
def generatePtypeFromFragment(flag, size, structureid):
    flag &= idc.DT_TYPE
    lookup = {
        idc.FF_BYTE : pint.uint8_t,
        idc.FF_WORD : pint.uint16_t,
        idc.FF_DWRD : pint.uint32_t,
        idc.FF_QWRD : pint.uint64_t,
        idc.FF_FLOAT : pfloat.single,
        idc.FF_DOUBLE : pfloat.double,
    }

    # lookup the type according to the flag
    try:
        t = lookup[flag]
        # found a match
        if t().size() == size:
            return t

    except KeyError, e:
        # FIXME: I can't figure out how to identify if a member is an array
        if flag == idc.FF_STRU:
            return getfragment(structureid, 0, structure.size(structureid))
        pass

    t = generatePtypeFromSize(size)
    return t

def generatePtypeFromSize(size):
    lookup = {
        1 : pint.uint8_t,
        2 : pint.uint16_t,
        4 : pint.uint32_t,
        8 : pint.uint64_t,
    }
    if size in lookup:
        return lookup[size]
    return dyn.block(size)

def getframe(pc, spdelta=None):
    top = function.top(pc)
    id = function.getFrameId(top)
    a,r,l = function.getAvarSize(top), function.getRvarSize(top), function.getLvarSize(top)
    spdelta = (spdelta, function.getSpDelta(pc))[spdelta is None]
    bs = (spdelta+l) + (r-4)

    class frame(pstruct.type):
        _fields_ = []

    # FIXME: sometimes this code doesn't decode the stack correctly. i suspect it's
    #        something in ida that i'm missing.

    # figure out if there's some extra stuff on the stack
    if bs < 0:
        fragment = getfragment(id, offset=0, size=l, baseoffset=-l)
        frame._fields_.append( (dyn.block(-bs), '__extrastate_%x'%(l - bs)) )
    else:
        fragment = getfragment(id, offset=bs, size=l-bs, baseoffset=-l)

    if fragment().a.size() > 0:
        frame._fields_.extend( fragment._fields_ )

    frame._fields_.extend( getfragment(id, offset=l, size=r)._fields_ )
    frame._fields_.extend( getfragment(id, offset=l+r, size=a)._fields_ )
    frame.offset = spdelta  # for show
    return frame

def getfragment(id, offset=0, size=None, baseoffset=0):
    '''Given a structure id, return the fragment in ptype form'''
    if size is None:
        size = structure.size(id)

    fieldarray = []
    for (o,s),(m_name, m_cmt) in structure.fragment(id, offset, size):
        if s == 0:
            continue

        if s > size:
            o += s-size
            s = size

        if m_name is None:
            m_name = '__unknown_%x'% abs(o+baseoffset)

        m_sid = idc.GetMemberStrId(id, o)
        m_flag = idc.GetMemberFlag(id, o)

        ptype = generatePtypeFromFragment(m_flag, s, m_sid)
        fieldarray.append( (ptype,m_name) )

        size -= s
        if size < 0:
            break
        continue

    class fragment(pstruct.type):
        _fields_ = fieldarray

    return fragment

def ptypedefinition(p, address=None):
    '''Given a ptype, attempt to output the string definition of it...'''
    name = p.__name__
    if address is not None:
        name += '_%x'% database.getoffset(address)

    if issubclass(p, pstruct.type):
        fields = ["(%s.%s, '%s')"% (t.__module__,t.__name__, n) for t,n in p._fields_]
        s = 'class %s(pstruct.type): _fields_=[%s]'% (name, ','.join(fields))
        return s
    if issubclass(p, parray.type):
        s = 'class %s(parray.type): _object_=[%s]; length=%d'% (name, p._object_.__name__, p.length)
        return s
    raise NotImplementedError

# this is from my idapythonrc.py file...
def dump(l):
    result  = []
    for n in l:
        try:
            if type(n) is tuple:
                n = '\t'.join((hex(int(x)) for x in list(n)))

            elif type(int(n)) is int:
                n = hex(n)

        except ValueError:
            n = repr(n)

        result.append(n)
    return '\n'.join(result)

### processing a database
def fnmap(l, functions, *args, **kwds):
    '''Execute provided callback on all functions in database. Synonymous to map(l,database.functions())'''
    all = functions
    result = []
    for i,x in enumerate(all):
        print '%x: processing # %d of %d'%( x, i+1, len(all) )
        result.append( l(x, *args, **kwds) )
        continue

        try:
            result.append( l(x, *args, **kwds) )
        except Exception,e:
            print '%x: FAILED'%x, repr(e)
        continue
    return result

def processall(**attrs):
    return fnmap(process, database.functions(), **attrs)

"""
def dostuff(prefix, z):
 items = z.items()
 for i,(k,v) in enumerate(items):
  print '%d of %d'%( i+1, len(items) )
  function.store(k, v, prefix)
 return

z = dict([(x,function.fetch(x)) for x in database.functions() if len(function.tag(x).values()) > 1])
a = fu.closure(dostuff, z=z)

b = fu.dumps(a)

c = fu.loads(b, namespace=globals())
c('wtf')
"""

try:
    import _PyDbgEng,ndk,os

    class windbg(object):
        class __provider(object):
            offset = 0
            def __init__(self, client):
                self.client = client

            def seek(self, offset):
                '''Seek to a particular offset'''
                self.offset = offset

            def consume(self, amount):
                '''Read some number of bytes'''
                try:
                    result = str( self.client.DataSpaces.Virtual.Read(self.offset, amount) )
                except RuntimeError, e:
                    raise StopIteration('Unable to read 0x%x bytes from address %x'% (amount, self.offset))
                return result
                
            def store(self, data):
                '''Write some number of bytes'''
                return self.client.DataSpaces.Virtual.Write(self.offset, data)

        class __registers_INT32(object):
            pc = property(fget=lambda self: self.client.Registers.InstructionOffset)
            sp = property(fget=lambda self: self.client.Registers.StackOffset)
            fp = property(fget=lambda self: self.client.Registers.FrameOffset)
    #        pc = property(fget=lambda self: self['eip'])
    #        sp = property(fget=lambda self: self['esp'])

            def __init__(self, client):
                self.client = client

            def __getitem__(self, name):
                registers = self.client.Registers.Registers
                result = registers[name]
                return int(result)

            def __setitem__(self, register, value):
                registers = self.client.Registers.Registers
                result = registers[name]
                result.Value = value

            def keys(self):
                registers = self.client.Registers.Registers
                INT32 = _PyDbgEng.ValueType.INT32

                return [ x for x in registers.keys() if int(registers[x].Type) == INT32 ]

            def __repr__(self):
                return repr( dict(((k, self[k]) for k in self.keys())) )

        r = None            # contains the current register state
        r32 = None          # contains the current 32-bit register state
        source = None       # contains a ptype source over the available address-space
        client = None       # the current DebugClient interface

        def __init__(self, client):
            self.client = client
            self.source = self.__provider(client)
            self.r32 = self.r = self.__registers_INT32(client)

            self.sync()

        def sync(self):
            print '[remote.load] syncing view with state at address %x'% self.r.pc

            print '[remote.load] loading the Peb'
            self.peb = ndk.PEB(source=self.source,offset=self.client.Control.Evaluate("@$peb")).l

            print '[remote.load] parsing the Peb.Ldr modules'
            self.__modules = list(self.peb['Ldr'].d.l['InLoadOrderModuleList'].walk())

            print '[remote.load] locating the current module for %s'% database.filename()
            try: 
                self.__current = self.getmodulebyfilename(database.filename())

                print '[remote.load] loading the executable structure'
                self.__executable = self.current['DllBase'].d.l

            except KeyError:
                print '[remote.load] unable to locate module %s in Peb.Ldr'% database.filename()
            return self

        __modules = __current = __executable = None
        modules = property(fget=lambda x: x.__modules)
        current = property(fget=lambda x: x.__current)
        executable = property(fget=lambda x: x.__executable)

        ### addressspace stuff
        def getmodulebyfilename(self, name):
            name = os.path.basename(name)   #jic

            def getfilename(m):
                modulename = os.path.basename(m['FullDllName'].str())
                return modulename.upper() == name.upper()

            try:
                return self.getmoduleby(getfilename)

            except KeyError,msg:
                raise KeyError('Basename %s not found in module list'% name)

        def getmodulebyaddress(self, address):
            def fn(m):
                base,size = int(m['DllBase']), int(m['SizeOfImage'])
                if (address >= base) and (address < base+size):
                    return True
                return False

            try:
                return self.getmoduleby(fn)
            except KeyError,msg:
                raise KeyError('Address %x not found'% address)
            
        def getmoduleby(self, lmb):
            for m in self.modules:
                if lmb(m):
                    return m
                continue
            raise KeyError('lambda %s did not find match'% repr(lmb))

        def getmodulebypath(self, path):
            try:
                result = self.getmoduleby(lambda m: m['FullDllName'].str() == path)
            except KeyError,msg:
                raise KeyError('Path %s not found'% path)
            return result
            
        ### windbg stuff
        def eval(self, string):
            return self.client.Control.Evaluate(string)

        def execute(self, string):
            return self.client.Control.Execute(string)

        status = property(fget=lambda self: self.client.Control.ExecutionStatus)    # XXX: no fset because _PyDbgEng doesn't seem to support it..

        def write(self, string):
            return self.client.Control.Output(string)

        def wait(self, status=_PyDbgEng.ExecutionStatus.BREAK):
            # FIXME: i tried making a decorator for this, but to no avail due to being
            #        unable to reference im_self while transforming a function. (function
            #        is not a method yet) ...try this again
            status = set( ([status], status)[type(status) in (list,tuple)] )

            if self.status not in status:
                print '[] waiting for one of the following states: %s'% (repr(status))
                # there's definitely a more efficient way to do this
                while self.status not in status:
                    pass
                pass
            return self.status

        def bpx(self, address, command=''):
            self.wait()
            b = self.client.Control.AddBreakpoint()
            b.Offset = self.put(address)
            b.Command = command
            b.Enable()
            return b.Id

        # FIXME: _PyDbgEng sucks, so these don't work
        # del( self.client.Control.Breakpoints[id] )
        # self.client.Control.RemoveBreakpoint(id)

        def bc(self, id):
            self.wait()
            self.execute("bc %d"% id)

        def bd(self, id):
            self.wait()
            self.execute("bd %d"% id)

        def be(self, id):
            self.wait()
            self.execute("be %d"% id)

        def t(self,count=1, command=''):
            self.wait()
            if len(command)>0:
                command = command.replace('\\','\\\\').replace('"','\\"')
                self.execute('t %d "%s"'% (count, command))
            else:
                self.execute('t %d'% count)

            self.wait()
            print '[] pc=%x:sp=%x | trace'%(self.r.pc,self.r.sp)

        def p(self,count=1, command=''):
            self.wait()
            if len(command)>0:
                command = command.replace('\\','\\\\').replace('"','\\"')
                self.execute('p %d "%s"'% (count, command))
            else:
                self.execute('p %d'% count)

            self.wait()
            print '[] pc=%x:sp=%x | proceed'%(self.r.pc,self.r.sp)

        def here(self):
            self.wait()
            original = database.here()
            ea = self.get(self.r.pc)

            if ea != original:
                print '[] visited address changed from %x to %x'%(original, ea )

            return database.go(ea)

        def h(self):
            self.wait()
            pc,sp = self.get(self.r.pc),self.get(self.r.sp)
            print '[] broke on %x with stack at %x'%(pc, sp) 

        def jump(self, address):
            return database.go(self.get(address))

        def g(self, address=None):
            self.wait()
            if address is None:
                print '[] go'
                self.execute("g")
                return

            self.wait()
    #        pc,sp = self.get(self.r.pc),self.get(self.r.sp)
    #        print '[] go from %x to %x with stack at %x'%(pc, address, sp) 
            self.execute("g %x"% self.put(address))
            self.h()

        def d(self, address, length, **attrs):
            pt = dyn.block(length)(source=self.source,offset=address)
            return pt.l.hexdump(**attrs)

        def ub(self, ea, count=5):
            result = []
            for x in range(count):
                row = '\t'.join(['%08x'% ea, idc.GetDisasm(ea)])
                result.append( row )
                ea = database.prev(ea)
            return '\n'.join(reversed(result))

        def u(self, ea, count=5):
            ea = self.put(ea)
            result = [
                '%s+0x%x:\n'%( self.client.Symbols.GetNameByOffset(ea) )
            ]
            for x in range(count):
                row,ea = self.client.Control.Disassemble(ea)
                result.append(row)
            return ''.join(result)

        # lol, i was obv stoned when i wrote these 3 backtrace functions
        def __backtrace(self, location=None, framedelta=0):
            if location is None:
                location = self.r.pc,self.r.sp
            pc,sp = (location[0], location[1]+framedelta)

            result = []
            for x in stackarray(source=self.source, pc=self.get(pc), offset=sp, transform=self.get).l:
                result.append(x)
            return result

        def backtrace(self, location=None, framedelta=0):
            result = self.__backtrace(location, framedelta)
            pc,sp = result[-1][' r'].int(),result[-1][' r'].getoffset()
            nextdwords = '|'+' '.join(map(lambda x:'%08x'%x.int(), dyn.array(pint.uint32_t,8)(source=self.source,offset=sp).l)).replace(' ', '|', 1)
            try:
                m = self.getmodulebyaddress(int(pc))
                print 'terminated at module %s [frame %d] (pc,sp)=(0x%x,0x%x) %s'% (m['FullDllName'].str(), len(result)-1, pc, sp, nextdwords)
            except KeyError:
                print 'terminated at unknown module [frame %d] (pc,sp)=(0x%x,0x%x) %s'% (len(result)-1, pc, sp, nextdwords)

            for x in result:
                try:
                    yield x.fetch()
                except Exception, e:
                    yield x
                continue
            return

        kv = lambda s,*args,**kwds: list(s.backtrace(*args,**kwds))

        def walkfp(self, fp=None):
            fp = (fp,self.r.fp)[fp is None]
            class frame(pstruct.type): _fields_ = [(pint.uint32_t, ' s'), (pint.uint32_t, ' r')]
            a = frame(source=self.source, offset=fp)
            fp,pc = map(long, a.l.values())
            while self.current.contains(pc):
                yield pc
                a.setoffset(fp)
                fp,pc = map(long, a.l.values())
            print 'stopped at (pc,fp)=location=(0x%x,0x%x)'% (pc, fp)
            return

        ### remoting
        def get(self, addr):
            offset = addr - int(self.current['DllBase'])
            return offset + database.baseaddress()

        def put(self, ea):
            offset = ea - database.baseaddress()
            return offset + int(self.current['DllBase'])

except ImportError:
    print 'unable to load _PyDbgEng'

class stackcontext(pstruct.type):
    def stackblock(self):
        delta = function.getSpDelta(self.pc)
        if delta is None:
            return ptype.empty
        return dyn.block( -delta )

    _fields_ = [
        (stackblock, '_contents'),
        (pint.uint32_t, ' r'),
    ]

    def fetch(self):
        return self.newelement(getframe(self.pc, function.getSpDelta(self.pc)), 'struct', self.getoffset()).l

class stackarray(parray.terminated):
    _object_ = stackcontext

    # FIXME: add some heuristics to switch between calculating the sp
    #        and using bp as the frame pointer

    # FIXME: what am i doing here, this logic seems retarded because i keep
    #        track of pc manually (and poorly) instead of keeping track of just
    #        the delta
    def isTerminator(self, value):
        value.pc = self.pc

        ea = int(value.load()[' r'])
        ea = self.transform(ea) # XXX: defined magically..

        self.pc = ea - 1
#        self.pc = database.prev(ea)

        if database.contains(ea):
            return False
        return True

    def walk(self):
        for x in self:
            yield int(x[' r'])
        return

    def __repr__(self):
        return '%s [%s]'%(self.name(), ','.join(('0x%x'%x for x in self.walk())))

if False:
    def save(list):
        d = dict( ((x, function.fetch(x)) for x in list) )
        def execute(function):
            max = len(d)
            for i,k in enumerate(d):
                print '%x: updating %d of %d'% (k,i+1,max)
                function.store(k, d[k])
            return set(d.keys())
        return execute

import collections
def frequency(list):
    result = collections.defaultdict(int)
    for x in list:
        result[x]+=1
    keys = result.keys()
    keys.sort()
    sorted = [(k,result[k]) for k in keys]
    return sorted

def recreatemarks():
    '''using any tags found in the database, update all the marks'''
    result = []

    # collect
    for x in (x for x in database.functions() if 'marks' in database.tag(x)):
        for y in function.select(x, mark=None):
            value = database.tag(y, 'mark')
            result.append((y, value))
        continue

    # sort it by name
    result.sort(cmp=lambda x,y: cmp(x[1],y[1]))

    # XXX: if a mark already exists, remove it from the list.

    # create
    for x,y in result:
        database.mark(x, y)
    colormarks()
    return

### pydbgeng structure creation
def getsymbol(debugclient, name):
    return getsymbol_recurse( debugclient.Symbols.GetType(name) )

def consolidate_fields(Fields):
    fields = [(name,type.Size,offset,type) for name,(type,offset) in Fields.items()]

    # FIXME: this is a super dumb way of consolidating fields into something that
    #        makes sense

    result = {}
    for name,size,offset,type in fields:
        if offset in result:
            n,t,s = result[offset]
            if s < size:
                continue
            pass
        result[offset] = name,type,size
    return result

def getsymbol_recurse(type):
    name,size = type.Name, type.Size
    if not type.Fields:
        return dyn.clone(ptype.type, shortname=lambda x:name, length=size)
    fields = []
    for offset,(n,t,s) in consolidate_fields(type.Fields).iteritems():
        if t.Name.endswith('*'):    # FIXME: handle pointers?
            fields.append( (dyn.block(s), n) )
        else:
            fields.append( (getsymbol_recurse(t), n) )
    return dyn.clone(pstruct.type, _fields_=fields, blocksize=lambda x: size)

###
def searchdelta(ea, delta, direction=-1):
    '''return the block containing all instructions within the specified stack delta'''
    assert direction != 0, 'you make no sense with your lack of direction'
    next = (database.prev, database.next)[direction > 0]

    sp = function.getSpDelta(ea)
    start = (ea,sp)
    while abs(sp - start[1]) < delta:
        sp = function.getSpDelta(ea)
        ea = next(ea)
    return ((start[0], ea), (ea+len(''.join(database.decode(ea))), start[0]+len(''.join(database.decode(start[0])))))[ea < start[0]]

selectdelta = searchdelta

class collection(list):
    '''A collection of addresses that can be navigated'''
    position = 0
    name = None

    def __init__(self, name):
        self.name = name

    def forward(self):
        next = (0, self.position + 1)[ self.position < len(self) ]
        database.go(self[next])
        self.position = next
        self.log("moved forward to %x (position %x of %x)", self[next], next, len(self))

    def backward(self):
        next = (len(self)-1, self.position-1)[ self.position >= 0 ]
        database.go( self[next] )
        self.position = next
        self.log("moved backward to %x (position %x of %x)", self[next], next, len(self))

    def add(self, address):
        self.append(address)

    def log(self, message, *args):
        return database.log(self.name + " " + message, *args)

class callstack(list):
    '''A collection of backtraces that can be navigated'''
    depth = 0
    name = None

    def __init__(self, name, stack):
        self.name = name
        super(list, self).__init__(stack)

    def up(self):
        if self.depth < l:
            self.depth += 1
        else:
            self.log("unable to move up stack due to being at top of call stack. (depth %x)", len(self))
            return
        pos = self.depth
        database.go(self[pos])
        self.log("moved forward to %x (depth %x of %x)", self[pos], next, len(self))

    def down(self):
        if self.depth > 0:
            self.depth -= 1
        else:
            self.log("unable to move down stack due to being at bottom of call stack. (depth %x)", len(self))
            return
        pos = self.depth
        database.go(self[pos])

    def log(self, message, *args):
        return database.log(self.name + " " + message, *args)

### some code for navigating switch statements
import emul
class switch(parray.terminated):
    _object_ = pint.uint32_t
    source = Ida
    def isTerminator(self, value):
        offset = value.getoffset()
        if len(self) == 0:
            return False

        # if the value of the currently read object doesn't point to code, then bail.
        ea = int(value)
        if not database.isCode(ea):
            del(self.value[-1])
            return True

        return False

    def shortname(self):
        return 'vt_%x'% self.getoffset()

def sib(state, pc, insn, **options):
    if ia32.isBranch(insn):
        # resolve sib branches (for switch statements usually)
        disp = ia32.getDisplacement(insn)
        if ia32.isSibBranch(insn) and len(disp) == 4:
            ea = ia32.decodeInteger(disp)
            for target in switch(offset=ea).l:
                state.store(emul.BRANCH, target.int())
            return True
        pass
    return False

def collect(address, depth, collect=set(), **options):
    return emul.i386.collect(Ida.producer, address, depth, set(collect).union((sib,)), **options)

if False:
    def collectbranches(address, depth=0):
        def isconditional(state, pc, insn):
            if ia32.isConditionalBranch(insn) or ia32.isUnconditionalBranch(insn):
                state.store('branch', pc)
            return 
        
        result = collect(address, depth, [isconditional])
        return result['branch']

    def collectchildren(address, depth=0):
        def ischild(state, pc, insn):
            if ia32.isRelativeCall(insn):
                address = ia32.getRelativeAddress(pc, insn)
                state.store('result', address)
            return 
        return collect(address, depth, [ischild])['result']

    def collectexternals(address, depth=0):
        def isexternal(state, pc, insn):
            if ia32.isMemoryCall(insn) or ia32.isMemoryBranch(insn):
                res = ia32.decodeInteger( ia32.getDisplacement(insn) )
                state.store('result', res)
            return 
        return collect(address, depth, [isexternal])['result']

    def collectinstruction(address, comparison, depth=0):
        def ismatch(state, pc, insn):
            if comparison(insn):
                state.store('result', pc)
            return 
        return collect(address, depth, [ismatch])['result']

    def collectdynamic(address, depth=0):
        def isdynamic(state, pc, insn):
            if isdynamiccall(insn):
                state.store('result', pc)
            return 
        return collect(address, depth, [isdynamic])['result']

    def collectfs(address, depth=0):
        return collectinstruction(address, lambda x: ia32.getPrefix(x) == 'd', depth=depth)

    def collectfourcc(address, depth=0):
        def isfourcc(insn):
            if not iscmpconstant(insn):
                return False
            constant = ia32.getImmediate(insn)
            a = len(''.join((x for x in constant if x in string.printable)))
            b = len(constant)
            
            return (a == b) or (a-1 == b)

        result = collectinstruction(address, isfourcc, depth=depth)
        result = [ ''.join(reversed(ia32.getImmediate(database.decode(x)))) for x in result]
        return set(result)

def coloring(state, pc, insn, **options):
    database.color(pc, options.get('color'))

### analyze for pre-processing ida shit, lol at me writing this last.
import string
class analyze(object):
    key = None
    definitions = []

    @classmethod
    def define(cls, definition):
        cls.definitions.append(definition)

    def enter(self, pc, **options):
        self.start = pc

    def iterate(self, state, pc, insn, **options):
        pass

    def exit(self, state, pc, **options):
        if self.key in state:
            options['database'].address(pc)[self.key] = list(state[self.key])

## analyzers
@analyze.define
class analyze_call(analyze):
    key = 'regular-call'

    def iterate(self, state, pc, insn, **options):
        if ia32.isRelativeCall(insn):
            address = ia32.getRelativeAddress(pc, insn)
            state.store(self.key, address)
        return 

    def exit(self, state, pc, **options):
        if self.key in state:
            options['database'].address(pc)['__down__']=set(state[self.key])
        return

@analyze.define
class analyze_leaf(analyze):
    key = 'node-type'

    def iterate(self, state, pc, insn, **options):
        if isacall(insn):
            state.store(self.key, pc)
        return

    def exit(self, state, pc, **options):
        if self.key in state and len(state[self.key]) > 0:
            return
        options['database'].address(pc)[self.key] = 'leaf'

@analyze.define
class analyze_external(analyze):
    key = 'external-call'

    def iterate(self, state, pc, insn, **options):
        if ia32.isMemoryCall(insn) or ia32.isMemoryBranch(insn):
            res = ia32.decodeInteger( ia32.getDisplacement(insn) )
            state.store(self.key, res)
            options['database'].address(self.start).address(pc)[self.key] = True
        return 

@analyze.define
class analyze_dynamic(analyze):
    key = 'dynamic-call'

    def iterate(self, state, pc, insn, **options):
#        if isdynamiccall(insn):
        p,i,m,s,d,imm = insn   #heh
        if i == '\xff':
            mod,r,rm = ia32.decoder.extractmodrm(ord(m))
            if (mod == 0) and (rm == 5):
                return False
            if (r == 2) or (r == 3):
                options['database'].address(self.start).address(pc)[self.key] = True
            pass
        return 

@analyze.define
class analyze_branch(analyze):
    key = 'is-branch'

    def iterate(self, state, pc, insn, **options):
        if options['database'] is store.ida:
            return

        if ia32.isBranch(insn):
            options['database'].address(self.start).address(pc)[self.key] = True
        return 

@analyze.define
class analyze_fourcc(analyze):
    key = 'use-fourcc'

    def stash_fourcc(self, state, pc, insn, **options):
        constant = ia32.getImmediate(insn)
        a,b = len(''.join((x for x in constant if x in string.printable))),len(constant)
        if (a == b) or (a-1 == b):
            fourcc = ''.join(reversed(constant))
            options['database'].address(self.start).address(pc)[self.key] = True
            state.store(self.key, fourcc)
        return

    def iterate(self, state, pc, insn, **options):
        m = ia32.modrm.extract(insn)
        if m:
            mod,reg,rm = m
            if reg == 7 and ia32.getOpcode(insn) == '\x81':
                self.stash_fourcc(state, pc,insn, **options)
        elif ia32.getOpcode(insn) in ('\x68','\xbf', '\xb8'):
            self.stash_fourcc(state, pc, insn, **options)
        return

@analyze.define
class analyze_libcalls(analyze):
    key = 'known-call'

    def iterate(self, state, pc, insn, **options):
        if ia32.isRelativeCall(insn):
            address = ia32.getRelativeAddress(pc, insn)
            if idc.GetFunctionFlags(address) & idc.FUNC_LIB:
                #state.store(self.key, address)
                state.store(self.key, database.name(address))
        return

# FIXME: implement this to log global addresses that are used
class analyze_globals(analyze):
    key = 'use-global'

    def iterate(self, state, pc, insn, **options):
        if ia32.isRelativeCall(insn):
            address = ia32.getRelativeAddress(pc, insn)
            if idc.GetFunctionFlags(address) & idc.FUNC_LIB:
                state.store(self.key, address)
        return

@analyze.define
class analyze_fs(analyze):
    key = 'use-fs'

    def iterate(self, state, pc, insn, **options):
        if ia32.getPrefix(insn) == 'd':
            state.store(self.key, pc)
        return

    def exit(self, state, pc, **options):
        if self.key in state and len(state[self.key]) > 0:
            options['database'].address(pc)[self.key] = True
        return

@analyze.define
class analyze_argsize(analyze):
    key = 'argument-size'

    def exit(self, state, pc, **options):
        total = function.getAvarSize(pc)
        options['database'].address(pc)[self.key] = total

@analyze.define
class analyze_framesize(analyze):
    key = 'frame-size'

    def exit(self, state, pc, **options):
        total = function.getRvarSize(pc)+function.getLvarSize(pc)
        options['database'].address(pc)[self.key] = total

@analyze.define
class analyze_regsize(analyze):
    key = 'reg-size'

    def exit(self, state, pc, **options):
        total = function.getRvarSize(pc)
        options['database'].address(pc)[self.key] = total

@analyze.define
class analyze_names(analyze):
    def iterate(self, state, pc, insn, **options):
        name = database.name(pc)
        if name:
            options['database'].address(self.start).address(pc)['__name__'] = name
        pass

    def exit(self, state, pc, **options):
        name = function.name(pc)
        options['database'].address(pc)['__name__'] = name

@analyze.define
class analyze_blocks(analyze):
    key = 'blockcount'
    def exit(self, state, pc, **options):
        count = list(function.blocks(pc))
        options['database'].address(pc)[self.key] = len(count)

@analyze.define
class analyze_delta(analyze):
    key = 'sp'
    def iterate(self, state, pc, insn, **options):
        if options['database'] is store.ida:
            return
        options['database'].address(self.start).address(pc)[self.key] = function.getSpDelta(pc)

@analyze.define
class analyze_ida(analyze):
    def iterate(self, state, pc, insn, **options):
        # WTF ida...
        if False and idc.isUnknown(pc) and not idc.isHead(pc):
            logging.warning('0x%x: tried to emulate an unknown type at 0x%x', self.start, pc)
            return True

        # steal xrefs from calls
        if ia32.isRelativeCall(insn):
            for x in database.down(pc):
                try:
                    t,x = function.top(x),x
                except ValueError:
                    t = None
                    
                options['database'].address(self.start).address(pc).edge((t,x))

            for x in database.up(pc):
                try:
                    t,x = function.top(x),x
                except ValueError:
                    t = None
                options['database'].address(self.start).address(pc).edge((t,x))
            pass

        try:
            options['database'].address(self.start).address(pc)['comment'] = database.tag(pc,'')
        except KeyError:
            pass

        return False

#@analyze.define
class analyze_dickhead(analyze):
    def iterate(self, state, pc, insn, **options):
        p = instruction_t(offset=pc,source=Ida).l
        print p
        options['database'].address(self.start).address(pc)['test'] = p

def process(ea, analyzers=analyze.definitions, **options):
    if 'database' not in options:
        options['database'] = store.ida

    analyzers = set(x() for x in analyzers)

    for x in analyzers:
        x.enter(ea, **options)

    collectors = [getattr(x, 'iterate') for x in analyzers]
    result = collect(ea, 0, collectors, **options)

    for x in analyzers:
        x.exit(result, ea, **options)

    options['database'].session.commit()

def nextreference(self,value):
    ea = value.getoffset()
    if len(self) <= 1:
        return False
    
    for x in xrange(value.getoffset(), value.getoffset()+value.blocksize()):
        if database.up(x):
            return True
    return False

class instruction_t(ptype.type):
    def blocksize(self):
        o = self.getoffset()
        s = idc.ItemSize(o)
        if s != len(''.join(database.decode(o))):
            a = repr(database.decode(o))
            b = repr(''.join(chr(idc.Byte(b)) for b in xrange(o, o+s)))
            logging.warning('%08x: inconsistency between ia32 and idc. (%s != %s)'% (o, a, b))
        return s

    pc = property(fget=lambda x: x.getoffset())

    # XXX: this'd only be useful if we could pivot the stack of the entire code_t
    sp = property(fget=lambda x: function.getSpDelta(x.getoffset()))

    def __repr__(self):
        o = self.getoffset()
        return '%s %x: %s'%(self.name(), o, idc.GetDisasm(o))

    # XXX: if i keep going, i can probably add a pointer to a code chunk soon...

class code_t(parray.terminated):
    _object_ = instruction_t
    def __repr__(self):
        o,s = self.getoffset(),self.blocksize()

        result = []
        for insn in self:
            o,s = insn.getoffset(),insn.blocksize()
            result.append('    %x: %s'%(o, idc.GetDisasm(o)) )

        intro = '[%08x] %s - %d instructions'% (self.getoffset(), self.name(), len(self))
        result = [''.join([' '*11,x]) for x in result]
        return '%s\n%s\n'%(intro, '\n'.join(result))

def coderange(start,end):
    return code_t(offset=start, isTerminator=lambda v: (True, False)[v.getoffset() < end]).l

def codelines(address, count):
    return code_t(offset=address, isTerminator=lambda v: len(v.parent.value) >= count).l

def codechunk(address):
    for start,end in function.chunks(address):
        if address >= start and address < end:
            return coderange(start,end)
        continue
    raise ValueError('%x not found in a chunk'%address)
        
def codestack(address, delta):
    start,end=selectdelta(address, delta)
    return coderange(start, end-idc.ItemSize(end))
