import sys,os
sys.path.append('f:/work')
sys.path.append('f:/work/syringe/lib')
sys.path.append('f:/work/syringe/work')

import idc
import database,function,segment,structure
import ia32,pecoff,ndk
import ptypes,ctypes
from ptypes import *
pint.setbyteorder(pint.littleendian)

class IdaProvider(ptypes.provider.provider):
    offset = 0xffffffff
    def seek(self, offset):
        '''Seek to a particular offset'''
        self.offset = offset
    def consume(self, amount):
        '''Read some number of bytes'''
        left,right = self.offset,self.offset+amount
        self.offset = right
        return database.getblock(left,right)
    def write(self, data):
        '''Write some number of bytes'''
        for count,x in enumerate(data):
            idc.PatchByte(self.offset, x)
            self.offset += 1
        return count
    def baseaddress(self):
        return database.baseaddress()

from database import log
kernel32 = ctypes.WinDLL('kernel32.dll')
ntdll = ctypes.WinDLL('ntdll.dll')

import ia32.decoder
def isdynamiccall(instruction):
    p,i,m,s,d,imm = instruction   #heh
    if i == '\xff':
        mod,r,rm = ia32.decoder.extractmodrm(ord(m))
        if r == 2 or r == 3:
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

def byteproducer(ea):
    while True:
        v = idc.Byte(ea)
        yield chr(v)
        ea += 1
    #return

class Ia32BranchState(object):
    pc = reader = None
    def __init__(self, ea, reader=byteproducer):
        self.pc = ea
        self.reader = reader

    def goto(self, ea):
        self.pc = ea    #heh
    
    def next(self):
        insn = self.get()
        self.pc += ia32.length(insn)
        return self.pc

    def follow(self):
        return ia32.getRelativeAddress(self.pc, self.get())

    def get(self):
        return ia32.consume(self.reader(self.pc))

## i should rewrite this...
##      each object should emulate a particular group of instructions

class Ia32Emulator(object):
    state = None
    running = False

    result = []

    def __init__(self, pc, **attrs):
        self.state = Ia32BranchState(pc)
        self.attrs = {'log' : attrs.get('log', None)}

    def run(self, **attrs):
        try:
            self.start(**attrs)
            self.result = []
            while self.running:
                insn = self.state.get()
                if 'color' in attrs:
                    database.color(self.state.pc, attrs['color'])
                res = self.execute(insn)
        except Exception:
            me = hex(id(self.state))
            self.log('fail', '%x %s', self.state.pc, me)
            raise
        return self.result

    def start(self, **attrs):
        self.running = True
        self.attrs.update(**attrs)

    def stop(self):
        self.running = False

    def fork(self, ea):
        return Ia32BranchState(ea)

    def store(self, value):
        self.result.append(value)

    def execute(self, insn):
        if ia32.isReturn(insn):
            self.stop()
            return True
        self.state.next()
        return False

    def log(self, cls, message, *args):
        if self.attrs['log'] is None:
            return database.log(message, *args)
        if cls in self.attrs['log']:
            return database.log(message, *args)
        return ''

class switch(parray.terminated):
    _object_ = pint.uint32_t
    source = IdaProvider()
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

class ForkingEmulator(Ia32Emulator):
    Machines = list
    def __init__(self, pc, **attrs):
        super(ForkingEmulator, self).__init__(pc, **attrs)
        self.Machines = []
        self.attrs['stats'] = {
            'peakmachines' : 0,
        }

    def addMachine(self, machinestate):
#        me = hex(id(self.state))
#        self.log('fork','%x %s will resume %x', self.state.pc, me, machinestate.pc)
        self.Machines.append(machinestate)

    def fork(self, ea):
        me = hex(id(self.state))
        res = super(ForkingEmulator, self).fork(ea)
        self.log('fork','%x %s forked to %x. %d other machines left to run', self.state.pc, me, id(res), len(self.Machines)+1)
        return res

    def start(self, **attrs):
        self.log('fork','%x machine %x starting', self.state.pc, id(self.state))
        return super(ForkingEmulator, self).start(**attrs)

    def stop(self):
        state = self.state
        me = hex(id(state))
        ea = state.pc

        # we're done
        if len(self.Machines) == 0:
            self.log('fork','%x %s machine %x terminated. emulator done', ea, me, id(state))
            self.log('fork','        stats %s', repr(self.attrs['stats']))
            self.running = False
            return

        # update stats
        if len(self.Machines) > self.attrs['stats']['peakmachines']:
            self.attrs['stats']['peakmachines'] = len(self.Machines)

        # try the next Machine
        if len(self.Machines) > 0:
            self.state = self.Machines.pop()

        self.log('fork','%x %s machine %x terminated. %d machines left to run', ea, me, id(state), len(self.Machines))
        return

    def execute(self, insn):
        if ia32.isBranch(insn):
            # resolve sib branches (for switch statements usually)
            disp = ia32.getDisplacement(insn)
            if ia32.isSibBranch(insn) and len(disp) == 4:
                me = hex(id(self.state))
                ea = ia32.decodeInteger(disp)
                for target in switch(offset=ea).l:
                    self.addMachine( self.fork(int(target)) )
                self.stop()
                return

            if ia32.isUnconditionalBranch(insn):
                me = hex(id(self.state))
                target = ia32.getRelativeAddress(self.state.pc, insn)
                self.state.goto(target)
                return

            if ia32.isConditionalBranch(insn):
                me = hex(id(self.state))
                target = ia32.getRelativeAddress(self.state.pc, insn)
                self.addMachine( self.fork(target) )
                return super(ForkingEmulator, self).execute(insn)

            me = hex(id(self.state))
            print '%x %s missed a branch instruction %s'% (self.state.pc, me, repr(insn))
            self.stop()
            return

        return super(ForkingEmulator, self).execute(insn)

class LoopEmulator(ForkingEmulator):
    def start(self, **attrs):
        self.blocks = set()
        self.blocks.add(self.state.pc)  # XXX: assume we're at the beginning of a block
        return super(LoopEmulator, self).start(**attrs)

    def execute(self, insn):
        if ia32.isConditionalBranch(insn):
            next = self.state.pc+ia32.length(insn)
            target = ia32.getRelativeAddress(self.state.pc, insn)

            if target in self.blocks and next in self.blocks:
                self.stop()
                return

            if target not in self.blocks:
                self.blocks.add(target)
                self.addMachine(self.fork(target))
            if next not in self.blocks:
                self.blocks.add(next)
                self.state.next()
            return

        if ia32.isUnconditionalBranch(insn):
            target = ia32.getRelativeAddress(self.state.pc, insn)
            if target in self.blocks:
#                print '%x already executed'% (self.state.pc)
                self.stop()
                return

            self.blocks.add(target)
            super(LoopEmulator, self).execute(insn)
            return

        if ia32.isCall(insn):
            target = ia32.getRelativeAddress(self.state.pc, insn)

        super(LoopEmulator, self).execute(insn)

    def stop(self):
        return super(LoopEmulator, self).stop()

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
    class remote(object):
        Peb = None
        debugger = None
        def __init__(self,debug):
            handle = debug.process.handle
            self.Peb = ndk.PEB()
            self.Peb.source = ptypes.provider.WindowsProcessHandle(handle)
            self.Peb.setoffset( getProcessBasicInformation(handle).PebBaseAddress )
            self.debugger = debug

        def __del__(self):
            # ...although this might never get called...
            # hopefully this will prevent handle leaking
            #  man, i hate python.
            self.close()

        def close(self):
            if self.Peb:
                self.Peb.source = None
                self.Peb = None
            if self.debugger:
                self.debugger.detach()
                self.debugger = None    # and free it...

        def newtype(self, ptype):
            result = ptype()
            result.source = self.Peb.source     # inherit from the parent
                # hopefully our handle lasts with all these refs to it bein around
            return result

        def load(self):
            print '[remote.load] current module name %s'% os.path.basename( idc.GetInputFile() )

            print '[remote.load] loading Peb'
            self.Peb.load()

            print '[remote.load] loading Ldr'
            self.Ldr = self.Peb['Ldr'].d.load()

            print '[remote.load] enumerating Modules'
            self.Modules = list(self.Ldr['InLoadOrderModuleList'].walk())

            print '[remote.load] saving CurrentModule'
            self.CurrentModule = self.getmodulebyfilename(idc.GetInputFile())

            print '[remote.load] loading Executable'
            #self.Executable = dyn.cast(self.CurrentModule['DllBase'], dyn.pointer(pecoff.Executable.File)).get().load()
            self.Executable = self.CurrentModule['DllBase'].d.load()
            return self

        def getmodulebyfilename(self, name):
            name = os.path.basename(name)   #jic

            def getfilename(m):
                modulename = os.path.basename(m['FullDllName'].get())
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
            for m in self.Modules:
                if lmb(m):
                    return m
                continue
            raise KeyError('lambda %s did not find match'% repr(lmb))

        def getmodulebypath(self, path):
            try:
                return self.getmoduleby(lambda m: m['FullDllName'].get() == path)
            except KeyError,msg:
                raise KeyError('Path %s not found'% path)

        def get(self, address):
            '''From remote process to IDA'''
            module = self.CurrentModule
            base,size = int(module['DllBase']), int(module['SizeOfImage'])
            if not((address >= base) and (address < base+size)):
                raise KeyError('address %x not found in current module'% address)

            executable = self.Executable
            virtualaddress = address - executable.getoffset()

            section = executable['Pe']['Sections'].getsectionbyaddress(virtualaddress)
            name,offset = section['Name'].get(), virtualaddress - int(section['VirtualAddress'])

            start,end = segment.getRange( segment.get(name) )
            return start + offset

        def put(self, address):
            '''From IDA to remote process'''
            start,end = segment.getRange(address)
            name,offset = segment.getName(start), address - start

            executable = self.Executable

            section = executable['Pe']['Sections'].getsectionbyname(name)
            virtualaddress = int(section['VirtualAddress']) + offset
            return executable.getoffset() + virtualaddress

        def valid(self, address):
            '''returns True if specified loaded address is within ida module'''
            module = self.CurrentModule
            base,size = int(module['DllBase']), int(module['SizeOfImage'])
            if (address >= base) and (address < base+size):
                return True
            return False

        def __searchcaller(self, eip, esp):
            if self.valid(eip):
                # XXX: perhaps check if it's executable while we're at it
                return eip      # XXX: - length of previous instruction

            # otherwise check to see if it's in a module list
            try:
                m = self.getmodulebyaddress(eip)
                return eip  # - length of previous instruction

            except KeyError, msg:
                print '[remote.searchcaller] caught exception %s'% msg

            # a totally invalid address, so
            #     pull the first dword off the stack and pray
            p = self.CurrentModule.newelement(dyn.addr_t, 'PreviousInstruction?', esp)
            return self.__searchcaller(int(p.load()), esp+4)

        def __getcallstack(self, eip, esp):
            ea = self.get(eip)
            delta = idc.GetSpd(ea-1)    # tail of prev instruction
            if delta is None:
                raise ValueError('[remote.getcallstack] previous address from %x is not in a function'% ea)
            if delta > 0:
                raise ValueError('[remote.getcallstack] unexpected stack delta %d at address %x'%(delta, ea))
            size = -delta

            res = callstack()
            res.callee = eip
            res.setoffset(esp)
            res.startsize = size
    #        print 'startsize',hex(res.startsize),hex(ea),hex(esp),hex(eip)
            return res

        def _btstart(self, eip, esp):
            eip = self.__searchcaller(eip, esp)
            cs = self.__getcallstack(eip,esp).load()
            yield cs['Current']
            for x in cs['Next']:
                yield x
            return

        def _btcontinue(self, esp):
            res = self.newtype(stackarray)
            res.setoffset(esp)
            for x in res.load():
                yield x
            return

        def btstart(self, eip, esp):
            source = self._btstart(eip, esp)
            source.next()       # discard current
            yield self.get(eip)
            for x in source:
                try:
                    yield self.get(int(x['return']))
                except KeyError, e:
                    print '[remote.btstart] Stopped at offset %x with error %s'%(x.getoffset(), repr(e))
            return

        def btcontinue(self, esp):
            for x in self._btcontinue(esp):
                try:
                    yield self.get(int(x['return']))
                except KeyError, e:
                    print '[remote.btcontinue] Stopped at offset %x with error %s'%(x.getoffset(), repr(e))
            return
            
        def getbacktrace(self, esp=None):
            if esp is None:
                registers = self.debugger.getcontext()
                eip = registers['Eip']
                esp = registers['Esp']
                return self.btstart(eip, esp)
            return self.btcontinue(esp)

        def getcallstack(self, esp=None):
            if esp is None:
                registers = self.debugger.getcontext()
                eip = registers['Eip']
                esp = registers['Esp']
                return self._btstart(eip, esp)
            return self._btcontinue(esp)

        def keys(self):
            return self.debugger.getcontext().keys()
        def __getitem__(self, name):
            return self.debugger.getcontext()[name]
        def __setitem__(self, name, value):
            result = self.debugger.getcontext()
            result[name] = value
            self.debugger.setcontext(result)
    #    def __repr__(self):
    #        return ' '.join([self.__class__.__name__, repr(self.debugger.getcontext())])

if False:
    __remotecontrol = None
    def getremote():
        '''fetch current opened process remote'''
        return __remotecontrol
    def setremote(r):
        '''set current opened remote'''
        __remotecontrol = r
        __source = r.Peb.source

    __source = None
    def getsource():
        '''return the current ptype source'''
        return __source

    def setsource(value):
        '''change the current ptype source'''
        __source =  value

    # we can wrap a lot of this in an object since it's dealing primarily with ida's interface
    class stackcontext(pstruct.type):
        def stackblock(self):
            address = int(self['return'].load())
            if getremote().valid(address):
                ea = getremote().get(address) - 1
                delta = idc.GetSpd(ea)
                assert delta <= 0
                size = -delta
#                print hex(self['args'].getoffset()),'stackblock',hex(size),hex(ea),hex(self.getoffset())
                return dyn.block(size)
            return dyn.block(0)

        def regblock(self):
            address = int(self['return'].load())
            if getremote().valid(address):
                ea = getremote().get(address) - 1
                size = idc.GetFrameRegsSize(ea)
#                print hex(self['args'].getoffset()),'regblock',hex(size),hex(ea),hex(self.getoffset())
                return dyn.block(size)
            return dyn.block(0)

        def argblock(self):
            ea = getremote().get(self.parent.callee)
            assert ea
            size = idc.GetFrameArgsSize(ea)
#            print hex(self['return'].getoffset()), 'args',hex(size),hex(ea),hex(self.getoffset())
            return dyn.block(size)

        def idastackblock(self):
            raise NotImplementedError
            address = int(self['return'].load())
            length = 0
            if getremote().valid(address):
                ea = getremote().get(address) - 1
                delta = idc.GetSpd(ea)
                print hex(Delta)
                assert delta <= 0
                size = -delta

                id = idc.GetFrame(ea)
                pt = makeptype(id)
                sanitycheck = pt().alloc()
                print sanitycheck
                sanitycheck = sanitycheck.size()
                assert sanitycheck == size, '%x != %x'% (sanitycheck,size)
                return pt

            return dyn.block(length)

    # FIXME: we need to figure out how to split up these boundaries from ida
#        _fields_ = [
#            (pint.uint32_t, 'return'),
#            (argblock, 'args'),
#            (stackblock, 'contents'),
#            (regblock, 'regs'),
#        ]
        _fields_ = [
            (pint.uint32_t, 'return'),
            (stackblock, 'contents'),
        ]

    class stackarray(parray.terminated):
        _object_ = stackcontext
        callee = None

        def isTerminator(self, value):
            value.callee = self.callee

            remote = getremote()
            address = int(value.load()['return'])
            self.callee = address
            res = remote.valid(address)
            if res:
                return False

            stackpointer = value.getoffset()
            try:
                m = remote.getmodulebyaddress(address)
                print '[stackarray.isTerminator] Stopped at %x in module %s[%x]'%(stackpointer, m['FullDllName'].get(), address)
                return True

            except KeyError,msg:
                print '[stackarray.isTerminator] Stopped at %x due to address %x not in any module'%(stackpointer, address)
                v = getremote().newtype(dyn.array(dyn.addr_t, 4))
                v.setoffset(stackpointer)
                print hex(stackpointer), ' '.join(['%08x'%int(e) for e in v.load()])
                return True
            raise NotImplementedError('Wtf')

        def walk(self):
            remote = getremote()
            try:
                for x in self:
                    ret = int(x['return'])
                    yield remote.get(ret)

            except ValueError,msg:
                print '[stackarray.walk] caught exception %s'% msg
            return
        pass

    class callstack(pstruct.type):
        callee = None

        def stackslack(self):
            return dyn.block(self.startsize, callee=self.callee)

        _fields_ = [
            (stackslack, 'Current'),
            (lambda s:dyn.clone(stackarray, callee=s.callee), 'Next'),
        ]

if False:
    import debugger
    def open(tid):
        '''Open up a thread by it's thread identifier'''
        dbg = debugger.ThreadId(tid)
        globals()['__source'] = ptypes.provider.WindowsProcessHandle(dbg.process.handle)
        globals()['__remotecontrol'] = remote(dbg)
        return getremote()

    def open(pid):
        globals()['__source'] = ptypes.provider.WindowsProcessId(pid)
        globals()['__remotecontrol'] = remote(dbg)
        return getremote()

    def print_backtrace(esp=None):
        '''Print a backtrace for the current opened thread'''
        remote = getremote()
        for x in map(hex, remote.getbacktrace(esp)):
            print x
    #    print '\n'.join(map(hex, remote.getbacktrace(esp)))

    def dump_backtrace(esp=None):
        remote = getremote()
        for x in remote.getcallstack(esp):
            print x

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

if False:
    class DebugCallEmulator(LoopEmulator):
        def execute(self, insn):
            me = '%x'% id(self.state)

            if ia32.isRelativeCall(insn):
                address = ia32.getRelativeAddress(self.state.pc, insn)
                print hex(self.state.pc), me, 'rel', hex(address), database.demangle(idc.Name(address))

            elif ia32.isMemoryCall(insn):
                offset = ia32.getDisplacement(insn)
                address, = struct.unpack('L', offset)
                print hex(self.state.pc), me, 'mem', hex(address), database.demangle(idc.Name(address))

            elif ia32.isRegisterCall(insn):
                print hex(self.state.pc), me, 'reg'
                # XXX: we can also keep track of immediate register assignments too,
                #      so we can catch assigns of func addrs, but if we do that, we
                #      might as well just keep track of the entire state

            elif ia32.isConditionalBranch(insn):
                #print hex(self.state.pc), me, 'forked'
                pass

            elif ia32.isSibBranch(insn):
                print hex(self.state.pc), me, 'encountered unemulateable instruction'
                self.stop()
                return

            return super(DebugCallEmulator, self).execute(insn)

    class TestEmulator(LoopEmulator):
        def __init__(self, pc):
            super(TestEmulator, self).__init__(pc)
            self.calls = []

        def execute(self, insn):
            if ia32.isRelativeCall(insn):
                address = ia32.getRelativeAddress(self.sate.pc, insn)
                database.tag(self.state.pc, '_type', 'relative-call')
                database.tag(self.state.pc, '_target', '%x'% address)
                self.calls.append(self.state.pc)

            if ia32.isMemoryCall(insn):
    #            print 'memory'
                database.tag(self.state.pc, '_type', 'memory-call')

                res = ia32.getDisplacement(insn)
    #            print repr(insn)
    #            print hex(self.state.pc),repr(res)

                if res:
                    v = pint.uint32_t()
                    v.deserialize(res)
                    address = int(v)
                    database.tag(self.state.pc, '_target', '%x'% address)

            if ia32.isRegisterCall(insn):
    #            print 'register'
                database.tag(self.state.pc, '_type', 'register-call')
                database.tag(self.state.pc, '_target', 'register')  # XXX: identify the register via the modrm

    #        if ia32.isRelativeBranch(insn):
    #            database.tag(self.state.pc, '_type', 'branch')
    #            database.tag(self.state.pc, '_branchoffset', hex(ia32.getBranchOffset(insn)))

    #        if ia32.isConditionalBranch(insn):
    #            print hex(self.state.pc)

            return

class MyBranchCollector(LoopEmulator):
    '''Collect the addresses of all the branches in the current function'''
    def execute(self, insn):
        if ia32.isConditionalBranch(insn) or ia32.isUnconditionalBranch(insn):
            self.store( self.state.pc )

        # XXX: should probably also catch branches like:  FF 24 85 74 29 55 30 

        return super(MyBranchCollector, self).execute(insn)

class MyChildCollector(LoopEmulator):
    '''Collect all the child functions by following known branches in the current function'''
    def execute(self, insn):
        if ia32.isCall(insn):
            address = ia32.getRelativeAddress(self.state.pc, insn)
            me = hex(id(self.state))

            if ia32.isRelativeCall(insn):
                if address not in self.result:
                    self.log('collector','%x %s descending into %x', self.state.pc, me, address)
                    self.store(address)
                    self.addMachine( self.fork(address) )
                else:
                    self.log('collector','%x %s skipping already processed call into %x', self.state.pc, me, address)
                pass
            pass
        return super(MyChildCollector, self).execute(insn)

class MyCallCollector(LoopEmulator):
    '''Collect the addresses of all the calls in the current function'''
    def execute(self, insn):
        if ia32.isRelativeCall(insn):
            self.store(self.state.pc)
        elif ia32.isCall(insn):
            print '%x unknown call with opcode %s found'%( self.state.pc, repr(ia32.getOpcode(insn)) )
            self.store(self.state.pc)
        return super(MyCallCollector, self).execute(insn)

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

        try:
            count = database.tag(ea, counttag) + 1
        except KeyError:
            count = 0
        database.tag(ea, counttag, count)

        try:
            count = database.tag(target, counttag) + 1
        except KeyError:
            count = 0
        database.tag(target, counttag, count)
    return

class MyExternalCollector(LoopEmulator):
    '''Collect the addresses of all the external calls in the specified function'''
    def execute(self, insn):
        if ia32.isMemoryCall(insn):
            res = ia32.decodeInteger( ia32.getDisplacement(insn) )
            self.store(res)
        if ia32.isMemoryBranch(insn):
            res = ia32.decodeInteger( ia32.getDisplacement(insn) )
            self.store(res)
        return super(MyExternalCollector, self).execute(insn)

if False:
    import ia32,ali
    for n in ali.MyChildCollector(h()).run():
        t = []
        for c in ali.MyCallCollector(n).run():
            target = ia32.getRelativeAddress(c, db.decode(c))
            t.append(target)
        fn.tag(n, 'calls', repr(map(hex,t)))
    pass

class MyInstructionCollector(LoopEmulator):
    '''Collect the addresses of all instructions matching the /cmp/ argument'''
    def run(self, **kwds):
        self.comparison = kwds['cmp']
        return super(MyInstructionCollector, self).run()

    def execute(self,insn):
        if self.comparison(insn):
            self.store(self.state.pc)

        return super(MyInstructionCollector, self).execute(insn)

def cmp_displacement(integer):
    return lambda i: ia32.decodeInteger(ia32.getDisplacement(i)) == integer

class DynamicCallCollector(LoopEmulator):
    '''Collect the addresses of all the dynamic calls in the current function'''
    def execute(self,insn):
        if isdynamiccall(insn):
            self.store(self.state.pc)
        return super(DynamicCallCollector, self).execute(insn)

def tagdynamiccalls(startea, key, value, color=None):
    collection = DynamicCallCollector(startea).run()
    for ea in collection:
        database.tag(ea, key, value)
        if color is not None:
            database.color(ea, color)
        continue
    database.tag(startea, 'dynamic-calls', repr(map(hex,collection)))

def tagfsinstructions(startea, key, color=None):
    collection = MyInstructionCollector(startea).run(cmp=lambda x: ia32.getPrefix(x) == 'd')
    for ea in collection:
        database.tag(ea, key, True)
        if color is not None:
            database.color(ea, color)
        continue
    if collection:
        database.tag(startea, 'fs-insns', repr(map(hex,collection)))
    return

class vtable(parray.terminated):
    _object_ = pint.uint32_t
    source = IdaProvider()
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

if False:
    def breaker(addresses):
        def do(control, command='r;g'):
            for x in addresses:
                b = control.AddBreakpoint()
                b.Offset = x
                b.Command = command
                b.Enable()
            return
        return do

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
        8 : pint.uint32_t,
    }
    if size in lookup:
        return lookup[size]
    return dyn.block(size)

def getframe(pc, spdelta=0):
    top = function.top(pc)
    id = function.getFrameId(top)
    a,r,l = function.getAvarSize(top), function.getRvarSize(top), function.getLvarSize(top)
    o = l + spdelta
    
    class frame(pstruct.type):
        _fields_ = []

    if o < 0:
        frame._fields_.append(( dyn.block(-o), ''))
        o = 0

    # FIXME: sometimes this code doesn't decode the stack correctly. i suspect it's
    #        something in ida that i'm missing.

    fragment = getfragment(id, offset=o, size=l-o)

    frame._fields_.extend( fragment._fields_ )
#    frame._fields_.append( (dyn.block(l-o),'n'))
    o+=l-o
    frame._fields_.extend( getfragment(id, offset=o, size=r)._fields_ )
    o+=r
    frame._fields_.extend( getfragment(id, offset=o, size=a)._fields_ )
    return frame

def getfragment(id, offset=0, size=None, baseoffset=0):
    '''Given a structure id, return the fragment in ptype form'''
    if size is None:
        size = structure.size(id)

    fieldarray = []
    for (o,s),(m_name, m_cmt) in structure.fragment(id, offset, size):
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

import string
def getFourCCs(functionea, **attrs):
    if 'log' not in attrs:
        attrs['log'] = []

    def isfourcc(insn):
        if not iscmpconstant(insn):
            return False
        constant = ia32.getImmediate(insn)
        a = len(''.join((x for x in constant if x in string.printable)))
        b = len(constant)
        
        return (a == b) or (a-1 == b)

    result = MyInstructionCollector(functionea, **attrs).run(cmp=isfourcc)
    result = [ ''.join(reversed(ia32.getImmediate(database.decode(x)))) for x in result]
    result=list(set(result))
    return result

def tagallfourccs(key='fourcc'):
    all = db.functions()
    for i,x in enumerate(all):
         print hex(x), '%d of %d'%(i, len(all))
         fourccs = ali.getFourCCs(x)
         fn.tag(x, key, repr(fourccs))
    return

def tagLibraryCalls(f):
    l = set(MyCallCollector(f, log=[]).run())
    libcalls = []
    for x in l:
        try:
            down = database.down(x)[0]
        except IndexError:
            print hex(x), 'failed'
            continue
        if idc.GetFunctionFlags(down) & idc.FUNC_LIB:
            libcalls.append(down)
        continue

    if libcalls:
#        function.tag(f, 'libcalls', '{ '+','.join(map(hex,set(libcalls)))+' }')
        function.tag(f, 'libcalls', list(set(libcalls)))
    return

def tagExternals(f):
    l = set(MyExternalCollector(f, log=[]).run())
    print map(hex,l)
    externals = []
    for x in l:
        try:
            externals.append( database.tag(x, 'name') )
        except KeyError:
            externals.append(x)
    if externals:
#        function.tag(f, 'externals', '{ '+','.join(set(externals))+' }')
        function.tag(f, 'externals', list(set((externals))))
    return

def tagImmediate(functionea, match, key='immediate', **attrs):
    if 'log' not in attrs:
        attrs['log'] = []

    def isimmediate(insn):
        if not iscmpconstant(insn):
            return False
        constant = ''.join(reversed(ia32.getImmediate(insn)))
        return constant == match

    result = MyInstructionCollector(functionea, **attrs).run(cmp=isimmediate)
    if result:
        function.tag(functionea, key, match)
    return

def tagLocalCalls(f):
    l = set(MyCallCollector(f, log=[]).run())
    calls = []
    for x in l:
        n = database.decode(x)
        if not isregularcall(n):
            continue
        try:
            down = database.down(x)[0]
        except IndexError:
            print hex(x), 'failed'
            continue
        calls.append(down)

    if calls:
#        function.tag(f, 'localcalls', '{ '+','.join(map(hex,set(calls)))+' }')
        function.tag(f, 'localcalls', list(set((calls))))
    return

def tagLeafNode(f):
    if not iscallinfunction(f):
        function.tag(f, 'node-type', 'leaf', repeatable=1)
    return

def process(x, **attrs):
    x = function.top(x)
    LoopEmulator(x).run(log=[], **attrs)
    tagLeafNode(x)
    tagLibraryCalls(x)
    tagExternals(x)
    tagLocalCalls(x)

def fnmap(l, functions, *args, **kwds):
    '''Execute provided callback on all functions in database. Synonymous to map(l,db.functions())'''
    all = functions
    result = []
    for i,x in enumerate(all):
        print '%x: processing # %d of %d'%( x, i+1, len(all) )
        result.append( l(x, *args, **kwds) )
    return result

def processall(**attrs):
    return fnmap(process, database.functions(), **attrs)

"""
def dostuff(prefix, z):
 items = z.items()
 for i,(k,v) in enumerate(items):
  print '%d of %d'%( i+1, len(items) )
  fn.store(k, v, prefix)
 return

z = dict([(x,fn.fetch(x)) for x in db.functions() if len(fn.tag(x).values()) > 1])
a = fu.closure(dostuff, z=z)

b = fu.dumps(a)

c = fu.loads(b, namespace=globals())
c('wtf')
"""

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
            return str( self.client.DataSpaces.Virtual.Read(self.offset, amount) )
            
        def store(self, data):
            '''Write some number of bytes'''
            return self.client.DataSpaces.Virtual.Write(self.offset, data)

    class __registers_INT32(object):
        pc = property(fget=lambda self: self.client.Registers.InstructionOffset)
        sp = property(fget=lambda self: self.client.Registers.StackOffset)

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
        return

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
        b.Offset = address
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
        pc,sp = self.get(self.r.pc),self.get(self.r.sp)

        print '[] go from %x to %x with stack at %x'%(pc, address, sp) 
        self.execute("g %x"% self.put(address))
        self.h()

    def d(self, address, length, **attrs):
        pt = dyn.block(length)(source=self.source,offset=address)
        return pt.l.hexdump(**attrs)

    def ub(ea, count=1):
        result = []
        for x in range(count):
            row = '\t'.join(['%08x'% ea, idc.GetDisasm(ea)])
            result.append( row )
            ea = database.prev(ea)
        return '\n'.join(reversed(result))

    def backtrace(self):
        for x in stackarray(source=self.source, pc=self.get(self.r.pc), offset=self.r.sp).l:
            yield x
        return

    def calls(self):
        # FIXME: perhaps use this to dump a prettier output
        for x in self.backtrace():
            yield x.fetch()
        return

    ### remoting
    def get(self, addr):
        offset = addr - int(self.current['DllBase'])
        return offset + database.baseaddress()

    def put(self, ea):
        offset = ea - database.baseaddress()
        return offset + int(self.current['DllBase'])

if False:
    class stackcontext(pstruct.type):
        def stackblock(self):
            ea = int(self['return'].load())
            delta = idc.GetSpd(ea)
            assert delta <= 0
            size = -delta
    #       print hex(self['args'].getoffset()),'stackblock',hex(size),hex(ea),hex(self.getoffset())
            return dyn.block(size)

        def regblock(self):
            ea = int(self['return'].load())
            size = idc.GetFrameRegsSize(ea)
    #       print hex(self['args'].getoffset()),'regblock',hex(size),hex(ea),hex(self.getoffset())
            return dyn.block(size)

        def argblock(self):
            ea = int(self['return'].load())
            size = idc.GetFrameArgsSize(ea)
    #        print hex(self['return'].getoffset()), 'args',hex(size),hex(ea),hex(self.getoffset())
            return dyn.block(size)

        _fields_ = [
            (stackblock, 'contents'),
            (pint.uint32_t, 'return'),
        ]

class stackcontext(pstruct.type):
    def stackblock(self):
        rvars = function.getRvarSize(self.pc)-4
        delta = function.getSpDelta(self.pc)
        assert delta <= 0
        size = -delta
        return dyn.block(size - rvars)

    def regblock(self):
        size = function.getRvarSize(self.pc)-4
        #print hex(self.pc),hex(size),hex(self.getoffset()),hex(function.getSpDelta(self.pc))
        return dyn.block(size)

    def idastackblock(self):
        ea = int(self[' r'].load())
        pt = getframe(ea)
        return pt

    _fields_ = [
        (stackblock, '_contents'),
        (regblock, '_regs'),
        (pint.uint32_t, ' r'),
    ]

    def fetch(self):
        return self.newelement(getframe(self.pc, function.getSpDelta(self.pc)), 'struct', self.getoffset()).l

class stackarray(parray.terminated):
    _object_ = stackcontext

    def isTerminator(self, value):
        value.pc = self.pc
        ea = int(value.load()[' r'])
        self.pc = ea - 1
        if database.contains(ea):
            return False
        return True

    def walk(self):
        for x in self:
            yield int(x[' r'])
        return

    def __repr__(self):
        return '%s [%s]'%(self.name(), ','.join(('0x%x'%x for x in self.walk())))

def save(list):
    d = dict( ((x, function.fetch(x)) for x in list) )
    def execute(function):
        max = len(d)
        for i,k in enumerate(d):
            print '%x: updating %d of %d'% (k,i+1,max)
            function.store(k, d[k])
        return set(d.keys())
    return execute

