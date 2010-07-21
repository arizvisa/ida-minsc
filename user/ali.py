import sys,os
sys.path.append('f:/work')
sys.path.append('f:/work/syringe/lib')
#sys.path.append('f:/work/syringe/work')

import idc
import database,function,segment
import ia32,pecoff,ndk
import ptypes,ctypes
from ptypes import *

class IdaProvider(ptypes.provider.provider):
    offset = 0xffffffff
    def seek(self, offset):
        '''Seek to a particular offset'''
        self.offset = offset
    def consume(self, amount):
        '''Read some number of bytes'''
        left,right = self.offset,self.offset+amount
        self.offset = right
        return database.getBlock(left,right)
    def write(self, data):
        '''Write some number of bytes'''
        for count,x in enumerate(data):
            idc.PatchByte(self.offset, x)
            self.offset += 1
        return count

ptypes.setsource(IdaProvider())

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

    for ea in function.chunks(ea):
        start,end = database.guessRange(ea)

        block = database.getBlock(start,end)
        try:
            if iscallinblock(block):
                return True
        except StopIteration:
            pass
        continue

    return False

import pedram
def markallleafnodes():
    '''label functions that don't call anything'''
    for ea in pedram.FetchLeafs():
        if iscallinfunction(ea):
            continue
        function.tag(ea, 'node-type', 'leaf', repeatable=1)

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

    def __addressfailure(fn):
        def new_fn(self, *args, **kwds):
            me = hex(id(self))
            try:
                return fn(self, *args, **kwds)
            except Exception, e:
                log('%x %s fail', self.pc, me)
                raise
            return
        return new_fn

    @__addressfailure
    def goto(self, ea):
        self.pc = ea    #heh
    
    @__addressfailure
    def next(self):
        insn = self.get()
        self.pc += ia32.length(insn)
        return self.pc

    @__addressfailure
    def follow(self):
        return ia32.getRelativeAddress(self.pc, self.get())

    @__addressfailure
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
        self.setcolor = False
        if 'color' in attrs:
            self.setcolor = True
            self.color = attrs['color']
        return

    def run(self):
        self.start()
        self.result = []
        while self.running:
            insn = self.state.get()
            if self.setcolor:
                database.color(self.state.pc, self.color)
            res = self.execute(insn)
        return self.result

    def start(self):
        self.running = True

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

class ForkingEmulator(Ia32Emulator):
    Machines = list
    __machinestats = dict
    def __init__(self, pc, **attrs):
        super(ForkingEmulator, self).__init__(pc, **attrs)
        self.Machines = []
        self.__stats = {
            'peakmachines' : 0,
        }

    def addMachine(self, machinestate):
        self.Machines.append(machinestate)

    def fork(self, ea):
        me = hex(id(self.state))
        res = super(ForkingEmulator, self).fork(ea)
        log('%x %s forked to %x. %d other machines left to run', self.state.pc, me, id(res), len(self.Machines)+1)
        return res

    def start(self):
        log('%x machine %x starting', self.state.pc, id(self.state))
        return super(ForkingEmulator, self).start()

    def stop(self):
        state = self.state
        me = hex(id(state))
        ea = state.pc

        # we're done
        if len(self.Machines) == 0:
            log('%x %s machine %x terminated. emulator done', ea, me, id(state))
            log('        stats %s', repr(self.__stats))
            self.running = False
            return

        # update stats
        if len(self.Machines) > self.__stats['peakmachines']:
            self.__stats['peakmachines'] = len(self.Machines)

        # try the next Machine
        if len(self.Machines) > 0:
            self.state = self.Machines.pop()

        log('%x %s machine %x terminated. %d machines left to run', ea, me, id(state), len(self.Machines))
        return

    def execute(self, insn):
        if ia32.isBranch(insn):
            # resolve sib branches (for switch statements usually)
            disp = ia32.getDisplacement(insn)
            if ia32.isSibBranch(insn) and len(disp) == 4:
                me = hex(id(self.state))
                ea = ia32.stringToNumber(disp)
                for target in makepointerarray(ea).l:
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
    def start(self):
        self.blocks = set()
        self.blocks.add(self.state.pc)  # XXX: assume we're at the beginning of a block
        return super(LoopEmulator, self).start()

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
    class ColoredEmulator(FunctionEmulator):
        '''Really horrible way of preventing loops'''
        def __init__(self, pc):
            super(ColoredEmulator, self).__init__(pc)
            self.__colored = set()

        def execute(self, insn):
            # XXX: slow? memory intensive??
            if self.state.pc in self.__colored:
                log('%x previous instruction has already been executed', self.state.pc)
                self.stop()
                return True

            self.__colored.add(self.state.pc)
    #        print '%x %x %s'%(self.state.pc, id(self.state), repr(insn))

            return super(ColoredEmulator, self).execute(insn)

if False:
    import struct
    def getBranchInstructionOffset(n):
        ihatepython = { 1:'b', 2:'h', 4:'l' }
        immediate = ia32.getImmediate(n)
        res, = struct.unpack(ihatepython[ len(immediate) ], immediate)
        return res

def getExtents(block):
    '''Return all basic block boundaries inside a string'''
    offset = last = 0
    for n in ia32.disassemble(block):
        offset += len(''.join(n))
        if ia32.isRelativeBranch(n) or ia32.isAbsoluteBranch(n) or ia32.isReturn(n):
            yield (last, offset)
            last = offset
        continue
    return

def getBlocks(start, end):
    '''Get all the basic blocks between 2 addresses'''
    block = database.getBlock(start,end)
    for x in getExtents(block):
        yield database.getBlock(x[0]+start, x[1]+start)
    return

if False:
    def markallbranchoffsets_function(ea):
        for ea in function.chunks(ea):
            start,end = database.guessRange(ea)

            for x in ia32.disassemble(database.getBlock(start,end)):
                database.tag(x, 'branch-address', hex(ia32.getRelativeAddress(self.state.pc,n)))
            continue
        return

    def markallbranchoffsets(ea):
        for x in database.functions():
            markallbranchoffsets_function(x)
        return

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

if True:
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
        source = property(fget=lambda x:getsource(), fset=lambda x,v: setsource(v) )
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
        source = property(fget=lambda x:getsource(), fset=lambda x,v: setsource(v) )
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
        source = property(fget=lambda x:getsource(), fset=lambda x,v: setsource(v) )
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
    remote = getremote()
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
    def relocatetoprocess(list):
        '''Relocate the addresses from IDA's addressspace to the thread's'''
        remote = getremote()
        return [ remote.put(ea) for ea in list ]
        
    def relocatetodatabase(list):
        '''Relocate the addresses from the thread's addressspace to IDA's'''
        remote = getremote()
        return [ remote.get(address) for address in list ]

if False:
    # need to figure out some fast way of identifying functions
    # that have a block that terminates with a jmp esp
    # or at least some way of identifying functions that might
    # branch to code outside of the function's boundaries
    pass

def makeptypefragment(id, offset, maxsize):
    fieldarray = []
    while maxsize > 0:
        m_size = idc.GetMemberSize(id, offset)
        if m_size is None:      # should prolly check the flag, but whatever
            break
        m_flag = idc.GetMemberFlag(id, offset)
        m_name = idc.GetMemberName(id, offset)
        if m_name is None:
            m_name = '__unknown_%x'% offset
        m_structureid = idc.GetMemberStrId(id, offset)
        ptype = generateptype(m_flag, m_size, m_structureid)
        fieldarray.append( (ptype, m_name) )

        offset += m_size
        maxsize -= m_size

    if maxsize > 0:
        fieldarray.append( ( dyn.block(maxsize), '__unknown_%x'% offset) )

    class structfragment(pstruct.type):
        _fields_ = fieldarray
    return structfragment

def makeptype(id):
    name = idc.GetStrucName(id)
    size = idc.GetStrucSize(id)
    return dyn.clone( makeptypefragment(id, 0, size), name=lambda x: 'structure %s'% name)
    
def generateptype(flag, size, structureid):
    '''produces a ptype from an ida structure member's flag,size, and structureid'''
    flag &= idc.DT_TYPE
    lookup = {
        idc.FF_BYTE : pint.uint8_t,
        idc.FF_WORD : pint.uint16_t,
        idc.FF_DWRD : pint.uint32_t,
        idc.FF_QWRD : pint.uint64_t,
    }

    try:
        return lookup[flag]
    except KeyError, e:
        pass

    if flag == idc.FF_STRU:
        return makeptype(structureid)
    return dyn.block(size)

if False:
    ea = idc.ScreenEA()
    id = idc.GetFrame(ea)
    lvars = idc.GetFrameLvarSize(ea)
    regs = idc.GetFrameRegsSize(ea)
    args = idc.GetFrameArgsSize(ea)
    print map(hex,(ea,id,qty,lvars,regs,args))

if False:
    def ordinalToAddress(number):
        # this should be abstracted to some global lookup object
        x = pecoff.Executable.open('mso.dll')
        pe = x['Pe']
        imagebase = int(pe['OptionalHeader']['ImageBase'])
        exports = pe['OptionalHeader']['DataDirectory'][0].get().load()
        ordinals = dict(exports.getOrdinalLookup())
        va = ordinals[number]
        x.source.close()
        return va + imagebase

if False:
    blah = byteproducer(idc.ScreenEA())
    insn = ia32.decode(blah)
    print ia32.isMemoryCall(insn),ia32.isRegisterCall(insn)
    raise NotImplementedError

def checkMarkLocality():
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

def colorAllMarks():
    for ea,m in database.marks():
        database.tag(ea, 'mark', m)
        database.color(ea, 0x7f007f)
    return

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
    def execute(self, insn):
        if ia32.isConditionalBranch(insn) or ia32.isUnconditionalBranch(insn):
            self.store( self.state.pc )

        return super(MyBranchCollector, self).execute(insn)

class MyChildCollector(LoopEmulator):
    def execute(self, insn):
        if ia32.isCall(insn):
            address = ia32.getRelativeAddress(self.state.pc, insn)

            if ia32.isRelativeCall(insn):
                self.addMachine( self.fork(address) )

                me = hex(id(self.state))
                if address in self.result:
                    log('%x %s duplicate function call to %x', self.state.pc, me, address)
                    self.stop()
                    return

                self.store(address)
                log('%x %s descending into %x', self.state.pc, me, address)
                return
        return super(MyChildCollector, self).execute(insn)

class MyCallCollector(LoopEmulator):
    def execute(self, insn):
        if ia32.isRelativeCall(insn):
            self.store(self.state.pc)
        elif ia32.isCall(insn):
            print '%x unknown call with opcode %s found'%( self.state.pc, repr(ia32.getOpcode(insn)) )
        return super(MyCallCollector, self).execute(insn)

class autopointerarray(parray.terminated):
    _object_ = pint.uint32_t
    source = IdaProvider()
    def isTerminator(self, value):
        offset = value.getoffset()
        if len(self) > 1:
            address = int(value)

            # if this doesn't point to code, then bail
            if not database.isCode(address):
                del(self.value[-1])
                return True
#            insn = database.decode(address)

        return False

    def name(self):
        return 'vt_%x'% self.getoffset()

def makepointerarray(ea):
    res = autopointerarray()
    res.setoffset(ea)
    return res

if False:
    class MyInstructionCollector(LoopEmulator):
        def execute(self, insn):
            if ia32.isRelativeCall(insn):
                address = ia32.getRelativeAddress(self.state.pc, insn)
                self.addMachine( self.fork(address) )

                me = hex(id(self.state))
                log('%x %s descending into %x', self.state.pc, me, address)
                return True

            im = ia32.getImmediate(insn)
            if im:
                z = dyn.clone(pint.uint32_t, value=im)()
                if int(z) == 0x30f0a6e0:
                    self.store(self.state.pc)
                pass
                
            return super(MyInstructionCollector, self).execute(insn)
    """
        z = dyn.clone(pint.uint32_t, value=ia32.getImmediate(db.decode(h())))()

        001363a0 30556966 053d591c 00000184 0550afe0 oart!Ordinal3227+0x79
        001363c8 30429c4f 04989624 04989510 00000001 EXCEL!Ordinal40+0x556966
        001363e8 3027d966 04989510 04989908 00000000 EXCEL!Ordinal40+0x429c4f
        0013641c 3027ed79 00000000 00136fc7 000000a6 EXCEL!Ordinal40+0x27d966
        00136984 3027e91a 00000000 000004f5 00000000 EXCEL!Ordinal40+0x27ed79
        00137008 3027de6f ffffffff 049892e4 00000000 EXCEL!Ordinal40+0x27e91a
        0013708c 30284080 00000000 ffffffff 00000001 EXCEL!Ordinal40+0x27de6f
        0013712c 3027b8da 052b1400 020bdd40 3cf3a9a5 EXCEL!Ordinal40+0x284080

    """

def writebreakpoints(list, filename, command="r;g"):
    '''Write the specified list to the file represented by filename'''
    f = file(filename, 'wt')
    f.write('\n'.join( ('bp %x "%s"'% (ea,command) for ea in list) ))
    f.close()

class remote(object):
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

def markhits(addresses, prefix='ht-', color=0x004000):
    sourcetag = '%ssource'% prefix
    destinationtag = '%sdestination'% prefix
    counttag = '%scount'% prefix
    for ea in addresses:
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

def getLvar(f):
    return makeptypefragment(function.getFrameId(f), 0, function.getLvarSize(f))
def getRvar(f):
    return makeptypefragment(function.getFrameId(f), function.getLvarSize(f), function.getRvarSize(f)+4)
def getArgs(f):
    return makeptypefragment(function.getFrameId(f), function.getLvarSize(f) + function.getRvarSize(f)+4, function.getArgsSize(f))

def ptypedefinition(p, address):
    name = '%s_%x'% (p.__name__, database.getOffset(address))
    if issubclass(p, pstruct.type):
        fields = ["(%s.%s, '%s')"% (t.__module__,t.__name__, n) for t,n in p._fields_]
        s = 'class %s(pstruct.type): _fields_=[%s]'% (name, ','.join(fields))
        return s
    if issubclass(p, parray.type):
        fields = ["(%s, '%s')"% (t.__name__, n) for t,n in p._fields]
        s = 'class %s(parray.type): _object_=[%s]; length=%d'% (name, p._object_.__name__, p.length)
        return s
    raise NotImplementedError
        
class MyExternalCollector(LoopEmulator):
    def execute(self, insn):
        if ia32.isMemoryCall(insn):
            res = ia32.stringToNumber( ia32.getDisplacement(insn) )
            self.store(res)
        if ia32.isMemoryBranch(insn):
            res = ia32.stringToNumber( ia32.getDisplacement(insn) )
            self.store(res)
        return super(MyExternalCollector, self).execute(insn)

def tagExternals(f):
    l = set(MyExternalCollector(f).run())
    externals = [ database.tag(ea, 'name') for ea in l ]
    if externals:
        function.tag(f, 'externals', repr(externals))
    return

if False:
    import ia32,ali
    for n in ali.MyChildCollector(h()).run():
        t = []
        for c in ali.MyCallCollector(n).run():
            target = ia32.getRelativeAddress(c, db.decode(c))
            t.append(target)
        fn.tag(n, 'calls', repr(map(hex,t)))
    pass
