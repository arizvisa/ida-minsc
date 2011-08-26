# XXX: i am still disgusted with this interface...

import logging,__init__
#logging.root=logging.RootLogger(logging.DEBUG)

###### stuff used for figuring out the code semantics of an addressspace
class reader(object):
    '''consumes a byte at a time from the specified address'''
    def __init__(self, ea):
        raise NotImplementedError

    def next(self):
        raise NotImplementedError

class architecture(object):
    '''this converts data into instructions, and instructions into meaning'''

    # instruction related
    @staticmethod
    def decode(ea, data):
        '''convert the bytes produced by data into an instruction'''
        raise NotImplementedError

    @staticmethod
    def length(ea, instruction):
        '''return the length of an instruction'''
        raise NotImplementedError

    # branch related
    @staticmethod
    def resolvebranch(ea, instruction):
        '''resolve a branch instruction's destination address'''
        raise NotImplementedError

    @staticmethod
    def isbranch(ea, instruction):
        '''determine if an instruction is a branch instruction'''
        raise NotImplementedError

    @staticmethod
    def isstop(ea, instruction):
        '''determine if an instruction is one to stop on'''
        raise NotImplementedError
    
    # function scope related
    @staticmethod
    def iscall(ea, instruction):
        '''determine if an instruction is a call'''
        raise NotImplementedError

    @staticmethod
    def isreturn(ea, instruction):
        '''determine if an instruction is a return'''
        raise NotImplementedError

###### 
class machine(object):
    '''
    abstraction around instruction decoding and byte consumption
    '''
    pc = 0
    def __init__(self, architecture, reader):
        self.architecture = architecture
        self.__reader = reader

    def goto(self, pc):
        '''change the address of the machine'''
        self.source = self.__reader(pc)
        self.pc = pc
        return self

    def next(self):
        '''seek to the next instruction'''
        pc,insn = self.pc,self.architecture.decode(self.pc, self.source)
        self.pc += self.architecture.length(pc, insn)
        return pc,insn

    def fork(self, pc):
        '''return a copy of the machine'''
        cls = type(self)
        return cls(self.arch, self.__reader).goto(pc)

    def __getattr__(self, key):
        return getattr(self.architecture, key)

###### 
class harvester(object):
    '''
    responsible for spawning machines and harvesting information from them
    this will store the results from things that have been collected
    '''
    __result = None
    machine = None

    def __init__(self, architecture, reader):
        self.machine = machine(architecture, reader)
        cls = type(self)
        self.duplicate = lambda: cls(architecture, reader)
        self.__result = {}

    def duplicate(self):
        '''makes a copy of the current harvester. this is assigned by __init__'''
        raise NotImplementedError

    def collect(self, collect=set(), **options):
        '''execute any instruction until we hit one for stopping'''
        while True:
            pc,insn = self.machine.next()

            # collect information about instruction
            stop = False
            for c in collect:
                if c(self, pc, insn, **options):
                    stop = True
                continue

            if stop:
                break

            # check to see if we need to branch
            if self.machine.isbranch(pc, insn):
                self.machine.goto(self.machine.resolvebranch(pc, insn))

            # or if we need to stop
            elif self.machine.isstop(pc, insn):
                break
            yield pc
        return

    result = property(fget=lambda s: s.__result)

    ## utilities for collectors
    def pop(self, key):
        result = self.__result[key]
        del(self.__result[key])
        return result

    def store(self, key, value):
        '''stash a key,value pair for fetching later'''
        if key not in self.__result:
            self.__result[key] = set()
        self.__result[key].add(value)

    def goto(self, pc):
        '''switch current harvesting pc to the one specified'''
        self.machine.goto(pc)

###### function that will collect attributes from a function's address
def __collect(harvester, pc, collectors=set(), **options):
    '''using the specified harvester, execute all instructions once...'''
    result = {}
    
    workqueue = [pc]
    executed = set()
    while workqueue:
        pc = workqueue.pop(0)

        # start collecting addresses at the specified pc
        harvester.goto(pc)
        for pc in harvester.collect(collectors, **options):
            if pc in executed:
#                logging.debug('terminating emulation due to %x already being executed'% pc)
                break
            executed.add(pc)

        # handle forking (and remove the 'fork' attribute from the result set)
        if __init__.BRANCH in harvester.result:
            workqueue.extend([br for br in harvester.pop(__init__.BRANCH)])
        
        # aggregate results
        for k,v in harvester.result.iteritems():
            if k not in result:
                result[k] = set()
            result[k].update(v)
        continue
    return result

def collect(harvester, pc, collectors=set(), depth=0, **options):
    def call(state, pc, insn, **options):
        if state.machine.iscall(pc, insn):
            target = state.machine.resolvebranch(pc,insn)
            state.store(__init__.CALL, target)
        return False

    result = {}
    workqueue = set((pc,))
    completed = set()
    while workqueue and depth >= 0:
        calls,workqueue = set(workqueue),set()
        
        for ea in calls:
            r = __collect(harvester, ea, set((call,)).union(collectors), **options)
            completed.add(ea)

            # gather next workload
            if __init__.CALL in r:
                workqueue.update(set(r.pop(__init__.CALL)).difference(completed))
                logging.debug('iteration of %x will add %d functions to process'% (ea,len(workqueue)))
        
            # aggregate results
            for k,v in r.iteritems():
                if k not in result:
                    result[k] = set()
                result[k].update(v)
            continue
        depth -= 1
    return result

if __name__ == '__main__':
    import base,i386

    """
    KERNELBASE!GetProcessId:
    7748e900 8bff            mov     edi,edi
    7748e902 55              push    ebp
    7748e903 8bec            mov     ebp,esp
    7748e905 83ec18          sub     esp,18h
    7748e908 6a00            push    0
    7748e90a 6a18            push    18h
    7748e90c 8d45e8          lea     eax,[ebp-18h]
    7748e90f 50              push    eax
    7748e910 6a00            push    0
    7748e912 ff7508          push    dword ptr [ebp+8]
    7748e915 ff152c104877    call    dword ptr [KERNELBASE!_imp__NtQueryInformationProcess (7748102c)]
    7748e91b 85c0            test    eax,eax
    7748e91d 7d0a            jge     KERNELBASE!GetProcessId+0x29 (7748e929)

    KERNELBASE!GetProcessId+0x1f:
    7748e91f 50              push    eax
    7748e920 e8ed830200      call    KERNELBASE!BaseSetLastNTError (774b6d12)
    7748e925 33c0            xor     eax,eax
    7748e927 eb03            jmp     KERNELBASE!GetProcessId+0x2c (7748e92c)

    KERNELBASE!GetProcessId+0x29:
    7748e929 8b45f8          mov     eax,dword ptr [ebp-8]

    KERNELBASE!GetProcessId+0x2c:
    7748e92c c9              leave
    7748e92d c20400          ret     4
    """

    address = 0x7748e900
    data = '''
    8b ff 55 8b ec 83 ec 18-6a 00 6a 18 8d 45 e8 50
    6a 00 ff 75 08 ff 15 2c-10 48 77 85 c0 7d 0a 50
    e8 ed 83 02 00 33 c0 eb-03 8b 45 f8 c9 c2 04 00
    '''
    data = data.replace('-','').replace(' ','').replace('\n','').decode('hex')

    def strreader(ea):
        base = 0x7748e900
        for x in data[ea - base:]:
            yield x
            ea += 1
        return

    import ia32
    def sib(state, ea, insn, **options):
        disp = ia32.getDisplacement(insn)
        if ia32.isSibBranch(insn) and len(disp) == 4:
            ea = ia32.decodeInteger(disp)
            for target in switch(offset=ea).l:
                state.store(__init__.BRANCH, pc)
            return True
        return False

    def memcall(state, ea, insn, **options):
        if ia32.isMemoryCall(insn):
            offset = ia32.getDisplacement(insn)
            dword = pint.uint32_t(offset=offset)
            pc = dword.l.int()
            state.store(__init__.BRANCH, pc)
        return False

    def conditional(state, pc, insn, **options):
        if ia32.isConditionalBranch(insn):
            pc = ia32.getRelativeAddress(pc, insn)
            state.store(__init__.BRANCH, pc)
        return False

    def coloring(state, ea, insn, **options):
        database.color(ea, options['color'])

    def output(state, ea, insn, **options):
        print '%x %s'%(ea, repr(insn))

    def call(state, pc, insn, **options):
        if ia32.isCall(insn):
            target = ia32.getRelativeAddress(pc,insn)
            state.store(__init__.CALL, (pc,target))
        return False

    def unknown(state, pc, insn, **options):
        return ia32.isRegisterBranch(insn) or ia32.isMemoryBranch(insn) or ia32.isDispBranch(insn) or ia32.isSibBranch(insn)

    default=[conditional,unknown]

    x86 = base.harvester(i386.i386,strreader)
    a = base.__collect(x86, address, default+[output,call], color=None)
