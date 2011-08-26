import __init__,base,ia32
class i386(base.architecture):
    @staticmethod
    def decode(ea, data):
        return ia32.consume(data)

    @staticmethod
    def length(ea, instruction):
        return ia32.length(instruction)

    #
    @staticmethod
    def resolvebranch(ea, instruction):
        return ia32.getRelativeAddress(ea, instruction)

    @staticmethod
    def isbranch(ea, instruction):
        return ia32.isUnconditionalBranch(instruction) or ia32.isAbsoluteBranch(instruction)

    @staticmethod
    def isstop(ea, instruction):
        return ia32.isReturn(instruction)

    #
    @staticmethod
    def iscall(ea, instruction):
        return ia32.isRelativeCall(instruction) or ia32.isAbsoluteCall(instruction)

    @staticmethod
    def isreturn(ea, instruction):
        return ia32.isReturn(instruction)

def __unknown(state, pc, insn, **options):
    return ia32.isRegisterBranch(insn) or ia32.isMemoryBranch(insn) or ia32.isDispBranch(insn) or ia32.isSibBranch(insn)

def __conditional(state, pc, insn, **options):
    if ia32.isConditionalBranch(insn):
        pc = ia32.getRelativeAddress(pc, insn)
        state.store(__init__.BRANCH, pc)
    return False

def collect(source, address, depth=0, collectors=set(), **options):
    '''Given the specified source and address and function depth, apply all the specified collectors'''
    harvester = base.harvester(i386, source)
    c = set((__conditional,__unknown))
    return base.collect(harvester, address, c.union(set(collectors)), depth=depth, **options)
