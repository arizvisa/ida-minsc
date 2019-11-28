'''QuickTime stuff'''

EXPORT = [ 'nameDispatch', 'nameAllDispatches' ]

import idc,idautils
import function,database
import app

def nextMnemonic(ea, mnem, maxaddr=0xc0*0x1000000):
    res = idc.print_insn_mnem(ea)
    if res == "": return idc.BADADDR
    if res == mnem: return ea
    return nextMnemonic( idc.next_head(ea, maxaddr), mnem, maxaddr )

def prevMnemonic(ea, mnem, minaddr=0):
    res = idc.print_insn_mnem(ea)
    #print "%x -> %s"% (ea, res)
    if res == "": return idc.BADADDR
    if res == mnem: return ea
    return prevMnemonic( idc.prev_head(ea, minaddr), mnem, minaddr )

def getMinorDispatchTableAddress(ea):
    """find address of last lea in function"""
    start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    end = idc.prev_head( idc.get_func_attr(ea, idc.FUNCATTR_END), start)
    res = prevMnemonic(end, 'lea', start)
    assert res != idc.BADADDR
    return idc.get_operand_value(res, 1)

def getMajorDispatchTableAddress():
    """find quicktime major dispatch table"""
    res = idc.get_name_ea_simple('theQuickTimeDispatcher')
    res = nextMnemonic(res, 'lea', idc.get_func_attr(res, idc.FUNCATTR_END))
    assert res != idc.BADADDR
    return idc.get_operand_value(res, 1)

def resolveDispatcher(code):
    major = (code & 0x00ff0000) >> 0x10
    minor = code & 0xff00ffff

    res = getMajorDispatchTableAddress() + major*8
    majorFlag = idc.get_wide_dword(res)
    majorAddress = idc.get_wide_dword(res+4)
    if majorFlag != 0:
        return majorAddress + (minor*0x10)

    #print "%x"% getMinorDispatchTableAddress(majorAddress)
    #print "resolved by 0x%x(%x)"% (majorAddress, minor)
    return majorAddress

def getDispatchCode(ea):
    # get dispatch code out of an instruction
    first, second = (idc.print_operand(ea, 0), idc.get_operand_value(ea, 1))
    if first == 'eax':
        return second
    raise ValueError("Search resulted in address %08x, but instruction '%s' does fulfill requested constraints"% (ea, idc.print_insn_mnem(ea)))

def FindLastAssignment(ea, register):
    start,end = database.guessrange(ea)
    while ea > start:
        ea = database.prev(ea)
        m = idc.print_insn_mnem(ea)
        r = idc.print_operand(ea, 0)

        if m == 'mov' and r == register:
            return ea
        continue

    raise ValueError('FindLastAssignment(0x%x, %s) Found no matches'% (ea, register))

def nameDispatch(address):
    '''Name the dispatch function at the specified address in quicktime.qts'''
    try:
        start, end = function.range(address)

    except ValueError:
        print '%x making a function'% address
        function.make(address)
        start, end = function.range(address)

    try:
        ea = FindLastAssignment(address, 'eax')
        code = getDispatchCode(ea)
    except ValueError:
        print '%08x - Unable to find dispatch code'% address
        return

    ofs = database.getoffset(start)
    function.setName(start, 'dispatch_%08x_%x'% (code, ofs))
    function.tag(start, 'code', hex(code))
    function.tag(start, 'group', 'dispatch')
    try:
        function.tag(start, 'realname', app.__quicktime.qt_fv_list[code])
    except KeyError:
        pass

    try:
        function.tag(start, 'address', hex(resolveDispatcher(code)), repeatable=True)
    except:
        pass

def nameAllDispatches(ea):
    '''Using the address of {theQuickTimeDispatcher}, name and tag all discovered dispatch calls in quicktime.qts'''
    for address in idautils.DataRefsTo(ea):
        nameDispatch(address)
    return
