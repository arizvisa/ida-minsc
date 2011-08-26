'''QuickTime stuff'''

EXPORT = [ 'nameDispatch', 'nameAllDispatches' ]

import idc, comment

import idc,idautils
import function,comment,database
import __quicktime

def nextMnemonic(ea, mnem, maxaddr=0xc0*0x1000000):
    res = idc.GetMnem(ea)
    if res == "": return idc.BADADDR
    if res == mnem: return ea
    return nextMnemonic( idc.NextHead(ea, maxaddr), mnem, maxaddr )

def prevMnemonic(ea, mnem, minaddr=0):
    res = idc.GetMnem(ea)
    #print "%x -> %s"% (ea, res)
    if res == "": return idc.BADADDR
    if res == mnem: return ea
    return prevMnemonic( idc.PrevHead(ea, minaddr), mnem, minaddr )

def getMinorDispatchTableAddress(ea):
    """find address of last lea in function"""
    start = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
    end = idc.PrevHead( idc.GetFunctionAttr(ea, idc.FUNCATTR_END), start)
    res = prevMnemonic(end, 'lea', start)
    assert res != idc.BADADDR
    return idc.GetOperandValue(res, 1)

def getMajorDispatchTableAddress():
    """find quicktime major dispatch table"""
    res = idc.LocByName('theQuickTimeDispatcher')
    res = nextMnemonic(res, 'lea', idc.GetFunctionAttr(res, idc.FUNCATTR_END))
    assert res != idc.BADADDR
    return idc.GetOperandValue(res, 1)
        
def resolveDispatcher(code):
    major = (code & 0x00ff0000) >> 0x10
    minor = code & 0xff00ffff

    res = getMajorDispatchTableAddress() + major*8
    majorFlag = idc.Dword(res)
    majorAddress = idc.Dword(res+4)
    if majorFlag != 0:
        return majorAddress + (minor*0x10)

    #print "%x"% getMinorDispatchTableAddress(majorAddress)
    #print "resolved by 0x%x(%x)"% (majorAddress, minor)
    return majorAddress

def getDispatchCode(ea):
    # get dispatch code out of an instruction
    first, second = (idc.GetOpnd(ea, 0), idc.GetOperandValue(ea, 1))
    if first == 'eax':
        return second
    raise ValueError("Search resulted in address %08x, but instruction '%s' does fulfill requested constraints"% (ea, idc.GetMnem(ea)))

def FindLastAssignment(ea, register):
    start,end = database.guessrange(ea)
    while ea > start:
        ea = database.prev(ea)
        m = idc.GetMnem(ea)
        r = idc.GetOpnd(ea, 0)

        if m == 'mov' and r == register:
            return ea
        continue
    
    raise ValueError('FindLastAssignment(0x%x, %s) Found no matches'% (ea, register))

def nameDispatch(address):
    '''Name the dispatch function at the specified address in quicktime.qts'''
    try:
        start, end = function.getRange(address)

    except ValueError:
        print '%x making a function'% address
        function.make(address)
        start, end = function.getRange(address)

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
        function.tag(start, 'realname', __quicktime.qt_fv_list[code])
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
