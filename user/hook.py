import sys
import ctypes as ct
u32 = ct.WinDLL('user32.dll')
k32 = ct.WinDLL('kernel32.dll')
ws2 = ct.WinDLL('ws2_32.dll')
NULL = 0

### generic code
import time
class logger(object):
    output = file('c:/users/arizvisa/fuck.txt', 'at')
    clock = delay = count = 0
    rate = 20

    @classmethod
    def pr(cls, *args):
        if len(args) == 1:
            message, = args
            cls.output.write(message)
        if len(args) == 2:
            message,tuple = args
            cls.output.write(message%tuple)

        cls.output.write("\n")

        if cls.timeout():
            cls.output.close()
            cls.output = file('c:/users/arizvisa/fuck.txt', 'at')
            cls.reset()
        return

    @classmethod
    def reset(cls):
        cls.clock = time.clock()
        cls.count = 0

    @classmethod
    def timeout(cls):
        if cls.clock + cls.delay > time.clock():
            return True
        return False

    @classmethod
    def limited(cls):
        if cls.count < cls.rate:
            return False
        return True

def getLastErrorTuple():
    errorCode = k32.GetLastError()
    p_string = ct.c_void_p(0)

    # FORMAT_MESSAGE_
    ALLOCATE_BUFFER = 0x100
    FROM_SYSTEM = 0x1000
    res = k32.FormatMessageA(
        ALLOCATE_BUFFER | FROM_SYSTEM, 0, errorCode,
        0, ct.pointer(p_string), 0, NULL
    )
    res = ct.cast(p_string, ct.c_char_p)
    errorString = str(res.value)
    res = k32.LocalFree(res)
    assert res == 0, "kernel32!LocalFree failed. Error 0x%08x."% k32.GetLastError()

    return (errorCode, errorString)

def getLastErrorString():
    code, string = getLastErrorTuple()
    return string

### some constants
FD_READ = 1
FD_WRITE = 2
FD_ACCEPT = 8
FD_CONNECT = 16
FD_CLOSE = 32
WM_APP = 0x8000
AF_INET = 2
SOCKET_ERROR = -1

GA_PARENT = 1
GA_ROOT = 2
GA_ROOTOWNER = 3

### Window Messages Structures
LRESULT = ct.c_uint32
WPARAM = ct.c_uint32
LPARAM = ct.c_uint32
HOOKPROC = ct.WINFUNCTYPE(LRESULT, ct.c_int, WPARAM, LPARAM)
WM_COMMAND= 0x111

class CWPSTRUCT(ct.Structure):
    _fields_ = [
        ("lParam", LPARAM),
        ("wParam", WPARAM),
        ("message", ct.c_uint32),
        ("hwnd", ct.c_ulong),
    ]

class RECT(ct.Structure):
    _fields_ = [
        ("left", ct.c_ulong),
        ("top", ct.c_ulong),
        ("right", ct.c_ulong),
        ("bottom", ct.c_ulong)
    ]

class GUITHREADINFO(ct.Structure):
    _fields_ = [
        ("cbSize", ct.c_ulong),
        ("flags", ct.c_ulong),
        ("hwndActive", ct.c_ulong),
        ("hwndFocus", ct.c_ulong),
        ("hwndCapture", ct.c_ulong),
        ("hwndMenuOwner", ct.c_ulong),
        ("hwndMoveSize", ct.c_ulong),
        ("hwndCaret", ct.c_ulong),
        ("rcCaret", RECT)
    ]

### Winsock2 Structures
class GUID(ct.Structure):
    _fields_ = [
        ("Data1", ct.c_ulong),
        ("Data2", ct.c_ushort),
        ("Data3", ct.c_ushort),
        ("Data4", ct.c_char*8)
    ]
class WSAPROTOCOLCHAIN(ct.Structure):
    _fields_ = [
        ("ChainLen", ct.c_int),
        ("ChainEntries", ct.c_ulong*0)      # yeah, this isn't a real structure
    ]

class WSAPROTOCOL_INFO(ct.Structure):
    _fields_ = [
        ("dwServiceFlags1", ct.c_ulong),
        ("dwServiceFlags2", ct.c_ulong),
        ("dwServiceFlags3", ct.c_ulong),
        ("dwServiceFlags4", ct.c_ulong),
        ("dwProviderFlags", ct.c_ulong),
        ("ProviderId", GUID),
        ("dwCatalogEntryId", ct.c_ulong),
        ("ProtocolChain", WSAPROTOCOLCHAIN),
        ("iVersion", ct.c_int),
        ("iAddressFamily", ct.c_int),
        ("iMaxSockAddr", ct.c_int),
        ("iMinSockAddr", ct.c_int),
        ("iSocketType", ct.c_int),
        ("iProtocol", ct.c_int),
        ("iProtocolMaxOffset", ct.c_int),
        ("iNetworkByteOrder", ct.c_int),
        ("iSecurityScheme", ct.c_int),
        ("dwMessageSize", ct.c_ulong),
        ("dwProviderReserved", ct.c_ulong),
        ("szProtocol", ct.c_char*255),
    ]

class WSAData(ct.Structure):
    _fields_ = [
        ("wVersion", ct.c_ushort),
        ("wHighVersion", ct.c_ushort),
        ("szDescription", ct.c_char*256),
        ("szSystemStatus", ct.c_char*128),
        ("iMaxSockets", ct.c_ushort),
        ("iMaxUdpDg", ct.c_ushort),
        ("lpVendorInfo", ct.c_char_p),
    ]

### native socket structures
class sockaddr_in(ct.Structure):
    family = AF_INET
    _fields_ = [
        ("sin_family", ct.c_short),
        ("sin_port", ct.c_ushort),
        ("sin_addr", ct.c_ulong),
        ("sin_zero", ct.c_char*8),
    ]

    @classmethod
    def new(cls, address, port):
        # address to octets
        octets = map(int,address.split('.'))

        # flip endianness
        port = ((port/0x100) & 0x00ff) + ((port & 0x00ff)*0x100)
        octets = reversed(octets)
        
        # populate structure
        result = cls()
        result.sin_family = cls.family
        result.sin_port = port      # FIXME: this port doesn't ever get set right 
        result.sin_addr = reduce(lambda a,x: (a*0x100)+x, octets, 0)
        result.sin_zero = '\x00'*8
        return result

### Window Messages Hooks
def getGUIThreadInfo():
    gti = GUITHREADINFO(cbSize=ct.sizeof(GUITHREADINFO))
    res = u32.GetGUIThreadInfo(0, ct.byref(gti) )
    if res == 0:
        raise OSError( repr(getLastErrorTuple()) )
    return gti

def getOwnerWindow():
    gti = getGUIThreadInfo()
    return u32.GetAncestor(gti.hwndFocus, GA_ROOT)

def this(port):
    hwnd = getOwnerWindow()
    print 'hooking hwnd %x'% hwnd

    x = listener()
    x.bind( ('127.0.0.1', port) )
    x.listen( hwnd )
    return x

### Socket Code
class listener(object):
    hwnd = None
    socket = None
    hookhandle = None
    message = WM_APP+0x1337

    startedwinsock = False  # heh

    def __init__(self):
        if not self.startedwinsock:
            self.startup()

        AF_INET = sockaddr_in.family
        SOCK_STREAM=1
        IPPROTO_TCP=6
        res = ws2.WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0)
        INVALID_SOCKET=-1
        if res == INVALID_SOCKET:
            raise OSError( ws2.WSAGetLastError() )
        self.socket = res

    ### socket stuff
    @classmethod
    def startup(cls):
        wsadata = WSAData()
        res = ws2.WSAStartup(0x0202, ct.byref(wsadata))
        if res != 0:
            raise OSError( ws2.WSAGetLastError() )

        h,l=wsadata.wHighVersion, wsadata.wVersion
        assert h == l, "Documentation defying error..."
        assert h == 0x0202, "Winsock Version is not as requested (0x0202 != %4x)"% realversion
        cls.startedwinsock = True

    @classmethod
    def cleanup(cls):
        assert cls.startedwinsock
        res = ws2.WSACleanup()
        if res != 0:
            raise OSError( ws2.WSAGetLastError() )
        cls.startedwinsock = False
        return
    
    def bind(self, address):
        host,port = address
        s = self.socket

        sin = sockaddr_in.new(host, port)

        res = ws2.bind(s, ct.byref(sin), ct.sizeof(sin))
        if res != 0:
            raise OSError( ws2.WSAGetLastError() )

        res = ws2.listen(s, 1)  # XXX: i don't feel right about more than one connection to an ida instance
        if res != 0:
            raise OSError( ws2.WSAGetLastError() )
        return

    def listen(self, hwnd):
        events = FD_READ|FD_WRITE|FD_ACCEPT|FD_CLOSE|FD_CONNECT
        res = ws2.WSAAsyncSelect( self.socket, hwnd, self.message, events )
        if res == SOCKET_ERROR:
            raise OSError( ws2.WSAGetLastError() )

        assert res == 0
        self.hwnd = hwnd

        # now go
        self.hook(hwnd)

    def close(self):
        res = ws2.WSAAsyncSelect(self.socket, self.hwnd, self.message, 0)
        if res == SOCKET_ERROR:
            raise OSError( ws2.WSAGetLastError() )

        res = ws2.closesocket(self.socket)
        if res == SOCKET_ERROR:
            raise OSError( ws2.WSAGetLastError() )

        self.unhook()
        self.hwnd = None

    def __del__(self):
        return self.close()     # jic

    # window hook stuff
    def hook(self, hwnd):
        assert self.hookhandle is None

        threadId = u32.GetWindowThreadProcessId(hwnd, NULL)
        WH_CALLWNDPROC = 4
        listener.object = self          # XXX: cheating
        hookprocedure = listener.hookprocedure
        self.hookhandle = u32.SetWindowsHookExA(WH_CALLWNDPROC, hookprocedure, 0, threadId)
        if self.hookhandle == 0:
            self.hookhandle = None
            raise OSError( getLastErrorTuple() )
        return True

    def unhook(self):
        res = u32.UnhookWindowsHookEx(self.hookhandle)
        if res == 0:
            raise OSError( getLastErrorTuple() )
        self.hookhandle = None
        return True

    @staticmethod
    @HOOKPROC
    def hookprocedure(nCode,wParam,lParam):
        listener = globals()['listener']
        self = listener.object

        # convert lparam argument to a structure that we can make sense out of
        n = ct.cast( ct.c_void_p(lParam), ct.POINTER(CWPSTRUCT) ).contents

        try:
            res = self.windowhandler(n.hwnd, n.message, n.wParam, n.lParam)

        except:
            tb = traceback.format_stack()
            t,e = sys.exc_info()[:2]
            logger.pr("failed with (%s,%s)", (repr(t), repr(e)))

        return u32.CallNextHookEx(self.hookhandle, nCode, wParam, lParam)

    def windowhandler(self, hWnd, wMsg, wParam, lParam):
        if wMsg == self.message:
            print 'yay'

        if (hWnd == self.hwnd) and (wMsg not in [20]):
            logger.pr("%x %x %x", (wMsg, wParam, lParam))
        return 0
