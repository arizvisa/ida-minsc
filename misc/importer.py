import database as db
import function as fn
import pickle

def database(data):
    data = pickle.loads(data)
    for offset,fndata in data.items():
        address = offset + db.baseaddress()
        function(address, fndata)
    return

def function(ea, data):
    ea = fn.top(ea)
    data = pickle.loads(data)
    fn.store(ea, data)
    return len(data)
