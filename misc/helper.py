import database

class remote(object):
    '''For poor folk without a dbgeng'''
    def __init__(self, remotebaseaddress, localbaseaddress=None):
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
