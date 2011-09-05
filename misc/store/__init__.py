import database,deploy,interface

from database import sqlite
from interface import user
from deploy import admin

if __name__ == '__main__':
    import sys
    sys.path.append('./store/')
    import database,interface,deploy
    db = database.sqlite('./test.db')
#    a = deploy.admin(db)
    u = interface.user(db, 'this')

    print u.context.get(0x00447FE0)
