import driver
from driver import sql

ida = driver.ida.Store()

def open(id=None, path=None):
    import os,sqlite3,logging

    if path is None:
        import idc
        path = idc.GetIdbPath().replace('\\','/')
        path = path[: path.rfind('/')] 
        path = '%s/%s.db'%(path,idc.GetInputFile())

    if os.path.exists(path):
        db = sqlite3.connect(path)
        session = sql.Session(db, id)
        logging.info('succcessfully opened up database %s as %s'% (path, id))
        return driver.sql.Store(session)

    db = sqlite3.connect(path)
    driver.sql.Deploy(db).create()
    db.commit()
    logging.info('succcessfully created database %s'% path)

    driver.sql.Deploy(db).session(id)
    session = sql.Session(db, id)
    logging.info('succcessfully created new session for %s'% id)

    return driver.sql.Store(session)

