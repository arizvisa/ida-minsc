import logging
list = set(('sqlite','ida'))

try:
    _='sqlite'
    import sqlite
except ImportError, message:
    logging.warning('store.driver: unable to load %s. %s'% (_,message))
    logging.debug(__import__('traceback').format_exc())
    list.discard(_)
    del(message)

try:
    _='ida'
    import ida
except ImportError, message:
    logging.warning('store.driver: unable to load %s. %s'% (_,message))
    logging.debug(__import__('traceback').format_exc())
    list.discard(_)
    del(message)

if False:
    list = set(('sqlite','ida'))

    for _ in set(list):
        print __import__(_)
        try:
            globals()[_] = __import__(_)
            logging.info('store.driver: loaded %s'% _)
        except ImportError, message:
            logging.warning('store.driver: unable to load %s. %s'% (_,message))
            logging.debug(__import__('traceback').format_exc())
            list.discard(_)
            del(message)
        continue
    del(_)
