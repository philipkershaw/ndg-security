#!/usr/bin/env python
import getpass
from sqlalchemy import create_engine

if __name__ == "__main__":
    import sys
    import pdb;pdb.set_trace()
    username, hostname, dbName = sys.argv[1:]
    
    # postgres
    pwd = getpass.getpass()
    pg_db = create_engine('postgres://%s:%s@%s/%s' % 
                          (username, pwd, hostname, dbName))
    connection = pg_db.connect()
    result = connection.execute("select * from users")
    for row in result:
        print ', '.join(["%s=%s" % (k,v) for k,v in row.items()])
    connection.close()


