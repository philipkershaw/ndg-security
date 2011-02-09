"""NDG Attribute Authority User Roles class - acts as an interface between
the data centre's user roles configuration and the Attribute Authority
                                                                                
NERC Data Grid Project
                                                                                
@author P J Kershaw 29/07/05
                                                                                
@copyright (C) 2006 CCLRC & NERC
                                                                                
@licence: This software may be distributed under the terms of the Q Public 
License, version 1.0 or later.
"""
__revision__ = '$Id:$'

# Properties file
from ConfigParser import SafeConfigParser, NoOptionError

# PostgreSQL interface
from psycopg import *

# User roles base class
from ndg.security.server.AttAuthority import AAUserRoles, AAUserRolesError
from ndg.security.common.X509 import X500DN


class TestUserRoles(AAUserRoles):
    """Test User Roles class dynamic import for Attribute Authority"""

    def __init__(self, configFilePath=None):
        pass


    def userIsRegistered(self, userId):
        return True


    def getRoles(self, userId):
        return ['coapec', 'rapid']


class UserRoles(AAUserRoles):
    """User Roles interface to BADC Attribute Authority"""

    def __init__(self, configFilePath=None):
        """Connect to BADC User database

        Omit connectKw or explicitly set CreateRoles to False if wish to
        avoid querying the database on object creation"""

        self.__con = None

        if configFilePath is not None:
            self.readConfigFile(configFilePath)

        
    def __del__(self):    
        """Close database connection"""
        self.close()


    def readConfigFile(self, configFilePath):
        """Read the configuration for the database connection

        @type configFilePath: string
        @param configFilePath: file path to config file"""
        
        if not isinstance(configFilePath, basestring):
            raise AAUserRolesError, "Input Properties file path " + \
                  "must be a valid string."

        cfg = SafeConfigParser()
        cfg.read(configFilePath)

	self.__userIsRegisteredQuery = cfg.get("userIsRegistered", "query")
        self.__host = cfg.get("Connection", "host")
        self.__dbName = cfg.get("Connection", "dbName")
        self.__username = cfg.get("Connection", "username")
        self.__pwd = cfg.get("Connection", "pwd")

        try:
            self.__getRolesQuery = []
            for i in range(10):
                self.__getRolesQuery += [cfg.get("getRoles", "query%d" % i)]
        except NoOptionError:
             # Continue until no more query<n> items left
             pass

        # This option may be omitted in the config file
        try:
	    self.__metOfficeFormQuery = cfg.get("getRoles","metOfficeFormQuery")
        except NoOptionError:
            self.__metOfficeFormQuery = None

        # Check for roles included in result of first query which would mean
        # the user must also have signed a MetOffice form
	self.__metOfficeFormQualifyingRoles = cfg.get("getRoles",
                                         "metOfficeFormQualifyingRoles").split()
	self.__metOfficeFormRoleName = cfg.get("getRoles",
                                               "metOfficeFormRoleName")


    def connect(self, 
                username=None,
                dbName=None,
                host=None,
                pwd=None,
                prompt="Database password: "):
        """Connect to database
        
        Values for keywords omitted are derived from the config file.  If pwd
        is not in the config file it will be prompted for from stdin

        @type username: string
        @keyword username: database account username
        @type dbName: string
        @keyword dbName: name of database
        @type host: string
        @keyword host: database host machine
        @type pwd: string
        @keyword pwd: password for database account.  If omitted and not in
        the config file it will be prompted for from stdin
        @type prompt: string
        @keyword prompt: override default password prompt"""
        
        if not host:
            host = self.__host
        
        if not dbName:
            dbName = self.__dbName
        
        if not username:
            username = self.__username

        if not pwd:
            pwd = self.__pwd

            if not pwd:
                import getpass
                pwd = getpass.getpass(prompt=prompt)

        try:
            self.__db = connect("host=%s dbname=%s user=%s password=%s" % \
				(host, dbName, username, pwd))
            self.__cursor = self.__db.cursor()
            
        except Exception, e:
            raise AAUserRolesError, \
                "Error connecting to database \"%s\": %s" % (dbName, e)

        
    def close(self):    
        """Close database connection"""
        if self.__con:
            self.__con.close()


    def userIsRegistered(self, dn):
        """Return boolean to indicate whether user with given DN is
        registered

        Interface method to AttAuthority - Overrides AAUserRoles base
        class"""

        # Parse username from DN string
        try:
            username = X500DN(dn)['CN']
                
        except Exception, e:
            raise AAUserRolesError, "Parsing username from DN %s: %s" % (dn, e)


        sqlStmt = self.__userIsRegisteredQuery % username

        try:
            try:
                self.connect()
                self.__cursor.execute(sqlStmt)
                count = self.__cursor.fetchall()[0][0]
            
            except Exception, e:
                raise AAUserRolesError, "Searching for user %s: %s" % \
								(username, e)
        finally:
            self.close()

        if count == 1:
            return True
        else:
            return False


    def getRoles(self, dn):
        """Return valid roles for the BADC database
        
        Interface method to AttAuthority - Overrides AAUserRoles base
        class

        @type param dn: string
        @param dn: distinguished name as a string"""

        # Parse username from DN string
        try:
            cn = X500DN(dn)['CN']
            if len(cn) == 2:
                # Proxy cert has two common names set - assume extra common name
                # will be 'prixy' or a number
                username = [n for n in cn if n!="proxy" and not n.isdigit()][0]
            else:
                username = cn
 
        except Exception, e:
            raise AAUserRolesError, "Parsing username from DN %s: %s" % (dn, e)

        try:
            self.connect()

            # Process each query in turn appending role names
            roles = []
            for query in self.__getRolesQuery:
                try:
                    self.__cursor.execute(query % username)
                    queryRes = self.__cursor.fetchall()
            
                except Exception, e:
                    raise AAUserRolesError, "Query for %s: %s" % \
							(username, str(e))

                roles += [res[0] for res in queryRes if res[0]]


            # Special Case for deterimining Met Office form role - i.e. role 
            # given to those users who have signed a Met Office form
            for qualRole in self.__metOfficeFormQualifyingRoles:
                if qualRole in roles:
                    roles += [self.__metOfficeFormRoleName]
                    break

            if self.__metOfficeFormRoleName not in roles and \
               self.__metOfficeFormQuery:
                try:
                    self.__cursor.execute(self.__metOfficeFormQuery % username)
                    nMetOfficeFormMat = self.__cursor.fetchall()[0][0]
            
                except Exception, e:
                    raise AAUserRolesError, "Querying for roles: %s" % str(e)

                if nMetOfficeFormMat > 0:
                    roles += [self.__metOfficeFormRoleName]

        finally:
            self.close()

        return roles


    def __getCursor(self):
        """Return a database cursor instance"""
        return self.__cursor

    cursor = property(fget=__getCursor, doc="database cursor")


def badcUserRolesTest(**keys):
    import pdb;pdb.set_trace()
    userRoles = UserRoles(**keys)
    print "User is registered? %s" % \
	userRoles.userIsRegistered('/O=NDG/OU=BADC/CN=pjkersha')
    print "User roles = %s" % \
	userRoles.getRoles('/O=NDG/OU=BADC/CN=lawrence')
    
    
if __name__ == "__main__":
    import sys
    badcUserRolesTest(configFilePath=sys.argv[1])
