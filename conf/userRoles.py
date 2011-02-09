"""NDG Attribute Authority User Roles class - acts as an interface between
the data centre's user roles configuration and the Attribute Authority

BODC User Roles Interface to Oracle database

@author P J Kershaw 09/08/07

@copyright (C) 2007 STFC & NERC

@licence: This software may be distributed under the terms of the Q Public
License, version 1.0 or later.
"""
__revision__ = '$Id:$'


from ConfigParser import SafeConfigParser

# Use a conditional import here because if the TestUserRoles class is used,
# cx_Oracle is not required
try:
    import cx_Oracle
except ImportError, e:
    from warnings import warn
    warn(str(e), RuntimeWarning)
    pass

from ndg.security.server.AttAuthority import AAUserRoles, AAUserRolesError
from ndg.security.common.X509 import X500DN


class TestUserRoles(AAUserRoles):
    """Test User Roles class dynamic import for Attribute Authority
    NOT for use on production system"""

    def __init__(self, propertiesFilePath=None):
        pass

    def getRoles(self, dn):
        """Test getRoles returns role attributes regardless of user Id!"""

        # Parse username from DN string
        # TODO: this may be e-mail address for BODC?
        try:
            cn = X500DN(dn)['CN']
            if len(cn) == 2:
                # Proxy cert has two common names set - assume extra common 
                # name will be 'prixy' or a number
                username=[n for n in cn if n!="proxy" and not n.isdigit()][0]
            else:
                username = cn

        except Exception, e:
            raise AAUserRolesError, "Parsing username from DN %s: %s" % (dn,e)

        return ['Public', 'Researcher']


class UserRoles(AAUserRoles):
    """User Roles class dynamically imported for Attribute Authority
    - see the Attribute Authority Properties file to make the correct
    settings"""

    def __init__(self, propertiesFilePath=None):
        if not propertiesFilePath:
            raise AAUserRolesError, "No user roles property file set"

	    # Retrieve database connection and query settings from config file
        configParser = SafeConfigParser()
        configParser.read(propertiesFilePath)

        self.__conxnStr = configParser.get('Oracle', 'connection')

        # The Oracle connection could be made HERE to make getRoles method
        # more efficient but then AA would hog an Oracle connection as long as
        # it is running.  There may be away to avoid this using a connection
	    # pool
        self.__query =  configParser.get('Oracle', 'query')


    def getRoles(self, dn):
        '''Roles interface for BODC database'''

        # Parse username from DN string
        # TODO: this may be e-mail address for BODC?
        try:
            cn = X500DN(dn)['CN']
            if len(cn) == 2:
                # Proxy cert has two common names set - assume extra common 
                # name will be 'prixy' or a number
                username=[n for n in cn if n!="proxy" and not n.isdigit()][0]
            else:
                username = cn

        except Exception, e:
            raise AAUserRolesError, "Parsing username from DN %s: %s" % (dn,e)

        # It may be possible to use a connection pool and move this
        # connect call to __init__ see:
        #
        # http://www.python.net/crew/atuining/cx_Oracle/html/module.html
        #
        try:
            con = cx_Oracle.connect(self.__conxnStr)
            cursor = con.cursor()
        except Exception, e:
            raise AAUserRolesError, "Error connecting to Oracle database: " +\
        			                str(e)
        
        # Substitute the username into the query - the query is expected to 
        # have a "%s" to allow this
        #
        # Convert username to string type explicitly as the execute method 
        # doesn't like unicode type
        try:
            try:
                query = self.__query % str(username)
                cursor.execute(query)
                result = cursor.fetchall()
            except Exception, e:
                raise AAUserRolesError, "Error executing query: " + str(e)
        finally:
        	cursor.close()
        	con.close()
        
        # Result is a list of tuples.  The first element of each tuple is a
        # role name -> Convert into a simple list of role names
        try:
            roleNames = [role[0] for role in result]
        except TypeError:
            # Catch non-iterable error with result var
            roleNames = []
        
        return roleNames

# Command line test - give user DN as command line option e.g. 
# /O=NDG/OU=BODC/CN=siva
if __name__ == "__main__":
    import sys
#    testUserRoles = TestUserRoles()
#    print "Roles = %s" % testUserRoles.getRoles(sys.argv[1])

    userRoles = UserRoles(propertiesFilePath="./database.cfg")
    print "Roles = %s" % userRoles.getRoles(sys.argv[1])
