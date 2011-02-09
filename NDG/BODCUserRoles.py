"""NDG Attribute Authority User Roles class for the BODC - acts as an interface
between BODC user database and the Attribute Authority

NERC Data Grid Project

P J Kershaw 09/09/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
from DCOracle2 import *

# For parsing of properties file
import cElementTree as ElementTree

from NDG.X509 import *
from NDG.AttAuthority import AAUserRoles
from NDG.AttAuthority import AAUserRolesError


class BODCUserRoles(AAUserRoles):
    """User Roles class dynamic import for BODC Attribute Authority"""

    # valid configuration property keywords
    __validKeys = [ 'userName', 'dbAddr']
		    
		    
    def __init__(self, propFilePath=None):
    
    	self.__db = None

	if propFilePath:
	    prop = self.readProperties(propFilePath)
	    self.connect(prop['userName'], prop['dbAddr'])
	

    def readProperties(self, propFilePath):

        """Read the configuration properties for the Attribute Authority

        propFilePath: file path to properties file
        """
        
        try:
            tree = ElementTree.parse(propFilePath)
            
        except IOError, ioErr:
            raise AAUserRolesError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror))

        
        prop = tree.getroot()

        # Copy properties from file as member variables
        userRolesProp = \
		dict([(elem.tag, elem.text.strip()) for elem in prop])


        # Check for missing properties
        propKeys = userRolesProp.keys()
        missingKeys = [key for key in BODCUserRoles.__validKeys \
                       if key not in propKeys]
        if missingKeys != []:
            raise AAUserRolesError("The following properties are " + \
                                    "missing from the properties file: " + \
                                    ', '.join(missingKeys))

	return userRolesProp
	
	
	

    def connect(self, 
		userName,
		dbAddr, 
		passPhrase=None,
		prompt=None):
    	"""Connect to database
	
	If no passphrase is given prompt from stdin"""
	
	
	if not passPhrase:
	    if not prompt:
	    	prompt = "Database Passphrase: "
		
	    import getpass
            passPhrase = getpass.getpass(prompt=prompt)


        try:
	    self.__db = connect("%s/%s@%s" % (userName, passPhrase, dbAddr))
	    self.__cursor = self.__db.cursor()
	    
	except Exception, e:
	    raise AAUserRolesError(\
	    	"Error connecting to database \"%s\": %s" % (dbAddr, e))
		
	
    def usrIsRegistered(self, dn):
    	"""Check user with given Distinguished Name is registered with 
	BODC database"""
	
    	try:
	    emailAddr = X500DN(dn)['CN']
	    query = "<BODC Database query>"
            self.__cursor.execute(query, emailAddr)

	    if self.__cursor.fetchall():
	    	return True
	    else:
	        return False
		
	except Exception, e:
	    raise AAUserRolesError(\
	    	"Error checking user \"%s\" is registered: %s" % (dn, e))


    def getRoles(self, dn):
        """Retrieve roles from user with given Distinguished Name"""
	try:
	    emailAddr = X500DN(dn)['CN']
	    query = "<BODC Database query>"
            self.__cursor.execute(query, emailAddr)
	    roles = self.__cursor.fetchall()
	    return [i[0] for i in roles]
	    
	except Exception, e:
	    raise AAUserRolesError(\
	    "Error getting roles for user \"%s\" is registered: %s" % (dn, e))
