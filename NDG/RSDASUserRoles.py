"""NDG Attribute Authority User Roles class for RSDAS - acts as an interface
between RSDAS user database and the Attribute Authority

converted from BODC example, Mike Grant, 10/Aug/2006.

NERC Data Grid Project

P J Kershaw 09/09/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
 # postgresql interface
from psycopg import *

# For parsing of properties file
import cElementTree as ElementTree

from NDG.X509 import *
from NDG.AttAuthority import AAUserRoles
from NDG.AttAuthority import AAUserRolesError


class RSDASUserRoles(AAUserRoles):
    """User Roles class dynamic import for RSDAS Attribute Authority"""

    # valid configuration property keywords
    __validKeys = [ 'userName', 'dbName', 'host', 'passPhrase']
                    
                    
    def __init__(self, propFilePath=None):
    
        self.__db = None

        if propFilePath:
            prop = self.readProperties(propFilePath)
            self.connect( prop['userName'], prop['dbName'], prop['host'], prop['passPhrase'] )
        

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
        missingKeys = [key for key in RSDASUserRoles.__validKeys \
                       if key not in propKeys]
        if missingKeys != []:
            raise AAUserRolesError("The following properties are " + \
                                    "missing from the properties file: " + \
                                    ', '.join(missingKeys))

        return userRolesProp
        
        
        

    def connect(self, 
                userName,
                dbName,
                host,
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
            self.__db = connect("host=%s dbname=%s user=%s password=%s" % (host, dbName, userName, passPhrase))
            self.__cursor = self.__db.cursor()
            
        except Exception, e:
            raise AAUserRolesError(\
                "Error connecting to database \"%s\": %s" % (dbName, e))
                
        
    def usrIsRegistered(self, dn):
        """Check user with given Distinguished Name is registered with 
        RSDAS database"""
        
        try:
            RSDAS_userid = X500DN(dn)['CN']
            query = "SELECT username FROM user_table WHERE username=%s"
            self.__cursor.execute(query, [RSDAS_userid])

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
            RSDAS_userid = X500DN(dn)['CN']

             # fetch all the shared agreements this user is in
            query = "SELECT sa_desc FROM shared_agreement WHERE sa_name IN (SELECT DISTINCT sa_name FROM web_sa WHERE web_sa.username=%s)"
            self.__cursor.execute(query, [RSDAS_userid])
            shared_agreement_descriptions = self.__cursor.fetchall()

             # return only the NDG shared agreements, as indicated by text in their description (ick!)
             # hopefully this'll get nicer when the authentication systems here change
            roles=[]
            for desc in shared_agreement_descriptions:
               if desc[0].startswith("NDG role:"):
                  roles.append(desc[0][9:])

            return roles
            
        except Exception, e:
            raise AAUserRolesError(\
            "Error getting roles for user \"%s\": %s" % (dn, e))


