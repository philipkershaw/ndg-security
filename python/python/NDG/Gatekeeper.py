"""NDG Gatekeeper - A PDP (Policy Decision Point) determines whether
a given Attribute Certificate can access a given resource.

NERC Data Grid Project

P J Kershaw 15/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
reposID = '$Id$'

# For parsing of properties file
import cElementTree as ElementTree

# Alter system path for dynamic import of user roles class
import sys

from AttCert import *


#_____________________________________________________________________________
class GatekeeperError(Exception):
    """Exception handling for NDG Gatekeeper class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg

            
#_____________________________________________________________________________
class Gatekeeper(object):
    """NDG Gatekeeper class - determines whether a given Attribute 
    Certificate can access a given resource."""
    
    __validKeys = ( 'resrcURI',
                    'resrcURImodFilePath',
                    'resrcURImodName',
                    'resrcURIclassName',
                    'resrcURIpropFile')
    
    #_________________________________________________________________________
    def __init__(self, propFilePath=None, **prop):
         
        self.__propFilePath = propFilePath               
        self.__resrcURIobj = None
        self.__prop = {}.fromkeys(self.__validKeys)
        
        if propFilePath:
            self.readProperties(propFilePath)
            
        # Any keywords set will override equivalent file property settings
        if prop:
            invalidKeys = [key for key in prop if key not in self.__validKeys]
            if invalidKeys:
                raise GatekeeperError("Invalid property or properties: " + \
                                      ", ".join(invalidKeys))
            self.__prop.update(prop)
            
            
        if max(self.__prop.values()) is not None:
            # Initialize if all required resource URI class properties are set
            self.initResrcURIinterface()
       
        
    #_________________________________________________________________________
    def initResrcURIinterface(self):
        """Set-up Resource URI interface to Gatekeeper"""
        
        try:
            try:
                # Temporarily extend system path ready for import
                sysPathBak = sys.path
                sys.path.append(self.__prop['resrcURImodFilePath'])
                
                # Import module name specified in properties file
                resrcURImod = __import__(self.__prop['resrcURImodName'],
                                         globals(),
                                         locals(),
                                         [self.__prop['resrcURIclassName']])
    
                resrcURIclass = eval('resrcURImod.' + \
                                        self.__prop['resrcURIclassName'])
            finally:
                sys.path = sysPathBak
                                
        except KeyError, e:
            raise GatekeeperError(\
                'Importing Resource URI module, key not recognised: %s' % e)
                                
        except Exception, e:
            raise GatekeeperError('Importing Resource URI module: %s' % e)


        # Check class inherits from GatekeeperResrcURI abstract base class
        if not issubclass(resrcURIclass, GatekeeperResrcURI):
            raise GatekeeperError(\
                "Resource URI interface class %s must be derived from " + \
                "GatekeeperResrcURI" % self.__prop['resrcURIclassName'])


        # Instantiate custom class
        try:
            self.__resrcURIobj = resrcURIclass(\
                                    filePath=self.__prop['resrcURIpropFile'])            
        except Exception, e:
            raise GatekeeperError(\
                "Error instantiating Resource URI interface: " + str(e))


    #_________________________________________________________________________
    def readProperties(self, propFilePath=None):

        """Read the configuration properties for the Attribute Authority

        propFilePath: file path to properties file
        """
        
        if propFilePath is not None:
            if not isinstance(propFilePath, basestring):
                raise AttAuthorityError("Input Properties file path " + \
                                        "must be a valid string.")
            
            self.__propFilePath = propFilePath


        try:
            tree = ElementTree.parse(self.__propFilePath)
            
        except IOError, ioErr:
            raise AttAuthorityError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror))

    
    #_________________________________________________________________________
    def __call__(self, input):
        
        if isinstance(input, basestring):
            # Input is a role
            roleList = [input]
            
        elif isinstance(input, list):
            # Input is list of roles
            roleList = input
            
        elif isinstance(input, AttCert):
            # Input is an Attribute Certificate
            roleList = input.getRoles()
        else:
            raise GatekeeperError("Input must be a role, role list or " + \
                                  "Attribute Certificate type")
                                  
                                      
        return dict([(role, self.__resrcURIobj.getPermissions(role)) \
                     for role in roleList])
        
    
    getPermissions = __call__



#_____________________________________________________________________________
class GatekeeperResrcURIError(Exception):
    """Exception handling for NDG Attribute Authority User Roles interface
    class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg



#_____________________________________________________________________________
class GatekeeperResrcURI:
    """An abstract base class to define the resource URI -> role interface 
    for the Gatekeeper.

    Each NDG resource should implement a derived class which implements
    the way a resource roles is served from the given resource URI."""

    # User defined class may wish to specify a URI or path for a configuration
    # file
    def __init__(self, uri=None, filePath=None):
        """Roles abstract base class - derive from this class to define
        resource role interface to Gatekeeper"""
        raise NotImplementedError(\
            self.__init__.__doc__.replace('\n       ',''))


    def __getRole(self):
        """Derived method should return the role for the resource
        This method is not essential to interface with GateKeeper class"""
        raise NotImplementedError(
            self.__getRole.__doc__.replace('\n       ',''))
    
    role = property(fget=__getRole, doc="Access resource access role")
    

    def getPermissions(self, role):
        """Derived method should return the permissions for the given resource
        role.  Format is a tuple e.g.
            
        ('r', 'w', 'x'): read, write and execute permission granted for this
                         role
        ():              access denied
        ('r',):          read only access
        ('r', 'x'):      read and execute permission granted
        
        This method is needed for the interface to the Gatekeeper class"""
        raise NotImplementedError(
            self.__getPermissions.__doc__.replace('\n       ',''))
