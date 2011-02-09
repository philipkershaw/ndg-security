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

# Alter system path for dynamic import of resource interface class
import sys

# Expand environment vars in paths
import os

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
    
    __validKeys = ( 'resrcID',
                    'resrcModFilePath',
                    'resrcModName',
                    'resrcClassName',
                    'resrcPropFile',
                    'caCertFilePath')
    
    #_________________________________________________________________________
    def __init__(self, propFilePath=None, **prop):
         
        self.__propFilePath = propFilePath               
        self.__resrcObj = None
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
            self.initResrcinterface()
       
        
    #_________________________________________________________________________
    def initResrcinterface(self):
        """Set-up Resource URI interface to Gatekeeper"""
        
        try:
            try:
                # Temporarily extend system path ready for import
                sysPathBak = sys.path[:]
                sys.path.append(self.__prop['resrcModFilePath'])
                
                # Import module name specified in properties file
                resrcMod = __import__(self.__prop['resrcModName'],
                                      globals(),
                                      locals(),
                                      [self.__prop['resrcClassName']])
    
                resrcClass = eval('resrcMod.' + self.__prop['resrcClassName'])
                
            finally:
                sys.path[:] = sysPathBak
                                
        except KeyError, e:
            raise GatekeeperError(\
                'Importing Resource URI module, key not recognised: %s' % e)
                                
        except Exception, e:
            raise GatekeeperError('Importing Resource URI module: %s' % e)


        # Check class inherits from GatekeeperResrc abstract base class
        if not issubclass(resrcClass, GatekeeperResrc):
            raise GatekeeperError, \
                "Resource interface class %s must be derived from " % \
                self.__prop['resrcClassName'] + "GatekeeperResrc"


        # Instantiate custom class
        try:
            self.__resrcObj = resrcClass(\
                                    resrcID=self.__prop['resrcID'],
                                    filePath=self.__prop['resrcPropFile'])            
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
                raise GatekeeperError("Input Properties file path " + \
                                        "must be a valid string.")
            
            self.__propFilePath = propFilePath


        try:
            elems = ElementTree.parse(self.__propFilePath).getroot()
            
        except IOError, ioErr:
            raise GatekeeperError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror))
                                
        # Copy properties from file as dictionary
        #
        # Nb. # Allow for environment variables in paths
        self.__prop.update(dict([(elem.tag, 
                                  os.path.expandvars(elem.text.strip())) \
                                 for elem in elems if elem.text is not None]))


        # Check for missing properties
        propKeys = self.__prop.keys()
        missingKeys = [key for key in Gatekeeper.__validKeys \
                       if key not in propKeys]
        if missingKeys != []:
            raise GatekeeperError("The following properties are " + \
                                  "missing from the properties file: " + \
                                  ', '.join(missingKeys))


    def __formatInput(self, input):
        """Convert generic input into a list of roles - use with access
        routines"""
        
        if isinstance(input, list):
            # Input is list of roles
            return input
              
        elif isinstance(input, basestring):
            # Input is a role
            return [input]
            
        elif isinstance(input, AttCert):
            # Input is an Attribute Certificate
            # Check signature of AttCert
            try:
                input.isValid(raiseExcep=True, 
                            certFilePathList=self.__prop['caCertFilePath'])                            
            except Exception, e:
                raise GatekeeperError, "Access denied for input: %s" % str(e)
            
            return input.getRoles()
        else:
            raise GatekeeperError("Input must be a role, role list or " + \
                                  "Attribute Certificate type")

   
    #_________________________________________________________________________
    def __call__(self, input):
        """Get the permissions for the input rile, list of roles or 
        Attribute Certificate containing roles.  A Dictionary of permissions
        are returned indexed by role name.  Permissions are expressed as a 
        tuple containing the relevant permissions flags e.g. ('r', 'w', 'x')
        for read/write/execute permission or e.g. ('x') for exceute only
        permission"""
        
        roleList = self.__formatInput(input)
                                      
        return dict([(role, self.__resrcObj.getPermissions(role)) \
                     for role in roleList])
        
    
    getPermissions = __call__
    
    
    #_________________________________________________________________________
    def readAccess(self, input):
        """Determine read access permitted against the given
        input role/role list or Attribute Certificate roles
        
        Return a dictionary of booleans for access granted/denied keyed
        by role name"""
        
        roleList = self.__formatInput(input)
        
        return dict([(role, self.__resrcObj.readAccess(role)) \
                     for role in roleList])
    
    
    #_________________________________________________________________________
    def writeAccess(self, input):
        """Determine write access permitted against the given
        input role/role list or Attribute Certificate roles
        
        Return a dictionary of booleans for access granted/denied keyed
        by role name"""
        
        roleList = self.__formatInput(input)
        
        return dict([(role, self.__resrcObj.writeAccess(role)) \
                     for role in roleList])
    
    
    #_________________________________________________________________________
    def executeAccess(self, input):
        """Determine execute access permitted against the given
        input role/role list or Attribute Certificate roles
        
        Return a dictionary of booleans for access granted/denied keyed
        by role name"""
        
        roleList = self.__formatInput(input)
        
        return dict([(role, self.__resrcObj.executeAccess(role)) \
                     for role in roleList])
                     

#_____________________________________________________________________________
class GatekeeperResrcError(GatekeeperError):
    """Exception handling for NDG Gatekeeper Resource interface class
    class."""
    pass


#_____________________________________________________________________________
class GatekeeperResrc:
    """An abstract base class to define the resource -> role interface 
    for the Gatekeeper.

    Each NDG resource should implement a derived class which implements
    the way a resource roles is served from the given resource."""

    # User defined class may wish to specify a URI or path for a configuration
    # file
    def __init__(self, resrcID=None, filePath=None):
        """Abstract base class - derive from this class to define
        resource role interface to Gatekeeper"""
        raise NotImplementedError(\
            self.__init__.__doc__.replace('\n       ',''))
    

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


    def readAccess(self, role):
        """Derived method should return the role for read access to the 
        resource - should return boolean for access granted/denied"""
        raise NotImplementedError(
            self.readAccess.__doc__.replace('\n       ',''))


    def writeAccess(self, role):
        """Derived method should return the role for write access to the 
        resource - should return boolean for access granted/denied"""
        raise NotImplementedError(
            self.writeAccess.__doc__.replace('\n       ',''))


    def executeAccess(self, role):
        """Derived method should return the role for execute access to the 
        resource - should return boolean for access granted/denied"""
        raise NotImplementedError(
            self.executeAccess.__doc__.replace('\n       ',''))
    
            