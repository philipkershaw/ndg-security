"""Example resource interface class for NDG Gatekeeper.

NERC Data Grid Project

P J Kershaw 19/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
reposID = '$Id$'

from NDG.Gatekeeper import *


#_____________________________________________________________________________
class TestGatekeeperResrc(GatekeeperResrc):
    """Example class to define the resource -> role interface 
    for the Gatekeeper."""

    # User defined class may wish to specify a URI or path for a configuration
    # file
    def __init__(self, resrcID=None, filePath=None):
        """Resource role interface to Gatekeeper"""
        
        self.__resrcID = resrcID
        self.__filePath = filePath
        
        # Example roles and permissions for this resource -
        # In practice, roles and permissions may be derived from the resource
        # itself id'd by resrcID
        self.__permissionsLUT = {    'ecmwfop': ('r'), 
                                     'ecmwfopAdmin': ('r', 'w'),
                                     'pum': ('w', 'x')    }
    
    
    def getPermissions(self, role):
        """Return the permissions for the resource role.  Format is a tuple 
        e.g.
            
        ('r', 'w', 'x'): read, write and execute permission granted for this
                         role
        ():              access denied
        ('r',):          read only access
        ('r', 'x'):      read and execute permission granted"""
        
        try:
            return self.__permissionsLUT[role]
        except:
            # Role is not recognised - return empty permissions tuple
            return ()


    def readAccess(self, role):
        """Return boolean for read access granted/denied for input role"""
        try:
            return 'r' in self.__permissionsLUT[role]
        except:
            # Role is not recognised
            return False
        


    def writeAccess(self, role):
        """Return boolean for write access granted/denied for input role"""
        try:
            return 'w' in self.__permissionsLUT[role]
        except:
            # Role is not recognised
            return False


    def executeAccess(self, role):
        """Return boolean for execute access granted/denied for input role"""
        try:
            return 'x' in self.__permissionsLUT[role]
        except:
            # Role is not recognised
            return False
            