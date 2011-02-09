"""NDG Attribute Authority User Roles class - acts as an interface between
the data centre's user roles configuration and the Attribute Authority
                                                                                
NERC Data Grid Project
                                                                                
P J Kershaw 29/07/05
                                                                                
Copyright (C) 2005 CCLRC & NERC
                                                                                
This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
cvsID = '$Id'


from AttAuthority import AAUserRoles


class TestUserRoles(AAUserRoles):
    """Test User Roles class dynamic import for Attribute Authority"""

    def __init__(self, propertiesFilePath=None):
        pass


    def usrIsRegistered(self, dn):
        return True


    def getRoles(self, dn):
        return ['staff', 'postdoc', 'undergrad'] 
