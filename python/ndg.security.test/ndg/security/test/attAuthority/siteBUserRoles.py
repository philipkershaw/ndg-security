"""NDG Attribute Authority User Roles class - acts as an interface between
the data centre's user roles configuration and the Attribute Authority
                                                                                
NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/07/05"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'


from ndg.security.server.AttAuthority import AAUserRoles


class TestUserRoles(AAUserRoles):
    """Test User Roles class dynamic import for Attribute Authority"""

    def __init__(self, propertiesFilePath=None):
        pass


    def userIsRegistered(self, userId):
        return False


    def getRoles(self, userId):
        # Make so that Site B never returns any roles - the only way to
        # get an Attribute Certificate is then through the role mapping
        return [] 
