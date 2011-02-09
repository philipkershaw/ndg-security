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


class UserRoles(AAUserRoles):
    """User Roles class dynamic import for Attribute Authority.  Customize
    according to your site's user role allocation system"""

    def __init__(self, propertiesFilePath=None):
        """Customize for example to initialise site user repository settings
        
        @type propertiesFilePath: string
        @param propertiesFilePath: file path to a properties from which
        to initialise the user roles interface. e.g. the file could contain
        user database settings.  The file path passed corresponds to the 
        userRolesPropFile element in the attAuthorityProperties.xml file.
        """
        pass


    def userIsRegistered(self, userId):
        """Convenience method NOT used by Attribute Authority API

        @type userId: string
        @param userId: identity of user to allocate roles to
        @rtype: bool
        @return: True if user is registered"""
        return False
    

    def getRoles(self, userId):
        """Allocate required roles to user given by userId.  Default to safe
        option of returning no user roles i.e. an empty list: []
        
        @type userId: string
        @param userId: identity of user to allocate roles to
        @rtype: list
        @return: roles to which user is entitled"""
        
        # Put in HERE some conditional statement to allocate roles based on 
        # the userId input. e.g. database query
        return [] 