"""NDG Security Basic OpenID Authentication Interface.

A demonstration implementation of an authentication interface for 
OpenIDProviderMiddleware WSGI.  Username/password and OpenId user identifier
details are read from a config file and passed as keywords.  This class is not 
intended for production use.

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "01/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ndg.security.server.wsgi.openid.provider import AbstractAuthNInterface
 
    
class BasicAuthNInterface(AbstractAuthNInterface):
    '''Basic Authentication interface class for OpenIDProviderMiddleware 
    
    it uses username/password details retrieved from config file / keyword
    entry.  This class is for testing only.  NOT for production use'''
    
    def __init__(self, **prop):
        """Make any initial settings
        
        Settings are held in a dictionary which can be set from **prop,
        a call to setProperties() or by passing settings in an XML file
        given by propFilePath
        
        @type **prop: dict
        @param **prop: set properties via keywords 
        @raise AuthNInterfaceConfigError: error with configuration
        """
        # Test/Admin username/password set from ini/kw args
        userCreds = prop.get('userCreds')
        if userCreds:
            self._userCreds = dict([i.strip().split(':')
                                    for i in userCreds.split(',')])
        else:
            raise AuthNInterfaceConfigError('No "userCreds" config option '
                                            "found")
            
        user2Identifier = prop.get('username2UserIdentifiers')
        if user2Identifier:
            self._username2Identifier = {}
            for i in user2Identifier.split():
                username, identifierStr = i.strip().split(':')
                identifiers = tuple(identifierStr.split(','))
                self._username2Identifier[username] = identifiers
        else:
            raise AuthNInterfaceConfigError('No "user2Identifier" config '
                                            'option found')
        
        userCredNames = self._userCreds.keys()
        userCredNames.sort()
        username2IdentifierNames = self._username2Identifier.keys()
        username2IdentifierNames.sort()
        if userCredNames != username2IdentifierNames:
            raise AuthNInterfaceConfigError('Mismatch between usernames in '
                                            '"userCreds" and '
                                            '"username2UserIdentifiers" '
                                            'options')   
    
    def logon(self, environ, userIdentifier, username, password):
        """Interface login method
        
        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type username: basestring
        @param username: user identifier
        
        @type password: basestring
        @param password: corresponding password for username givens
        
        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        """
        if self._userCreds.get(username) != password:
            raise AuthNInterfaceInvalidCredentials()
        
        if userIdentifier is not None and \
           userIdentifier not in self._username2Identifier.get(username):
            raise AuthNInterfaceUsername2IdentifierMismatch()
    
    def username2UserIdentifiers(self, environ, username):
        """Map the login username to an identifier which will become the
        unique path suffix to the user's OpenID identifier.  The 
        OpenIDProviderMiddleware takes self.urls['id_url'] and adds it to this
        identifier:
        
            identifier = self._authN.username2UserIdentifiers(environ,username)
            identityURL = self.urls['url_id'] + '/' + identifier
        
        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type username: basestring
        @param username: user identifier
        
        @rtype: tuple
        @return: identifiers to be used to make OpenID user identity URLs. 
        
        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to identifier e.g. error with database look-up.
        """
        try:
            return self._username2Identifier[username]
        except KeyError:
            raise AuthNInterfaceRetrieveError('No entries for "%s" user' % 
                                              username)
