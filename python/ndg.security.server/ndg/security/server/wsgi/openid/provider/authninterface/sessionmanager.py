"""NDG Security OpenID Authentication Interface to a Session Manager.

This enables an OpenID Provider's signin to link to a Session Manager running
in the same WSGI stack or else running as a separate service via the Session
Manager SOAP interface

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
from string import Template
from sqlalchemy import create_engine

from ndg.security.server.wsgi.openid.provider import AbstractAuthNInterface, \
    AuthNInterfaceConfigError, AuthNInterfaceInvalidCredentials, \
    AuthNInterfaceUsername2IdentifierMismatch
    
from ndg.security.server.wsgi.utils.sessionmanagerclient import \
    WSGISessionManagerClient, AuthNServiceInvalidCredentials
    
    
class SessionManagerOpenIDAuthNInterface(AbstractAuthNInterface):
    '''Authentication interface class for OpenIDProviderMiddleware to enable
    authentication to a Session Manager instance running in the same WSGI
    stack or via a SOAP call to a remote service
    
    @type dbParamNames: tuple
    @cvar dbParamNames: permitted config keywords.  Nb. SQL queries takes
    String Template style '$' substitutions for username, password and OpenID
    identifier'''
    
    dbParamNames = (
        'connectionString',
        'logonSQLQuery', 
        'userIdentifiersSQLQuery')
    
    def __init__(self, **prop):
        """Make any initial settings
        
        Settings are held in a dictionary which can be set from **prop,
        a call to setProperties() or by passing settings in an XML file
        given by propFilePath
        
        @type **prop: dict
        @param **prop: set properties via keywords 
        @raise AuthNInterfaceConfigError: error with configuration
        """
        try:
            for name in SessionManagerOpenIDAuthNInterface.dbParamNames:
                setattr(self, name, prop.pop(name))
                
        except KeyError, e:
            raise AuthNInterfaceConfigError("Missing property setting for "
                                            "database connection: %s" % e)

        self._client = WSGISessionManagerClient(**prop)
        
        
    def logon(self, environ, userIdentifier, username, password):
        """Interface login method
        
        @type environ: dict
        @param environ: standard WSGI environ parameter
        
        @type username: basestring
        @param username: user identifier
        
        @type password: basestring
        @param password: corresponding password for username givens
        
        @raise AuthNInterfaceUsername2IdentifierMismatch: no OpenID identifiers
        match the given username
        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        """
        if userIdentifier is not None:
            # Check for a match between the OpenID user identifier and the 
            # username
            try:
                dbEngine = create_engine(self.connectionString)
                connection = dbEngine.connect()
            except Exception, e:
                log.error('Connecting database for user logon query : %s' % e)
                raise
            
            try:
                try:
                    queryInputs = dict(username=username,
                                       userIdentifier=userIdentifier)
                    query=Template(self.logonSQLQuery).substitute(queryInputs)
                    result = connection.execute(query)
                except Exception, e:
                    log.error('Connecting database for user logon query : %s' %
                              e)
                    raise
                
                if not result.rowcount:
                    raise AuthNInterfaceUsername2IdentifierMismatch()
            finally:
                connection.close()
        
        try:
            self._client.environ = environ
            self._client.connect(username, passphrase=password)
            
        except AuthNServiceInvalidCredentials, e:
            log.exception(e)
            raise AuthNInterfaceInvalidCredentials()
        
    
    def username2UserIdentifiers(self, environ, username):
        """Map the login username to an identifier which will become the
        unique path suffix to the user's OpenID identifier.  The 
        OpenIDProviderMiddleware takes self.urls['id_url'] and adds it to this
        identifier:
        
            identifier = self._authN.username2UserIdentifiers(username)
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
            dbEngine = create_engine(self.connectionString)
            connection = dbEngine.connect()
        except Exception, e:
            log.error('Connecting database for user identifiers query : %s'%e)
            raise
            
        try:
            try:
                tmpl = Template(self.userIdentifiersSQLQuery)
                sqlQuery = tmpl.substitute(dict(username=username))
                result = connection.execute(sqlQuery)
                if not result.rowcount:
                    raise AuthNInterfaceRetrieveError()
                
                userIdentifiers = tuple([row.values()[0] for row in result])
            except Exception, e:
                log.error('Querying database for user identifiers for user '
                          '"%s": %s' (username, e))
                raise
        finally:
            connection.close()
            
        return userIdentifiers
