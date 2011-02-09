"""NDG Security

Client interface to Session Manager for WSGI based applications

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "27/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
log = logging.getLogger(__name__)

import sys
import os

from ndg.security.server.wsgi.utils.attributeauthorityclient import \
    WSGIAttributeAuthorityClient

# Session Manager Authentication interface ...
from ndg.security.server.sessionmanager import AuthNServiceError, \
    AuthNServiceInvalidCredentials, AuthNServiceRetrieveError, \
    AuthNServiceInitError, AuthNServiceConfigError

# Session Manager SOAP client interface
from ndg.security.common.sessionmanager import SessionManagerClient
    
# Import exception types from Session Manager and Session Manager client to
# give caller some capability to trap errors
# Session Manager server side exceptions ...
from ndg.security.server.sessionmanager import SessionManagerError, \
    UserSessionExpired, UserSessionX509CertNotBeforeTimeError, \
    InvalidUserSession, CredentialWalletAttributeRequestDenied
    
from ndg.security.server.sessionmanager import SessionNotFound as \
    _SrvSessionNotFound

# ... and client side exceptions ...
from ndg.security.common.sessionmanager import SessionNotFound as \
    _ClntSessionNotFound

from ndg.security.common.sessionmanager import SessionExpired as \
    _ClntSessionExpired

from ndg.security.common.sessionmanager import InvalidSession as \
    _ClntInvalidSession
  
from ndg.security.common.sessionmanager import AttributeRequestDenied as \
    _ClntAttributeRequestDenied
     
from ndg.security.common.sessionmanager import InvalidSessionManagerClientCtx,\
    SessionManagerClientError, SessionCertTimeError

SessionNotFound = (_SrvSessionNotFound, _ClntSessionNotFound)

# Combine client and server session not before time error exceptions to 
# enable easier exception handling for a WSGISessionManagerClient caller.  
# See SessionNotFound.__doc__ for more details of reasoning
SessionNotBeforeTimeError = (UserSessionX509CertNotBeforeTimeError, 
                             SessionCertTimeError)

# Combine client and server session expired exceptions to enable easier
# exception handling for a WSGISessionManagerClient caller.  See
# SessionNotFound.__doc__ for more details of reasoning
SessionExpired = (UserSessionExpired, _ClntSessionExpired)

# Combine client and server invalid session exceptions to enable easier
# exception handling for a WSGISessionManagerClient caller.  See
# SessionNotFound.__doc__ for more details of reasoning""" 
InvalidSession = (InvalidUserSession, _ClntInvalidSession)
   
# Combine client and server invalid session exceptions to enable easier
# exception handling for a WSGISessionManagerClient caller.  See
# SessionNotFound.__doc__ for more details of reasoning
AttributeRequestDenied = (CredentialWalletAttributeRequestDenied, 
                          _ClntAttributeRequestDenied)

# End of server/client side exception combinations

        
class WSGISessionManagerClientError(Exception):
    """Base class exception for WSGI Session Manager client errors"""
    
class WSGISessionManagerClientConfigError(WSGISessionManagerClientError):
    """Configuration error for WSGI Session Manager Client"""
    
class WSGISessionManagerClient(object):
    """Client interface to Session Manager for WSGI based applications
    
    This class wraps the SOAP based web service client and alternate access to
    a Session Manager instance in the same code stack available via an environ
    keyword
    
    @type environKey: basestring
    @cvar environKey: default WSGI environ keyword name for reference to a 
    local Session Manager instance.  Override with the environKey keyword to 
    __init__
    
    @type attributeAuthorityEnvironKey: basestring
    @cvar attributeAuthorityEnvironKey: default WSGI environ keyword name for 
    reference to a local Attribute Authority instance used in calls to 
    getAttCert().  Override with the attributeAuthorityEnvironKey keyword to
    __init__
    """
    environKey = "ndg.security.server.wsgi.sessionManagerFilter"
    attributeAuthorityEnvironKey = WSGIAttributeAuthorityClient.environKey
    
    _refInEnviron = lambda self: self._environKey in self._environ
    
    # Define as property for convenient call syntax
    refInEnviron = property(fget=_refInEnviron,
                            doc="return True if a Session Manager instance is "
                                "available in WSGI environ")
    
    _getRef = lambda self:self._environ[self._environKey].serviceSOAPBinding.sm
    ref = property(fget=_getRef, doc="Session Manager local instance")

    
    def __init__(self, 
                 environKey=None, 
                 attributeAuthorityEnvironKey=None,
                 environ={}, 
                 **soapClientKw):
 
        log.debug("WSGISessionManagerClient.__init__ ...")
        
        self._environKey = environKey or WSGISessionManagerClient.environKey
        self._attributeAuthorityEnvironKey = attributeAuthorityEnvironKey or \
                        WSGISessionManagerClient.attributeAuthorityEnvironKey
                        
        # Standard WSGI environment dict
        self._environ = environ
        
        if soapClientKw.get('uri'):
            self._soapClient = SessionManagerClient(**soapClientKw)
        else:
            self._soapClient = None
    
    def _setEnviron(self, environ):
        if not isinstance(environ, dict):
            raise TypeError("Expecting dict type for 'environ' property")
        self._environ = environ
        
    def _getEnviron(self, environ):
        return self._environ
    
    environ = property(fget=_getEnviron, 
                       fset=_setEnviron, 
                       doc="WSGI environ dictionary")
    
    def connect(self, username, **kw):
        """Request a new user session from the Session Manager
        
        @type username: string
        @param username: the username of the user to connect
        """
    
        if self.refInEnviron:
            log.debug("Connecting to local Session Manager instance")
            if 'username' in kw:
                raise TypeError("connect() got an unexpected keyword argument "
                                "'username'")
                
            # Connect to local instance
            res = self.ref.connect(username=username, **kw)
            
        elif self._soapClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            log.debug("Connecting to remote Session Manager service")
            
            # Filter out keywords which apply to a Session Manager local 
            # instance call
            kw.pop('userX509Cert', None)
            
            # Make connection to remote service
            res = self._soapClient.connect(username, **kw)
    
            # Convert from unicode because unicode causes problems with
            # M2Crypto private key load
            res = tuple([isinstance(i,unicode) and str(i) or i for i in res])
            
        return res
    
    
    def disconnect(self, **kw):
        """Delete an existing user session from the Session Manager
        
        @type **kw: dict
        @param **kw: disconnect keywords applicable to 
        ndg.security.server.sessionmanager.SessionManager.getSessionStatus and
        ndg.security.common.sessionmanager.SessionManagerClient.getSessionStatus
        the SOAP client"""
    
        # Modify keywords according to correct interface for server side /
        # SOAP client
        if self.refInEnviron:
            if 'userDN' in kw:
                log.warning('Removing keyword "userDN": this is not supported '
                            'for calls to ndg.security.server.sessionmanager.'
                            'SessionManager.deleteUserSession')
                kw.pop('userX509Cert', None)
                
            self.ref.deleteUserSession(**kw)
            
        elif self._soapClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            if 'userX509Cert' in kw:
                kw['userDN'] = kw.pop('userX509Cert').dn
                
            self._soapClient.disconnect(**kw)
        
    
    def getSessionStatus(self, **kw):
        """Check for the existence of a session with a given
        session ID / user certificate Distinguished Name
                               
        @type **kw: dict
        @param **kw: disconnect keywords applicable to 
        ndg.security.server.sessionmanager.SessionManager.getSessionStatus and
        ndg.security.common.sessionmanager.SessionManagerClient.getSessionStatus
        the SOAP client"""
    
        if self.refInEnviron:
            return self.ref.getSessionStatus(**kw)
        
        elif self._soapClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            return self._soapClient.getSessionStatus(**kw)
    


    def getAttCert(self, **kw):
        """Request NDG Session Manager to retrieve an Attribute
        Certificate from the given Attribute Authority and cache it in the
        user's credential wallet held by the session manager.
        
        @type **kw: dict
        @param **kw: disconnect keywords applicable to 
        ndg.security.server.sessionmanager.SessionManager.getAttCert and
        ndg.security.common.sessionmanager.SessionManagerClient.getAttCert
        the SOAP client
        """
        
        if self.refInEnviron:
            # Connect to local instance of Session Manager - next check for 
            # an Attribute Authority URI or instance running locally
            if kw.get('attributeAuthorityURI') is None and \
               kw.get('attributeAuthority') is None:
                wsgiAttributeAuthorityClient = WSGIAttributeAuthorityClient(
                                environ=self._environ,
                                environKey=self._attributeAuthorityEnvironKey)

                if wsgiAttributeAuthorityClient.refInEnviron:
                    kw['attributeAuthority'] = wsgiAttributeAuthorityClient.ref
                else:
                    raise WSGISessionManagerClientConfigError(
                        "No Attribute Authority URI or server object has been "
                        "set and no reference is available in environ")
                    
            return self.ref.getAttCert(**kw)
    
        elif self._soapClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            # Filter out keywords which apply to a Session Manager local 
            # instance call
            if 'username' in kw:
                kw.pop('username')
                log.warning('Trying call via SOAP interface: '
                            'removing the "username" keyword '
                            'ndg.security.common.sessionmanager.'
                            'SessionManagerClient.getAttCert doesn\'t support '
                            'this keyword')
                
            if 'refreshAttCert' in kw:
                kw.pop('refreshAttCert')
                log.warning('Trying call via SOAP interface: '
                            'removing the "refreshAttCert" keyword '
                            'ndg.security.common.sessionmanager.'
                            'SessionManagerClient.getAttCert doesn\'t support '
                            'this keyword')
                
            if 'attCertRefreshElapse' in kw:
                kw.pop('attCertRefreshElapse')
                log.warning('Trying call via SOAP interface: '
                            'removing the "attCertRefreshElapse" keyword '
                            'ndg.security.common.sessionmanager.'
                            'SessionManagerClient.getAttCert doesn\'t support '
                            'this keyword')

            return self._soapClient.getAttCert(**kw)