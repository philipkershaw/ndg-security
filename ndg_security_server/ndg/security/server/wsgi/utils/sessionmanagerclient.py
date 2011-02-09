"""NDG Security

Client interface to Session Manager for WSGI based applications

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import sys
import os

from ndg.security.server.wsgi.utils.clientbase import WSGIClientBase
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
    UserSessionExpired, UserSessionNotBeforeTimeError, \
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
SessionNotBeforeTimeError = (UserSessionNotBeforeTimeError, 
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
    
class WSGISessionManagerClient(WSGIClientBase):
    """Client interface to Session Manager for WSGI based applications
    
    This class wraps the SOAP based web service client and alternate access to
    a Session Manager instance in the same code stack available via an environ
    keyword
    
    @type defaultEnvironKeyName: basestring
    @cvar defaultEnvironKeyName: default WSGI environ keyword name for 
    reference to a local Session Manager instance.  Override with the 
    environKeyName keyword to __init__
    
    @type attributeAuthorityEnvironKeyName: basestring
    @cvar attributeAuthorityEnvironKeyName: default WSGI environ keyword name 
    for reference to a local Attribute Authority instance used in calls to 
    getAttCert().  Override with the attributeAuthorityEnvironKeyName keyword 
    to __init__
    """
    defaultEnvironKeyName = "ndg.security.server.wsgi.sessionManagerFilter"
    attributeAuthorityEnvironKeyName = \
        WSGIAttributeAuthorityClient.defaultEnvironKeyName
        
    _getLocalClient = lambda self:self._environ[
                                    self.environKeyName].serviceSOAPBinding.sm
                                    
    localClient = property(fget=_getLocalClient, 
                           doc="local session manager instance")

    
    def __init__(self, 
                 environKeyName=None, 
                 attributeAuthorityEnvironKeyName=None,
                 environ={}, 
                 **clientKw):
        """Initialise an interface to a Session Manager accessible either via a
        keyword to a WSGI environ dictionary or via a web service call
        
        @type environKeyName: basestring or None
        @param environKeyName: dict key reference to service object to be 
        invoked.  This may be set later using the environKeyName property
        or may be omitted altogether if the service is to be invoked via a
        web service call
        @type environ: dict
        @param environ: WSGI environment dictionary containing a reference to
        the service object.  This may not be known at instantiation of this
        class.  environ is not required if the service is to be invoked over
        a web service interface
        @type clientKw: dict
        @param clientKw: custom keywords to instantiate a web service client
        interface.  Derived classes are responsible for instantiating this
        from an extended version of this __init__ method.
        """
 
        log.debug("WSGISessionManagerClient.__init__ ...")
        
        self.environKeyName = environKeyName or \
                               WSGISessionManagerClient.defaultEnvironKeyName
                               
        self._attributeAuthorityEnvironKeyName = \
                    attributeAuthorityEnvironKeyName or \
                    WSGISessionManagerClient.attributeAuthorityEnvironKeyName
                        
        # Standard WSGI environment dict
        self._environ = environ
        
        if clientKw.get('uri'):
            self.wsClient = SessionManagerClient(**clientKw)
        else:
            self.wsClient = None

   
    def connect(self, username, **kw):
        """Request a new user session from the Session Manager
        
        @type username: string
        @param username: the username of the user to connect
        """
    
        if self.localClientInEnviron:
            log.debug("Connecting to local Session Manager instance")
            if 'username' in kw:
                raise TypeError("connect() got an unexpected keyword argument "
                                "'username'")
                
            # Connect to local instance
            res = self.localClient.connect(username=username, **kw)
            
        elif self.wsClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            log.debug("Connecting to remote Session Manager service")
            
            # Filter out keywords which apply to a Session Manager local 
            # instance call
            kw.pop('userX509Cert', None)
            
            # Make connection to remote service
            res = self.wsClient.connect(username, **kw)
    
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
        if self.localClientInEnviron:
            if 'userDN' in kw:
                log.warning('Removing keyword "userDN": this is not supported '
                            'for calls to ndg.security.server.sessionmanager.'
                            'SessionManager.deleteUserSession')
                kw.pop('userX509Cert', None)
                
            self.localClient.deleteUserSession(**kw)
            
        elif self.wsClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            if 'userX509Cert' in kw:
                kw['userDN'] = kw.pop('userX509Cert').dn
                
            self.wsClient.disconnect(**kw)
        
    
    def getSessionStatus(self, **kw):
        """Check for the existence of a session with a given
        session ID / user certificate Distinguished Name
                               
        @type **kw: dict
        @param **kw: disconnect keywords applicable to 
        ndg.security.server.sessionmanager.SessionManager.getSessionStatus and
        ndg.security.common.sessionmanager.SessionManagerClient.getSessionStatus
        the SOAP client"""
    
        if self.localClientInEnviron:
            return self.localClient.getSessionStatus(**kw)
        
        elif self.wsClient is None:            
            raise WSGISessionManagerClientConfigError("No reference to a "
                        "local Session Manager is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            return self.wsClient.getSessionStatus(**kw)
    


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
        
        if self.localClientInEnviron:
            # Connect to local instance of Session Manager - next check for 
            # an Attribute Authority URI or instance running locally
            if kw.get('attributeAuthorityURI') is None and \
               kw.get('attributeAuthority') is None:
                wsgiAttributeAuthorityClient = WSGIAttributeAuthorityClient(
                                environ=self._environ,
                                environKeyName=self._attributeAuthorityEnvironKeyName)

                if wsgiAttributeAuthorityClient.localClientInEnviron:
                    kw['attributeAuthority'] = wsgiAttributeAuthorityClient.ref
                else:
                    raise WSGISessionManagerClientConfigError(
                        "No Attribute Authority URI or server object has been "
                        "set and no reference is available in environ")
                    
            return self.localClient.getAttCert(**kw)
    
        elif self.wsClient is None:            
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

            return self.wsClient.getAttCert(**kw)