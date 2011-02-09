"""Session handling middleware module

Refactored authn module moving session specific code to here
 
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/01/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ndg.security.server.wsgi import (NDGSecurityMiddlewareBase,
                                      NDGSecurityMiddlewareError)


class SessionMiddlewareBase(NDGSecurityMiddlewareBase):
    """Base class for Authentication redirect middleware and Session Handler
    middleware
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: valid configuration property keywords 
    """   
    propertyDefaults = {
        'sessionKey': 'beaker.session.ndg.security'
    }

    # Key names for PEP context information
    PEPCTX_SESSION_KEYNAME = 'pepCtx'
    PEPCTX_REQUEST_SESSION_KEYNAME = 'request'
    PEPCTX_RESPONSE_SESSION_KEYNAME = 'response'
    PEPCTX_TIMESTAMP_SESSION_KEYNAME = 'timestamp'
   
    _isAuthenticated = lambda self: \
        SessionMiddlewareBase.USERNAME_SESSION_KEYNAME in \
        self.environ.get(self.sessionKey, ())
        
    isAuthenticated = property(fget=_isAuthenticated,
                               doc='boolean to indicate is user logged in')
       

class SessionHandlerMiddlewareError(NDGSecurityMiddlewareError):
    """Base exception for SessionHandlerMiddleware"""
            
            
class SessionHandlerMiddlewareConfigError(SessionHandlerMiddlewareError):
    """Configuration errors from SessionHandlerMiddleware"""
    
    
class OpenIdAXConfigError(SessionHandlerMiddlewareError):
    """Error parsing OpenID Ax (Attribute Exchange) parameters"""
    
    
class SessionHandlerMiddleware(SessionMiddlewareBase):
    '''Middleware to:
    - establish user session details following redirect from OpenID Relying 
    Party sign-in or SSL Client authentication
    - end session redirecting back to referrer URI following call to a logout
    URI as implemented in AuthKit
    '''
    AX_SESSION_KEYNAME = 'openid.ax'
    SM_URI_SESSION_KEYNAME = 'sessionManagerURI'
    ID_SESSION_KEYNAME = 'sessionId'
    PEP_CTX_SESSION_KEYNAME = 'pepCtx'
    CREDENTIAL_WALLET_SESSION_KEYNAME = 'credentialWallet'
    
    SESSION_KEYNAMES = (
        SessionMiddlewareBase.USERNAME_SESSION_KEYNAME, 
        SM_URI_SESSION_KEYNAME, 
        ID_SESSION_KEYNAME, 
        PEP_CTX_SESSION_KEYNAME, 
        CREDENTIAL_WALLET_SESSION_KEYNAME
    )
    
    AX_KEYNAME = 'ax'
    SM_URI_AX_KEYNAME = 'value.sessionManagerURI.1'
    SESSION_ID_AX_KEYNAME = 'value.sessionId.1'
    
    AUTHKIT_COOKIE_SIGNOUT_PARAMNAME = 'authkit.cookie.signoutpath'
    SIGNOUT_PATH_PARAMNAME = 'signoutPath'
    SESSION_KEY_PARAMNAME = 'sessionKey'
    propertyDefaults = {
        SIGNOUT_PATH_PARAMNAME: None,
        SESSION_KEY_PARAMNAME: 'beaker.session.ndg.security'
    }
    
    AUTH_TKT_SET_USER_ENVIRON_KEYNAME = 'paste.auth_tkt.set_user'
    
    PARAM_PREFIX = 'sessionHandler.'
    
    def __init__(self, app, global_conf, prefix=PARAM_PREFIX, **app_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        signoutPathParamName = prefix + \
                                SessionHandlerMiddleware.SIGNOUT_PATH_PARAMNAME
        
        if signoutPathParamName not in app_conf:
            authKitSignOutPath = app_conf.get(
                    SessionHandlerMiddleware.AUTHKIT_COOKIE_SIGNOUT_PARAMNAME)
            
            if authKitSignOutPath:
                app_conf[signoutPathParamName] = authKitSignOutPath
                
                log.info('Set signoutPath=%s from "%s" setting', 
                     authKitSignOutPath,
                     SessionHandlerMiddleware.AUTHKIT_COOKIE_SIGNOUT_PARAMNAME)
            else:
                raise SessionHandlerMiddlewareConfigError(
                                        '"signoutPath" parameter is not set')
            
        super(SessionHandlerMiddleware, self).__init__(app,
                                                       global_conf,
                                                       prefix=prefix, 
                                                       **app_conf)
        
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """Manage setting of session from AuthKit following OpenID Relying
        Party sign in and manage logout
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        """
        log.debug("SessionHandlerMiddleware.__call__ ...")
        
        session = environ.get(self.sessionKey)
        if session is None:
            raise SessionHandlerMiddlewareConfigError(
                   'SessionHandlerMiddleware.__call__: No beaker session key '
                   '"%s" found in environ' % self.sessionKey)
        
        if self.signoutPath and self.pathInfo == self.signoutPath:
            log.debug("SessionHandlerMiddleware.__call__: caught sign out "
                      "path [%s]", self.signoutPath)
            
            _start_response = self._doLogout(environ, start_response, session)
        else:
            log.debug("SessionHandlerMiddleware.__call__: checking for "
                      "REMOTE_* environment variable settings set by OpenID "
                      "Relying Party signin...")
            self._setSession(environ, session)

            _start_response = start_response
            
        return self._app(environ, _start_response)
    
    def _doLogout(self, environ, start_response, session):
        """Execute logout action, 
         - clear the beaker session
         - set the referrer URI to redirect back to by setting a custom 
        start_response function which modifies the HTTP header setting the
        location field for a redirect
        
        @param environ: environment dictionary
        @type environ: dict like object
        @type start_response: function
        @param start_response: standard WSGI start response function
        @param session: beaker session
        @type session: beaker.session.SessionObject
        """
            
        # Clear user details from beaker session
        for keyName in self.__class__.SESSION_KEYNAMES:
            session.pop(keyName, None)
        session.save()
        
        referrer = environ.get('HTTP_REFERER')
        if referrer is not None:
            def _start_response(status, header, exc_info=None):
                """Alter the header to send a redirect to the logout
                referrer address"""
                filteredHeader = [(field, val) for field, val in header 
                                  if field.lower() != 'location']        
                filteredHeader.extend([('Location', referrer)])
                return start_response(self.getStatusMessage(302), 
                                      filteredHeader,
                                      exc_info)
                
            return _start_response        
        else:
            log.error('No referrer set for redirect following logout')
            return start_response
        
    def _setSession(self, environ, session):
        """Check for REMOTE_USER and REMOTE_USER_DATA set by authentication
        handlers and set a new session from them if present
        
        @type environ: dict like object
        @param environ: WSGI environment variables dictionary
        @param session: beaker session
        @type session: beaker.session.SessionObject
        """
        
        # Set user id
        if (SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME not in session
            and SessionHandlerMiddleware.USERNAME_ENVIRON_KEYNAME in environ):
            
            log.debug("SessionHandlerMiddleware.__call__: updating session "
                      "username=%s", environ[
                        SessionHandlerMiddleware.USERNAME_ENVIRON_KEYNAME])
            
            session[SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME
                    ] = environ[
                        SessionHandlerMiddleware.USERNAME_ENVIRON_KEYNAME]
            session.save()
            
        # Check for auxiliary user data
        remoteUserData = environ.get(
                        SessionHandlerMiddleware.USERDATA_ENVIRON_KEYNAME, '')    
        if remoteUserData:
            log.debug("SessionHandlerMiddleware.__call__: found "
                      "REMOTE_USER_DATA=%s, set from OpenID Relying Party "
                      "signin", 
                      environ[
                          SessionHandlerMiddleware.USERDATA_ENVIRON_KEYNAME
                      ])
            
            if (SessionHandlerMiddleware.SM_URI_SESSION_KEYNAME not in 
                session or 
                SessionHandlerMiddleware.ID_SESSION_KEYNAME not in session):
                
                # eval is safe here because AuthKit cookie is signed and 
                # AuthKit middleware checks for tampering            
                axData = eval(remoteUserData)
                if (isinstance(axData, dict) and 
                    SessionHandlerMiddleware.AX_KEYNAME in axData):
                    
                    ax = axData[SessionHandlerMiddleware.AX_KEYNAME]
                    
                    # Save attributes keyed by attribute name
                    session[SessionHandlerMiddleware.AX_SESSION_KEYNAME
                            ] = SessionHandlerMiddleware._parseOpenIdAX(ax)
                    
                    log.debug("SessionHandlerMiddleware.__call__: updated "
                              "session with OpenID AX values: %r",
                              session[
                                SessionHandlerMiddleware.AX_SESSION_KEYNAME
                              ])
                        
                    # Save Session Manager specific attributes
                    sessionManagerURI = ax.get(
                            SessionHandlerMiddleware.SM_URI_AX_KEYNAME)
                        
                    session[SessionHandlerMiddleware.SM_URI_SESSION_KEYNAME
                            ] = sessionManagerURI

                    sessionId = ax.get(
                            SessionHandlerMiddleware.SESSION_ID_AX_KEYNAME)
                    session[SessionHandlerMiddleware.ID_SESSION_KEYNAME
                            ] = sessionId
                            
                    session.save()
                    
                    log.debug("SessionHandlerMiddleware.__call__: updated "
                              "session "
                              "with sessionManagerURI=%s and "
                              "sessionId=%s", 
                              sessionManagerURI, 
                              sessionId)
                
            # Reset cookie removing user data by accessing the Auth ticket 
            # function available from environ
            setUser = environ[
                    SessionHandlerMiddleware.AUTH_TKT_SET_USER_ENVIRON_KEYNAME]
            setUser(session[SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME])
        else:
            log.debug("SessionHandlerMiddleware.__call__: REMOTE_USER_DATA "
                      "is not set")
                    
    @staticmethod                    
    def _parseOpenIdAX(ax):
        """Return a dictionary of attribute exchange attributes parsed from the 
        OpenID Provider response set in the REMOTE_USER_DATA AuthKit environ
        key
        
        @param ax: dictionary of AX parameters - format of keys is e.g.
        count.paramName, value.paramName.<n>, type.paramName
        @type ax: dict
        @return: dictionary of parameters keyed by parameter with values for
        each parameter a tuple of count.paramName values
        @rtype: dict
        """
        
        # Copy Attributes into session
        outputKeys = [k.replace('type.', '') for k in ax.keys()
                      if k.startswith('type.')]
        
        output = {}
        for outputKey in outputKeys:
            axCountKeyName = 'count.' + outputKey
            axCount = int(ax[axCountKeyName])
            
            axValueKeyPrefix = 'value.%s.' % outputKey
            output[outputKey] = tuple([v for k, v in ax.items() 
                                       if k.startswith(axValueKeyPrefix)])
            
            nVals = len(output[outputKey])
            if nVals != axCount:
                raise OpenIdAXConfigError('Got %d parameters for AX attribute '
                                          '"%s"; but "%s" AX key is set to %d'
                                          % (nVals,
                                             axCountKeyName,
                                             axCountKeyName,
                                             axCount))
                                             
        return output
