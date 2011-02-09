"""Module containing:
 * HTTP Basic Authentication Middleware
 * middleware to enable redirection to OpenID Relying Party for login
 * logout middleware for deleting AuthKit cookie and redirecting back to 
   referrer
 
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "13/01/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

import re
import base64
import httplib
import urllib
from paste.request import construct_url, parse_querystring
import authkit.authenticate

from ndg.security.server.wsgi import NDGSecurityMiddlewareBase, \
    NDGSecurityMiddlewareError, NDGSecurityMiddlewareConfigError        

class AuthnException(NDGSecurityMiddlewareError):
    """Base exception for this module"""
    
    
class HTTPBasicAuthMiddlewareError(AuthnException):
    """Base exception type for HTTPBasicAuthMiddleware"""
    
    
class HTTPBasicAuthMiddlewareConfigError(NDGSecurityMiddlewareConfigError):
    """Configuration error with HTTP Basic Auth middleware"""


class HTTPBasicAuthUnauthorized(HTTPBasicAuthMiddlewareError):  
    """Raise from custom authentication interface in order to set HTTP 
    401 Unuathorized response"""
    
    
class HTTPBasicAuthMiddleware(NDGSecurityMiddlewareBase):
    '''HTTP Basic Authentication Middleware
    
    '''
    
    AUTHN_FUNC_ENV_KEYNAME = ('ndg.security.server.wsgi.authn.'
                              'HTTPBasicAuthMiddleware.authenticate')
    AUTHN_FUNC_ENV_KEYNAME_OPTNAME = 'authnFuncEnvKeyName'       
    PARAM_PREFIX = 'http.auth.basic.'
    HTTP_HDR_FIELDNAME = 'basic'
    FIELD_SEP = ':'
    AUTHZ_ENV_KEYNAME = 'HTTP_AUTHORIZATION'
    
    RE_PATH_MATCH_LIST_OPTNAME = 'rePathMatchList'
    
    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        self.__rePathMatchList = None
        self.__authnFuncEnvironKeyName = None
        
        super(HTTPBasicAuthMiddleware, self).__init__(app, app_conf, 
                                                      **local_conf)

        rePathMatchListOptName = prefix + \
                            HTTPBasicAuthMiddleware.RE_PATH_MATCH_LIST_OPTNAME
        rePathMatchListVal = app_conf.pop(rePathMatchListOptName, '')
        
        self.rePathMatchList = [re.compile(i) 
                                for i in rePathMatchListVal.split()]

        paramName = prefix + \
                    HTTPBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME_OPTNAME
                    
        self.authnFuncEnvironKeyName = local_conf.get(paramName,
                                HTTPBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME)

    def _getAuthnFuncEnvironKeyName(self):
        return self.__authnFuncEnvironKeyName

    def _setAuthnFuncEnvironKeyName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"authnFuncEnvironKeyName"; got %r type' % 
                            type(value))
        self.__authnFuncEnvironKeyName = value

    authnFuncEnvironKeyName = property(fget=_getAuthnFuncEnvironKeyName, 
                                       fset=_setAuthnFuncEnvironKeyName, 
                                       doc="key name in environ for the "
                                           "custom authentication function "
                                           "used by this class")

    def _getRePathMatchList(self):
        return self.__rePathMatchList

    def _setRePathMatchList(self, value):
        if not isinstance(value, (list, tuple)):
            raise TypeError('Expecting list or tuple type for '
                            '"rePathMatchList"; got %r' % type(value))
        
        self.__rePathMatchList = value

    rePathMatchList = property(fget=_getRePathMatchList, 
                               fset=_setRePathMatchList, 
                               doc="List of regular expressions determine the "
                                   "URI paths intercepted by this middleware")

    def _pathMatch(self):
        """Apply a list of regular expression matching patterns to the contents
        of environ['PATH_INFO'], if any match, return True.  This method is
        used to determine whether to apply SSL client authentication
        """
        path = self.pathInfo
        for regEx in self.rePathMatchList:
            if regEx.match(path):
                return True
            
        return False   

    def _parseCredentials(self):
        """Extract username and password from HTTP_AUTHORIZATION environ key
        
        @rtype: tuple
        @return: username and password.  If the key is not set or the auth
        method is not basic return a two element tuple with elements both set
        to None
        """
        basicAuthHdr = self.environ.get(
                                    HTTPBasicAuthMiddleware.AUTHZ_ENV_KEYNAME)
        if basicAuthHdr is None:
            log.debug("No %r setting in environ: skipping HTTP Basic Auth",
                      HTTPBasicAuthMiddleware.AUTHZ_ENV_KEYNAME)
            return None, None
                       
        method, encodedCreds = basicAuthHdr.split(None, 1)
        if method.lower() != HTTPBasicAuthMiddleware.HTTP_HDR_FIELDNAME:
            log.debug("Auth method is %r not %r: skipping request",
                      method, HTTPBasicAuthMiddleware.HTTP_HDR_FIELDNAME)
            return None, None
            
        creds = base64.decodestring(encodedCreds)
        username, password = creds.split(HTTPBasicAuthMiddleware.FIELD_SEP, 1)
        return username, password

    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """Authenticate based HTTP header elements as specified by the HTTP
        Basic Authentication spec."""
        log.debug("HTTPBasicAuthNMiddleware.__call__ ...")
        
        if not self._pathMatch():
            return self._app(environ, start_response)
        
        authenticate = environ.get(self.authnFuncEnvironKeyName)
        if authenticate is None:
            # HTTP 500 default is right for this error
            raise HTTPBasicAuthMiddlewareConfigError("No authentication "
                                                     "function set in environ")
            
        username, password = self._parseCredentials()
        if username is None:
            return self._setErrorResponse(code=httplib.UNAUTHORIZED)
        
        # Call authentication application
        try:
            return authenticate(environ, start_response, username, password)
        
        except HTTPBasicAuthUnauthorized, e:
            log.error(e)
            return self._setErrorResponse(code=httplib.UNAUTHORIZED)
        else:
            return self._app(environ, start_response)


# AuthKit based HTTP basic authentication plugin not currently needed but may 
# need resurrecting

#from authkit.permissions import UserIn
#from ndg.security.server.wsgi.utils.sessionmanagerclient import \
#    WSGISessionManagerClient
#            
#class HTTPBasicAuthentication(object):
#    '''Authkit based HTTP Basic Authentication.   __call__ defines a 
#    validation function to fit with the pattern for the AuthKit interface
#    '''
#    
#    def __init__(self):
#        self._userIn = UserIn([])
#        
#    def __call__(self, environ, username, password):
#        """validation function"""
#        try:
#            client = WSGISessionManagerClient(environ=environ,
#                                environKeyName=self.sessionManagerFilterID)
#            res = client.connect(username, passphrase=password)
#
#            if username not in self._userIn.users:
#                self._userIn.users += [username]
#            
#            # TODO: set session
#                
#        except Exception, e:
#            return False
#        else:
#            return True


class SessionMiddlewareBase(NDGSecurityMiddlewareBase):
    """Base class for Authentication redirect middleware and Session Handler
    middleware
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: valid configuration property keywords 
    """   
    propertyDefaults = {
        'sessionKey': 'beaker.session.ndg.security'
    }
   
    _isAuthenticated = lambda self: \
        SessionMiddlewareBase.USERNAME_SESSION_KEYNAME in \
        self.environ.get(self.sessionKey, ())
        
    isAuthenticated = property(fget=_isAuthenticated,
                               doc='boolean to indicate is user logged in')

        
class AuthnRedirectMiddleware(SessionMiddlewareBase):
    """Base class for Authentication HTTP redirect initiator and redirect
    response WSGI middleware

    @type RETURN2URI_ARGNAME: basestring
    @cvar RETURN2URI_ARGNAME: name of URI query argument used to pass the 
    return to URI between initiator and consumer classes"""
    RETURN2URI_ARGNAME = 'ndg.security.r'


class AuthnRedirectInitiatorMiddleware(AuthnRedirectMiddleware):
    '''Middleware to initiate a redirect to another URI if a user is not 
    authenticated i.e. security cookie is not set
    
    AuthKit.authenticate.middleware must be in place upstream of this 
    middleware.  AuthenticationMiddleware wrapper handles this.
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: valid configuration property keywords    
    '''
    propertyDefaults = {
        'redirectURI': None,
    }
    propertyDefaults.update(AuthnRedirectMiddleware.propertyDefaults)
    

    TRIGGER_HTTP_STATUS_CODE = '401'
    MIDDLEWARE_ID = 'AuthnRedirectInitiatorMiddleware'

    def __init__(self, app, global_conf, **app_conf):
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
        self._redirectURI = None
        super(AuthnRedirectInitiatorMiddleware, self).__init__(app, 
                                                               global_conf, 
                                                               **app_conf)
        
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        '''Invoke redirect if user is not authenticated'''
        
        log.debug("AuthnRedirectInitiatorMiddleware.__call__ ...")
        
        if self.isAuthenticated:
            # Call next app in stack
            return self._app(environ, start_response)        
        else:
            # User is not authenticated - Redirect to OpenID Relying Party URI
            # for user OpenID entry
            return self._setRedirectResponse()
   
    def _setRedirectURI(self, uri):
        if not isinstance(uri, basestring):
            raise TypeError("Redirect URI must be set to string type")   
         
        self._redirectURI = uri
        
    def _getRedirectURI(self):
        return self._redirectURI
    
    redirectURI = property(fget=_getRedirectURI,
                       fset=_setRedirectURI,
                       doc="URI to redirect to if user is not authenticated")

    def _setRedirectResponse(self):
        """Construct a redirect response adding in a return to address in a
        URI query argument
        
        @rtype: basestring
        @return: redirect response
        """       
        return2URI = construct_url(self.environ)
        quotedReturn2URI = urllib.quote(return2URI, safe='')
        return2URIQueryArg = urllib.urlencode(
                    {AuthnRedirectInitiatorMiddleware.RETURN2URI_ARGNAME: 
                     quotedReturn2URI})

        redirectURI = self.redirectURI
        
        if '?' in redirectURI:
            if redirectURI.endswith('&'):
                redirectURI += return2URIQueryArg
            else:
                redirectURI += '&' + return2URIQueryArg
        else:
            if redirectURI.endswith('?'):
                redirectURI += return2URIQueryArg
            else:
                redirectURI += '?' + return2URIQueryArg
          
        # Call NDGSecurityMiddlewareBase.redirect utility method      
        return self.redirect(redirectURI)
        
    @classmethod
    def checker(cls, environ, status, headers):
        """Set the MultiHandler checker function for triggering this 
        middleware.  In this case, it's a HTTP 401 Unauthorized response 
        detected in the middleware chain
        """
        if status.startswith(cls.TRIGGER_HTTP_STATUS_CODE):
            log.debug("%s.checker caught status [%s]: invoking authentication"
                      " handler", cls.__name__, cls.TRIGGER_HTTP_STATUS_CODE)
            return True
        else:
            log.debug("%s.checker skipping status [%s]", cls.__name__, status)
            return False


class AuthnRedirectResponseMiddleware(AuthnRedirectMiddleware):
    """Compliment to AuthnRedirectInitiatorMiddleware 
    functioning as the opposite end of the HTTP redirect interface.  It 
    performs the following tasks:
    - Detect a redirect URI set in a URI query argument and copy it into
    a user session object. 
    - Redirect back to the redirect URI once a user is authenticated
    
    Also see,
    ndg.security.server.wsgi.openid.relyingparty.OpenIDRelyingPartyMiddleware 
    which performs a similar function.
    """
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        session = environ[self.sessionKey]
        
        # Check for return to address in URI query args set by 
        # AuthnRedirectInitiatorMiddleware in application code stack
        if environ['REQUEST_METHOD'] == "GET":
            params = dict(parse_querystring(environ))
        else:
            params = {}
        
        # Store the return URI query argument in a beaker session
        quotedReferrer = params.get(self.__class__.RETURN2URI_ARGNAME, '')
        referrerURI = urllib.unquote(quotedReferrer)
        if referrerURI:
            session[self.__class__.RETURN2URI_ARGNAME] = referrerURI
            session.save()
            
        # Check for a return URI setting in the beaker session and if the user
        # is authenticated, redirect to this URL deleting the beaker session
        # URL setting
        return2URI = session.get(self.__class__.RETURN2URI_ARGNAME)    
        if self.isAuthenticated and return2URI:
            del session[self.__class__.RETURN2URI_ARGNAME]
            session.save()
            return self.redirect(return2URI)

        return self._app(environ, start_response)


class AuthKitRedirectResponseMiddleware(AuthnRedirectResponseMiddleware):
    """Overload isAuthenticated method in parent class to set Authenticated 
    state based on presence of AuthKit 'REMOTE_USER' environ variable
    """
    _isAuthenticated = lambda self: \
        AuthnRedirectResponseMiddleware.USERNAME_ENVIRON_KEYNAME in self.environ
        
    isAuthenticated = property(fget=_isAuthenticated,
                               doc="Boolean indicating if AuthKit "
                                   "'REMOTE_USER' environment variable is set")
    def __init__(self, app, app_conf, **local_conf):
        super(AuthKitRedirectResponseMiddleware, self).__init__(app, app_conf,
                                                                **local_conf)
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        return super(AuthKitRedirectResponseMiddleware, self).__call__(environ,
                                                                start_response)
       

class SessionHandlerMiddlewareError(AuthnException):
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
                    
            else:
                log.error('No referrer set for redirect following logout')
                _start_response = start_response
                
            # Clear user details from beaker session
            for keyName in self.__class__.SESSION_KEYNAMES:
                session.pop(keyName, None)
            session.save()
        else:
            log.debug("SessionHandlerMiddleware.__call__: checking for "
                      "REMOTE_* environment variable settings set by OpenID "
                      "Relying Party signin...")
            
            if SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME not in session\
               and SessionHandlerMiddleware.USERNAME_ENVIRON_KEYNAME in environ:
                log.debug("SessionHandlerMiddleware: updating session "
                          "username=%s", environ[
                            SessionHandlerMiddleware.USERNAME_ENVIRON_KEYNAME])
                
                session[SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME
                        ] = environ[
                            SessionHandlerMiddleware.USERNAME_ENVIRON_KEYNAME]
                session.save()
                
            remoteUserData = environ.get(
                        SessionHandlerMiddleware.USERDATA_ENVIRON_KEYNAME, '')    
            if remoteUserData:
                log.debug("SessionHandlerMiddleware: found REMOTE_USER_DATA="
                          "%s, set from OpenID Relying Party signin",
                          environ[
                          SessionHandlerMiddleware.USERDATA_ENVIRON_KEYNAME])
                
                # eval is safe here because AuthKit cookie is signed and 
                # AuthKit middleware checks for tampering
                if SessionHandlerMiddleware.SM_URI_SESSION_KEYNAME not in \
                   session or \
                   SessionHandlerMiddleware.ID_SESSION_KEYNAME not in session:
                    
                    axData = eval(remoteUserData)
                    if isinstance(axData, dict) and \
                       SessionHandlerMiddleware.AX_KEYNAME in axData:
                        
                        ax = axData[SessionHandlerMiddleware.AX_KEYNAME]
                        
                        # Save attributes keyed by attribute name
                        session[
                            SessionHandlerMiddleware.AX_SESSION_KEYNAME
                        ] = SessionHandlerMiddleware._parseOpenIdAX(ax)
                        
                        log.debug("SessionHandlerMiddleware: updated session "
                                  "with OpenID AX values: %r" % 
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
                        
                        log.debug("SessionHandlerMiddleware: updated session "
                                  "with sessionManagerURI=%s and "
                                  "sessionId=%s", 
                                  sessionManagerURI, 
                                  sessionId)
                    
                # Reset cookie removing user data
                setUser = environ[
                    SessionHandlerMiddleware.AUTH_TKT_SET_USER_ENVIRON_KEYNAME]
                setUser(
                    session[SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME])

            _start_response = start_response
            
        return self._app(environ, _start_response)
    
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


from authkit.authenticate.multi import MultiHandler

class AuthenticationMiddlewareConfigError(NDGSecurityMiddlewareConfigError):
    '''Authentication Middleware Configuration error'''


class AuthenticationMiddleware(MultiHandler, NDGSecurityMiddlewareBase):
    '''Top-level class encapsulates session and authentication handlers
    in this module
    
    Handler to intercept 401 Unauthorized HTTP responses and redirect to an
    authentication URI.  This class also implements a redirect handler to
    redirect back to the referrer if logout is invoked.
    '''

    def __init__(self, app, global_conf, prefix='', **app_conf):
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
        
        # Set logout URI parameter from AuthKit settings if not otherwise set
        sessionHandlerPrefix = prefix + SessionHandlerMiddleware.PARAM_PREFIX        
        app = SessionHandlerMiddleware(app, 
                                       global_conf, 
                                       prefix=sessionHandlerPrefix,
                                       **app_conf)
        
        # Remove session handler middleware specific parameters
        for k in app_conf.keys():
            if k.startswith(sessionHandlerPrefix):
                del app_conf[k]
        
        app = authkit.authenticate.middleware(app, app_conf)        
        
        MultiHandler.__init__(self, app)

        # Redirection middleware is invoked based on a check method which 
        # catches HTTP 401 responses.
        self.add_method(AuthnRedirectInitiatorMiddleware.MIDDLEWARE_ID, 
                        AuthnRedirectInitiatorMiddleware.filter_app_factory, 
                        global_conf,
                        prefix=prefix,
                        **app_conf)
        
        self.add_checker(AuthnRedirectInitiatorMiddleware.MIDDLEWARE_ID, 
                         AuthnRedirectInitiatorMiddleware.checker)
