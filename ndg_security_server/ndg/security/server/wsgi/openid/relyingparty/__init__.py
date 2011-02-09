"""NDG Security OpenID Relying Party Middleware

Wrapper to AuthKit OpenID Middleware

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/01/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

import httplib # to get official status code messages
import urllib # decode quoted URI in query arg
from urlparse import urlsplit, urlunsplit


from paste.request import parse_querystring, parse_formvars
import authkit.authenticate
from authkit.authenticate.open_id import AuthOpenIDHandler
from beaker.middleware import SessionMiddleware

from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authn import AuthnRedirectMiddleware
from ndg.security.common.utils.classfactory import instantiateClass


class OpenIDRelyingPartyMiddlewareError(Exception):
    """OpenID Relying Party WSGI Middleware Error"""


class OpenIDRelyingPartyConfigError(OpenIDRelyingPartyMiddlewareError):
    """OpenID Relying Party Configuration Error"""
  

class OpenIDRelyingPartyMiddleware(NDGSecurityMiddlewareBase):
    '''OpenID Relying Party middleware which wraps the AuthKit implementation.
    This middleware is to be hosted in it's own security middleware stack.
    WSGI middleware applications to be protected can be hosted in a separate
    stack.  The AuthnRedirectMiddleware filter can respond to a HTTP 
    401 response from this stack and redirect to this middleware to initiate
    OpenID based sign in.  AuthnRedirectMiddleware passes a query
    argument in its request containing the URI return address for this 
    middleware to return to following OpenID sign in.
    '''
    sslPropertyDefaults = {
        'certFilePath': '',
        'priKeyFilePath': None,
        'priKeyPwd': None,
        'caCertDirPath': None,
        'providerWhitelistFilePath': None
    }
    propertyDefaults = {
        'sslPeerCertAuthN': True,
        'signinInterfaceMiddlewareClass': None,
        'baseURL': ''
    }
    propertyDefaults.update(sslPropertyDefaults)
    propertyDefaults.update(NDGSecurityMiddlewareBase.propertyDefaults)
    
    def __init__(self, app, global_conf, prefix='openid.relyingparty.', 
                 **app_conf):
        """Add AuthKit and Beaker middleware dependencies to WSGI stack and 
        set-up SSL Peer Certificate Authentication of OpenID Provider set by
        the user
        
        @type app: callable following WSGI interface signature
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy application global configuration - 
        must follow format of propertyDefaults class variable
        @type prefix: basestring
        @param prefix: prefix for OpenID Relying Party configuration items
        @type app_conf: dict
        @param app_conf: application specific configuration - must follow 
        format of propertyDefaults class variable"""    

        # Default to set SSL peer cert authN where no flag is set in the config
        # To override, it must explicitly be set to False in the config
        if app_conf.get('sslPeerCertAuthN', 'true').lower() != 'false':
            
            # Set parameters for SSL client connection to OpenID Provider Yadis
            # retrieval URI
            for paramName in self.__class__.sslPropertyDefaults:
                paramDefault = self.__class__.sslPropertyDefaults[paramName]
                setattr(self, 
                        paramName, 
                        app_conf.get(prefix+paramName, paramDefault))
                
            self._initSSLPeerAuthN()
        
        # Check for sign in template settings
        if prefix+'signinInterfaceMiddlewareClass' in app_conf:
            if 'authkit.openid.template.obj' in app_conf or \
               'authkit.openid.template.string' in app_conf or \
               'authkit.openid.template.file' in app_conf:
                log.warning("OpenID Relying Party "
                            "'signinInterfaceMiddlewareClass' "
                            "setting overrides 'authkit.openid.template.*' "
                            "AuthKit settings")
                
            signinInterfacePrefix = prefix+'signinInterface.'
            classProperties = {'prefix': signinInterfacePrefix}
            classProperties.update(app_conf)
            app = instantiateClass(
                           app_conf[prefix+'signinInterfaceMiddlewareClass'], 
                           None,  
                           objectType=SigninInterface, 
                           classArgs=(app, global_conf),
                           classProperties=classProperties)            
            
            # Delete sign in interface middleware settings
            for conf in app_conf, global_conf or {}:
                for k in conf.keys():
                    if k.startswith(signinInterfacePrefix):
                        del conf[k]
        
            app_conf['authkit.openid.template.string'] = app.makeTemplate()
                
        self.signoutPath = app_conf.get('authkit.cookie.signoutpath')

        app = authkit.authenticate.middleware(app, app_conf)
        _app = app
        while True:
            if isinstance(_app, AuthOpenIDHandler):
                authOpenIDHandler = _app
                self._authKitVerifyPath = authOpenIDHandler.path_verify
                self._authKitProcessPath = authOpenIDHandler.path_process
                break
            
            elif hasattr(_app, 'app'):
                _app = _app.app
            else:
                break
         
        if not hasattr(self, '_authKitVerifyPath'):
            raise OpenIDRelyingPartyConfigError("Error locating the AuthKit "
                                                "AuthOpenIDHandler in the "
                                                "WSGI stack")
        
        # Put this check in here after sessionKey has been set by the 
        # super class __init__ above
        self.sessionKey = authOpenIDHandler.session_middleware
            
        
        # Check for return to argument in query key value pairs
        self._return2URIKey = AuthnRedirectMiddleware.RETURN2URI_ARGNAME + '='
    
        super(OpenIDRelyingPartyMiddleware, self).__init__(app, 
                                                           global_conf, 
                                                           prefix=prefix, 
                                                           **app_conf)
    
    @NDGSecurityMiddlewareBase.initCall     
    def __call__(self, environ, start_response):
        '''
        - Alter start_response to override the status code and force to 401.
        This will enable non-browser based client code to bypass the OpenID 
        interface
        - Manage AuthKit verify and process actions setting the referrer URI
        to manage redirects
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        '''
        # Skip Relying Party interface set-up if user has been authenticated
        # by other middleware
        if 'REMOTE_USER' in environ:
            log.debug("Found REMOTE_USER=%s in environ, AuthKit "
                      "based authentication has taken place in other "
                      "middleware, skipping OpenID Relying Party interface" %
                      environ['REMOTE_USER'])
            return self._app(environ, start_response)

        session = environ.get(self.sessionKey)
        if session is None:
            raise OpenIDRelyingPartyConfigError('No beaker session key "%s" '
                                                'found in environ' % 
                                                self.sessionKey)
        
        # Check for return to address in URI query args set by 
        # AuthnRedirectMiddleware in application code stack
        params = dict(parse_querystring(environ))
        quotedReferrer = params.get(AuthnRedirectMiddleware.RETURN2URI_ARGNAME,
                                    '')
        
        referrer = urllib.unquote(quotedReferrer)
        referrerPathInfo = urlsplit(referrer)[2]

        if referrer and \
           not referrerPathInfo.endswith(self._authKitVerifyPath) and \
           not referrerPathInfo.endswith(self._authKitProcessPath):
            # Subvert authkit.authenticate.open_id.AuthOpenIDHandler.process
            # reassigning it's session 'referer' key to the URI specified in
            # the referrer query argument set in the request URI
            session['referer'] = referrer
            session.save()
            
        if self._return2URIKey in environ.get('HTTP_REFERER', ''):
            # Remove return to arg to avoid interfering with AuthKit OpenID
            # processing
            splitURI = urlsplit(environ['HTTP_REFERER'])
            query = splitURI[3]
            
            filteredQuery = '&'.join([arg for arg in query.split('&')
                                if not arg.startswith(self._return2URIKey)])
            
            environ['HTTP_REFERER'] = urlunsplit(splitURI[:3] + \
                                                 (filteredQuery,) + \
                                                 splitURI[4:])
                            
        # See _start_response doc for an explanation...
        if environ['PATH_INFO'] == self._authKitVerifyPath: 
            def _start_response(status, header, exc_info=None):
                '''Make OpenID Relying Party OpenID prompt page return a 401
                status to signal to non-browser based clients that 
                authentication is required.  Requests are filtered on content 
                type so that static content such as graphics and style sheets 
                associated with the page are let through unaltered
                
                @type status: str
                @param status: HTTP status code and status message
                @type header: list
                @param header: list of field, value tuple HTTP header content
                @type exc_info: Exception
                @param exc_info: exception info
                '''
                _status = status
                for name, val in header:
                    if name.lower() == 'content-type' and \
                       val.startswith('text/html'):
                        _status = self.getStatusMessage(401)
                        break
                    
                return start_response(_status, header, exc_info)
        else:
            _start_response = start_response

        return self._app(environ, _start_response)

    def _initSSLPeerAuthN(self):
        """Initialise M2Crypto based urllib2 HTTPS handler to enable SSL 
        authentication of OpenID Providers"""
        log.info("Setting parameters for SSL Authentication of OpenID "
                 "Provider ...")
        
        def verifySSLPeerCertCallback(preVerifyOK, x509StoreCtx):
            '''SSL verify callback function used to control the behaviour when 
            the SSL_VERIFY_PEER flag is set
            
            http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
            
            @type preVerifyOK: int
            @param preVerifyOK: If a verification error is found, this 
            parameter will be set to 0
            @type x509StoreCtx: M2Crypto.X509_Store_Context
            @param x509StoreCtx: locate the certificate to be verified and 
            perform additional verification steps as needed
            @rtype: int
            @return: controls the strategy of the further verification process. 
            - If verify_callback returns 0, the verification process is 
            immediately stopped with "verification failed" state. If 
            SSL_VERIFY_PEER is set, a verification failure alert is sent to the
            peer and the TLS/SSL handshake is terminated. 
            - If verify_callback returns 1, the verification process is 
            continued. 
            If verify_callback always returns 1, the TLS/SSL handshake will not
            be terminated with respect to verification failures and the 
            connection 
            will be established. The calling process can however retrieve the 
            error code of the last verification error using 
            SSL_get_verify_result or by maintaining its own error storage 
            managed by verify_callback.
            '''
            if preVerifyOK == 0:
                # Something is wrong with the certificate don't bother 
                # proceeding any further
                log.error("verifyCallback: pre-verify OK flagged an error "
                          "with the peer certificate, returning error state "
                          "to caller ...")
                return preVerifyOK
            
            x509Cert = x509StoreCtx.get_current_cert()
            x509Cert.get_subject()
            x509CertChain = x509StoreCtx.get1_chain()
            for cert in x509CertChain:
                subject = cert.get_subject()
                dn = subject.as_text()
                log.debug("verifyCallback: dn = %r", dn)
                
            # If all is OK preVerifyOK will be 1.  Return this to the caller to
            # that it's OK to proceed
            return preVerifyOK
           
        # Imports here so that if SSL Auth is not set the app will not need 
        # these packages 
        import urllib2
        from M2Crypto import SSL
        from M2Crypto.m2urllib2 import build_opener
        from openid.fetchers import setDefaultFetcher, Urllib2Fetcher
        
        # Create a context specifying verification of the peer but with an
        # additional callback function
        ctx = SSL.Context()
        ctx.set_verify(SSL.verify_peer|SSL.verify_fail_if_no_peer_cert, 
                       9, 
                       callback=verifySSLPeerCertCallback)

        # Point to a directory containing CA certificates.  These must be named
        # in their hashed form as expected by the OpenSSL API.  Use c_rehash
        # utility to generate names or in the CA directory:
        #
        # $ for i in *.crt *.pem; do ln -s $i $(openssl x509 -hash -noout -in $i).0; done
        ctx.load_verify_locations(capath=self.caCertDirPath)
        
        # Load this client's certificate and private key to enable the peer 
        # OpenID Provider to authenticate it
        ctx.load_cert(self.certFilePath, 
                      keyfile=self.priKeyFilePath, 
                      callback=lambda *arg, **kw: self.priKeyPwd)
    
        # Force Python OpenID library to use Urllib2 fetcher instead of the 
        # Curl based one otherwise the M2Crypto SSL handler will be ignored.
        setDefaultFetcher(Urllib2Fetcher())
        
        log.debug("Adding the M2Crypto SSL handler to urllib2's list of "
                  "handlers...")
        urllib2.install_opener(build_opener(ssl_context=ctx))
    
class SigninInterfaceError(Exception):
    """Base class for SigninInterface exceptions
    
    A standard message is raised set by the msg class variable but the actual
    exception details are logged to the error log.  The use of a standard 
    message enables callers to use its content for user error messages.
    
    @type msg: basestring
    @cvar msg: standard message to be raised for this exception"""
    userMsg = ("An internal error occurred with the page layout,  Please "
               "contact your system administrator")
    errorMsg = "SigninInterface error"
    
    def __init__(self, *arg, **kw):
        if len(arg) > 0:
            msg = arg[0]
        else:
            msg = self.__class__.errorMsg
            
        log.error(msg)
        Exception.__init__(self, msg, **kw)
        
class SigninInterfaceInitError(SigninInterfaceError):
    """Error with initialisation of SigninInterface.  Raise from __init__"""
    errorMsg = "SigninInterface initialisation error"
    
class SigninInterfaceConfigError(SigninInterfaceError):
    """Error with configuration settings.  Raise from __init__"""
    errorMsg = "SigninInterface configuration error"    

class SigninInterface(NDGSecurityMiddlewareBase):
    """Base class for sign in rendering.  This is implemented as WSGI 
    middleware to enable additional middleware to be added into the call
    stack e.g. StaticFileParser to enable rendering of graphics and other
    static content in the Sign In page"""
    
    def getTemplateFunc(self):
        """Return template function for AuthKit to render OpenID Relying
        Party Sign in page"""
        raise NotImplementedError()
    
    def __call__(self, environ, start_response):
        return self._app(self, environ, start_response)

