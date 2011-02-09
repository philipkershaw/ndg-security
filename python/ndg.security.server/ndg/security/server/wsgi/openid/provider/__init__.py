"""NDG Security OpenID Provider Middleware

Compliments AuthKit OpenID Middleware used for OpenID *Relying Party*

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "01/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import httplib
import sys
import cgi
import os
import logging
log = logging.getLogger(__name__)
_debugLevel = log.getEffectiveLevel() <= logging.DEBUG

import paste.request
from paste.util.import_string import eval_import

from authkit.authenticate import AuthKitConfigError

from openid.extensions import sreg, ax
from openid.server import server
from openid.store.filestore import FileOpenIDStore
from openid.consumer import discover

quoteattr = lambda s: '"%s"' % cgi.escape(s, 1)


class AuthNInterfaceError(Exception):
    """Base class for AbstractAuthNInterface exceptions
    
    A standard message is raised set by the msg class variable but the actual
    exception details are logged to the error log.  The use of a standard 
    message enables callers to use its content for user error messages.
    
    @type msg: basestring
    @cvar msg: standard message to be raised for this exception"""
    userMsg = ("An internal error occurred during login,  Please contact your "
               "system administrator")
    errorMsg = "AuthNInterface error"
    
    def __init__(self, *arg, **kw):
        if len(arg) > 0:
            msg = arg[0]
        else:
            msg = self.__class__.errorMsg
            
        log.error(msg)
        Exception.__init__(self, msg, **kw)
        
class AuthNInterfaceInvalidCredentials(AuthNInterfaceError):
    """User has provided incorrect username/password.  Raise from logon"""
    userMsg = ("Invalid username / password provided.  Please try again.  If "
               "the problem persists please contact your system administrator")
    errorMsg = "Invalid username/password provided"

class AuthNInterfaceUsername2IdentifierMismatch(AuthNInterfaceError): 
    """User has provided a username which doesn't match the identifier from
    the OpenID URL that they provided.  DOESN'T apply to ID Select mode where
    the user has given a generic URL for their OpenID Provider."""
    userMsg = ("Invalid username for the OpenID entered.  Please ensure you "
               "have the correct OpenID and username and try again.  If the "
               "problem persists contact your system administrator")
    errorMsg = "invalid username / OpenID identifier combination"
    
class AuthNInterfaceRetrieveError(AuthNInterfaceError):
    """Error with retrieval of information to authenticate user e.g. error with
    database look-up.  Raise from logon"""
    errorMsg = ("An error occurred retrieving information to check the login "
                "credentials")

class AuthNInterfaceInitError(AuthNInterfaceError):
    """Error with initialisation of AuthNInterface.  Raise from __init__"""
    errorMsg = "AuthNInterface initialisation error"
    
class AuthNInterfaceConfigError(AuthNInterfaceError):
    """Error with Authentication configuration.  Raise from __init__"""
    errorMsg = "AuthNInterface configuration error"
    
class AbstractAuthNInterface(object):
    '''OpenID Provider abstract base class for authentication configuration.
    Derive from this class to define the authentication interface for users
    logging into the OpenID Provider'''
    
    def __init__(self, **prop):
        """Make any initial settings
        
        Settings are held in a dictionary which can be set from **prop,
        a call to setProperties() or by passing settings in an XML file
        given by propFilePath
        
        @type **prop: dict
        @param **prop: set properties via keywords 
        @raise AuthNInterfaceInitError: error with initialisation
        @raise AuthNInterfaceConfigError: error with configuration
        @raise AuthNInterfaceError: generic exception not described by the 
        other specific exception types.
        """
    
    def logon(self, environ, userIdentifier, username, password):
        """Interface login method
        
        @type environ: dict
        @param environ: standard WSGI environ parameter
        
        @type userIdentifier: basestring or None
        @param userIdentifier: OpenID user identifier - this implementation of
        an OpenID Provider uses the suffix of the user's OpenID URL to specify
        a unique user identifier.  It ID Select mode was chosen, the identifier
        will be None and can be ignored.  In this case, the implementation of
        the decide method in the rendering interface must match up the username
        to a corresponding identifier in order to construct a complete OpenID
        user URL.
        
        @type username: basestring
        @param username: user identifier for authentication
        
        @type password: basestring
        @param password: corresponding password for username givens
        
        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        @raise AuthNInterfaceUsername2IdentifierMismatch: username doesn't 
        match the OpenID URL provided by the user.  (Doesn't apply to ID Select
        type requests).
        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to authenticate user e.g. error with database look-up.
        @raise AuthNInterfaceError: generic exception not described by the 
        other specific exception types.
        """
        raise NotImplementedError()
    
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
        @return: one or more identifiers to be used to make OpenID user 
        identity URL(s).
        
        @raise AuthNInterfaceConfigError: problem with the configuration 
        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to identifier e.g. error with database look-up.
        @raise AuthNInterfaceError: generic exception not described by the 
        other specific exception types.
        """
        raise NotImplementedError()
        
        
class OpenIDProviderMiddlewareError(Exception):
    """OpenID Provider WSGI Middleware Error"""

class OpenIDProviderConfigError(OpenIDProviderMiddlewareError):
    """OpenID Provider Configuration Error"""

class OpenIDProviderMissingRequiredAXAttrs(OpenIDProviderMiddlewareError): 
    """Raise if a Relying Party *requires* one or more attributes via
    the AX interface but this OpenID Provider cannot return them.  This doesn't
    apply to attributes that are optional"""

class OpenIDProviderMissingAXResponseHandler(OpenIDProviderMiddlewareError): 
    """Raise if a Relying Party *requires* one or more attributes via
    the AX interface but no AX Response handler has been set"""
  
class OpenIDProviderMiddleware(object):
    """WSGI Middleware to implement an OpenID Provider
    
    @cvar defOpt: app_conf options / keywords to __init__ and their default 
    values.  Input keywords must match these
    @type defOpt: dict
    
    @cvar defPaths: subset of defOpt.  These are keyword items corresponding
    to the URL paths to be set for the individual OpenID Provider functions
    @type: defPaths: dict
    
    @cvar formRespWrapperTmpl: If the response to the Relying Party is too long
    it's rendered as form with the POST method instead of query arguments in a 
    GET 302 redirect.  Wrap the form in this document to make the form submit 
    automatically without user intervention.  See _displayResponse method 
    below...
    @type formRespWrapperTmpl: basestring"""
    
    formRespWrapperTmpl = """<html>
    <head>
        <script type="text/javascript">
            function doRedirect()
            {
                document.forms[0].submit();
            }
        </script>
    </head>
    <body onLoad="doRedirect()">
        %s
    </body>
</html>"""

    defOpt = dict(
        path_openidserver='/openidserver',
        path_login='/login',
        path_loginsubmit='/loginsubmit',
        path_id='/id',
        path_yadis='/yadis',
        path_serveryadis='/serveryadis',
        path_allow='/allow',
        path_decide='/decide',
        path_mainpage='/',
        session_middleware='beaker.session', 
        base_url='',
        consumer_store_dirpath='./',
        charset=None,
        trace=False,
        renderingClass=None,
        sregResponseHandler=None,
        axResponseHandler=None,
        authNInterface=AbstractAuthNInterface)
    
    defPaths=dict([(k,v) for k,v in defOpt.items() if k.startswith('path_')])
     
    def __init__(self, app, app_conf=None, prefix='openid.provider.', **kw):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type app_conf: dict        
        @param app_conf: PasteDeploy application configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for OpenID Provider configuration items
        @type kw: dict
        @param kw: keyword dictionary - must follow format of defOpt 
        class variable    
        '''

        opt = OpenIDProviderMiddleware.defOpt.copy()
        if app_conf is not None:
            # Update from application config dictionary - filter from using
            # prefix
            OpenIDProviderMiddleware._filterOpts(opt, app_conf, prefix=prefix)
                        
        # Similarly, filter keyword input                 
        OpenIDProviderMiddleware._filterOpts(opt, kw, prefix=prefix)
       
        # Update options from keywords - matching app_conf ones will be 
        # overwritten
        opt.update(kw)
        
        # Convert from string type where required   
        opt['charset'] = opt.get('charset', '')
        opt['trace'] = opt.get('trace', 'false').lower() == 'true'
         
        renderingClassVal = opt.get('renderingClass', None)      
        if renderingClassVal:
            opt['renderingClass'] = eval_import(renderingClassVal)
        
        sregResponseHandlerVal = opt.get('sregResponseHandler', None)  
        if sregResponseHandlerVal:
            opt['sregResponseHandler'] = eval_import(sregResponseHandlerVal)  
        else:
            opt['sregResponseHandler'] = None

        axResponseHandlerVal = opt.get('axResponseHandler', None)  
        if axResponseHandlerVal:
            opt['axResponseHandler'] = eval_import(axResponseHandlerVal)
        else:
            opt['axResponseHandler'] = None

        # Authentication interface to OpenID Provider - interface to for 
        # example a user database or other means of authentication
        authNInterfaceName = opt.get('authNInterface')
        if authNInterfaceName:
            authNInterfaceClass = eval_import(authNInterfaceName)
            if not issubclass(authNInterfaceClass, AbstractAuthNInterface):
                raise OpenIDProviderMiddlewareError("Authentication interface "
                                                    "class %r is not a %r "
                                                    "derived type" % 
                                                    (authNInterfaceClass, 
                                                     AbstractAuthNInterface))
        else:
            authNInterfaceClass = AbstractAuthNInterface
        
        # Extract Authentication interface specific properties
        authNInterfaceProperties = dict([(k.replace('authN_', ''), v) 
                                         for k,v in opt.items() 
                                         if k.startswith('authN_')]) 
         
        try:
            self._authN = authNInterfaceClass(**authNInterfaceProperties)
        except Exception, e:
            log.error("Error instantiating authentication interface: %s" % e)
            raise

        # Paths relative to base URL - Nb. remove trailing '/'
        self.paths = dict([(k, opt[k].rstrip('/'))
                           for k in OpenIDProviderMiddleware.defPaths])
        
        if not opt['base_url']:
            raise TypeError("base_url is not set")
        
        self.base_url = opt['base_url']

        # Full Paths
        self.urls = dict([(k.replace('path_', 'url_'), self.base_url+v)
                          for k,v in self.paths.items()])

        self.method = dict([(v, k.replace('path_', 'do_'))
                            for k,v in self.paths.items()])

        self.session_middleware = opt['session_middleware']

        if not opt['charset']:
            self.charset = ''
        else:
            self.charset = '; charset='+charset
        
        # If True and debug log level is set display content of response
        self._trace = opt['trace']

        log.debug("opt=%r", opt)        
       
        # Pages can be customised by setting external rendering interface
        # class
        renderingClass = opt.get('renderingClass', None) or RenderingInterface         
        if not issubclass(renderingClass, RenderingInterface):
            raise OpenIDProviderMiddlewareError("Rendering interface "
                                                "class %r is not a %r "
                                                "derived type" % \
                                                (renderingClass, 
                                                 RenderingInterface))
        
        # Extract rendering interface specific properties
        renderingProperties = dict([(k.replace('rendering_', ''), v) 
                                         for k,v in opt.items() 
                                         if k.startswith('rendering_')])    

        try:
            self._render = renderingClass(self._authN,
                                          self.base_url,
                                          self.urls,
                                          **renderingProperties)
        except Exception, e:
            log.error("Error instantiating rendering interface: %s" % e)
            raise
                    
        # Callable for setting of Simple Registration attributes in HTTP header
        # of response to Relying Party
        self.sregResponseHandler = opt.get('sregResponseHandler', None)
        if self.sregResponseHandler and not callable(self.sregResponseHandler):
            raise OpenIDProviderMiddlewareError("Expecting callable for "
                                                "sregResponseHandler keyword, "
                                                "got %r" %
                                                self.sregResponseHandler)
            
        # Callable to handle OpenID Attribute Exchange (AX) requests from
        # the Relying Party
        self.axResponseHandler = opt.get('axResponseHandler', None)
        if self.axResponseHandler and not callable(self.axResponseHandler):
            raise OpenIDProviderMiddlewareError("Expecting callable for "
                                                "axResponseHandler keyword, "
                                                "got %r" %
                                                self.axResponseHandler)
        
        self.app = app
        
        # Instantiate OpenID consumer store and OpenID consumer.  If you
        # were connecting to a database, you would create the database
        # connection and instantiate an appropriate store here.
        store = FileOpenIDStore(
                            os.path.expandvars(opt['consumer_store_dirpath']))
        self.oidserver = server.Server(store, self.urls['url_openidserver'])

    @classmethod
    def main_app(cls, global_conf, **app_conf):
        '''Provide Paste main_app function signature for inclusion in Paste ini
        files
        @type global_conf: dict        
        @param global_conf: PasteDeploy configuration dictionary
        @type app_conf: dict
        @param app_conf: keyword dictionary - must follow format of defOpt 
        class variable'''   
        
        openIDProviderApp = cls(None, global_conf, **app_conf)
        
        # Make an application to handle invalid URLs making use of the 
        # rendering object created in the OpenID Provider initialisation
        def app(environ, start_response):
            msg = "Page not found"
            response = openIDProviderApp.render.errorPage(environ, 
                                                          start_response, 
                                                          msg, 
                                                          code=404)
            return response
        
        # Update the OpenID Provider object with the new app
        openIDProviderApp.app = app
        
        return openIDProviderApp
        
    @classmethod
    def _filterOpts(cls, opt, newOpt, prefix=''):
        '''Convenience utility to filter input options set in __init__ via
        app_conf or keywords
        
        Nb. exclusions for authN and rendering interface properties.
        
        @type opt: dict
        @param opt: existing options set.  These will be updated by this
        method based on the content of newOpt
        @type newOpt: dict
        @param newOpt: new options to update opt with
        @type prefix: basestring 
        @param prefix: if set, remove the given prefix from the input options
        @raise KeyError: if an option is set that is not in the classes
        defOpt class variable
        '''
        def _isBadOptName(optName):
            # Allow for authN.* and rendering.* properties used by the 
            # Authentication and Rendering interfaces respectively
            return optName not in cls.defOpt and \
               not optName.startswith('authN_') and \
               not optName.startswith('rendering_')
               
        badOptNames = [] 
        for optName, optVal in newOpt.items():
            if prefix:
                if optName.startswith(prefix):
                    optName = optName.replace(prefix, '')                
                    filtOptName = '_'.join(optName.split('.'))
                                            
                    # Skip assignment for bad option names and record them in
                    # an error list instead 
                    if _isBadOptName(filtOptName):
                        badOptNames += [optName]                    
                    else:
                        opt[filtOptName] = optVal
#                else:
                    # Options not starting with prefix are ignored - omit debug
                    # it's too verbose even for debug setting :)
#                    log.debug("Skipping option \"%s\": it doesn't start with "
#                              "the prefix \"%s\"", optName, prefix)
            else:
                filtOptName = '_'.join(optName.split('.'))

                # Record any bad option names 
                if _isBadOptName(filtOptName):
                    badOptNames += [optName]                    
                else:
                    opt[filtOptName] = optVal
                
        if len(badOptNames) > 0:
            raise TypeError("Invalid input option(s) set: %s" % 
                            (", ".join(badOptNames)))
            

    def __call__(self, environ, start_response):
        """Standard WSGI interface.  Intercepts the path if it matches any of 
        the paths set in the path_* keyword settings to the config
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response
        """
        if not environ.has_key(self.session_middleware):
            raise OpenIDProviderConfigError('The session middleware %r is not '
                                            'present. Have you set up the '
                                            'session middleware?' % \
                                            self.session_middleware)

        self.path = environ.get('PATH_INFO').rstrip('/')
        self.environ = environ
        self.start_response = start_response
        self.session = environ[self.session_middleware]
        self._render.session = self.session
        
        if self.path in (self.paths['path_id'], self.paths['path_yadis']):
            log.debug("No user id given in URL %s" % self.path)
            
            # Disallow identifier and yadis URIs where no ID was specified
            return self.app(environ, start_response)
            
        elif self.path.startswith(self.paths['path_id']) or \
             self.path.startswith(self.paths['path_yadis']):
            
            # Match against path minus ID as this is not known in advance            
            pathMatch = self.path[:self.path.rfind('/')]
        else:
            pathMatch = self.path
            
        if pathMatch in self.method:
            self.query = dict(paste.request.parse_formvars(environ)) 
            log.debug("Calling method %s ..." % self.method[pathMatch]) 
            
            action = getattr(self, self.method[pathMatch])
            response = action(environ, start_response) 
            if self._trace and _debugLevel:
                if isinstance(response, list):
                    log.debug('Output for %s:\n%s', self.method[pathMatch],
                                                    ''.join(response))
                else:
                    log.debug('Output for %s:\n%s', self.method[pathMatch],
                                                    response)
                    
            return response
        else:
            log.debug("No match for path %s" % self.path)
            return self.app(environ, start_response)


    def do_id(self, environ, start_response):
        '''URL based discovery with an ID provided
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response
       
        '''
        response = self._render.identityPage(environ, start_response)
        return response


    def do_yadis(self, environ, start_response):
        """Handle Yadis based discovery with an ID provided
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response

        """
        response = self._render.yadis(environ, start_response)
        return response


    def do_serveryadis(self, environ, start_response):
        """Yadis based discovery for ID Select mode i.e. no user ID given for 
        OpenID identifier at Relying Party
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response

        """
        response = self._render.serverYadis(environ, start_response)
        return response


    def do_openidserver(self, environ, start_response):
        """OpenID Server endpoint - handles OpenID Request following discovery
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response
        """

        try:
            oidRequest = self.oidserver.decodeRequest(self.query)
            
        except server.ProtocolError, why:
            response = self._displayResponse(why)
            
        else:
            if oidRequest is None:
                # Display text indicating that this is an endpoint.
                response = self.do_mainpage(environ, start_response)
            
            # Check mode is one of "checkid_immediate", "checkid_setup"
            elif oidRequest.mode in server.BROWSER_REQUEST_MODES:
                response = self._handleCheckIDRequest(oidRequest)
            else:
                oidResponse = self.oidserver.handleRequest(oidRequest)
                response = self._displayResponse(oidResponse)
            
        return response
            

    def do_allow(self, environ, start_response):
        """Handle allow request processing the result of do_decide: does user 
        allow credentials to be passed back to the Relying Party?
        
        This method expects the follow fields to have been set in the posted
        form created by the RedneringInterface.decidePage method called by 
        do_decide:
        
        'Yes'/'No': for return authentication details back to the RP or 
        abort return to RP respectively
        'remember': remember the decision corresponding to the above 'Yes'
        /'No'.
        This may be set to 'Yes' or 'No'
        'identity': set to the user's identity URL.  This usually is not 
        required since it can be obtained from oidRequest.identity attribute
        but in ID Select mode, the identity URL will have been selected or set
        in the decide page interface.
        
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response

        """
        
        oidRequest = self.session.get('lastCheckIDRequest')
        if oidRequest is None:
            log.error("Suspected do_allow called from stale request")
            return self._render.errorPage(environ, start_response,
                                          "Invalid request",
                                          code=400)
        
        if 'Yes' in self.query:
            if oidRequest.idSelect():
                identity = self.query.get('identity')
                if identity is None:
                    log.error("No identity field set from decide page for "
                              "processing in ID Select mode")
                    return self._render.errorPage(environ, start_response,
                                                  "An internal error has "
                                                  "occurred setting the "
                                                  "OpenID user identity")
            else:
                identity = oidRequest.identity

            trust_root = oidRequest.trust_root
            if self.query.get('remember', 'No') == 'Yes':
                self.session['approved'] = {trust_root: 'always'}
                self.session.save()
             
            try:
                oidResponse = self._identityApprovedPostProcessing(oidRequest, 
                                                                   identity)

            except (OpenIDProviderMissingRequiredAXAttrs, 
                    OpenIDProviderMissingAXResponseHandler):
                response = self._render.errorPage(environ, start_response,
                    'The site where you wish to signin requires '
                    'additional information which this site isn\'t '
                    'configured to provide.  Please report this fault to '
                    'your site administrator.')
                return response
                    
            except Exception, e:
                log.error("Setting response following ID Approval: %s" % e)
                return self._render.errorPage(environ, start_response,
                        'An error occurred setting additional parameters '
                        'required by the site requesting your ID.  Please '
                        'report this fault to your site administrator.')
            else:
                return self._displayResponse(oidResponse)
        
        elif 'No' in self.query:
            # TODO: Check 'No' response is OK - No causes AuthKit's Relying 
            # Party implementation to crash with 'openid.return_to' KeyError
            # in Authkit.authenticate.open_id.process
            oidResponse = oidRequest.answer(False)
            #return self._displayResponse(oidResponse)
            return self._render.mainPage(environ, start_response)            
        else:
            return self._render.errorPage(environ, start_response,
                                          'Expecting Yes/No in allow '
                                          'post. %r' % self.query,
                                          code=400)


    def do_login(self, environ, start_response, **kw):
        """Display Login form
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @type kw: dict
        @param kw: keywords to login renderer - see RenderingInterface class
        @rtype: basestring
        @return: WSGI response
        """
        
        if 'fail_to' not in kw:
            kw['fail_to'] = self.urls['url_login']
            
        response = self._render.login(environ, start_response, **kw)
        return response


    def do_loginsubmit(self, environ, start_response):
        """Handle user submission from login and logout
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response
        """
        
        if 'submit' in self.query:
            if 'username' in self.query:
                # login
                if 'username' in self.session:
                    log.error("Attempting login for user %s: user %s is "
                              "already logged in", self.session['username'],
                              self.session['username'])
                    return self._redirect(start_response,self.query['fail_to'])
                
                oidRequest = self.session.get('lastCheckIDRequest')
                if oidRequest is None:
                    log.error("Getting OpenID request for login - No request "
                              "found in session")
                    return self._render.errorPage(environ, start_response,
                        "An internal error occured possibly due to a request "
                        "that's expired.  Please retry from the site where "
                        "you entered your OpenID.  If the problem persists "
                        "report it to your site administrator.")
                    
                # Get user identifier to check against credentials provided
                if oidRequest.idSelect():
                    # ID select mode enables the user to request specifying
                    # their OpenID Provider without giving a personal user URL 
                    userIdentifier = None
                else:
                    # Get the unique user identifier from the user's OpenID URL
                    userIdentifier = oidRequest.identity.split('/')[-1]
                    
                # Invoke custom authentication interface plugin
                try:
                    self._authN.logon(environ,
                                      userIdentifier,
                                      self.query['username'],
                                      self.query.get('password', ''))
                    
                except AuthNInterfaceError, e:
                    return self._render.login(environ, start_response,
                                          msg=e.userMsg,
                                          success_to=self.urls['url_decide'])                   
                except Exception, e:
                    log.error("Unexpected exception raised during "
                              "authentication: %s" % e)
                    msg = ("An internal error occured.  "
                           "Please try again or if the problems persists "
                           "contact your system administrator.")

                    response = self._render.login(environ, start_response,
                                      msg=msg,
                                      success_to=self.urls['url_decide'])
                    return response
                       
                self.session['username'] = self.query['username']
                self.session['approved'] = {}
                self.session.save()
            else:
                # logout
                if 'username' not in self.session:
                    log.error("No user is logged in")
                    return self._redirect(start_response,self.query['fail_to'])
                
                del self.session['username']
                self.session.pop('approved', None)
                self.session.save()
                
            return self._redirect(start_response, self.query['success_to'])
        
        elif 'cancel' in self.query:
            return self._redirect(start_response, self.query['fail_to'])
        else:
            log.error('Login input not recognised %r' % self.query)
            return self._redirect(start_response, self.query['fail_to'])
            

    def do_mainpage(self, environ, start_response):
        '''Show an information page about the OpenID Provider
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response
        '''    
        response = self._render.mainPage(environ, start_response)
        return response

    def _getRender(self):
        """Get method for rendering interface object
        @rtype: RenderingInterface
        @return: rendering interface object
        """
        return self._render
    
    render = property(fget=_getRender, doc="Rendering interface instance")
    
    
    def do_decide(self, environ, start_response):
        """Display page prompting the user to decide whether to trust the site
        requesting their credentials
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: standard WSGI callable to set HTTP headers
        @rtype: basestring
        @return: WSGI response
        """

        oidRequest = self.session.get('lastCheckIDRequest')
        if oidRequest is None:
            log.error("No OpenID request set in session")
            return self._render.errorPage(environ, start_response,
                                          "Invalid request.  Please report "
                                          "the error to your site "
                                          "administrator.",
                                          code=400)
        
        approvedRoots = self.session.get('approved', {})
        
        if oidRequest.trust_root in approvedRoots and \
           not oidRequest.idSelect():
            try:
                response = self._identityApprovedPostProcessing(oidRequest, 
                                                        oidRequest.identity)
            except (OpenIDProviderMissingRequiredAXAttrs, 
                    OpenIDProviderMissingAXResponseHandler):
                response = self._render.errorPage(environ, start_response,
                    'The site where you wish to signin requires '
                    'additional information which this site isn\'t '
                    'configured to provide.  Please report this fault to '
                    'your site administrator.')
                return response
                    
            except Exception, e:
                log.error("Setting response following ID Approval: %s" % e)
                response = self._render.errorPage(environ, start_response,
                        'An error occurred setting additional parameters '
                        'required by the site requesting your ID.  Please '
                        'report this fault to your site administrator.')
                return response

            return self.oidResponse(response)
        else:
            return self._render.decidePage(environ, start_response, oidRequest)
        
        
    def _identityIsAuthorized(self, oidRequest):
        '''Check that a user is authorized i.e. does a session exist for their
        username and if so does it correspond to the identity URL provided.
        This last check doesn't apply for ID Select mode where No ID was input
        at the Relying Party.
        
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Request object
        @rtype: bool
        @return: True/False is user authorized
        '''
        username = self.session.get('username')
        if username is None:
            return False

        if oidRequest.idSelect():
            log.debug("OpenIDProviderMiddleware._identityIsAuthorized - "
                      "ID Select mode set but user is already logged in")
            return True
        
        identifiers = self._authN.username2UserIdentifiers(self.environ,
                                                           username)
        idURLBase = self.urls['url_id']+'/'
        identityURLs = [idURLBase+i for i in identifiers]
        if oidRequest.identity not in identityURLs:
            log.debug("OpenIDProviderMiddleware._identityIsAuthorized - "
                      "user is already logged in with a different ID=%s" % \
                      username)
            return False
        
        log.debug("OpenIDProviderMiddleware._identityIsAuthorized - "
                  "user is logged in with ID matching ID URL")
        return True
    
    
    def _trustRootIsAuthorized(self, trust_root):
        '''Return True/False for the given trust root (Relying Party) 
        previously been approved by the user
        
        @type trust_root: dict
        @param trust_root: keyed by trusted root (Relying Party) URL and 
        containing string item 'always' if approved
        @rtype: bool
        @return: True - trust has already been approved, False - trust root is
        not approved'''
        approvedRoots = self.session.get('approved', {})
        return approvedRoots.get(trust_root) is not None


    def _addSRegResponse(self, oidRequest, oidResponse):
        '''Add Simple Registration attributes to response to Relying Party
        
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @type oidResponse: openid.server.server.OpenIDResponse
        @param oidResponse: OpenID response object'''
        
        if self.sregResponseHandler is None:
            # No Simple Registration response object was set
            return
        
        sreg_req = sreg.SRegRequest.fromOpenIDRequest(oidRequest)

        # Callout to external callable sets additional user attributes to be
        # returned in response to Relying Party        
        sreg_data = self.sregResponseHandler(self.session.get('username'))
        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        oidResponse.addExtension(sreg_resp)


    def _addAXResponse(self, oidRequest, oidResponse):
        '''Add attributes to response based on the OpenID Attribute Exchange 
        interface
        
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @type oidResponse: openid.server.server.OpenIDResponse
        @param oidResponse: OpenID response object'''


        ax_req = ax.FetchRequest.fromOpenIDRequest(oidRequest)
        if ax_req is None:
            log.debug("No Attribute Exchange extension set in request")
            return
        
        ax_resp = ax.FetchResponse(request=ax_req)
        
        if self.axResponseHandler is None:
            requiredAttr = ax_req.getRequiredAttrs()
            if len(requiredAttr) > 0:
                msg = ("Relying party requires these attributes: %s; but No"
                       "Attribute exchange handler 'axResponseHandler' has "
                       "been set" % requiredAttr)
                log.error(msg)
                raise OpenIDProviderMissingAXResponseHandler(msg)
            
            return
        
        # Set requested values - need user intervention here to confirm 
        # release of attributes + assignment based on required attributes - 
        # possibly via FetchRequest.getRequiredAttrs()
        try:
            self.axResponseHandler(ax_req,ax_resp,self.session.get('username'))
            
        except OpenIDProviderMissingRequiredAXAttrs, e:
            log.error("OpenID Provider is unable to set the AX attributes "
                      "required by the Relying Party's request: %s" % e)
            raise
        
        except Exception, e:
            log.error("%s exception raised setting requested Attribute "
                      "Exchange values: %s" % (e.__class__, e))
            raise
        
        oidResponse.addExtension(ax_resp)
        
        
    def _identityApprovedPostProcessing(self, oidRequest, identifier=None):
        '''Action following approval of a Relying Party by the user.  Add
        Simple Registration and/or Attribute Exchange parameters if handlers
        were specified - See _addSRegResponse and _addAXResponse methods - and
        only if the Relying Party has requested them
        
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @type identifier: basestring
        @param identifier: OpenID selected by user - for ID Select mode only
        @rtype: openid.server.server.OpenIDResponse
        @return: OpenID response object'''

        oidResponse = oidRequest.answer(True, identity=identifier)
        self._addSRegResponse(oidRequest, oidResponse)
        self._addAXResponse(oidRequest, oidResponse)
        
        return oidResponse


    def _handleCheckIDRequest(self, oidRequest):
        """Handle "checkid_immediate" and "checkid_setup" type requests from
        Relying Party
        
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID request
        @rtype: basestring
        @return: WSGI response
        """
        log.debug("OpenIDProviderMiddleware._handleCheckIDRequest ...")
        
        # Save request
        self.session['lastCheckIDRequest'] = oidRequest
        self.session.save()
        
        if self._identityIsAuthorized(oidRequest):
            
            # User is logged in - check for ID Select type request i.e. the
            # user entered their IdP address at the Relying Party and not their
            # OpenID Identifier.  In this case, the identity they wish to use
            # must be confirmed.
            if oidRequest.idSelect():
                # OpenID identifier must be confirmed
                return self.do_decide(self.environ, self.start_response)
            
            elif self._trustRootIsAuthorized(oidRequest.trust_root):
                # User has approved this Relying Party
                try:
                    oidResponse = self._identityApprovedPostProcessing(
                                                                    oidRequest)
                except (OpenIDProviderMissingRequiredAXAttrs, 
                        OpenIDProviderMissingAXResponseHandler):
                    response = self._render.errorPage(environ, start_response,
                        'The site where you wish to signin requires '
                        'additional information which this site isn\'t '
                        'configured to provide.  Please report this fault to '
                        'your site administrator.')
                    return response
                    
                except Exception, e:
                    log.error("Setting response following ID Approval: %s" % e)
                    response = self._render.errorPage(environ, start_response,
                        'An error occurred setting additional parameters '
                        'required by the site requesting your ID.  Please '
                        'report this fault to your site administrator.')
                    return response
                
                return self._displayResponse(oidResponse)
            else:
                return self.do_decide(self.environ, self.start_response)
                
        elif oidRequest.immediate:
            oidResponse = oidRequest.answer(False)
            return self._displayResponse(oidResponse)
        
        else:
            # User is not logged in
            
            # Call login and if successful then call decide page to confirm
            # user wishes to trust the Relying Party.
            response = self.do_login(self.environ,
                                     self.start_response,
                                     success_to=self.urls['url_decide'])
            return response


    def _displayResponse(self, oidResponse):
        """Serialize an OpenID Response object, set headers and return WSGI
        response.
        
        If the URL length for a GET request exceeds a maximum, then convert the
        response into a HTML form and use POST method.
        
        @type oidResponse: openid.server.server.OpenIDResponse
        @param oidResponse: OpenID response object
        
        @rtype: basestring
        @return: WSGI response'''
        """
        
        try:
            webresponse = self.oidserver.encodeResponse(oidResponse)
        except server.EncodingError, why:
            text = why.response.encodeToKVForm()
            return self.showErrorPage(text)
        
        hdr = webresponse.headers.items()
        
        # If the content length exceeds the maximum to represent on a URL, it's
        # rendered as a form instead
        # FIXME: Commented out oidResponse.renderAsForm() test as it doesn't 
        # give consistent answers.  Testing based on body content should work
        # OK
        if webresponse.body:
        #if oidResponse.renderAsForm():
            # Wrap in HTML with Javascript OnLoad to submit the form
            # automatically without user intervention
            response = OpenIDProviderMiddleware.formRespWrapperTmpl % \
                                                        webresponse.body
        else:
            response = webresponse.body
            
        hdr += [('Content-type', 'text/html'+self.charset),
                ('Content-length', str(len(response)))]
            
        self.start_response('%d %s' % (webresponse.code, 
                                       httplib.responses[webresponse.code]), 
                            hdr)
        return response


    def _redirect(self, start_response, url):
        """Do a HTTP 302 redirect
        
        @type start_response: callable following WSGI start_response convention
        @param start_response: WSGI start response callable
        @type url: basestring
        @param url: URL to redirect to
        @rtype: list
        @return: empty HTML body
        """
        start_response('302 %s' % httplib.responses[302], 
                       [('Content-type', 'text/html'+self.charset),
                        ('Location', url)])
        return []
    
    
class RenderingInterfaceError(Exception):
    """Base class for RenderingInterface exceptions
    
    A standard message is raised set by the msg class variable but the actual
    exception details are logged to the error log.  The use of a standard 
    message enables callers to use its content for user error messages.
    
    @type msg: basestring
    @cvar msg: standard message to be raised for this exception"""
    userMsg = ("An internal error occurred with the page layout,  Please "
               "contact your system administrator")
    errorMsg = "RenderingInterface error"
    
    def __init__(self, *arg, **kw):
        if len(arg) > 0:
            msg = arg[0]
        else:
            msg = self.__class__.errorMsg
            
        log.error(msg)
        Exception.__init__(self, msg, **kw)
        
class RenderingInterfaceInitError(RenderingInterfaceError):
    """Error with initialisation of RenderingInterface.  Raise from __init__"""
    errorMsg = "RenderingInterface initialisation error"
    
class RenderingInterfaceConfigError(RenderingInterfaceError):
    """Error with Authentication configuration.  Raise from __init__"""
    errorMsg = "RenderingInterface configuration error"    
    
class RenderingInterface(object):
    """Interface class for rendering of OpenID Provider pages.  It implements
    methods for handling Yadis requests only.  All other interface methods
    return a 404 error response.  Create a derivative from this class to 
    implement the other rendering methods as required.  DemoRenderingInterface
    provides an example of how to do this.  To apply a custom 
    RenderingInterface class pass it's name in the OpenIDProviderMiddleware
    app_conf dict or as a keyword argument using the option name 
    renderingClass.
    
    @cvar tmplServerYadis: template for returning Yadis document to Relying 
    Party.  Derived classes can reset this or completely override the 
    serverYadis method.
    
    @type tmplServerYadis: basestring
    
    @cvar tmplYadis: template for returning Yadis document containing user
    URL to Relying Party.  Derived classes can reset this or completely 
    override the yadis method.
    
    @type tmplYadis: basestring"""
   
    tmplServerYadis = """\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($OptNameSfx*2.0)">
  <XRD>

    <Service priority="0">
      <Type>%(openid20type)s</Type>
      <URI>%(endpoint_url)s</URI>
    </Service>

  </XRD>
</xrds:XRDS>
"""

    tmplYadis = """\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>

    <Service priority="0">
      <Type>%(openid20type)s</Type>
      <Type>%(openid10type)s</Type>
      <URI>%(endpoint_url)s</URI>
      <LocalID>%(user_url)s</LocalID>
    </Service>

  </XRD>
</xrds:XRDS>"""    
   
    def __init__(self, authN, base_url, urls, **opt):
        """
        @type authN: AuthNInterface
        @param param: reference to authentication interface to enable OpenID
        user URL construction from username
        @type base_url: basestring
        @param base_url: base URL for OpenID Provider to which individual paths
        are appended
        @type urls: dict
        @param urls: full urls for all the paths used by all the exposed 
        methods - keyed by method name - see OpenIDProviderMiddleware.paths
        @type opt: dict
        @param opt: additional custom options passed from the 
        OpenIDProviderMiddleware config
        """
        self._authN = authN
        self.base_url = base_url
        self.urls = urls
        self.charset = ''
    
    
    def serverYadis(self, environ, start_response):
        '''Render Yadis info for ID Select mode request
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        '''
        endpoint_url = self.urls['url_openidserver']
        response = RenderingInterface.tmplServerYadis % \
                                {'openid20type': discover.OPENID_IDP_2_0_TYPE, 
                                 'endpoint_url': endpoint_url}
             
        start_response("200 OK", 
                       [('Content-type', 'application/xrds+xml'),
                        ('Content-length', str(len(response)))])
        return response


    def yadis(self, environ, start_response):
        """Render Yadis document containing user URL
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        # Override this method to implement an alternate means to derive the 
        # username identifier
        userIdentifier = environ['PATH_INFO'].rstrip('/').split('/')[-1]
        
        endpoint_url = self.urls['url_openidserver']
        user_url = self.urls['url_id'] + '/' + userIdentifier
        
        yadisDict = dict(openid20type=discover.OPENID_2_0_TYPE, 
                         openid10type=discover.OPENID_1_0_TYPE,
                         endpoint_url=endpoint_url, 
                         user_url=user_url)
        
        response = RenderingInterface.tmplYadis % yadisDict
     
        start_response('200 OK',
                       [('Content-type', 'application/xrds+xml'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    

    def identityPage(self, environ, start_response):
        """Render the identity page.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        response = "Page is not implemented"
        start_response('%d %s' % (404, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    
        
    def login(self, environ, start_response, 
              success_to=None, fail_to=None, msg=''):
        """Render the login form.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type success_to: basestring
        @param success_to: URL put into hidden field telling  
        OpenIDProviderMiddleware.do_loginsubmit() where to forward to on 
        successful login
        @type fail_to: basestring
        @param fail_to: URL put into hidden field telling  
        OpenIDProviderMiddleware.do_loginsubmit() where to forward to on 
        login error
        @type msg: basestring
        @param msg: display (error) message below login form e.g. following
        previous failed login attempt.
        @rtype: basestring
        @return: WSGI response
        """
        
        response = "Page is not implemented"
        start_response('%d %s' % (404, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response


    def mainPage(self, environ, start_response):
        """Rendering the main page.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """   
        response = "Page is not implemented"
        start_response('%d %s' % (404, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    

    def decidePage(self, environ, start_response, oidRequest):
        """Show page giving the user the option to approve the return of their
        credentials to the Relying Party.  This page is also displayed for
        ID select mode if the user is already logged in at the OpenID Provider.
        This enables them to confirm the OpenID to be sent back to the 
        Relying Party

        These fields should be posted by this page ready for 
        OpenIdProviderMiddleware.do_allow to process:
        
        'Yes'/'No': for return authentication details back to the RP or 
        abort return to RP respectively
        'remember': remember the decision corresponding to the above 'Yes'
        /'No'.
        This may be set to 'Yes' or 'No'
        'identity': set to the user's identity URL.  This usually is not 
        required since it can be obtained from oidRequest.identity attribute
        but in ID Select mode, the identity URL will have been selected or set
        here.
        
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @rtype: basestring
        @return: WSGI response
        """
        response = "Page is not implemented"
        start_response('%d %s' % (404, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response


    def errorPage(self, environ, start_response, msg, code=500):
        """Display error page 
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type msg: basestring
        @param msg: optional message for page body
        @type code: int
        @param code: HTTP Error code to return
        @rtype: basestring
        @return: WSGI response
        """     
        response = "Page is not implemented"
        start_response('%d %s' % (404, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
        
    
class DemoRenderingInterface(RenderingInterface):
    """Example rendering interface class for demonstration purposes"""
   
    def identityPage(self, environ, start_response):
        """Render the identity page.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        path = environ.get('PATH_INFO').rstrip('/')
        userIdentifier = path.split('/')[-1]
        
        link_tag = '<link rel="openid.server" href="%s">' % \
              self.urls['url_openidserver']
              
        yadis_loc_tag = '<meta http-equiv="x-xrds-location" content="%s">' % \
            (self.urls['url_yadis']+'/'+userIdentifier)
            
        disco_tags = link_tag + yadis_loc_tag
        ident = self.base_url + path

        response = self._showPage(environ, 
                                  'Identity Page', 
                                  head_extras=disco_tags, 
                                  msg='<p>This is the identity page for %s.'
                                      '</p>' % ident)
        
        start_response("200 OK", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    
        
    def login(self, environ, start_response, 
              success_to=None, fail_to=None, msg=''):
        """Render the login form.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type success_to: basestring
        @param success_to: URL put into hidden field telling  
        OpenIDProviderMiddleware.do_loginsubmit() where to forward to on 
        successful login
        @type fail_to: basestring
        @param fail_to: URL put into hidden field telling  
        OpenIDProviderMiddleware.do_loginsubmit() where to forward to on 
        login error
        @type msg: basestring
        @param msg: display (error) message below login form e.g. following
        previous failed login attempt.
        @rtype: basestring
        @return: WSGI response
        """
        
        if success_to is None:
            success_to = self.urls['url_mainpage']
            
        if fail_to is None:
            fail_to = self.urls['url_mainpage']
        
        form = '''\
<h2>Login</h2>
<form method="GET" action="%s">
  <input type="hidden" name="success_to" value="%s" />
  <input type="hidden" name="fail_to" value="%s" />
  <table cellspacing="0" border="0" cellpadding="5">
    <tr>
        <td>Username:</td> 
        <td><input type="text" name="username" value=""/></td>
    </tr><tr>
        <td>Password:</td>
        <td><input type="password" name="password"/></td>
    </tr><tr>
        <td colspan="2" align="right">
            <input type="submit" name="submit" value="Login"/>
            <input type="submit" name="cancel" value="Cancel"/>
        </td>
    </tr>
  </table>
</form>
%s
''' % (self.urls['url_loginsubmit'], success_to, fail_to, msg)

        response = self._showPage(environ, 'Login Page', form=form)
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response


    def mainPage(self, environ, start_response):
        """Rendering the main page.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        
        yadis_tag = '<meta http-equiv="x-xrds-location" content="%s">' % \
                    self.urls['url_serveryadis']
        username = environ['beaker.session'].get('username')    
        if username:
            openid_url = self.urls['url_id'] + '/' + username
            user_message = """\
            <p>You are logged in as %s. Your OpenID identity URL is
            <tt><a href=%s>%s</a></tt>. Enter that URL at an OpenID
            consumer to test this server.</p>
            """ % (username, quoteattr(openid_url), openid_url)
        else:
            user_message = "<p>You are not <a href='%s'>logged in</a>.</p>" % \
                            self.urls['url_login']

        msg = '''\
<p>OpenID server</p>

%s

<p>The URL for this server is <a href=%s><tt>%s</tt></a>.</p>
''' % (user_message, quoteattr(self.base_url), self.base_url)
        response = self._showPage(environ,
                                  'Main Page', 
                                  head_extras=yadis_tag, 
                                  msg=msg)
    
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    

    def decidePage(self, environ, start_response, oidRequest):
        """Show page giving the user the option to approve the return of their
        credentials to the Relying Party.  This page is also displayed for
        ID select mode if the user is already logged in at the OpenID Provider.
        This enables them to confirm the OpenID to be sent back to the 
        Relying Party
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @rtype: basestring
        @return: WSGI response
        """
        idURLBase = self.urls['url_id'] + '/'
        
        # XXX: This may break if there are any synonyms for idURLBase,
        # such as referring to it by IP address or a CNAME.
        
        # TODO: OpenID 2.0 Allows oidRequest.identity to be set to 
        # http://specs.openid.net/auth/2.0/identifier_select.  See,
        # http://openid.net/specs/openid-authentication-2_0.html.  This code
        # implements this overriding the behaviour of the example code on
        # which this is based.  - Check is the example code based on OpenID 1.0
        # and therefore wrong for this behaviour?
#        assert oidRequest.identity.startswith(idURLBase), \
#               repr((oidRequest.identity, idURLBase))
        userIdentifier = oidRequest.identity[len(idURLBase):]
        username = environ['beaker.session']['username']
        
        if oidRequest.idSelect(): # We are being asked to select an ID
            userIdentifier = self._authN.username2UserIdentifiers(environ,
                                                                  username)[0]
            identity = idURLBase + userIdentifier
            
            msg = '''\
            <p>A site has asked for your identity.  You may select an
            identifier by which you would like this site to know you.
            On a production site this would likely be a drop down list
            of pre-created accounts or have the facility to generate
            a random anonymous identifier.
            </p>
            '''
            fdata = {
                'pathAllow': self.urls['url_allow'],
                'identity': identity,
                'trust_root': oidRequest.trust_root,
                }
            form = '''\
<form method="POST" action="%(pathAllow)s">
<table>
  <tr><td>Identity:</td>
     <td>%(identity)s</td></tr>
  <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
</table>
<p>Allow this authentication to proceed?</p>
<input type="checkbox" id="remember" name="remember" value="Yes"
    /><label for="remember">Remember this
    decision</label><br />
<input type="hidden" name="identity" value="%(identity)s" />
<input type="submit" name="Yes" value="Yes" />
<input type="submit" name="No" value="No" />
</form>
''' % fdata
            
        elif userIdentifier in self._authN.username2UserIdentifiers(environ,
                                                                    username):
            msg = '''\
            <p>A new site has asked to confirm your identity.  If you
            approve, the site represented by the trust root below will
            be told that you control identity URL listed below. (If
            you are using a delegated identity, the site will take
            care of reversing the delegation on its own.)</p>'''

            fdata = {
                'pathAllow': self.urls['url_allow'],
                'identity': oidRequest.identity,
                'trust_root': oidRequest.trust_root,
                }
            form = '''\
<table>
  <tr><td>Identity:</td><td>%(identity)s</td></tr>
  <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
</table>
<p>Allow this authentication to proceed?</p>
<form method="POST" action="%(pathAllow)s">
  <input type="checkbox" id="remember" name="remember" value="Yes"
      /><label for="remember">Remember this
      decision</label><br />
  <input type="submit" name="Yes" value="Yes" />
  <input type="submit" name="No" value="No" />
</form>''' % fdata
        else:
            mdata = {
                'userIdentifier': userIdentifier,
                'username': username,
                }
            msg = '''\
            <p>A site has asked for an identity belonging to
            %(userIdentifier)s, but you are logged in as %(username)s.  To
            log in as %(userIdentifier)s and approve the login oidRequest,
            hit OK below.  The "Remember this decision" checkbox
            applies only to the trust root decision.</p>''' % mdata

            fdata = {
                'pathAllow': self.urls['url_allow'],
                'identity': oidRequest.identity,
                'trust_root': oidRequest.trust_root,
                'username': username,
                }
            form = '''\
<table>
  <tr><td>Identity:</td><td>%(identity)s</td></tr>
  <tr><td>Trust Root:</td><td>%(trust_root)s</td></tr>
</table>
<p>Allow this authentication to proceed?</p>
<form method="POST" action="%(pathAllow)s">
  <input type="checkbox" id="remember" name="remember" value="Yes"
      /><label for="remember">Remember this
      decision</label><br />
  <input type="hidden" name="login_as" value="%(username)s"/>
  <input type="submit" name="Yes" value="Yes" />
  <input type="submit" name="No" value="No" />
</form>''' % fdata

        response = self._showPage(environ, 'Approve OpenID request?', 
                                  msg=msg, form=form)            
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    

    def _showPage(self, 
                  environ, 
                  title, 
                  head_extras='', 
                  msg=None, 
                  err=None, 
                  form=None):
        """Generic page rendering method.  Derived classes may ignore this.
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type title: basestring
        @param title: page title
        @type head_extras: basestring
        @param head_extras: add extra HTML header elements
        @type msg: basestring
        @param msg: optional message for page body
        @type err: basestring
        @param err: optional error message for page body
        @type form: basestring
        @param form: optional form for page body        
        @rtype: basestring
        @return: WSGI response
        """
        
        username = environ['beaker.session'].get('username')
        if username is None:
            user_link = '<a href="/login">not logged in</a>.'
        else:
            user_link = 'logged in as <a href="%s/%s">%s</a>.<br />'\
                        '<a href="%s?submit=true&'\
                        'success_to=%s">Log out</a>' % \
                        (self.urls['url_id'], username, username, 
                         self.urls['url_loginsubmit'],
                         self.urls['url_login'])

        body = ''

        if err is not None:
            body +=  '''\
            <div class="error">
              %s
            </div>
            ''' % err

        if msg is not None:
            body += '''\
            <div class="message">
              %s
            </div>
            ''' % msg

        if form is not None:
            body += '''\
            <div class="form">
              %s
            </div>
            ''' % form

        contents = {
            'title': 'Python OpenID Provider - ' + title,
            'head_extras': head_extras,
            'body': body,
            'user_link': user_link,
            }

        response = '''<html>
  <head>
    <title>%(title)s</title>
    %(head_extras)s
  </head>
  <style type="text/css">
      h1 a:link {
          color: black;
          text-decoration: none;
      }
      h1 a:visited {
          color: black;
          text-decoration: none;
      }
      h1 a:hover {
          text-decoration: underline;
      }
      body {
        font-family: verdana,sans-serif;
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      table {
        margin: none;
        padding: none;
      }
      .banner {
        padding: none 1em 1em 1em;
        width: 100%%;
      }
      .leftbanner {
        text-align: left;
      }
      .rightbanner {
        text-align: right;
        font-size: smaller;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
        margin: .5em;
      }
      .message {
        border: 1px solid #2233ff;
        background: #eeeeff;
        margin: .5em;
      }
      .form {
        border: 1px solid #777777;
        background: #ddddcc;
        margin: .5em;
        margin-top: 1em;
        padding-bottom: 0em;
      }
      dd {
        margin-bottom: 0.5em;
      }
  </style>
  <body>
    <table class="banner">
      <tr>
        <td class="leftbanner">
          <h1><a href="/">Python OpenID Provider</a></h1>
        </td>
        <td class="rightbanner">
          You are %(user_link)s
        </td>
      </tr>
    </table>
%(body)s
  </body>
</html>
''' % contents

        return response

    def errorPage(self, environ, start_response, msg, code=500):
        """Display error page 
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @type msg: basestring
        @param msg: optional message for page body
        @rtype: basestring
        @return: WSGI response
        """
        
        response = self._showPage(environ, 'Error Processing Request', err='''\
        <p>%s</p>
        <!--

        This is a large comment.  It exists to make this page larger.
        That is unfortunately necessary because of the "smart"
        handling of pages returned with an error code in IE.

        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************
        *************************************************************

        -->
        ''' % msg)
        
        start_response('%d %s' % (code, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
