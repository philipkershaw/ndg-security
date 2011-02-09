"""NDG Security OpenID Provider Middleware

Compliments AuthKit OpenID Middleware used for OpenID *Relying Party*

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import httplib
import sys
import os
import traceback
import logging
log = logging.getLogger(__name__)
_debugLevel = log.getEffectiveLevel() <= logging.DEBUG

import re
from string import Template

import paste.request
from paste.util.import_string import eval_import
from openid.extensions import sreg, ax
from openid.server import server
from openid.store.filestore import FileOpenIDStore
from openid.consumer import discover

from ndg.security.common.utils.classfactory import instantiateClass
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase  


class IdentityMapping(object):
    """Utility class to map between user identifiers and OpenID URIs
    The user identifier is the user unique component of an OpenID URI
    """
    USER_IDENTIFIER_NAME = 'userIdentifier'
    
    # Template substitution may or may not contain braces
    USER_IDENTIFIER_RE = re.compile('\$\{?%s\}?' % USER_IDENTIFIER_NAME)
    
    @classmethod
    def userIdentifier2IdentityURI(cls, identityUriTmpl, userIdentifier):
        """Convert an OpenID user identifier into an identity URI given a
        template e.g.
        
        https://${userIdentifier}.openid.ac.uk + pjk => https://pjk.openid.ac.uk
        """
        mapping = {cls.USER_IDENTIFIER_NAME: userIdentifier}
        tmpl = Template(identityUriTmpl)
        return tmpl.substitute(mapping)
        
    @classmethod
    def identityUri2UserIdentifier(cls, identityUriTmpl, identityUri):
        """Parse an OpenID user identifier from an identity URI given a
        template e.g.
        
        https://pjk.openid.ac.uk + https://${userIdentifier}.openid.ac.uk => pjk
        """
        # Subtract start and end URI snippets from the template
        try:
            uriPrefix, uriSuffix = cls.USER_IDENTIFIER_RE.split(identityUriTmpl)
        except ValueError:
            raise OpenIDProviderConfigError('Error parsing identity URI %r '
                                            'using template %r' %
                                            (identityUri, identityUriTmpl))
            
        if not identityUri.startswith(uriPrefix): 
            raise OpenIDProviderConfigError('Identity URI %r doesn\'t match '
                                            'the template prefix %r' %
                                            (identityUri, uriPrefix))
            
        suffixIndex = identityUri.rfind(uriSuffix)    
        if suffixIndex == -1: 
            raise OpenIDProviderConfigError('Identity URI %r doesn\'t match '
                                            'the template suffix %r' %
                                            (identityUri, uriSuffix))
        
        userIdentifier = identityUri[:suffixIndex].replace(uriPrefix, '', 1)
        return userIdentifier
 
# Place here to avoid circular import error with IdentityMapping class     
from ndg.security.server.wsgi.openid.provider.authninterface import \
    AbstractAuthNInterface, AuthNInterfaceError
from ndg.security.server.wsgi.openid.provider.axinterface import AXInterface,\
    MissingRequiredAttrs, AXInterfaceReloginRequired


# Aliases to AXInterface exception types    
class OpenIDProviderMissingRequiredAXAttrs(MissingRequiredAttrs): 
    """Raise if a Relying Party *requires* one or more attributes via
    the AX interface but this OpenID Provider cannot return them.  This 
    doesn't apply to attributes that are optional"""

class OpenIDProviderReloginRequired(AXInterfaceReloginRequired):
    pass

# end aliases to AXInterface exception types


class OpenIDProviderMiddlewareError(Exception):
    """OpenID Provider WSGI Middleware Error"""

class OpenIDProviderConfigError(OpenIDProviderMiddlewareError):
    """OpenID Provider Configuration Error"""


class OpenIDProviderMissingAXResponseHandler(OpenIDProviderMiddlewareError): 
    """Raise if a Relying Party *requires* one or more attributes via
    the AX interface but no AX Response handler has been set"""
  
  
class OpenIDProviderMiddleware(NDGSecurityMiddlewareBase):
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
        path_id='/id/${userIdentifier}',
        path_yadis='/yadis/${userIdentifier}',
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
    
    defPaths = dict([(k, v) for k, v in defOpt.items() 
                     if k.startswith('path_')])
    
    userIdentifierPat = '([^/]*)'
    
    USERNAME_SESSION_KEYNAME = 'username'
    IDENTITY_URI_SESSION_KEYNAME = 'identityURI'
    APPROVED_FLAG_SESSION_KEYNAME = 'approved'
    LAST_CHECKID_REQUEST_SESSION_KEYNAME = 'lastCheckIDRequest'
    PARAM_PREFIX = 'openid.provider.'
    
    IDENTITY_URI_TMPL_PARAMNAME = 'identityUriTemplate'
    
    def __init__(self, app, app_conf=None, prefix=PARAM_PREFIX, **kw):
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
        self._app = app
        self._environ = {}
        self._start_response = None
        self._pathInfo = None
        self._path = None
        self.mountPath = '/'

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
                                         for k, v in opt.items() 
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


        self.identityUriTmpl = opt.get(
                        OpenIDProviderMiddleware.IDENTITY_URI_TMPL_PARAMNAME)
        if not self.identityUriTmpl:
            raise TypeError("%s is not set" % 
                        OpenIDProviderMiddleware.IDENTITY_URI_TMPL_PARAMNAME)
        
        # Full Paths
        self.urls = dict([(k.replace('path_', 'url_'), self.base_url + v)
                          for k, v in self.paths.items()])

        self.method = dict([(v, k.replace('path_', 'do_'))
                            for k, v in self.paths.items()])

        self.session_middleware = opt['session_middleware']

        if not opt['charset']:
            self.charset = ''
        else:
            self.charset = '; charset=' + charset
        
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
                                         for k, v in opt.items() 
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
            
        # Class to handle OpenID Attribute Exchange (AX) requests from
        # the Relying Party
        axResponseClassName = opt.pop('axResponse_class', None)
        if axResponseClassName is None:
            # No AX Response handler set
            self.axResponse = None
        else:
            axResponseModuleFilePath = opt.pop('axResponse_moduleFilePath',
                                               None)
            axResponseProperties = dict(
                [(k.replace('axResponse_', ''), v) 
                 for k,v in opt.items() if k.startswith('axResponse_')])
               
            try:
                self.axResponse = instantiateClass(
                                    axResponseClassName, 
                                    None, 
                                    moduleFilePath=axResponseModuleFilePath,
                                    objectType=AXInterface, 
                                    classProperties=axResponseProperties)
            except Exception, e:
                log.error("Error instantiating AX interface: %s" % e)
                raise
        
        # Instantiate OpenID consumer store and OpenID consumer.  If you
        # were connecting to a database, you would create the database
        # connection and instantiate an appropriate store here.
        store = FileOpenIDStore(
                            os.path.expandvars(opt['consumer_store_dirpath']))
        self.oidserver = server.Server(store, self.urls['url_openidserver'])
        
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
               not optName.startswith('rendering_') and \
               not optName.startswith('axResponse_')
               
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
                       
    def _matchIdentityURI(self):
        idPaths = (self.paths['path_id'], self.paths['path_yadis'])
        idPathMatches = [Template(path).substitute(
                    userIdentifier=OpenIDProviderMiddleware.userIdentifierPat)
                    for path in idPaths]
        
        for idPathMatch, idPath in zip(idPathMatches, idPaths):
            if re.search(idPathMatch, self.path):
                return idPath
            
        return None

    def _isAnIdentityURI(self):
        """Check input URI is an identity URI.  Use to determine whether a
        RP discovery request has been made based on a provided user OpenID. 
        i.e. do_id / do_yadis should be invoked - see __call__ method for 
        details.  It takes the identity portion of the URI from the config
        path_id / path_yadis settings - which ever matches e.g.
        
        <http/https>://<domainname>/<path>/${userIdentifier}
        
        e.g.
        
        https://badc.rl.ac.uk/openid/johnsmith
        
        This method should be overridden in a derived class if some
        other means of representing identity URIs is required. e.g.
        
        https://johnsmith.badc.rl.ac.uk
        
        but note also see _matchIdentityURI method
        
        @rtype: bool
        @return: return True if the given URI is an identity URI, otherwise
        False
        """        
        return self._matchIdentityURI() is not None

    def _parseIdentityURI(self):
        '''Split path into identity and path fragment components
        
        @rtype: list
        @return: 2 element list containing the Identity URI path fragment and
        user identifier respectively.
        '''
        return OpenIDProviderMiddleware.parseIdentityURI(self.path)   

    @classmethod
    def parseIdentityURI(cls, uri):
        '''Split uri into identity and uri fragment components
        
        FIXME: this method assumes a fixed identity URI scheme and should be
        refactored to use a template based parsing
        
        @type uri: basestring
        @param uri: identity URI to be parsed
        @rtype: list
        @return: 2 element list containing the Identity URI fragment and
        user identifier respectively.
        '''
        return uri.rsplit('/', 1)
    
    @classmethod
    def createIdentityURI(cls, uri, userIdentifier):
        '''This method is the compliment to parseIdentityURI.  Make an OpenID
        URI from a user identifier and URI fragment
        
        @type uri: basestring
        @param uri: identity URI containing $userIdentifier where user id is
        to be substituted in 
        @type userIdentifier: basestring
        @param userIdentifier: identity URI to be parsed
        @rtype: basestring
        @return: user OpenID URI
        '''
        return Template(uri).substitute(userIdentifier=userIdentifier)
        
    @NDGSecurityMiddlewareBase.initCall
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
                                            'session middleware?' %
                                            self.session_middleware)

        # Beware path is a property and invokes the _setPath method
        self.session = environ[self.session_middleware]
        self._render.session = self.session
        
        pathMatch = self._matchIdentityURI()
        if not pathMatch:
            pathMatch = self.path

        if pathMatch in self.method:
            # Calls to parse_formvars seem to gobble up the POST content such
            # that a 2nd call yields nothing! (with Paste 1.7.1) 
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
            return self._setResponse(environ, start_response)

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
        form created by the RenderingInterface.decidePage method called by 
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
        
        oidRequest = self.session.get(
                    OpenIDProviderMiddleware.LAST_CHECKID_REQUEST_SESSION_KEYNAME)
        if oidRequest is None:
            log.error("Suspected do_allow called from stale request")
            return self._render.errorPage(environ, start_response,
                                          "Invalid request.  Please report "
                                          "this fault to your site "
                                          "administrator.",
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
                                                  "OpenID user identity.  "
                                                  "Please report this fault "
                                                  "to your site "
                                                  "administrator.")
            else:
                identity = oidRequest.identity

            trust_root = oidRequest.trust_root
            if self.query.get('remember', 'No') == 'Yes':
                self.session[
                    OpenIDProviderMiddleware.APPROVED_FLAG_SESSION_KEYNAME] = {
                        trust_root: 'always'
                    }
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
                log.error("%s type exception raised setting response "
                          "following ID Approval: %s", e.__class__.__name__,e)
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
            log.error('Setting response following ID Approval: expecting '
                      'Yes/No in allow post. %r' % self.query)
            return self._render.errorPage(environ, start_response,
                                          'Error setting Yes/No response to '
                                          'return your credentials back to '
                                          'the requesting site.  Please '
                                          'report this fault to your site '
                                          'administrator.',
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
                if OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME in \
                   self.session:
                    log.error("Attempting login for user %s: user is already "
                              "logged in", self.session[
                            OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME])
                    
                    return self._redirect(start_response,
                                          self.query['fail_to'])
                
                oidRequest = self.session.get(
                OpenIDProviderMiddleware.LAST_CHECKID_REQUEST_SESSION_KEYNAME)
                
                if oidRequest is None:
                    log.error("Getting OpenID request for login - No request "
                              "found in session")
                    return self._render.errorPage(environ, start_response,
                        "An internal error occurred possibly due to a request "
                        "that's expired.  Please retry from the site where "
                        "you entered your OpenID.  If the problem persists "
                        "report it to your site administrator.")
                    
                # Get user identifier to check against credentials provided
                if oidRequest.idSelect():
                    # ID select mode enables the user to request specifying
                    # their OpenID Provider without giving a personal user URL 
                    userIdentifiers = self._authN.username2UserIdentifiers(
                                                        environ,
                                                        self.query['username'])
                    if not isinstance(userIdentifiers, (list, tuple)):
                        log.error("Unexpected type %r returned from %r for "
                                  "user identifiers; expecting list or tuple"
                                  % (type(userIdentifiers), type(self._authN)))
                                  
                        return self._render.errorPage(environ, start_response,
                            "An internal error occurred setting your default "
                            "OpenID URL.  Please retry from the site where "
                            "you entered your OpenID providing your full "
                            "identity URL.  If the problem persists report it "
                            "to your site administrator.")
                        
                    # FIXME: Assume the *first* user identifier entry is the
                    # one to use.  The user could have multiple identifiers
                    # but in practice it's more manageable to have a single one
                    identityURI = self.createIdentityURI(self.identityUriTmpl,
                                                         userIdentifiers[0])
                else:
                    # Get the unique user identifier from the user's OpenID URL
                    identityURI = oidRequest.identity
                    
                # Invoke custom authentication interface plugin
                try:
                    self._authN.logon(environ,
                                      identityURI,
                                      self.query['username'],
                                      self.query.get('password', ''))
                    
                except AuthNInterfaceError, e:
                    return self._render.login(environ, start_response,
                                            msg=e.userMsg,
                                            success_to=self.urls['url_decide'])                   
                except Exception, e:
                    log.error("Unexpected %s type exception raised during "
                              "authentication: %s", type(e),
                              traceback.format_exc())
                    msg = ("An internal error occurred.  "
                           "Please try again or if the problems persists "
                           "contact your system administrator.")

                    response = self._render.login(environ, start_response,
                                          msg=msg,
                                          success_to=self.urls['url_decide'])
                    return response
                       
                self.session[
                    OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME
                ] = self.query['username']
                
                self.session[
                    OpenIDProviderMiddleware.IDENTITY_URI_SESSION_KEYNAME
                ] = identityURI
                
                self.session[
                    OpenIDProviderMiddleware.APPROVED_FLAG_SESSION_KEYNAME] = {}
                    
                self.session.save()
                
                log.info("user [%s] logged in", self.session[
                        OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME])
            else:
                # logout
                if OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME not in \
                   self.session:
                    log.error("No user is logged in")
                    return self._redirect(start_response, 
                                          self.query['fail_to'])
                
                log.info("user [%s] logging out ...", self.session[
                        OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME])

                del self.session[
                        OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME]
                self.session.pop(
                        OpenIDProviderMiddleware.APPROVED_FLAG_SESSION_KEYNAME, 
                        None)
                self.session.save()
                
                try:
                    self._authN.logout()
                    
                except Exception:
                    log.error("Unexpected exception raised during "
                              "logout: %s" % traceback.format_exc())
                    msg = ("An internal error occured during logout.  If the "
                           "problem persists contact your system "
                           "administrator.")

                    response = self._render.errorPage(environ, start_response,
                                                      msg) 
                    return response
                
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
        oidRequest = self.session.get(
                    OpenIDProviderMiddleware.LAST_CHECKID_REQUEST_SESSION_KEYNAME)
        if oidRequest is None:
            log.error("No OpenID request set in session")
            return self._render.errorPage(environ, start_response,
                                          "Invalid request.  Please report "
                                          "the error to your site "
                                          "administrator.",
                                          code=400)
        
        approvedRoots = self.session.get(
                            OpenIDProviderMiddleware.APPROVED_FLAG_SESSION_KEYNAME, 
                            {})
        
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
                log.error("%s type exception raised setting response "
                          "following ID Approval: %s", 
                          e.__class__.__name__,
                          traceback.format_exc())
                response = self._render.errorPage(environ, start_response,
                        'An error occurred setting additional parameters '
                        'required by the site requesting your ID.  Please '
                        'report this fault to your site administrator.')
                return response

            return self.oidResponse(response)
        else:
            try:
                return self._render.decidePage(environ, 
                                               start_response, 
                                               oidRequest)
            except AuthNInterfaceError, e:
                log.error("%s type exception raised calling decide page "
                          "rendering - an OpenID identifier look-up error? "
                          "message is: %s", e.__class__.__name__,
                          traceback.format_exc())
                response = self._render.errorPage(environ, start_response,
                        'An error has occurred displaying an options page '
                        'which checks whether you want to return to the site '
                        'requesting your ID.  Please report this fault to '
                        'your site administrator.')
                return response

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
        username = self.session.get(
                            OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME)
        if username is None:
            return False

        if oidRequest.idSelect():
            log.debug("OpenIDProviderMiddleware._identityIsAuthorized - "
                      "ID Select mode set but user is already logged in")
            return True
        
        identityURI = self.session.get(
                        OpenIDProviderMiddleware.IDENTITY_URI_SESSION_KEYNAME)
        if identityURI is None:
            return False
        
        if oidRequest.identity != identityURI:
            log.debug("OpenIDProviderMiddleware._identityIsAuthorized - user "
                      "is already logged in with a different ID=%s and "
                      "identityURI=%s" %
                      (username, identityURI))
            return False
        
        log.debug("OpenIDProviderMiddleware._identityIsAuthorized - "
                  "user is logged in with ID matching ID URI")
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
        approvedRoots = self.session.get(
                        OpenIDProviderMiddleware.APPROVED_FLAG_SESSION_KEYNAME, 
                        {})
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
        sreg_data = self.sregResponseHandler(self.session.get(
                            OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME))
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
        
        if self.axResponse is None:
            requiredAttr = ax_req.getRequiredAttrs()
            if len(requiredAttr) > 0:
                msg = ("Relying party requires these attributes: %s; but No"
                       "Attribute exchange handler 'axResponseHandler' has "
                       "been set" % requiredAttr)
                log.error(msg)
                raise OpenIDProviderMissingAXResponseHandler(msg)
            
            return
        
        log.debug("Calling AX plugin: %s ...",
                  self.axResponse.__class__.__name__)
        
        # Set requested values - need user intervention here to confirm 
        # release of attributes + assignment based on required attributes - 
        # possibly via FetchRequest.getRequiredAttrs()
        try:
            self.axResponse(ax_req, ax_resp, self._authN, self.session)
        
        except OpenIDProviderMissingRequiredAXAttrs, e:
            log.error("OpenID Provider is unable to set the AX attributes "
                      "required by the Relying Party's request: %s" % e)
            raise
        
        except OpenIDProviderReloginRequired, e:
            log.exception(e)
            raise
        
        except Exception, e:
            log.error("%s exception raised setting requested Attribute "
                      "Exchange values: %s", 
                      e.__class__.__name__, 
                      traceback.format_exc())
            raise
        
        log.debug("Adding AX parameters to response: %s ...", ax_resp)
        oidResponse.addExtension(ax_resp)
        log.debug("Added AX parameters to response")
        
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
        self.session[
            OpenIDProviderMiddleware.LAST_CHECKID_REQUEST_SESSION_KEYNAME
        ] = oidRequest
        
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
                    response = self._render.errorPage(self.environ, 
                                                      self.start_response,
                        'The site where you wish to signin requires '
                        'additional information which this site isn\'t '
                        'configured to provide.  Please report this fault to '
                        'your site administrator.')
                    return response
                    
                except OpenIDProviderReloginRequired, e:
                    response = self._render.errorPage(self.environ, 
                                                      self.start_response,
                        'An error occurred setting additional parameters '
                        'required by the site requesting your ID.  Please '
                        'try logging in again.')
                    return response
                    
                except Exception, e:
                    log.error("%s type exception raised setting response "
                              "following ID Approval: %s", 
                              e.__class__.__name__, 
                              traceback.format_exc())
                    response = self._render.errorPage(self.environ,
                                                      self.start_response,
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
            response = self._render.errorPage(environ, start_response, text)
            return response
        
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
            
        hdr += [('Content-type', 'text/html' + self.charset),
                ('Content-length', str(len(response)))]
            
        self.start_response('%d %s' % (webresponse.code,
                                       httplib.responses[webresponse.code]),
                            hdr)
        return response

    def _redirect(self, start_response, url):
        """Do a HTTP 302 redirect
        
        @type start_response: function
        @param start_response: WSGI start response callable
        @type url: basestring
        @param url: URL to redirect to
        @rtype: list
        @return: empty HTML body
        """
        start_response('302 %s' % httplib.responses[302],
                       [('Content-type', 'text/html' + self.charset),
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
    """Error with configuration settings.  Raise from __init__"""
    errorMsg = "RenderingInterface configuration error"    
    
    
class RenderingInterface(object):
    """Interface class for rendering of OpenID Provider pages.  It implements
    methods for handling Yadis requests only.  All other interface methods
    return a 404 error response.  Create a derivative from this class to 
    implement the other rendering methods as required.  
    ndg.security.server.wsgi.openid.provider.renderingInterface.demo.DemoRenderingInterface
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
    
    # Enable slot support for derived classes if they require it 
    __slots__ = ('_authN', 'base_url', 'urls', 'charset')
    
    tmplServerYadis = """\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
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
        userIdentifier = OpenIDProviderMiddleware.parseIdentityURI(
                                                    environ['PATH_INFO'])[-1]
        
        endpoint_url = self.urls['url_openidserver']
        user_url = self.urls['url_id'] + '/' + userIdentifier
        
        yadisDict = dict(openid20type=discover.OPENID_2_0_TYPE,
                         openid10type=discover.OPENID_1_0_TYPE,
                         endpoint_url=endpoint_url,
                         user_url=user_url)
        
        response = RenderingInterface.tmplYadis % yadisDict
     
        start_response('200 OK',
                       [('Content-type', 'application/xrds+xml' + self.charset),
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
        start_response('%d %s' % (404, httplib.responses[404]),
                       [('Content-type', 'text/html' + self.charset),
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
        start_response('%d %s' % (404, httplib.responses[404]),
                       [('Content-type', 'text/html' + self.charset),
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
        start_response('%d %s' % (404, httplib.responses[404]),
                       [('Content-type', 'text/html' + self.charset),
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
        start_response('%d %s' % (404, httplib.responses[404]),
                       [('Content-type', 'text/html' + self.charset),
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
                       [('Content-type', 'text/html' + self.charset),
                        ('Content-length', str(len(response)))])
        return response
        
