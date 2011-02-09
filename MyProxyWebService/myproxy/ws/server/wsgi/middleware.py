"""MyProxy WSGI middleware - places a MyProxy client instance in environ for
other downstream middleware or apps to access and use
 
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)
import traceback
import socket
import httplib
import base64
import re

from webob import Request
from OpenSSL import crypto

from myproxy.client import MyProxyClient, MyProxyClientError
from myproxy.ws.server.wsgi.httpbasicauth import HttpBasicAuthResponseException
  

class MyProxyClientMiddlewareError(Exception):
    """Runtime error with MyProxyClientMiddleware"""

       
class MyProxyClientMiddlewareConfigError(MyProxyClientMiddlewareError):
    """Configuration error with MyProxyClientMiddleware"""


class MyProxyClientMiddlewareBase(object):
    """Base class for common functionality
    
    @cvar CLIENT_ENV_KEYNAME_OPTNAME: ini file option which sets the key name
    in the WSGI environ for referring to the MyProxy client instance shared
    between MyProxy* middleware/apps
    @type CLIENT_ENV_KEYNAME_OPTNAME: string
    
    @cvar DEFAULT_CLIENT_ENV_KEYNAME: default value for key name set in the
    WSGI environ dict which refers to the MyProxy client instance shared
    between MyProxy* middleware/apps
    @type DEFAULT_CLIENT_ENV_KEYNAME: string
    
    @ivar __app: WSGI callable for next middleware or app in the WSGI stack
    @type __app: function
    
    @ivar __clientEnvironKeyName: key name set in the WSGI environ dict which 
    refers to the MyProxy client instance shared between MyProxy* middleware/
    apps
    @type __clientEnvironKeyName: string
    """
    __slots__ = (
        '__app', 
        '__clientEnvironKeyName',
    )
    
    CLIENT_ENV_KEYNAME_OPTNAME = 'clientEnvKeyName'
    DEFAULT_CLIENT_ENV_KEYNAME = ('myproxy.server.wsgi.middleware.'
                                  'MyProxyClientMiddleware.myProxyClient')
        
    def __init__(self, app):
        """Create WSGI app and MyProxy client attributes
        @type app: function
        @param app: WSGI callable for next middleware or app in the WSGI stack
        """
        self.__app = app
        self.__clientEnvironKeyName = None
    
    def _getClientEnvironKeyName(self):
        """Get MyProxyClient environ key name
        
        @rtype: basestring
        @return: MyProxyClient environ key name
        """
        return self.__clientEnvironKeyName

    def _setClientEnvironKeyName(self, value):
        """Set MyProxyClient environ key name
        
        @type value: basestring
        @param value: MyProxyClient environ key name
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "clientEnvironKeyName"; '
                            'got %r type' % type(value))
        self.__clientEnvironKeyName = value

    clientEnvironKeyName = property(fget=_getClientEnvironKeyName, 
                                    fset=_setClientEnvironKeyName, 
                                    doc="key name in environ for the "
                                        "MyProxyClient instance")  
    
    @property
    def app(self):
        """Get Property method for reference to next WSGI application in call
        stack
        @rtype: function
        @return: WSGI application
        """
        return self.__app
    
    @staticmethod
    def getStatusMessage(statusCode):
        '''Make a standard status message for use with start_response
        @type statusCode: int
        @param statusCode: HTTP status code
        @rtype: string
        @return: status code with standard message
        @raise KeyError: for invalid status code
        '''
        return '%d %s' % (statusCode, httplib.responses[statusCode])
        
    
class MyProxyClientMiddleware(MyProxyClientMiddlewareBase):
    '''Create a MyProxy client and make it available to other middleware in the 
    WSGI stack
    
    @cvar LOGON_FUNC_ENV_KEYNAME_OPTNAME: ini file option name to set the key 
    name in WSGI environ dict to assign to the Logon function created by this
    middleware
    @type LOGON_FUNC_ENV_KEYNAME_OPTNAME: string
    
    @cvar DEFAULT_LOGON_FUNC_ENV_KEYNAME: default value for the key name in 
    WSGI environ dict to assign to the Logon function created by this
    middleware
    @type DEFAULT_LOGON_FUNC_ENV_KEYNAME: string
    
    @cvar CERT_REQ_POST_PARAM_KEYNAME: HTTP POST field name for the 
    certificate request posted in logon calls
    @type CERT_REQ_POST_PARAM_KEYNAME: string
    
    @cvar PARAM_PREFIX: prefix for ini file option names 
    @type PARAM_PREFIX: string
    
    @cvar MYPROXY_CLIENT_PARAM_PREFIX: default value for ini file sub-prefix 
    used for MyProxyClient initialisation settings such as MyProxy server 
    hostname, CA cert directory etc.  The prefix is such that option names 
    will look like this e.g.
    <PARAM_PREFIX><MYPROXY_CLIENT_PARAM_PREFIX>hostname
    ...
    @type MYPROXY_CLIENT_PARAM_PREFIX: string
    
    @ivar __myProxyClient: MyProxy client interface object to enable this
    middleware to communicate with a backend MyProxy server using the MyProxy
    protocol
    @type __myProxyClient: myproxy.client.MyProxyClient
    
    @ivar __logonFuncEnvironKeyName: 
    @type __logonFuncEnvironKeyName: string
    '''
    # Options for ini file
    LOGON_FUNC_ENV_KEYNAME_OPTNAME = 'logonFuncEnvKeyName'     
    
    # Default environ key names
    DEFAULT_LOGON_FUNC_ENV_KEYNAME = ('myproxy.server.wsgi.middleware.'
                                      'MyProxyClientMiddleware.logon')
    
    CERT_REQ_POST_PARAM_KEYNAME = 'certificate_request'
    
    # Option prefixes
    PARAM_PREFIX = 'myproxy.'
    MYPROXY_CLIENT_PARAM_PREFIX = 'client.'
    
    __slots__ = (
        '__myProxyClient', 
        '__logonFuncEnvironKeyName',
    )
    
    def __init__(self, app):
        '''Create attributes
        
        @type app: function
        @param app: WSGI callable for next application in stack
        '''
        super(MyProxyClientMiddleware, self).__init__(app)
        self.__myProxyClient = None
        self.__logonFuncEnvironKeyName = None

    @classmethod
    def filter_app_factory(cls, app, global_conf, 
                           prefix=PARAM_PREFIX, 
                           myProxyClientPrefix=MYPROXY_CLIENT_PARAM_PREFIX, 
                           **app_conf):
        """Function following Paste filter app factory signature
        
        @type app: callable following WSGI interface
        @param app: next middleware/application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: ini file sub-prefix used for MyProxyClient 
        initialisation settings such as MyProxy server  hostname, CA cert. 
        directory etc.  
        @param myProxyClientPrefix: basestring
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        
        @rtype: myproxy.server.wsgi.middleware.MyProxyClientMiddleware
        @return: an instance of this application
        """
        app = cls(app)
        app.parseConfig(prefix=prefix, myProxyClientPrefix=myProxyClientPrefix,
                        **app_conf)
        return app
    
    def parseConfig(self, 
                    prefix=PARAM_PREFIX, 
                    myProxyClientPrefix=MYPROXY_CLIENT_PARAM_PREFIX,
                    **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: basestring
        @param myProxyClientPrefix: explicit prefix for MyProxyClient class 
        specific configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        
        # Get MyProxyClient initialisation parameters
        myProxyClientFullPrefix = prefix + myProxyClientPrefix
                            
        myProxyClientKw = dict([(k.replace(myProxyClientFullPrefix, ''), v) 
                                 for k,v in app_conf.items() 
                                 if k.startswith(myProxyClientFullPrefix)])
        
        self.myProxyClient = MyProxyClient(**myProxyClientKw)
        clientEnvKeyOptName = prefix + \
                            MyProxyClientMiddleware.CLIENT_ENV_KEYNAME_OPTNAME
                    
        self.clientEnvironKeyName = app_conf.get(clientEnvKeyOptName,
                            MyProxyClientMiddleware.DEFAULT_CLIENT_ENV_KEYNAME)
                    
        logonFuncEnvKeyOptName = prefix + \
                        MyProxyClientMiddleware.LOGON_FUNC_ENV_KEYNAME_OPTNAME

        self.logonFuncEnvironKeyName = app_conf.get(logonFuncEnvKeyOptName,
                        MyProxyClientMiddleware.DEFAULT_LOGON_FUNC_ENV_KEYNAME)

    def _getLogonFuncEnvironKeyName(self):
        """Get MyProxyClient logon function environ key name
        
        @rtype: basestring
        @return: MyProxyClient logon function environ key name
        """
        return self.__logonFuncEnvironKeyName

    def _setLogonFuncEnvironKeyName(self, value):
        """Set MyProxyClient environ key name
        
        @type value: basestring
        @param value: MyProxyClient logon function environ key name
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"logonFuncEnvironKeyName"; got %r type' % 
                            type(value))
        self.__logonFuncEnvironKeyName = value

    logonFuncEnvironKeyName = property(fget=_getLogonFuncEnvironKeyName, 
                                       fset=_setLogonFuncEnvironKeyName, 
                                       doc="key name in environ for the "
                                           "MyProxy logon function")
    
    def _getMyProxyClient(self):
        """Get MyProxyClient instance
        
        @rtype: myproxy.client.MyProxyClient
        @return: MyProxyClient instance
        """
        return self.__myProxyClient

    def _setMyProxyClient(self, value):
        """Set MyProxyClient instance
        
        @type value: myproxy.client.MyProxyClient
        @param value: MyProxyClient instance
        """
        if not isinstance(value, MyProxyClient):
            raise TypeError('Expecting %r type for "myProxyClient" attribute '
                            'got %r' % (MyProxyClient, type(value)))
        self.__myProxyClient = value
        
    myProxyClient = property(fget=_getMyProxyClient,
                             fset=_setMyProxyClient, 
                             doc="MyProxyClient instance used to convert HTTPS"
                                 " call into a call to a MyProxy server")

    def __call__(self, environ, start_response):
        '''Set MyProxyClient instance and MyProxy logon method in environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        log.debug("MyProxyClientMiddleware.__call__ ...")
        environ[self.clientEnvironKeyName] = self.myProxyClient
        environ[self.logonFuncEnvironKeyName] = self.myProxyLogon
        
        return self.app(environ, start_response)
    
    @property
    def myProxyLogon(self):
        """Return the MyProxy logon method wrapped as a HTTP Basic Auth 
        authenticate interface function
        
        @rtype: function
        @return: MyProxy logon HTTP Basic Auth Callback
        """
        def _myProxylogon(environ, start_response, username, password):
            """Wrap MyProxy logon method as a WSGI app
            @type environ: dict
            @param environ: WSGI environment variables dictionary
            @type start_response: function
            @param start_response: standard WSGI start response function
            @type username: basestring
            @param username: username credential to MyProxy logon
            @type password: basestring
            @param password: pass-phrase for MyProxy logon call
            @raise HttpBasicAuthResponseException: invalid client request
            @raise MyProxyClientMiddlewareError: socket error for backend
            MyProxy server
            """  
            request = Request(environ)
            
            requestMethod = environ.get('REQUEST_METHOD')                         
            if requestMethod != 'POST':
                response = "HTTP Request method not recognised"
                log.error("HTTP Request method %r not recognised", 
                          requestMethod)
                raise HttpBasicAuthResponseException(response, 
                                                     httplib.METHOD_NOT_ALLOWED)
                
            certReqKey = self.__class__.CERT_REQ_POST_PARAM_KEYNAME
            pemCertReq = request.POST.get(certReqKey)
            if pemCertReq is None:
                response = ("No %r form variable set in POST message" % 
                            certReqKey)
                log.error(response)
                raise HttpBasicAuthResponseException(response, 
                                                     httplib.BAD_REQUEST)
        
            log.debug("cert req = %r", pemCertReq)
            
            # Expecting PEM encoded request
            try:
                certReq = crypto.load_certificate_request(
                                                        crypto.FILETYPE_PEM,
                                                        pemCertReq)
            except crypto.Error, e:
                log.error("Error loading input certificate request: %r", 
                          pemCertReq)
                raise HttpBasicAuthResponseException("Error loading input "
                                                     "certificate request",
                                                     httplib.BAD_REQUEST)
            
            # Convert to ASN1 format expect by logon client call
            asn1CertReq = crypto.dump_certificate_request(
                                                    crypto.FILETYPE_ASN1, 
                                                    certReq)

            try:
                credentials = self.myProxyClient.logon(username, 
                                                       password,
                                                       certReq=asn1CertReq)
                status = self.getStatusMessage(httplib.OK)
                response = '\n'.join(credentials)
                
                start_response(status,
                               [('Content-length', str(len(response))),
                                ('Content-type', 'text/plain')])
                return [response]
                       
            except MyProxyClientError, e:
                raise HttpBasicAuthResponseException(str(e),
                                                     httplib.UNAUTHORIZED)
            except socket.error, e:
                raise MyProxyClientMiddlewareError("Socket error "
                                        "with MyProxy server %r: %s" % 
                                        (self.myProxyClient.hostname, e))
            except Exception, e:
                log.error("MyProxyClient.logon raised an unknown exception "
                          "calling %r: %s", 
                          self.myProxyClient.hostname,
                          traceback.format_exc())
                raise # Trigger 500 Internal Server Error
            
        return _myProxylogon
    
    
class MyProxyGetTrustRootsMiddlewareError(Exception):
    """MyProxyGetTrustRootsMiddleware exception class"""
    
    
class MyProxyGetTrustRootsMiddleware(MyProxyClientMiddlewareBase):
    """HTTP client interface for MyProxy server Get Trust Roots method
    
    It relies on a myproxy.server.wsgi.MyProxyClientMiddleware instance called 
    upstream in the WSGI stack to set up a MyProxyClient instance and make it 
    available in the environ to call its getTrustRoots method.
    
    @cvar PATH_OPTNAME: ini file option to set the URI path for this service
    @type PATH_OPTNAME: string
    
    @cvar DEFAULT_PATH: default URI path setting
    @type DEFAULT_PATH: string

    @cvar PARAM_PREFIX: prefix for ini file option names 
    @type PARAM_PREFIX: string
    
    @ivar __path: URI path setting for this service
    @type __path: basestring
    """
        
    PATH_OPTNAME = 'path'     
    DEFAULT_PATH = '/myproxy/get-trustroots'
    
    # Option prefixes
    PARAM_PREFIX = 'myproxy.getTrustRoots.'
    
    __slots__ = (
        '__path',
    )
    
    def __init__(self, app):
        '''Create attributes
        
        @type app: function
        @param app: WSGI callable for next application in stack
        '''
        super(MyProxyGetTrustRootsMiddleware, self).__init__(app)
        self.__path = None
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=PARAM_PREFIX, 
                           **app_conf):
        """Function following Paste filter app factory signature
        
        @type app: callable following WSGI interface
        @param app: next middleware/application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        
        @rtype: myproxy.server.wsgi.middleware.MyProxyGetTrustRootsMiddleware
        @return: an instance of this middleware
        """
        app = cls(app)
        app.parseConfig(prefix=prefix, **app_conf)
        return app
    
    def parseConfig(self, prefix=PARAM_PREFIX, **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        clientEnvKeyOptName = prefix + self.__class__.CLIENT_ENV_KEYNAME_OPTNAME
                    
        self.clientEnvironKeyName = app_conf.get(clientEnvKeyOptName,
                                    self.__class__.DEFAULT_CLIENT_ENV_KEYNAME)
        
        pathOptName = prefix + self.__class__.PATH_OPTNAME
        self.path = app_conf.get(pathOptName, self.__class__.DEFAULT_PATH)

    def _getPath(self):
        """Get URI path for get trust roots method
        @rtype: basestring
        @return: path for get trust roots method
        """
        return self.__path

    def _setPath(self, value):
        """Set URI path for get trust roots method
        @type value: basestring
        @param value: path for get trust roots method
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "path"; got %r' % 
                            type(value))
        
        self.__path = value

    path = property(fget=_getPath, fset=_setPath, 
                    doc="environ SCRIPT_NAME path which invokes the "
                        "getTrustRoots method on this middleware")
    
    def __call__(self, environ, start_response):
        '''Get MyProxyClient instance from environ and call MyProxy 
        getTrustRoots method returning the response.
        
        MyProxyClientMiddleware must be in place upstream in the WSGI stack
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        
        @rtype: list
        @return: get trust roots response
        '''
        # Skip if path doesn't match
        if environ['PATH_INFO'] != self.path:
            return self.app(environ, start_response)
        
        log.debug("MyProxyGetTrustRootsMiddleware.__call__ ...")
        
        # Check method
        requestMethod = environ.get('REQUEST_METHOD')             
        if requestMethod != 'GET':
            response = "HTTP Request method not recognised"
            log.error("HTTP Request method %r not recognised", requestMethod)
            status = self.__class__.getStatusMessage(httplib.BAD_REQUEST)
            start_response(status,
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
            return [response]
        
        myProxyClient = environ[self.clientEnvironKeyName]
        if not isinstance(myProxyClient, MyProxyClient):
            raise TypeError('Expecting %r type for "myProxyClient" environ[%r] '
                            'attribute got %r' % (MyProxyClient, 
                                                  self.clientEnvironKeyName,
                                                  type(myProxyClient)))
        
        response = self._getTrustRoots(myProxyClient)
        start_response(self.getStatusMessage(httplib.OK),
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/plain')])

        return [response]
    
    @classmethod
    def _getTrustRoots(cls, myProxyClient):
        """Call getTrustRoots method on MyProxyClient instance retrieved from
        environ and format and return a HTTP response
        
        @type myProxyClient: myproxy.client.MyProxyClient
        @param myProxyClient: MyProxyClient instance on which to call 
        getTrustRoots method
        
        @rtype: basestring
        @return: trust roots base64 encoded and concatenated together
        @raise MyProxyGetTrustRootsMiddlewareError: socket error with backend
        MyProxy server
        @raise MyProxyClientError: error response received by MyProxyClient
        instance
        """
        try:
            trustRoots = myProxyClient.getTrustRoots()
            
            # Serialise dict response
            response = "\n".join(["%s=%s" % (k, base64.b64encode(v))
                                  for k,v in trustRoots.items()])
            
            return response
                   
        except MyProxyClientError, e:
            log.error("MyProxyClient.getTrustRoots raised an "
                      "MyProxyClientError exception calling %r: %s", 
                      myProxyClient.hostname,
                      traceback.format_exc())
            
        except socket.error, e:
            raise MyProxyGetTrustRootsMiddlewareError("Socket error with "
                                                      "MyProxy server %r: %s" % 
                                                      (myProxyClient.hostname, 
                                                       e))
        except Exception, e:
            log.error("MyProxyClient.getTrustRoots raised an unknown exception "
                      "calling %r: %s", 
                      myProxyClient.hostname,
                      traceback.format_exc())
            raise # Trigger 500 Internal Server Error
       