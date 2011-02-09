"""Functionality for WSGI HTTPS proxy to MyProxy server.
 
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
import traceback
import re
import httplib
import socket

from myproxy.client import MyProxyClient, MyProxyClientError
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase, \
    NDGSecurityMiddlewareConfigError
    
from ndg.security.server.wsgi.authn import HTTPBasicAuthMiddleware
        
        
class MyProxyClientMiddlewareConfigError(NDGSecurityMiddlewareConfigError):
    """Configuration error with MyProxyClientMiddleware"""


class MyProxyClientMiddleware(NDGSecurityMiddlewareBase):
    '''
    Create a MyProxy client and make it available to other middleware in the 
    WSGI stack
    '''
    # Options for ini file
    CLIENT_ENV_KEYNAME_OPTNAME = 'clientEnvKeyName'
    LOGON_FUNC_ENV_KEYNAME_OPTNAME = 'logonFuncEnvKeyName'     
    
    # Default environ key names
    CLIENT_ENV_KEYNAME = ('ndg.security.server.wsgi.authn.'
                          'MyProxyClientMiddleware')
    LOGON_FUNC_ENV_KEYNAME = ('ndg.security.server.wsgi.authn.'
                              'MyProxyClientMiddleware.logon')
    
    # Option prefixes
    PARAM_PREFIX = 'myproxy.'
    MYPROXY_CLIENT_PARAM_PREFIX = 'client.'
    
    def __init__(self, app, global_conf, prefix=PARAM_PREFIX, 
                 myProxyClientPrefix=MYPROXY_CLIENT_PARAM_PREFIX, **app_conf):
        ''''''
        super(MyProxyClientMiddleware, self).__init__(app, global_conf)
        self.__myProxyClient = None

        # Get MyProxyClient initialisation parameters
        myProxyClientFullPrefix = prefix + myProxyClientPrefix
                            
        myProxyClientKw = dict([(k.replace(myProxyClientFullPrefix, ''), v) 
                                 for k,v in app_conf.items() 
                                 if k.startswith(myProxyClientFullPrefix)])
        
        self.myProxyClient = MyProxyClient(**myProxyClientKw)
        clientEnvKeyOptName = prefix + \
                            MyProxyClientMiddleware.CLIENT_ENV_KEYNAME_OPTNAME
                    
        self.clientEnvironKeyName = app_conf.get(clientEnvKeyOptName,
                                MyProxyClientMiddleware.CLIENT_ENV_KEYNAME)
                    
        logonFuncEnvKeyOptName = prefix + \
                    MyProxyClientMiddleware.LOGON_FUNC_ENV_KEYNAME_OPTNAME

        self.logonFuncEnvironKeyName = app_conf.get(logonFuncEnvKeyOptName,
                                MyProxyClientMiddleware.LOGON_FUNC_ENV_KEYNAME)

    def _getClientEnvironKeyName(self):
        return self.__clientEnvironKeyName

    def _setClientEnvironKeyName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "clientEnvironKeyName"; '
                            'got %r type' % type(value))
        self.__clientEnvironKeyName = value

    clientEnvironKeyName = property(fget=_getClientEnvironKeyName, 
                                    fset=_setClientEnvironKeyName, 
                                    doc="key name in environ for the "
                                        "MyProxyClient instance")    

    def _getLogonFuncEnvironKeyName(self):
        return self.__logonFuncEnvironKeyName

    def _setLogonFuncEnvironKeyName(self, value):
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
        return self.__myProxyClient

    def _setMyProxyClient(self, value):
        if not isinstance(value, MyProxyClient):
            raise TypeError('Expecting %r type for "myProxyClient" attribute '
                            'got %r' % (MyProxyClient, type(value)))
        self.__myProxyClient = value
        
    myProxyClient = property(fget=_getMyProxyClient,
                             fset=_setMyProxyClient, 
                             doc="MyProxyClient instance used to convert HTTPS"
                                 " call into a call to a MyProxy server")

    @NDGSecurityMiddlewareBase.initCall
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
        
        return self._app(environ, start_response)
    
    @property
    def myProxyLogon(self):
        """Return the MyProxy logon method wrapped as a HTTP Basic Auth 
        authenticate interface function
        """
        def _myProxylogon(environ, start_response, username, password):
            """Wrap MyProxy logon method as a WSGI app
            """
            try:
                credentials = self.myProxyClient.logon(username, password)
                status = self.getStatusMessage(httplib.OK)
                response = '\n'.join(credentials)
                
            except MyProxyClientError, e:
                status = self.getStatusMessage(httplib.UNAUTHORIZED)
                response = str(e)
            
            except socket.error, e:
                raise MyProxyClientMiddlewareConfigError("Socket error "
                                        "with MyProxy server %r: %s" % 
                                        (self.myProxyClient.hostname, e))
            except Exception, e:
                log.error("MyProxyClient.logon raised an unknown exception "
                          "calling %r: %s", 
                          self.myProxyClient.hostname,
                          traceback.format_exc())
                raise
            
            start_response(status,
                           [('Content-length', str(len(response))),
                            ('Content-type', 'text/plain')])
            return [response]
        
        return _myProxylogon
        
        
class MyProxyLogonMiddlewareConfigError(NDGSecurityMiddlewareConfigError):
    """Configuration error with MyProxyLogonMiddleware"""
    
    
class MyProxyLogonMiddleware(NDGSecurityMiddlewareBase):
    """HTTP Basic Auth interface to MyProxy logon.  This interfaces creates a
    MyProxy client instance and HTTP Basic Auth based web service interface
    for MyProxy logon calls.  This WSGI must be run over HTTPS to ensure
    confidentiality of username/passphrase credentials
    """
    PARAM_PREFIX = 'myproxy.logon.'
    
    def __init__(self, app, global_conf, prefix=PARAM_PREFIX, **app_conf):        
        
        authnFuncEnvKeyNameOptName = HTTPBasicAuthMiddleware.PARAM_PREFIX + \
                        HTTPBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME_OPTNAME
                        
        if authnFuncEnvKeyNameOptName in app_conf:
            raise MyProxyLogonMiddlewareConfigError("Found %r option name in "
                "application configuration settings.  Use %r instead" %
                (authnFuncEnvKeyNameOptName, 
                 MyProxyClientMiddleware.PARAM_PREFIX + \
                 MyProxyClientMiddleware.LOGON_FUNC_ENV_KEYNAME_OPTNAME))
        
        httpBasicAuthApp = HTTPBasicAuthMiddleware(app, app_conf, **app_conf)
        app = MyProxyClientMiddleware(httpBasicAuthApp, app_conf, **app_conf)
        
        # Set HTTP Basic Auth to use the MyProxy client logon for its
        # authentication method
        httpBasicAuthApp.authnFuncEnvironKeyName = app.logonFuncEnvironKeyName
        
        super(MyProxyLogonMiddleware, self).__init__(app, global_conf, 
                                                     prefix=prefix, **app_conf)
