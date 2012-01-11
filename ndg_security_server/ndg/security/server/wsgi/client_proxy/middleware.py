'''
Created on 21 Dec 2010

@author: pjkersha
'''
from datetime import datetime, timedelta

from paste import httpexceptions
from paste.proxy import Proxy
from webob.dec import wsgify
from webob import Request, Response
from OpenSSL import SSL, crypto

from myproxy.ws.server.wsgi.middleware import MyProxyClientMiddleware
from ndg.security.common.utils import pyopenssl


class SSLCtxSessionMiddleware(object):
    """Store an SSL Context object in session middleware for client callouts"""
    __slots__ = (
        '_app',
        '__environSessionKeyName',
        '__ctxSessionKeyName',
    )
    PARAM_NAMES = ('environSessionKeyName', 'ctxEnvironKeyName', 'caCertDir',)
    DEFAULT_ENVIRON_SESSION_KEYNAME = "ndg.security.session"
    DEFAULT_CTX_SESSION_KEYNAME = "ssl_ctx"
    DEFAULT_PARAM_PREFIX = 'ssl_ctx.'
    
    '''@param SSL_VERSION: SSL version for context object
    @type SSL_VERSION: string'''
    SSL_VERSION = SSL.SSLv3_METHOD
    
    def __init__(self, app):
        self._app = app
        self.__environSessionKeyName = \
            self.__class__.DEFAULT_ENVIRON_SESSION_KEYNAME
        
    def initialise(self, app_conf, prefix=DEFAULT_PARAM_PREFIX, **local_conf):
        for k in local_conf:
            if k in self.__class__.PARAM_NAMES:
                if prefix:
                    paramName = k.lstrip(prefix)
                else:
                    paramName = k
                    
                setattr(self, paramName, local_conf[i])
            
    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        obj = cls(app)
        obj.initialise(app_conf, **kw)
        return obj
    
    @wsgify
    def __call__(self, request):
        session = request.environ.get(self.__environSessionKeyName)
        if session is None:
            raise httpexceptions.HTTPInternalServerError(
                'Expecting session assigned to %r environ key' % 
                self.__environSessionKeyName)
            
        self._create_ssl_ctx()

        return self._app(request.environ, request.start_response)
    
    def _create_ssl_ctx(self, session):
        """Create or refresh SSL Context object"""
        # TODO: refresh existing context if client credentials are near expiry
        ctx = session.get(self.__ctxSessionKeyName)
        if ctx is None:
            session[self.__ctxSessionKeyName
                    ] = SSL.Context(self.__class__.SSL_VERSION)
        

class MyProxyProvisionedSessionMiddlewareError(Exception):
    """Exception class for MyProxyProvisionedSessionMiddleware, a WSGI 
    middleware class which provisions a session object with PKI credentials from
    a MyProxy server
    """
        

class MyProxyRetrievalError(MyProxyProvisionedSessionMiddlewareError):
    """Exception class to flag errors from MyProxy logon calls made from 
    MyProxyProvisionedSessionMiddleware"""
        

class MyProxyRetrievalSocketError(MyProxyProvisionedSessionMiddlewareError):
    """Exception class to flag socket errors from MyProxy logon calls made from 
    MyProxyProvisionedSessionMiddleware"""
    
    
class MyProxyProvisionedSessionMiddleware(SSLCtxSessionMiddleware):
    """Provisions a session object with PKI credentials from a MyProxy server.
    Call MyProxy logon to populate a session based SSL context object with
    client PKI credentials to make SSL calls to other services.
    
    @cvar DEFAULT_CERT_EXPIRY_OFFSET: default time offset prior to certificate
    expiry used to trigger certificate renewal. e.g. if the offset is 1 day
    and the certificate will expiry within one day then certificate renewal
    is invoked with a fresh MyProxy logon call.
    @type DEFAULT_CERT_EXPIRY_OFFSET: timedelta
    """
    __slots__ = (
        '__environMyProxyClientKeyName',
        '__certExpiryOffset'
    )
    DEFAULT_ENVIRON_SESSION_KEYNAME = "ndg.security.session"
    DEFAULT_PARAM_PREFIX = 'myproxy_provision_session.'
    DEFAULT_CERT_EXPIRY_OFFSET = timedelta(days=1)
    
    def __init__(self, app):
        super(MyProxyProvisionedSessionMiddleware, self).__init__(app)
        self.__certExpiryOffset = self.__class__.DEFAULT_CERT_EXPIRY_OFFSET
                    
    @property
    def certExpiryOffset(self):
        '''Certificate expiry offset measured in seconds before current time
        '''
        return self.__certExpiryOffset
    
    @certExpiryOffset.setter
    def certExpiryOffset(self, val):
        '''Certificate expiry offset measured in seconds before current time
        '''
        if isinstance(val, basestring):
            self.__certExpiryOffset = timedelta(seconds=float(val))
            
        elif isinstance(val, (float, int, long)):
            self.__certExpiryOffset = timedelta(seconds=val)
            
        elif isinstance(val, timedelta):
            self.__certExpiryOffset = val
            
        else:
            raise TypeError('Expecting string, int, long, float or timedelta '
                            'type for "certExpiryOffset", got %r' % type(val))
        
    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        """Configure filter and associated SSL Context session middleware
        """
        _app = cls(app)
        obj.initialise(_app, app_conf, **kw)
        
        # Set SSL Context middleware upstream from this app
        _app = SSLCtxSessionMiddleware.filter_app_factory(_app, app_conf, **kw)
        return _app
    
    @wsgify
    def __call__(self, request):
        resp = super(MyProxyProvisionedSessionMiddleware, self).__call__(
                                    request)
        
        # if not certificate has been set or if it is present but expired,
        # renew        
        if (not self.__class__._is_cert_set(session) or 
            self._is_cert_expired(session)):
            self._refresh_credentials(session)
            
        return resp
    
    def _refresh_credentials(self, session):
        """Refresh credentials by making a MyProxy server logon request"""

        try:
            credentials = myProxyClient.logon(username, password)
                   
        except MyProxyClientError, e:
            raise httpexceptions.HTTPUnauthorized(str(e))
        
        except socket.error, e:
            raise MyProxyRetrievalSocketError("Socket error with MyProxy "
                                              "server %r: %s" % 
                                              (self.myProxyClient.hostname, e))
        except Exception:
            raise MyProxyRetrievalError("MyProxyClient.logon raised an unknown "
                                        "exception calling %r: %s" %
                                        (self.myProxyClient.hostname,
                                        traceback.format_exc())) 
            
        # Get Context from session and update with credentials just retrieved
        sslCtx = session[self.__ctxSessionKeyName]
        
        # The first element is the certificate, the second the private key,
        # the remainder, any associated certificate chain  
        session['certs'] = credentials[0]
        session['privateKey'] = credentials[1]
              
        sslCtx.use_certificate(credentials[0])
        sslCtx.use_privatekey(credentials[1])
        
        if len(credentials) > 2:
            session['certs'].extend(credentials[2:])
            for chainCert in credentials[2:]:
                sslCtx.add_extra_chain_cert(chainCert)
    
    @classmethod
    def _is_cert_set(self, session): 
        return len(session.get('certs', [])) > 0 
              
    def _is_cert_expired(self, session):
        '''Check if input certificate has expired
        @param session: session
        @type session: beaker.session
        @return: true if expired, false otherwise
        @rtype: bool
        '''
        cert = session['certs'][0]
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        notAfter = x509.get_notAfter()
        dtNotAfter = datetime.strptime(notAfter, '%Y%m%d%H%M%S%fZ')       
        dtNow = datetime.utcNow()
        
        return dtNotAfter < dtNow - self.certExpiryOffset


class NDGSecurityProxy(Proxy):
    """Extend paste.proxy.Proxy to enable an SSL context to be set with client
    certificate and key from a user session
    """
    def __init__(self, address, **kw):
        super(NDGSecurityProxy, self).__init__(address, **kw)

        self.__environSessionKeyName = \
            MyProxyProvisionedSessionMiddleware.DEFAULT_ENVIRON_SESSION_KEYNAME
            
        self.__ctxSessionKeyName = \
            MyProxyProvisionedSessionMiddleware.DEFAULT_CTX_SESSION_KEYNAME
            
        self.__environMyProxyClientKeyName = \
            MyProxyClientMiddleware.DEFAULT_CLIENT_ENV_KEYNAME
                    
    def __call__(self, environ, start_response):
        if (self.allowed_request_methods and 
            environ['REQUEST_METHOD'
                    ].lower() not in self.allowed_request_methods):
            disallowedRequest = httpexceptions.HTTPBadRequest("Disallowed")
            return disallowedRequest(environ, start_response)

        if not self.environ_session_keyname:
            sslCtx = None
        else:
            session = environ.get(self.__environSessionKeyName)
            if session is None:
                msg = "No session in environ"
                http500Error = httpexceptions.HTTPInternalServerError(msg)
                return http500Error(environ, start_response)
            
            sslCtx = session[self.__ctxSessionKeyName]
            
        if self.scheme == 'http':
            conn = httplib.HTTPConnection(self.host)
        elif self.scheme == 'https':
            conn = pyopenssl.HTTPSConnection(self.host, ssl_context=sslCtx)
        else:
            raise ValueError(
                "Unknown scheme for %r: %r" % (self.address, self.scheme))
        
        headers = {}
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                key = key[5:].lower().replace('_', '-')
                if key == 'host' or key in self.suppress_http_headers:
                    continue
                headers[key] = value
        headers['host'] = self.host
        if 'REMOTE_ADDR' in environ:
            headers['x-forwarded-for'] = environ['REMOTE_ADDR']
        if environ.get('CONTENT_TYPE'):
            headers['content-type'] = environ['CONTENT_TYPE']
        if environ.get('CONTENT_LENGTH'):
            if environ['CONTENT_LENGTH'] == '-1':
                # This is a special case, where the content length is basically undetermined
                body = environ['wsgi.input'].read(-1)
                headers['content-length'] = str(len(body))
            else:
                headers['content-length'] = environ['CONTENT_LENGTH'] 
                length = int(environ['CONTENT_LENGTH'])
                body = environ['wsgi.input'].read(length)
        else:
            body = ''
            
        path_info = urllib.quote(environ['PATH_INFO'])
        if self.path:            
            request_path = path_info
            if request_path and request_path[0] == '/':
                request_path = request_path[1:]
                
            path = urlparse.urljoin(self.path, request_path)
        else:
            path = path_info
        if environ.get('QUERY_STRING'):
            path += '?' + environ['QUERY_STRING']
            
        conn.request(environ['REQUEST_METHOD'],
                     path,
                     body, headers)
        res = conn.getresponse()
        headers_out = parse_headers(res.msg)
                
        status = '%s %s' % (res.status, res.reason)
        start_response(status, headers_out)
        # @@: Default?
        length = res.getheader('content-length')
        if length is not None:
            body = res.read(int(length))
        else:
            body = res.read()
        conn.close()
        return [body]
