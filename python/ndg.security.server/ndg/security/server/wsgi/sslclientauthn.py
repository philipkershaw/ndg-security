"""SSL Client Authentication Middleware

Apply to SSL client authentication to configured URL paths.

SSL Client certificate is expected to be present in environ as SSL_CLIENT_CERT
key as set by standard Apache SSL.

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "11/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import os
import httplib
from ndg.security.common.X509 import X509Stack, X509Cert, X509CertError

class SSLClientAuthNMiddleware(object):

    sslClientCertKeyName = 'SSL_CLIENT_CERT'
    
    propertyDefaults = {
        'errorResponseCode': 401,
        'pathMatchList': '/',
        'caCertFilePathList': []
    }

    _isSSLClientCertSet = lambda self: bool(self._environ.get(
                                SSLClientAuthNMiddleware.sslClientCertKeyName)) 
    isSSLClientCertSet = property(fget=_isSSLClientCertSet,
                                  doc="Check for client cert. set in environ")
    
    _pathMatch = lambda self: self._path in self.pathMatchList
    pathMatch = property(fget=_pathMatch,
                         doc="Check for input path match to list of paths"
                             "to which SSL client AuthN is to be applied")
    
    def __init__(self, app, app_conf, prefix='', **local_conf):
        self._app = app

        opt = SSLClientAuthNMiddleware.propertyDefaults.copy()
        
        # If no prefix is set, there is no way to distinguish options set for 
        # this app and those applying to other applications
        if app_conf is not None and prefix:
            # Update from application config dictionary - filter using prefix
            SSLClientAuthNMiddleware._filterOpts(opt, app_conf, prefix=prefix)
                        
        # Similarly, filter keyword input                 
        SSLClientAuthNMiddleware._filterOpts(opt, local_conf, prefix=prefix)
       
        # Update options from keywords - matching app_conf ones will be 
        # overwritten
        opt.update(local_conf)
        
        # Set options as object attributes
        for name, val in opt.items():
            setattr(self, name, val)
    
    def _getErrorResponseCode(self):
        """
        @rtype: int
        @return: HTTP error code set by this middleware on client cert.
        verification error
        """
        return self._errorResponseCode
            
    def _setErrorResponseCode(self, code):
        """
        @type code: int or basestring
        @param code: error response code set if client cert. verification
        fails"""
        if isinstance(code, int):
            self._errorResponseCode = code
        elif isinstance(code, basestring):
            self._errorResponseCode = int(code)
        else:
            raise TypeError('Expecting int or string type for '
                            '"errorResponseCode" attribute')
            
        if self._errorResponseCode not in httplib.responses: 
            raise ValueError("Error response code [%d] is not recognised "
                             "standard HTTP response code" % 
                             self._errorResponseCode)  
            
    errorResponseCode = property(fget=_getErrorResponseCode,
                            fset=_setErrorResponseCode,
                            doc="Response code raised if client certificate "
                                "verification fails")
        
    def _setCACertsFromFileList(self, caCertFilePathList):
        '''Read CA certificates from file and add them to an X.509 Cert.
        stack
        
        @type caCertFilePathList: list or tuple
        @param caCertFilePathList: list of file paths for CA certificates to
        be used to verify certificate used to sign message'''
        
        if isinstance(caCertFilePathList, basestring):
            # Try parsing a space separated list of file paths
            caCertFilePathList = caCertFilePathList.split()
            
        elif not isinstance(caCertFilePathList, (list, tuple)):
            raise TypeError('Expecting a list or tuple for '
                            '"caCertFilePathList"')

        self._caCertStack = X509Stack()

        for caCertFilePath in caCertFilePathList:
            x509Cert = X509Cert.Read(os.path.expandvars(caCertFilePath))
            self._caCertStack.push(x509Cert)
        
    caCertFilePathList = property(fset=_setCACertsFromFileList,
                                  doc="list of CA certificate file paths - "
                                      "peer certificate must validate against "
                                      "one")
    def _getPathMatchList(self):
        return self._pathMatchList
    
    def _setPathMatchList(self, pathList):
        '''
        @type pathList: list or tuple
        @param pathList: list of URL paths to apply SSL client authentication 
        to. Paths are relative to the point at which this middleware is mounted
        as set in environ['PATH_INFO']
        '''
        # TODO: refactor to:
        # * enable reading of path list from a database or some other 
        # configuration source.
        # * enable some kind of pattern matching for paths
        
        if isinstance(pathList, basestring):
            # Try parsing a space separated list of file paths
             self._pathMatchList = pathList.split()
            
        elif not isinstance(pathList, (list, tuple)):
            raise TypeError('Expecting a list or tuple for "pathMatchList"')
        else:
            self._pathMatchList = pathList
            
    pathMatchList = property(fget=_getPathMatchList,
                             fset=_setPathMatchList,
                             doc='List of URL paths to which to apply SSL '
                                 'client authentication')
    
    @classmethod
    def _filterOpts(cls, opt, newOpt, prefix=''):
        '''Convenience utility to filter input options set in __init__ via
        app_conf or keywords
        
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
        
        badOpt = []
        for k,v in newOpt.items():
            if prefix and k.startswith(prefix):
                subK = k.replace(prefix, '')                    
                filtK = '_'.join(subK.split('.'))  
            else:
                filtK = k
                    
            if filtK not in cls.propertyDefaults:
                badOpt += [k]                
            else:
                opt[filtK] = v
                
        if len(badOpt) > 0:
            raise TypeError("Invalid input option(s) set: %s" % 
                            (", ".join(badOpt)))
               
    def __call__(self, environ, start_response):
        
        self._path = environ.get('PATH_INFO')
        if self._path != '/':
            self._path.rstrip('/')
        
        self._environ = environ
        
        if not self.pathMatch:
            log.debug("ignoring path [%s]" % self._path)
            return self._setResponse(environ, start_response)
                    
        if not self.isSSLClientCertSet:
            log.error("No SSL Client path set for request to [%s]"%self._path)
            return self._setErrorResponse(environ, start_response,
                                          msg='No client SSL Certificate set')
            
        if self.isValidClientCert(environ):            
            return self._setResponse(environ, start_response)
        else:
            return self._setErrorResponse(environ, start_response)
            
    def _setResponse(self, environ, start_response):
        if self._app:
            return self._app(environ, start_response)
        else:
            response = 'No application set for SSLClientAuthNMiddleware'
            status = '%d %s' % (404, httplib.responses[404])
            start_response(status,
                           [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(response)))])
            return response

    def _setErrorResponse(self, environ, start_response,
                          msg='Invalid SSL client certificate'):
        response = msg
        status = '%d %s' % (self.errorResponseCode, 
                            httplib.responses[self.errorResponseCode])
        
        start_response(status,
                       [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(response)))])
        return response

    def isValidClientCert(self, environ):
        sslClientCert = environ[SSLClientAuthNMiddleware.sslClientCertKeyName]
        x509Cert = X509Cert.Parse(sslClientCert)
        
        if len(self._caCertStack) == 0:
            log.warning("No CA certificates set for Client certificate "
                        "signature verification")
        else:
            try:
                self._caCertStack.verifyCertChain(x509Cert2Verify=x509Cert)

            except X509CertError, e:
                log.info("Client certificate verification failed: %s" % e)
                return False
            
            except Exception, e:
                log.error("Client certificate verification failed with "
                          "unexpected error: %s" % e)
                return False
            
        return True
        

# Utility functions to support Paste Deploy application and filter function
# signatures        
def filter_app_factory(app, app_conf, **local_conf):
    '''Wrapper to SSLClientAuthNMiddleware for Paste Deploy filter'''
    return SSLClientAuthNMiddleware(app, app_conf, **local_conf)
   
def app_factory(app_conf, **local_conf):
    '''Wrapper to SSLClientAuthNMiddleware for Paste Deploy app'''
    return SSLClientAuthNMiddleware(None, app_conf, **local_conf)
