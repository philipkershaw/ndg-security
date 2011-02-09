"""Extend M2Crypto SSL functionality for cert verification and custom
timeout settings.

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import httplib
import socket

from M2Crypto import SSL, X509
from M2Crypto.httpslib import HTTPSConnection as _HTTPSConnection

from ndg.security.common.X509 import X509Cert, X509Stack, X500DN

class InvalidCertSignature(SSL.Checker.SSLVerificationError):
    """Raise if verification against CA cert public key fails"""

class InvalidCertDN(SSL.Checker.SSLVerificationError):
    """Raise if verification against a list acceptable DNs fails"""
   

class HostCheck(SSL.Checker.Checker, object):
    """Override SSL.Checker.Checker to enable alternate Common Name
    setting match for peer cert"""

    def __init__(self, 
                 peerCertDN=None, 
                 peerCertCN=None,
                 acceptedDNs=[], 
                 caCertList=[],
                 caCertFilePathList=[], 
                 **kw):
        """Override parent class __init__ to enable setting of myProxyServerDN
        setting
        
        @type peerCertDN: string/list
        @param peerCertDN: Set the expected Distinguished Name of the
        server to avoid errors matching hostnames.  This is useful
        where the hostname is not fully qualified.  

        *param acceptedDNs: a list of acceptable DNs.  This enables validation 
        where the expected DN is where against a limited list of certs.
        
        @type peerCertCN: string
        @param peerCertCN: enable alternate Common Name to peer
        hostname
        
        @type caCertList: list type of M2Crypto.X509.X509 types
        @param caCertList: CA X.509 certificates - if set the peer cert's 
        CA signature is verified against one of these.  At least one must
        verify
        
        @type caCertFilePathList: list string types
        @param caCertFilePathList: same as caCertList except input as list
        of CA cert file paths"""
        
        SSL.Checker.Checker.__init__(self, **kw)
        
        self.peerCertDN = peerCertDN
        self.peerCertCN = peerCertCN
        self.acceptedDNs = acceptedDNs
        
        if caCertList:
            self.caCertList = caCertList
        elif caCertFilePathList:
            self.caCertFilePathList = caCertFilePathList
            
    def __call__(self, peerCert, host=None):
        """Carry out checks on server ID
        @param peerCert: MyProxy server host certificate as M2Crypto.X509.X509
        instance
        @param host: name of host to check
        """
        if peerCert is None:
            raise SSL.Checker.NoCertificate('SSL Peer did not return '
                                            'certificate')

        peerCertDN = '/'+peerCert.get_subject().as_text().replace(', ', '/')
        try:
            SSL.Checker.Checker.__call__(self, peerCert, host=self.peerCertCN)
            
        except SSL.Checker.WrongHost, e:
            # Try match against peerCertDN set   
            if peerCertDN != self.peerCertDN:
                raise e

        # At least one match should be found in the list - first convert to
        # NDG X500DN type to allow per field matching for DN comparison
        peerCertX500DN = X500DN(dn=peerCertDN)
        
        if self.acceptedDNs:
           matchFound = False
           for dn in self.acceptedDNs:
               x500dn = X500DN(dn=dn)
               if x500dn == peerCertX500DN:
                   matchFound = True
                   break
               
           if not matchFound:
               raise InvalidCertDN('Peer cert DN "%s" doesn\'t match '
                                   'verification list' % peerCertDN)

        if len(self.__caCertStack) > 0:
            try:
                self.__caCertStack.verifyCertChain(
                           x509Cert2Verify=X509Cert(m2CryptoX509=peerCert))
            except Exception, e:
                raise InvalidCertSignature("Peer certificate verification "
                                           "against CA cert failed: %s" % e)
              
        # They match - drop the exception and return all OK instead          
        return True
      
    def __setCACertList(self, caCertList):
        """Set list of CA certs - peer cert must validate against at least one
        of these"""
        self.__caCertStack = X509Stack()
        for caCert in caCertList:
            self.__caCertStack.push(caCert)

    caCertList = property(fset=__setCACertList,
              doc="list of CA certs - peer cert must validate against one")

    def __setCACertsFromFileList(self, caCertFilePathList):
        '''Read CA certificates from file and add them to the X.509
        stack
        
        @type caCertFilePathList: list or tuple
        @param caCertFilePathList: list of file paths for CA certificates to
        be used to verify certificate used to sign message'''
        
        if not isinstance(caCertFilePathList, (list, tuple)):
            raise AttributeError(
                        'Expecting a list or tuple for "caCertFilePathList"')

        self.__caCertStack = X509Stack()

        for caCertFilePath in caCertFilePathList:
            self.__caCertStack.push(X509.load_cert(caCertFilePath))
        
    caCertFilePathList = property(fset=__setCACertsFromFileList,
    doc="list of CA cert file paths - peer cert must validate against one")


class HTTPSConnection(_HTTPSConnection):
    """Modified version of M2Crypto equivalent to enable custom checks with
    the peer and timeout settings
    
    @type defReadTimeout: M2Crypto.SSL.timeout
    @cvar defReadTimeout: default timeout for read operations
    @type defWriteTimeout: M2Crypto.SSL.timeout
    @cvar defWriteTimeout: default timeout for write operations"""    
    defReadTimeout = SSL.timeout(sec=20.)
    defWriteTimeout = SSL.timeout(sec=20.)
    
    def __init__(self, *args, **kw):
        '''Overload to enable setting of post connection check
        callback to SSL.Connection
        
        type *args: tuple
        param *args: args which apply to M2Crypto.httpslib.HTTPSConnection
        type **kw: dict
        param **kw: additional keywords
        @type postConnectionCheck: SSL.Checker.Checker derivative
        @keyword postConnectionCheck: set class for checking peer
        @type readTimeout: M2Crypto.SSL.timeout
        @keyword readTimeout: readTimeout - set timeout for read
        @type writeTimeout: M2Crypto.SSL.timeout
        @keyword writeTimeout: similar to read timeout'''
        
        self._postConnectionCheck = kw.pop('postConnectionCheck',
                                           SSL.Checker.Checker)
        
        if 'readTimeout' in kw:
            if not isinstance(kw['readTimeout'], SSL.timeout):
                raise AttributeError("readTimeout must be of type " + \
                                     "M2Crypto.SSL.timeout")
            self.readTimeout = kw.pop('readTimeout')
        else:
            self.readTimeout = HTTPSConnection.defReadTimeout
              
        if 'writeTimeout' in kw:
            if not isinstance(kw['writeTimeout'], SSL.timeout):
                raise AttributeError("writeTimeout must be of type " + \
                                     "M2Crypto.SSL.timeout") 
            self.writeTimeout = kw.pop('writeTimeout')
        else:
            self.writeTimeout = HTTPSConnection.defWriteTimeout
    
        self._clntCertFilePath = kw.pop('clntCertFilePath', None)
        self._clntPriKeyFilePath = kw.pop('clntPriKeyFilePath', None)
        
        _HTTPSConnection.__init__(self, *args, **kw)
        
        # load up certificate stuff
        if self._clntCertFilePath is not None and \
           self._clntPriKeyFilePath is not None:
            self.ssl_ctx.load_cert(self._clntCertFilePath, 
                                   self._clntPriKeyFilePath)
        
        
    def connect(self):
        '''Overload M2Crypto.httpslib.HTTPSConnection to enable
        custom post connection check of peer certificate and socket timeout'''

        self.sock = SSL.Connection(self.ssl_ctx)
        self.sock.set_post_connection_check_callback(self._postConnectionCheck)

        self.sock.set_socket_read_timeout(self.readTimeout)
        self.sock.set_socket_write_timeout(self.writeTimeout)

        self.sock.connect((self.host, self.port))

    def putrequest(self, method, url, **kw):
        '''Overload to work around bug with unicode type URL'''
        url = str(url)
        _HTTPSConnection.putrequest(self, method, url, **kw)