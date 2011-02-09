"""NDG Security Certificate Authority client - client interface classes to the
Certificate Authority.  

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/11/06"
__copyright__ = "(C) 2007 STFC & NERC"
__contact__ = "P.J.Kershaw@rl.ac.uk"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"

__all__ = [
    'CertificateAuthority_services',
    'CertificateAuthority_services_types',
    ]

# Handling for public key retrieval
import tempfile
from ZSI.wstools.Utility import HTTPResponse
from M2Crypto import X509, RSA, EVP, m2

from CertificateAuthority_services import CertificateAuthorityServiceLocator
from ndg.security.common.wsSecurity import SignatureHandler
from ndg.security.common.openssl import OpenSSLConfig


#_____________________________________________________________________________
class CertificateAuthorityClientError(Exception):
    """Exception handling for CertificateAuthorityClient class"""


#_____________________________________________________________________________
class CertificateAuthorityClient(object):
    """Client interface to Certificate Authority web service
    
    @ctype _certReqDNparamName: tuple
    @cvar _certReqDNparamName: names of parameters needed to generate a 
    certificate request e.g. CN, OU etc."""

    _certReqDNparamName = ('O', 'OU')
    
    #_________________________________________________________________________
    def __init__(self, 
                 uri=None, 
                 tracefile=None,
                 openSSLConfigFilePath=None, 
                 **signatureHandlerKw):
        """
        @type uri: string
        @param uri: URI for Attribute Authority WS.  Setting it will also
        initialise the Service Proxy
                                         
        @param tracefile: set to file object such as sys.stderr to give 
        extra WS debug information
        
        @type **signatureHandlerKw: dict
        @param **signatureHandlerKw: keywords for SignatureHandler class"""

        self.__srv = None
        self.__uri = None
        

        # Set-up parameter names for certificate request
        self.__openSSLConfig = OpenSSLConfig(filePath=openSSLConfigFilePath)

        
        if uri:
            self.__setURI(uri)

        # WS-Security Signature handler
        self.__signatureHandler = SignatureHandler(**signatureHandlerKw)
           
        self.__tracefile = tracefile

         
        # Instantiate Attribute Authority WS proxy
        if self.__uri:
            self.initService()
        

    #_________________________________________________________________________
    def __setURI(self, uri):
        
        if not isinstance(uri, basestring):
            raise CertificateAuthorityClientError, \
                        "Attribute Authority WSDL URI must be a valid string"
        
        self.__uri = uri
        
    uri = property(fset=__setURI, doc="Set Attribute Authority WSDL URI")


    #_________________________________________________________________________
    def __getOpenSSLConfig(self):
        "Get OpenSSLConfig object property method"
        return self.__openSSLConfig
    
    openSSLConfig = property(fget=__getOpenSSLConfig,
                             doc="OpenSSLConfig object")


    #_________________________________________________________________________
    def __getSignatureHandler(self):
        "Get SignatureHandler object property method"
        return self.__signatureHandler
    
    signatureHandler = property(fget=__getSignatureHandler,
                                doc="SignatureHandler object")


    #_________________________________________________________________________
    def __setSrvCertFilePath(self, srvCertFilePath):
        
        if not isinstance(srvCertFilePath, basestring):
            raise CertificateAuthorityClientError, \
                "Attribute Authority public key URI must be a valid string"
        
        self.__srvCertFilePath = srvCertFilePath
        
    srvCertFilePath = property(fset=__setSrvCertFilePath,
                              doc="Set Attribute Authority public key URI")

 
    #_________________________________________________________________________
    def __setClntCertFilePath(self, clntCertFilePath):
        
        if not isinstance(clntCertFilePath, basestring):
            raise CertificateAuthorityClientError, \
                "Client public key file path must be a valid string"
        
        self.__clntCertFilePath = clntCertFilePath
        
        try:
            self.__clntCert = open(self.__clntCertFilePath).read()
            
        except IOError, (errNo, errMsg):
            raise CertificateAuthorityClientError, \
                    "Reading certificate file \"%s\": %s" % \
                    (self.__clntCertFilePath, errMsg)
                               
        except Exception, e:
            raise CertificateAuthorityClientError, \
                                    "Reading certificate file \"%s\": %s" % \
                                    (self.__clntCertFilePath, str(e))
        
    clntCertFilePath = property(fset=__setClntCertFilePath,
                                doc="File path for client public key")

 
    #_________________________________________________________________________
    def __setClntPriKeyFilePath(self, clntPriKeyFilePath):
        
        if not isinstance(clntPriKeyFilePath, basestring):
            raise CertificateAuthorityClientError(\
                "Client public key file path must be a valid string")
        
        self.__clntPriKeyFilePath = clntPriKeyFilePath
        
    clntPriKeyFilePath = property(fset=__setClntPriKeyFilePath,
                                  doc="File path for client private key")

 
    #_________________________________________________________________________
    def __setClntPriKeyPwd(self, clntPriKeyPwd):
        
        if not isinstance(clntPriKeyPwd, basestring):
            raise SessionMgrClientError, \
                        "Client private key password must be a valid string"
        
        self.__clntPriKeyPwd = clntPriKeyPwd
        
    clntPriKeyPwd = property(fset=__setClntPriKeyPwd,
                         doc="Password protecting client private key file")

        
    #_________________________________________________________________________
    def initService(self, uri=None):
        """Set the WS proxy for the Attribute Authority
        
        @type uri: string
        @param uri: URI for service to invoke"""
        
        if uri:
            self.__setURI(uri)

        # WS-Security Signature handler object is passed to binding
        try:
            locator = CertificateAuthorityServiceLocator()
            self.__srv = locator.getCertificateAuthority(self.__uri, 
                                         sig_handler=self.__signatureHandler,
                                         tracefile=self.__tracefile)
        except HTTPResponse, e:
            raise CertificateAuthorityClientError, \
                "Error initialising WSDL Service for \"%s\": %s %s" % \
                (self.__uri, e.status, e.reason)
            
        except Exception, e:
            raise CertificateAuthorityClientError, \
                "Initialising WSDL Service for \"%s\": %s" % \
                 (self.__uri, str(e))
                 
                 
    #_________________________________________________________________________        
    def _createCertReq(self, CN, nBitsForKey=1024, messageDigest="md5"):
        """
        Create a certificate request.
        
        @param CN: Common Name for certificate - effectively the same as the
        username for the MyProxy credential
        @param nBitsForKey: number of bits for private key generation - 
        default is 1024
        @param messageDigest: message disgest type - default is MD5
        @return tuple of certificate request PEM text and private key PEM text
        """
        
        # Check all required certifcate request DN parameters are set                
        # Create certificate request
        req = X509.Request()
    
        # Generate keys
        key = RSA.gen_key(nBitsForKey, m2.RSA_F4)
    
        # Create public key object
        pubKey = EVP.PKey()
        pubKey.assign_rsa(key)
        
        # Add the public key to the request
        req.set_version(0)
        req.set_pubkey(pubKey)
        
        defaultReqDN = self.__openSSLConfig.reqDN        
            
        # Set DN
        x509Name = X509.X509_Name()
        x509Name.CN = CN
        x509Name.OU = defaultReqDN['OU']
        x509Name.O = defaultReqDN['O']
                        
        req.set_subject_name(x509Name)
        
        req.sign(pubKey, messageDigest)
        
        return req, key
    
                                    
    #_________________________________________________________________________
    def issueCert(self, 
                  certReq=None, 
                  CN=None, 
                  openSSLConfigFilePath=None,
                  **createCertReqKw):
        """Send a certificate request to the CA for signing
        
        signCert([certReq=cr]|[CN=cn, openSSLConfigFilePath=p, **kw])
        
        @type certReq: M2Crypto.X509.Request
        @param certReq: X.509 certificate request.  If omitted,
        _createCertReq method is called to create a new public and private 
        key and a certificate request
        
        @type CN: string
        @param CN: common name component of Distinguished Name for new
        cert.  This keyword is ignored if certReq keyword is set.
        
        @type openSSLConfigFilePath: string
        @param openSSLConfigFilePath: file path for OpenSSL configuration
        file from which to get settings for Distinguished Name for new 
        certificate.  This keyword is ignored if certReq keyword is set.
        
        @type **createCertReqKw: dict
        @param **createCertReqKw: keywords to call to _createCertReq - only
        applies if certReq is not set.
        
        @rtype: tuple
        @return: signed certificate and private key.  Private key will be 
        None if certReq keyword was passed in
        """

        priKey = None
        if not certReq:
            # Create the certificate request
            certReq, priKey = self._createCertReq(CN, **createCertReqKw)
        
        try:   
            cert = self.__srv.issueCert(certReq.as_pem())

        except Exception, e:
            raise CertificateAuthorityClientError, \
                                            "Signing Certificate: " + str(e)      
        return cert, priKey

                                    
    #_________________________________________________________________________
    def revokeCert(self, x509Cert):
        """Request that the CA revoke the given certificate
        
        @type x509Cert: string
        @param x509Cert: X.509 certificate to be revoked"""
            
        try:   
            self.__srv.revokeCert(x509Cert)

        except Exception, e:
            raise CertificateAuthorityClientError, \
                                            "Revoking certificate: " + str(e)
    

    #_________________________________________________________________________
    def getCRL(self):
        """Request Certificate Revocation List (CRL) for the CA
        
        @rtype string
        @return PEM encoded CRL"""

        try: 
            crl = self.__srv.getCRL()  
            
        except Exception, e:
            raise CertificateAuthorityClientError, "Requesting CRL: " + str(e)

        return crl
