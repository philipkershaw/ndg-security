""" Base class for the WS-Security digital signature handlers - to allow 
sharing of common code

NERC Data Grid Project
"""
__author__ = "C Byrom"
__date__ = "18/08/08"
__copyright__ = ""
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

import re

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
import base64

# Conditional import as this is required for the encryption
# handler
try:
    # For shared key encryption
    from Crypto.Cipher import AES, DES3
except:
    from warnings import warn
    warn('Crypto.Cipher not available: EncryptionHandler disabled!',
         RuntimeWarning)
    class AES:
        MODE_ECB = None
        MODE_CBC = None
        
    class DES3: 
        MODE_CBC = None

import os

import ZSI
from ZSI.wstools.Namespaces import DSIG, ENCRYPTION, WSU, WSA200403, \
                                   SOAP, SCHEMA # last included for xsi

from ZSI.wstools.Namespaces import OASIS as _OASIS

# Enable settings from a config file
from ndg.security.common.wssecurity import WSSecurityConfig

from ndg.security.common.X509 import X509Cert, X509CertParse, X509CertRead, \
X509Stack, X509StackParseFromDER

from datetime import datetime, timedelta
import logging
log = logging.getLogger(__name__)


class _ENCRYPTION(ENCRYPTION):
    '''Derived from ENCRYPTION class to add in extra 'tripledes-cbc' - is this
    any different to 'des-cbc'?  ENCRYPTION class implies that it is the same
    because it's assigned to 'BLOCK_3DES' ??'''
    BLOCK_TRIPLEDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"

class _WSU(WSU):
    '''Try different utility namespace for use with WebSphere'''
    #UTILITY = "http://schemas.xmlsoap.org/ws/2003/06/utility"
    UTILITY = \
"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

class OASIS(_OASIS):
    # wss4j 1.5.3
    WSSE11 = \
        "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
    # wss4j 1.5.1
    #WSSE11 = "http://docs.oasis-open.org/wss/2005/xx/oasis-2005xx-wss-wssecurity-secext-1.1.xsd"


class WSSecurityError(Exception):
    """For WS-Security generic exceptions not covered by other exception
    classes in this module"""
    def __init__(self, errorMessage):
        log.warning(errorMessage)
        super(WSSecurityError, self).__init__(errorMessage)

class InvalidCertChain(WSSecurityError):    
    """Raised from SignatureHandler.verify if the certificate submitted to
    verify a signature is not from a known CA"""
    
class VerifyError(WSSecurityError):
    """Raised from SignatureHandler.verify if an error occurs in the signature
    verification"""
 
class TimestampError(WSSecurityError):
    """Raised from SignatureHandler._verifyTimestamp if there is a problem with
    the created or expiry times in an input message Timestamp"""
    
class InvalidSignature(WSSecurityError):
    """Raised from verify method for an invalid signature"""

class SignatureError(WSSecurityError):
    """Flag if an error occurs during signature generation"""

class NoSignatureFound(WSSecurityError):
    """Raise from SignatureHandler.verify if inbound message is not signed"""


class BaseSignatureHandler(object):
    """Class to handle signature and verification of signature with 
    WS-Security
    
    @cvar binSecTokValType: supported ValueTypes for BinarySecurityToken
    element in WSSE header
    @type binSecTokValType: dict
    
    @ivar addTimestamp: set to true to add a timestamp to outbound messages
    @type addTimestamp: bool 

    @ivar applySignatureConfirmation: for servers - set this flag to enable the 
    signature value of a request to be recorded and included with a 
    SignatureConfirmation element in the response.
    @type applySignatureConfirmation: bool
    
    @param b64EncSignatureValue: base 64 encoded signature value for the last 
    message verified
    @type b64EncSignatureValue: string/None"""

    _binSecTokEncType = \
"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    
    binSecTokValType = {
        "X509PKIPathv1": OASIS.X509TOKEN.X509PKIPathv1,
        "X509":          OASIS.X509TOKEN.X509,
        "X509v3":        OASIS.X509TOKEN.X509+"v3"
    }


    def __init__(self, cfg=None, cfgFileSection='DEFAULT', cfgFilePrefix='',
                 cfgClass=WSSecurityConfig, **kw):
        '''
        @keyword reqBinSecTokValType: set the ValueType for the 
        BinarySecurityToken added to the WSSE header for a signed message.  See 
        __setReqBinSecTokValType method and binSecTokValType class variable
        for options.  binSecTokValType determines whether signingCert or
        signingCertChain attributes will be used.        
        @type binSecTokValType: string
        
        @keyword verifyingCert: X.509 certificate used by verify method to
        verify a message.  This argument can be omitted if the message to
        be verified contains the X.509 certificate in the 
        BinarySecurityToken element.  In this case, the cert read from the
        message will be assigned to the verifyingCert attribute.
        @type verifyingCert: M2Crypto.X509.X509 / 
        ndg.security.common.X509.X509Cert
        
        @keyword verifyingCertFilePath: alternative input to the above, pass 
        the file path to the certificate stored in a file
        @type verifyingCertFilePath: string
        
        @keyword signingCert: certificate associated with private key used to
        sign a message.  The sign method will add this to the 
        BinarySecurityToken element of the WSSE header.  binSecTokValType
        attribute must be set to 'X509' or 'X509v3' ValueTyep.  As an 
        alternative, use signingCertChain - see below...
        @type signingCert: M2Crypto.X509.X509 / 
        ndg.security.common.X509.X509Cert
        
        @keyword signingCertFilePath: alternative input to the above, pass 
        the file path to the certificate stored in a file
        @type signingCertFilePath: string
        
        @keyword signingCertChain: pass a list of certificates constituting a 
        chain of trust from the certificate used to verifying the signature 
        backward to the CA cert.  The CA cert need not be included.  To use 
        this option, reqBinSecTokValType must be set to the 'X509PKIPathv1'
        ValueType
        @type signingCertChain: list or tuple 
        
        @keyword signingPriKey: private key used to be sign method to sign
        message
        @type signingPriKey: M2Crypto.RSA.
        
        @keyword signingPriKeyFilePath: equivalent to the above but pass 
        private key from PEM file
        @type signingPriKeyFilePath: string
        
        @keyword signingPriKeyPwd: password protecting private key.  Set /
        default to None if there is no password.
        @type signingPriKeyPwd: string or None
        
        @keyword caCertDirPath: establish trust for signature verification. 
        This is a directory containing CA certificates.  These are used to
        verify the certificate used to verify the message signature.
        @type caCertDirPath: string
        
        @keyword caCertFilePathList: same as above except pass in a list of
        file paths instead of a single directory name.
        @type caCertFilePathList: list or tuple
        
        @keyword addTimestamp: set to true to add a timestamp to outbound 
        messages
        @type addTimestamp: bool 
        
        @keyword applySignatureConfirmation: for servers - set this flag to 
        enable the signature value of a request to be recorded and included 
        with a SignatureConfirmation element in the response.
        @type : bool 
        
        @param refC14nInclNS: list of namespaces to include in reference 
        Canonicalization.
        @type refC14nInclNS: list
        
        @param signedInfoC14nInclNS: list of namespaces to include in 
        Signed Info Canonicalization.
        @type signedInfoC14nInclNS: list
        '''
        log.debug("BaseSignatureHandler.__init__ ...")

        # WSSecurityConfig is the default class for reading config params but
        # alternative derivative class may be passed in instead.
        if not issubclass(cfgClass, WSSecurityConfig):
            raise TypeError("%s is not a sub-class of WSSecurityConfig" % 
                            cfgClass)
        
        # Read parameters from config file if set
        if isinstance(cfg, basestring):
            log.debug("BaseSignatureHandler.__init__: config file path input "
                      "...")
            self.cfg = cfgClass()
            self.cfg.read(cfg)
        else:
            log.debug("BaseSignatureHandler.__init__: config object input ...")
            self.cfg = cfgClass(cfg=cfg)
            
        if cfg: # config object or config file path was set
            log.debug("BaseSignatureHandler.__init__: Processing config "
                      "file...")
            self.cfg.parse(section=cfgFileSection, prefix=cfgFilePrefix)

        # Also update config from keywords set 
        log.debug("BaseSignatureHandler.__init__: setting config from "
                  "keywords...")
        
        # Filter keywords if a prefix is set removing any that don't start with
        # the prefix given
#        if cfgFilePrefix:
#            pfxWithDot = cfgFilePrefix+'.'
#            kw = dict([(k.replace(pfxWithDot, ''), v) for k, v in kw.items() 
#                       if k.startswith(pfxWithDot)])
#                    
        self.cfg.update(kw, prefix=cfgFilePrefix)
        
        # set default value type, if none specified in config file
        if not self.cfg['reqBinSecTokValType']:
            self.cfg['reqBinSecTokValType'] = "X509v3"
            
        self.reqBinSecTokValType = self.cfg['reqBinSecTokValType']

        # Set keywords for canonicalization of SignedInfo and reference 
        # elements
        self.refC14nKw = {'inclusive_namespaces': self.cfg['refC14nInclNS']}

        self.signedInfoC14nKw = {'inclusive_namespaces': 
                                 self.cfg['signedInfoC14nInclNS']}

        self.verifyingCert = self.cfg['verifyingCert']
        self.verifyingCertFilePath = self.cfg['verifyingCertFilePath']
        
        self.signingCert = self.cfg['signingCert']
        self.signingCertFilePath = self.cfg['signingCertFilePath']

        self.signingCertChain = self.cfg['signingCertChain']
             
        # MUST be set before _setSigningPriKeyFilePath / _setSigningPriKey
        # are called
        self.signingPriKeyPwd = self.cfg['signingPriKeyPwd']
        
        if self.cfg.get('signingPriKey'):
            # Don't allow None for private key setting
            self.signingPriKey = self.cfg['signingPriKey']
            
        self.signingPriKeyFilePath = self.cfg['signingPriKeyFilePath']
        
        # CA certificate(s) for verification of X.509 certificate used with
        # signature.
        if self.cfg.get('caCertDirPath'):
            self.caCertDirPath = self.cfg['caCertDirPath']
            
        elif self.cfg.get('caCertFilePathList'):
            self.caCertFilePathList = self.cfg['caCertFilePathList']
        
        self.addTimestamp = self.cfg['addTimestamp']
        
        # set default value, if none specified in config file
        if not self.cfg['applySignatureConfirmation']:
            self.cfg['applySignatureConfirmation'] = False

        self.applySignatureConfirmation=self.cfg['applySignatureConfirmation']
        self.b64EncSignatureValue = None
        
        log.debug("WSSE Config = %s" % self.cfg)

                
    def _setReqBinSecTokValType(self, value):
        """Set ValueType attribute for BinarySecurityToken used in a request
         
        @type value: string
        @param value: name space for BinarySecurityToken ValueType check
        'binSecTokValType' class variable for supported types.  Input can be 
        shortened to binSecTokValType keyword if desired.
        """
        log.debug("Setting reqBinSecTokValType - to %s" %value)
        if value in self.__class__.binSecTokValType:
            self._reqBinSecTokValType = self.__class__.binSecTokValType[value]
 
        elif value in self.__class__.binSecTokValType.values():
            self._reqBinSecTokValType = value
        else:
            raise WSSecurityError('Request BinarySecurityToken ValueType '
                                  '"%s" not recognised' % value)
            
    def _getReqBinSecTokValType(self):
        """
        Get ValueType attribute for BinarySecurityToken used in a request
        """
        log.debug("Getting reqBinSecTokValType value")
        if hasattr(self, '_reqBinSecTokValType'):
            return self._reqBinSecTokValType
        else:
            return ""
        
    reqBinSecTokValType = property(fset=_setReqBinSecTokValType,
                                   fget=_getReqBinSecTokValType,
         doc="ValueType attribute for BinarySecurityToken used in request")
        

    def __checkC14nKw(self, kw):
        """Check keywords for canonicalization in signing process - generic
        method for setting keywords for reference element and SignedInfo
        element C14N
        
        @type kw: dict
        @param kw: keyword used with ZSI.wstools.Utility.Canonicalization"""
        
        # Check for dict/None - Set to None in order to use inclusive 
        # canonicalization
        if kw is not None and not isinstance(kw, dict):
            # Otherwise keywords must be a dictionary
            raise AttributeError("Expecting dictionary type for reference "
                                 "C14N keywords")
                
        elif kw.get('inclusive_namespaces') and \
             not isinstance(kw['inclusive_namespaces'], list) and \
             not isinstance(kw['inclusive_namespaces'], tuple):
            raise AttributeError('Expecting list or tuple of prefix names for '
                                 '"%s" keyword' % 'inclusive_namespaces')
        
                
    def _setRefC14nKw(self, kw):
        """Set keywords for canonicalization of reference elements in the 
        signing process"""
        self.__checkC14nKw(kw)                    
        self._refC14nKw = kw
        
    def _getRefC14nKw(self):
        if hasattr(self, '_refC14nKw'):
            return self._refC14nKw
        else:
            return {}
        
    refC14nKw = property(fset=_setRefC14nKw,
                         fget=_getRefC14nKw,
                         doc="Keywords for C14N of reference elements")
        
                
    def _setSignedInfoC14nKw(self, kw):
        """Set keywords for canonicalization of SignedInfo element in the 
        signing process"""
        self.__checkC14nKw(kw)                    
        self._signedInfoC14nKw = kw
        
    def _getSignedInfoC14nKw(self):
        if hasattr(self, '_signedInfoC14nKw'):
            return self._signedInfoC14nKw
        else:
            return {}
        
    signedInfoC14nKw = property(fset=_setSignedInfoC14nKw,
                                fget=_getSignedInfoC14nKw,
                                doc="Keywords for C14N of SignedInfo element")


    def _refC14nIsExcl(self):
        '''
        @rtype: bool
        @return: true if Exclusive C14N is set as algorithm to apply to
        reference elements
        '''
        # TODO: alter logic here if inclusive C14N is re-instated.
        return True
               
    refC14nIsExcl = property(fget=_refC14nIsExcl,
    doc="Return True/False C14N for reference elements set to exclusive type")

     
    def _signedInfoC14nIsExcl(self):
        '''
        @rtype: bool
        @return: true if Exclusive C14N is set as algorithm to apply to
        the signed info elements of the XML Digital Signature
        '''
        # TODO: alter logic here if inclusive C14N is re-instated.
        return True
        
    signedInfoC14nIsExcl = property(fget=_signedInfoC14nIsExcl,
                                    doc="Return True/False C14N for "
                                    "SignedInfo element set to exclusive type")
    
    
    def _setCert(self, cert):
        """filter and convert input cert to signing verifying cert set 
        property methods.  For signingCert, set to None if it is not to be
        included in the SOAP header.  For verifyingCert, set to None if this
        cert can be expected to be retrieved from the SOAP header of the 
        message to be verified
        
        @type: ndg.security.common.X509.X509Cert / M2Crypto.X509.X509 /
        PEM encoded string or None
        @param cert: X.509 certificate.  
        
        @rtype ndg.security.common.X509.X509Cert
        @return X.509 certificate object"""
        
        if not cert or isinstance(cert, X509Cert):
            # ndg.security.common.X509.X509Cert type / None
            x509Cert = cert
            
        elif isinstance(cert, X509.X509):
            # M2Crypto.X509.X509 type
            x509Cert = X509Cert(m2CryptoX509=cert)
            
        elif isinstance(cert, basestring):
            # Nb. Assume PEM encoded string!
            x509Cert = X509CertParse(cert)
        
        else:
            raise AttributeError("X.509 Cert. must be type: ndg.security."
                                 "common.X509.X509Cert, M2Crypto.X509.X509 or "
                                 "a base64 encoded string")
        
        # Check for expired certificate
        if x509Cert:   
            x509Cert.isValidTime(raiseExcep=True)
            
        return x509Cert

    
    def _getVerifyingCert(self):
        '''Return X.509 cert object corresponding to cert used to verify the 
        signature in the last call to verify
        
         * Cert will correspond to one used in the LATEST call to verify, on
         the next call it will be replaced
         * if verify hasn't been called, the cert will be None
        
        @rtype: M2Crypto.X509.X509
        @return: certificate object
        '''
        log.debug("Getting verifying cert")
        return self._verifyingCert


    def _setVerifyingCert(self, verifyingCert):
        "Set property method for X.509 cert. used to verify a signature"
        log.debug("Setting verifying cert")
        self._verifyingCert = self._setCert(verifyingCert)
        # Reset file path as it may no longer apply
        self._verifyingCertFilePath = None
        
    verifyingCert = property(fset=_setVerifyingCert,
                             fget=_getVerifyingCert,
                             doc="Set X.509 Cert. for verifying signature")


    def _setVerifyingCertFilePath(self, verifyingCertFilePath):
        "Set method for Service X.509 cert. file path property"
        if verifyingCertFilePath:
            if isinstance(verifyingCertFilePath, basestring):
                self._verifyingCert = X509CertRead(verifyingCertFilePath)
            else:
                raise AttributeError, "X.509 Cert file path is not a valid string"
        
        self._verifyingCertFilePath = verifyingCertFilePath
        
    verifyingCertFilePath = property(fset=_setVerifyingCertFilePath,
                    doc="file path of X.509 Cert. for verifying signature")

    
    def _getSigningCert(self):
        '''Return X.509 certificate object corresponding to certificate used 
        with signature
        
        @rtype: M2Crypto.X509.X509
        @return: certificate object
        '''
        return self._signingCert


    def _setSigningCert(self, signingCert):
        "Set property method for X.509 cert. to be included with signature"
        self._signingCert = self._setCert(signingCert)
    
        # Reset file path as it may no longer apply
        self._signingCertFilePath = None
        
    signingCert = property(fget=_getSigningCert,
                           fset=_setSigningCert,
                           doc="X.509 Certificate to include signature")

 
    def _setSigningCertFilePath(self, signingCertFilePath):
        "Set signature X.509 certificate property method"
        
        if isinstance(signingCertFilePath, basestring):
            self._signingCert = X509CertRead(signingCertFilePath)
            
        elif signingCertFilePath is not None:
            raise AttributeError("Signature X.509 certificate file path must "
                                 "be a valid string")
        
        self._signingCertFilePath = signingCertFilePath
        
        
    signingCertFilePath = property(fset=_setSigningCertFilePath,
                   doc="File path X.509 cert. to include with signed message")

    
    def _setSigningCertChain(self, signingCertChain):
        '''Signature set-up with "X509PKIPathv1" BinarySecurityToken 
        ValueType.  Use an X.509 Stack to store certificates that make up a 
        chain of trust to certificate used to verify a signature
        
        @type signingCertChain: list or tuple of M2Crypto.X509.X509Cert or
        ndg.security.common.X509.X509Cert types.
        @param signingCertChain: list of certificate objects making up the
        chain of trust.  The last certificate is the one associated with the
        private key used to sign the message.'''
        
        if not isinstance(signingCertChain, (list, tuple)):
            log.warning('Expecting a list or tuple for "signingCertChain" - '
                        'ignoring value set, "%s"' % signingCertChain)
            self._signingCertChain = None
            return
        
        self._signingCertChain = X509Stack()
            
        for cert in signingCertChain:
            self._signingCertChain.push(cert)
            
    def _getSigningCertChain(self):
        return self._signingCertChain
    
    signingCertChain = property(fset=_setSigningCertChain,
                                fget=_getSigningCertChain,
                                doc="Cert.s in chain of trust to cert. used "
                                    "to verify msg.")

 
    def _setSigningPriKeyPwd(self, signingPriKeyPwd):
        "Set method for private key file password used to sign message"
        if signingPriKeyPwd is not None and \
           not isinstance(signingPriKeyPwd, basestring):
            raise AttributeError("Signing private key password must be None "
                                 "or a valid string")
        
        self._signingPriKeyPwd = signingPriKeyPwd

    def _getSigningPriKeyPwd(self):
        if hasattr(self, '_signingPriKeyPwd'):
            return self._signingPriKeyPwd
        else:
            return ""
        
    signingPriKeyPwd = property(fset=_setSigningPriKeyPwd,
                                fget=_getSigningPriKeyPwd,
                                doc="Password protecting private key file "
                                    "used to sign message")

 
    def _setSigningPriKey(self, signingPriKey):
        """Set method for client private key
        
        Nb. if input is a string, signingPriKeyPwd will need to be set if
        the key is password protected.
        
        @type signingPriKey: M2Crypto.RSA.RSA / string
        @param signingPriKey: private key used to sign message"""
        
        if isinstance(signingPriKey, basestring):
            pwdCallback = lambda *ar, **kw: self._signingPriKeyPwd
            self._signingPriKey = RSA.load_key_string(signingPriKey,
                                                       callback=pwdCallback)

        elif isinstance(signingPriKey, RSA.RSA):
            self._signingPriKey = signingPriKey 
                   
        else:
            raise AttributeError("Signing private key must be a valid "
                                  "M2Crypto.RSA.RSA type or a string")
                
    def _getSigningPriKey(self):
        return self._signingPriKey

    signingPriKey = property(fset=_setSigningPriKey,
                             fget=_getSigningPriKey,
                             doc="Private key used to sign outbound message")

 
    def _setSigningPriKeyFilePath(self, signingPriKeyFilePath):
        """Set method for client private key file path
        
        signingPriKeyPwd MUST be set prior to a call to this method"""
        if isinstance(signingPriKeyFilePath, basestring):                           
            try:
                # Read Private key to sign with    
                priKeyFile = BIO.File(open(signingPriKeyFilePath)) 
                pwdCallback = lambda *ar, **kw: self._signingPriKeyPwd                                           
                self._signingPriKey = RSA.load_key_bio(priKeyFile, 
                                                        callback=pwdCallback)           
            except Exception, e:
                raise AttributeError("Setting private key for signature: %s"%e)
        
        elif signingPriKeyFilePath is not None:
            raise AttributeError("Private key file path must be a valid "
                                 "string or None")
        
        self.__signingPriKeyFilePath = signingPriKeyFilePath
        
    signingPriKeyFilePath = property(fset=_setSigningPriKeyFilePath,
                      doc="File path for private key used to sign message")

    def __caCertIsSet(self):
        '''Check for CA certificate set (X.509 Stack has been created)'''
        return hasattr(self, '_caX509Stack')
    
    caCertIsSet = property(fget=__caCertIsSet,
           doc='Check for CA certificate set (X.509 Stack has been created)')
    
    def __appendCAX509Stack(self, caCertList):
        '''Store CA certificates in an X.509 Stack
        
        @param caCertList: list or tuple
        @type caCertList: M2Crypto.X509.X509 certificate objects'''
        
        if not hasattr(self, '_caX509Stack'):
            self._caX509Stack = X509Stack()
            
        for cert in caCertList:
            self._caX509Stack.push(cert)


    def __setCAX509StackFromDir(self, caCertDir):
        '''Read CA certificates from directory and add them to the X.509
        stack
        
        @param caCertDir: string
        @type caCertDir: directory from which to read CA certificate files'''
        
        # Mimic OpenSSL -CApath option which expects directory of CA files
        # of form <Hash cert subject name>.0
        reg = re.compile('\d+\.0')
        try:
            caCertList = [X509CertRead(caFile) \
                          for caFile in os.listdir(caCertDir) \
                          if reg.match(caFile)]
        except Exception, e:
            raise WSSecurityError('Loading CA certificate "%s" from CA '
                                  'directory: %s' % (caFile, str(e)))
                    
        # Add to stack
        self.__appendCAX509Stack(caCertList)
        
    caCertDirPath = property(fset=__setCAX509StackFromDir,
                             doc="Dir. containing CA cert.s used for "
                                "verification")


    def __setCAX509StackFromCertFileList(self, caCertFilePathList):
        '''Read CA certificates from file and add them to the X.509
        stack
        
        @type caCertFilePathList: list or tuple
        @param caCertFilePathList: list of file paths for CA certificates to
        be used to verify certificate used to sign message'''
        
        if not isinstance(caCertFilePathList, (list, tuple)):
            raise WSSecurityError('Expecting a list or tuple for '
                                  '"caCertFilePathList"')

        # Mimic OpenSSL -CApath option which expects directory of CA files
        # of form <Hash cert subject name>.0
        try:
            caCertList=[X509CertRead(caFile) for caFile in caCertFilePathList]
        except Exception, e:
            raise WSSecurityError('Loading CA certificate "%s" from file '
                                  'list: %s' % (caFile, str(e)))
                    
        # Add to stack
        self.__appendCAX509Stack(caCertList)
        
    caCertFilePathList = property(fset=__setCAX509StackFromCertFileList,
                      doc="List of CA cert. files used for verification")
                
