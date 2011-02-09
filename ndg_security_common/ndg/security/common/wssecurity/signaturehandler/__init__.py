""" Base class for the WS-Security digital signature handlers - to allow 
sharing of common code

NERC DataGrid Project
"""
__author__ = "C Byrom"
__date__ = "18/08/08"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import re

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
import base64

import os

import ZSI
from ZSI.wstools.Namespaces import ENCRYPTION, WSU
from ZSI.wstools.Namespaces import OASIS as _OASIS
from ConfigParser import RawConfigParser

# Enable settings from a config file
from ndg.security.common.wssecurity import WSSecurityConfig, WSSecurityError

from ndg.security.common.X509 import X509Cert, X509CertParse, X509CertRead, \
X509Stack, X509StackParseFromDER

from datetime import datetime, timedelta
import logging
log = logging.getLogger(__name__)


class _WSU(WSU):
    '''Try different utility namespace for use with WebSphere'''
    #UTILITY = "http://schemas.xmlsoap.org/ws/2003/06/utility"
    UTILITY = ("http://docs.oasis-open.org/wss/2004/01/"
               "oasis-200401-wss-wssecurity-utility-1.0.xsd")

class OASIS(_OASIS):
    # wss4j 1.5.3
    WSSE11 = ("http://docs.oasis-open.org/wss/"
              "oasis-wss-wssecurity-secext-1.1.xsd")
    # wss4j 1.5.1
#    WSSE11 = ("http://docs.oasis-open.org/wss/2005/xx/"
#              "oasis-2005xx-wss-wssecurity-secext-1.1.xsd")


class InvalidCertChain(WSSecurityError):    
    """Raised from SignatureHandler.verify if the certificate submitted to
    verify a signature is not from a known CA"""
    
class VerifyError(WSSecurityError):
    """Raised from SignatureHandler.verify if an error occurs in the signature
    verification"""
 
class TimestampError(WSSecurityError):
    """Raised from SignatureHandler._verifyTimestamp if there is a problem with
    the created or expiry times in an input message Timestamp"""

class MessageExpired(TimestampError):
    """Raised from SignatureHandler._verifyTimestamp if the timestamp of
    the message being processed is before the current time.  Can be caught in
    order to set a wsu:MessageExpired fault code"""
    
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

    _binSecTokEncType = ("http://docs.oasis-open.org/wss/2004/01/"
                         "oasis-200401-wss-soap-message-security-1.0#"
                         "Base64Binary")
    
    binSecTokValType = {
        "X509PKIPathv1": OASIS.X509TOKEN.X509PKIPathv1,
        "X509":          OASIS.X509TOKEN.X509,
        "X509v3":        OASIS.X509TOKEN.X509+"v3"
    }


    def __init__(self, cfg=None, cfgFileSection='DEFAULT', cfgFilePrefix='',
                 cfgClass=WSSecurityConfig, **kw):
        '''
        @param cfg: object from which to read config items - a file path,
        config parser object or WSSecurityConfig object
        @type cfg: basestring/RawConfigParser/WSSecurityConfig
        
        @param cfgFileSection: section name in config file containing 
        parameters
        @type cfgFileSection: basestring
        
        @param cfgFilePrefix: prefix for parameter names in the config file.
        This enables these parameters to be filtered from other unrelated
        parameters in the same section
        @type cfgFilePrefix: basestring
        
        @param cfgClass: class used to parse the settings
        @type cfgClass: WSSecurityConfig derived class type
        
        @param kw: any config parameters as specified by WSSecurityConfig class
        @type kw: dict
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
            self.cfg.parse(section=cfgFileSection, prefix=cfgFilePrefix)

        elif isinstance(cfg, RawConfigParser):
            log.debug("BaseSignatureHandler.__init__: config object input ...")
            self.cfg = cfgClass(cfg=cfg)
            self.cfg.parse(section=cfgFileSection, prefix=cfgFilePrefix)
            
        elif isinstance(cfg, WSSecurityConfig):
            log.debug("BaseSignatureHandler.__init__:  WSSSecurityConfig "
                      "object input ...")
            self.cfg = cfg
        else:
            self.cfg = cfgClass()
                
        # Also update config from keywords set 
        log.debug("BaseSignatureHandler.__init__: updating config from "
                  "keywords...")
        
        # Filter keywords if a prefix is set removing any that don't start with
        # the prefix given
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
        
        # Configure signature generation to add/omit a timestamp
        self.addTimestamp = self.cfg['addTimestamp']
        
        # Configure timestamp checking in Signature verification handler
        self.timestampClockSkew = self.cfg['timestampClockSkew']
        self.timestampMustBeSet = self.cfg['timestampMustBeSet']
        self.createdElemMustBeSet = self.cfg['createdElemMustBeSet']
        self.expiresElemMustBeSet = self.cfg['expiresElemMustBeSet']
        
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
             not isinstance(kw['inclusive_namespaces'], (list, tuple)):
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
        return self._verifyingCert


    def _setVerifyingCert(self, verifyingCert):
        "Set property method for X.509 cert. used to verify a signature"
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
        
    def _get_timestampClockSkew(self):
        return getattr(self, "_timestampClockSkew", 0.)

    def _set_timestampClockSkew(self, val):
        if isinstance(val, basestring):
            self._timestampClockSkew = float(val)
            
        elif isinstance(val, (float, int)):
            self._timestampClockSkew = val
            
        else:
            raise TypeError("Expecting string, float or int type for "
                            "timestampClockSkew attribute, got %r" % 
                            getattr(val, "__class__", val))
        
    timestampClockSkew = property(fset=_set_timestampClockSkew,
                                  fget=_get_timestampClockSkew,
                                  doc="adjust the current time calculated by "
                                      "the number of seconds specified in "
                                      "this parameter.  This enables "
                                      "allowance to be made for clock skew "
                                      "between a client and server system "
                                      "clocks.")
    
    def _setBool(self, val):
        """Convert input string, float or int to bool type
        
        @type val: int, float or basestring
        @param val: input value to be converted
        @rtype: bool
        @return: input value converted to bool type
        """
        
        if isinstance(val, bool):
            return val
        
        elif isinstance(val, basestring):
            val = val.lower()
            if val not in ("true", "false"):
                raise ValueError("String conversion failed for input: %r"%val)
            
            return val == "true"
            
        elif isinstance(val, (int, float)): 
            return bool(val)
        else:
            raise TypeError("Invalid type for bool conversion: %r" % 
                            val.__class__)
        
    def _get_timestampMustBeSet(self):
        return getattr(self, "_timestampMustBeSet", False)

    def _set_timestampMustBeSet(self, val):
        self._timestampMustBeSet = self._setBool(val)
        
    timestampMustBeSet = property(fset=_set_timestampMustBeSet,
                                  fget=_get_timestampMustBeSet,
                                  doc="Set to True to raise an exception if a "
                                      "message to be verified doesn't have a "
                                      "timestamp element.  Set to False to "
                                      "log a warning message and continue "
                                      "processing")
    
    def _get_createdElemMustBeSet(self):
        return getattr(self, "_createdElemMustBeSet", False)

    def _set_createdElemMustBeSet(self, val):
        self._createdElemMustBeSet = self._setBool(val)
        
    createdElemMustBeSet = property(fset=_set_createdElemMustBeSet,
                                    fget=_get_createdElemMustBeSet,
                                    doc="Set to True to raise an exception if "
                                        "a message to be verified doesn't "
                                        "have <wsu:Created/> element with its "
                                        "timestamp element.  Set to False to "
                                        "log a warning message and continue "
                                        "processing")
    
    def _get_expiresElemMustBeSet(self):
        return getattr(self, "_expiresElemMustBeSet", False)

    def _set_expiresElemMustBeSet(self, val):
        self._expiresElemMustBeSet = self._setBool(val)
        
    expiresElemMustBeSet = property(fset=_set_expiresElemMustBeSet,
                                    fget=_get_expiresElemMustBeSet,
                                    doc="Set to True to raise an exception if "
                                        "a message to be verified doesn't "
                                        "have <wsu:Expires/> element with its "
                                        "timestamp element.  Set to False to "
                                        "log a warning message and continue "
                                        "processing")                                  

                              
