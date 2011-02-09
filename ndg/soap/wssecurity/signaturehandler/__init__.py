"""Base class for the WS-Security digital signature handlers - to allow 
sharing of common code

NERC DataGrid Project
"""
__author__ = "C Byrom, Philip Kershaw"
__date__ = "18/08/08, refactored for NDGSoap egg 22/01/2010"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
log = logging.getLogger(__name__)

import os
import re
import base64
import traceback
from datetime import datetime, timedelta
from sha import sha # Digest and signature/verify

from M2Crypto import X509, BIO, RSA

import ZSI
from ZSI.wstools.Namespaces import ENCRYPTION, WSU
from ZSI.wstools.Namespaces import OASIS as _OASIS

from ndg.soap.utils import classfactory
from ndg.soap.utils.configfileparsers import (CaseSensitiveConfigParser, 
                                              WithGetListConfigParser)
from ndg.soap.wssecurity import WSSecurityConfigError, WSSecurityError
from ndg.soap.wssecurity.utils.pki import (X509Cert, X509Stack, 
                                           X509StackParseFromDER)


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
    
    
class VerifyError(WSSecurityError):
    """Raised from SignatureHandler.verify if an error occurs in the signature
    verification"""
    
    
class InvalidSignature(WSSecurityError):
    """Raised from verify method for an invalid signature"""


class SignatureError(WSSecurityError):
    """Flag if an error occurs during signature generation"""


class NoSignatureFound(WSSecurityError):
    """Raise from SignatureHandler.verify if inbound message is not signed"""


_isIterable = lambda obj: getattr(obj, '__iter__', False) 
 

class BaseSignatureHandler(object):
    """Class to handle signature and verification of signature with 
    WS-Security
    
    @cvar BINARY_SECURITY_TOK_VAL_TYPE: supported ValueTypes for 
    BinarySecurityToken
    element in WSSE header
    @type BINARY_SECURITY_TOK_VAL_TYPE: dict
    
    @ivar addTimestamp: set to true to add a timestamp to outbound messages
    @type addTimestamp: bool 

    @ivar applySignatureConfirmation: for servers - set this flag to enable the 
    signature value of a request to be recorded and included with a 
    SignatureConfirmation element in the response.
    @type applySignatureConfirmation: bool
    
    @param b64EncSignatureValue: base 64 encoded signature value for the last 
    message verified
    @type b64EncSignatureValue: string/None"""
    isIterable = staticmethod(_isIterable)

    BINARY_SECURITY_TOK_ENCODING_TYPE = (
        "http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    )
    
    BINARY_SECURITY_TOK_VAL_TYPE = {
        "X509PKIPathv1": OASIS.X509TOKEN.X509PKIPathv1,
        "X509":          OASIS.X509TOKEN.X509,
        "X509v3":        OASIS.X509TOKEN.X509+"v3"
    }

    # keyword used with ZSI.wstools.Utility.Canonicalization
    ZSI_C14N_KEYWORD_NAME = 'inclusive_namespaces'
    
    CFG_PARSER_CLASS = WithGetListConfigParser
    PROPERTY_DEFAULTS = dict(
        className=('',),
        reqBinarySecurityTokValType=(OASIS.X509TOKEN.X509,),
        verifyingCert=(None, ''),
        verifyingCertFilePath=(None, ''),
        signingCert=(None, ''),
        signingCertFilePath=(None, ''), 
        signingCertChain=([],),
        signingPriKey=(None, ''),
        signingPriKeyFilePath=(None, ''), 
        signingPriKeyPwd=(None, ''),
        caCertDirPath=(None, ''),
        caCertFilePathList=([],),
        addTimestamp=(True,),
        timestampClockSkew=(0.,),
        timestampMustBeSet=(False,),
        createdElemMustBeSet=(True,),
        expiresElemMustBeSet=(True,),
        applySignatureConfirmation=(False,),
        refC14nInclNS=([],),
        signedInfoC14nInclNS=([],),
        cfg=(CFG_PARSER_CLASS(),))
    
    CFG_PARSER_GET_FUNC_MAP = {
        str: CFG_PARSER_CLASS.get,
        unicode: CFG_PARSER_CLASS.get,
        bool: CFG_PARSER_CLASS.getboolean,
        float: CFG_PARSER_CLASS.getfloat,
        int: CFG_PARSER_CLASS.getint,
        list: CFG_PARSER_CLASS.getlist
    }
    
    TYPE_MAP = dict([(k, tuple([type(i) for i in v]))
                     for k,v in PROPERTY_DEFAULTS.items()])
    
    __slots__ = TYPE_MAP.copy()
    __slots__.update({}.fromkeys(['__%s' % i for i in TYPE_MAP.keys()]))   
    __slots__.update(
        __caX509Stack=None,
        __referenceElemsC14nKeywords=None,
        __signedInfoElemC14nKeywords=None
    )
    
    def __init__(self):
        ''''''
        log.debug("BaseSignatureHandler.__init__ ...")
        for name, val in BaseSignatureHandler.PROPERTY_DEFAULTS.items():
            setattr(self, name, val[0])

        self.__caX509Stack = X509Stack()
        self.__referenceElemsC14nKeywords = {}
        self.__signedInfoElemC14nKeywords = {}

    @classmethod
    def fromConfigFile(cls, filePath, **kw):
        """Instantiate from settings in a config file"""
        signatureHandler = cls()
        signatureHandler.read(filePath)
        signatureHandler.parse(**kw)
        return signatureHandler

    @classmethod
    def fromKeywords(cls, *arg, **kw):
        """Instantiate from keyword settings - this is useful when integrating
        with Paste WSGI apps app_conf settings"""
        signatureHandler = cls()
        signatureHandler.update(**kw)
        return signatureHandler
    
    @classmethod
    def expandVars(cls, val):
        if cls.isIterable(val):
            for i, v in zip(range(len(val)), val):
                if isinstance(v, basestring):
                    val[i] = os.path.expandvars(v) 
            return val
        
        elif isinstance(val, basestring):
            return os.path.expandvars(val)
        else:
            return val
        
    def __setattr__(self, name, val):
        expectedTypes = BaseSignatureHandler.TYPE_MAP.get(name)
        if expectedTypes is not None:
            if not isinstance(val, expectedTypes):
                raise TypeError('Expected type(s) for % attribute are %r; '
                                'got %r' % (name, expectedTypes, type(val)))
                                
        super(BaseSignatureHandler, self).__setattr__(name, val)

    def read(self, filePath):
        '''Read ConfigParser object
        
        @type filePath: basestring
        @param filePath: file to read config from'''
        
        # Expand environment variables in file path
        expandedFilePath = os.path.expandvars(filePath)
        
        # Add 'here' item to enable convenient path substitutions in the config
        # file
        defaultItems = dict(here=os.path.dirname(expandedFilePath))
        self.cfg.defaults().update(defaults=defaultItems)
        
        readFilePaths = self.cfg.read(expandedFilePath)
        
        # Check file was read in OK
        if len(readFilePaths) == 0:
            raise IOError('Missing config file: "%s"' % expandedFilePath)

    def parse(self, sectionName='DEFAULT', prefix=None):
        '''Extract items from config file and assign to instance attributes
        
        @type prefix: None type or basestring
        @param prefix: Prefix for option names - optNames = name as they appear 
        in the config file
        '''
        if prefix:
            optNames = ["%s.%s" % (prefix, optName) 
                        for optName in BaseSignatureHandler.PROPERTY_DEFAULTS] 
        else:
            optNames = BaseSignatureHandler.PROPERTY_DEFAULTS.keys()
            
        paramSettings = zip(optNames, 
                            BaseSignatureHandler.PROPERTY_DEFAULTS.keys()) 
           
        for optName, attrName in paramSettings:
            
            # Parameters may be omitted and set later
            if self.cfg.has_option(sectionName, optName):
                types = BaseSignatureHandler.TYPE_MAP.get(attrName)
                if types is None:
                    raise WSSecurityConfigError("No type set for %r attribute" %
                                                attrName)
                    
                getFunc = BaseSignatureHandler.CFG_PARSER_GET_FUNC_MAP.get(
                                                                    types[-1])
                if getFunc is None:
                    raise WSSecurityConfigError("No Config parser get method "
                                                "configured for attribute %r "
                                                "with type %r" %
                                                (attrName, types[-1]))
                     
                val = getFunc(self.cfg, sectionName, optName)
                setattr(self, attrName, BaseSignatureHandler.expandVars(val))
                 
    def update(self, prefix=None, **kw):
        '''Extract items from a dictionary and assign to instance attributes
        
        @type prefix: None type or basestring
        @param prefix: Prefix for option names - optNames = name as they appear 
        in the config file
        @type **kw: dict
        @param **kw: this enables WS-Security params to be set in a config file
        with other sections e.g. params could be under the section 'wssecurity'
        '''           
        for optName, val in kw.items():
            # Parameters may be omitted and set later
            if prefix:
                optName = optName.replace(prefix, '', 1)
                setattr(self, optName, BaseSignatureHandler.expandVars(val))
                
    def sign(self, soapWriter):
        '''Sign the message body and binary security token of a SOAP message
        
        Derived class must implement
        
        @type soapWriter: ZSI.writer.SoapWriter
        @param soapWriter: ZSI object to write SOAP message
        '''
        raise NotImplementedError()
    
    def verify(self, parsedSOAP):
        """Verify signature.  Derived class must implement
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender"""        
        raise NotImplementedError()
                                      
    def _setReqBinarySecurityTokValType(self, value):
        """Set ValueType attribute for BinarySecurityToken used in a request
         
        @type value: string
        @param value: name space for BinarySecurityToken ValueType check
        'BINARY_SECURITY_TOK_VAL_TYPE' class variable for supported types.  
        Input can be shortened to BINARY_SECURITY_TOK_VAL_TYPE keyword if 
        desired.
        """
        if value in self.__class__.BINARY_SECURITY_TOK_VAL_TYPE:
            self.__reqBinarySecurityTokValType = \
                self.__class__.BINARY_SECURITY_TOK_VAL_TYPE[value]
 
        elif value in self.__class__.BINARY_SECURITY_TOK_VAL_TYPE.values():
            self.__reqBinarySecurityTokValType = value
        else:
            raise TypeError('Request BinarySecurityToken ValueType %r not '
                            'recognised' % value)
            
    def _getReqBinarySecurityTokValType(self):
        """
        Get ValueType attribute for BinarySecurityToken used in a request
        """
        return self.__reqBinarySecurityTokValType
        
    reqBinarySecurityTokValType = property(fset=_setReqBinarySecurityTokValType,
                                           fget=_getReqBinarySecurityTokValType,
                                           doc="ValueType attribute for "
                                               "BinarySecurityToken used in "
                                               "request")
    
    @classmethod
    def __checkC14nKw(cls, kw):
        """Check keywords for canonicalization in signing process - generic
        method for setting keywords for reference element and SignedInfo
        element C14N
        
        @type kw: dict
        @param kw: keyword used with ZSI.wstools.Utility.Canonicalization"""
        
        # Check for dict/None - Set to None in order to use inclusive 
        # canonicalization
        if not isinstance(kw, (dict, type(None))):
            # Otherwise keywords must be a dictionary
            raise TypeError("Expecting dictionary type for reference C14N "
                            "keywords")
                
        elif not isinstance(kw.get(cls.ZSI_C14N_KEYWORD_NAME), (list, tuple)):
            raise TypeError('Expecting list or tuple of prefix names for '
                            '"%s" keyword' % cls.ZSI_C14N_KEYWORD_NAME)
        
                
    def _setReferenceElemsC14nKeywords(self, kw):
        """Set keywords for canonicalization of reference elements in the 
        signing process"""
        self.__checkC14nKw(kw)                    
        self.__referenceElemsC14nKeywords = kw
        
    def _getReferenceElemsC14nKeywords(self):
        return self.__referenceElemsC14nKeywords
        
    referenceElemsC14nKeywords = property(fset=_setReferenceElemsC14nKeywords,
                         fget=_getReferenceElemsC14nKeywords,
                         doc="Keywords for C14N of reference elements")
        
    def _setSignedInfoElemC14nKeywords(self, kw):
        """Set keywords for canonicalization of SignedInfo element in the 
        signing process"""
        self.__checkC14nKw(kw)                    
        self.__signedInfoElemC14nKeywords = kw
        
    def _getSignedInfoElemC14nKeywords(self):
        if hasattr(self, '_signedInfoElemC14nKeywords'):
            return self.__signedInfoElemC14nKeywords
        else:
            return {}
        
    signedInfoElemC14nKeywords = property(fset=_setSignedInfoElemC14nKeywords,
                                fget=_getSignedInfoElemC14nKeywords,
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
            x509Cert = X509Cert.Parse(cert)
        
        else:
            raise TypeError("X.509 Cert. must be type: ndg.security."
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
        return self.__verifyingCert

    def _setVerifyingCert(self, verifyingCert):
        "Set property method for X.509 cert. used to verify a signature"
        self.__verifyingCert = self._setCert(verifyingCert)
        
        # Reset file path as it may no longer apply
        self.__verifyingCertFilePath = None
        
    verifyingCert = property(fset=_setVerifyingCert,
                             fget=_getVerifyingCert,
                             doc="Set X.509 Cert. for verifying signature")

    def _setVerifyingCertFilePath(self, verifyingCertFilePath):
        "Set method for Service X.509 cert. file path property"
        if verifyingCertFilePath:
            if isinstance(verifyingCertFilePath, basestring):
                self.__verifyingCert = X509Cert.Read(verifyingCertFilePath)
            else:
                raise TypeError("X.509 Cert file path is not a valid string")
        
        self.__verifyingCertFilePath = verifyingCertFilePath
        
    verifyingCertFilePath = property(fset=_setVerifyingCertFilePath,
                    doc="file path of X.509 Cert. for verifying signature")

    def _getSigningCert(self):
        '''Return X.509 certificate object corresponding to certificate used 
        with signature
        
        @rtype: M2Crypto.X509.X509
        @return: certificate object
        '''
        return self.__signingCert

    def _setSigningCert(self, signingCert):
        "Set property method for X.509 cert. to be included with signature"
        self.__signingCert = self._setCert(signingCert)
    
        # Reset file path as it may no longer apply
        self.__signingCertFilePath = None
        
    signingCert = property(fget=_getSigningCert,
                           fset=_setSigningCert,
                           doc="X.509 Certificate to include signature")

    def _getSigningCertFilePath(self):
        "Get signature X.509 certificate property method"
        return self.__signingCertFilePath
    
    def _setSigningCertFilePath(self, signingCertFilePath):
        "Set signature X.509 certificate property method"
        
        if isinstance(signingCertFilePath, basestring):
            self.__signingCert = X509Cert.Read(signingCertFilePath)
            
        elif signingCertFilePath is not None:
            raise AttributeError("Signature X.509 certificate file path must "
                                 "be a valid string")
        
        self.__signingCertFilePath = signingCertFilePath
        
    signingCertFilePath = property(fget=_getSigningCertFilePath,
                                   fset=_setSigningCertFilePath,
                                   doc="File path X.509 cert. to include with "
                                       "signed message")

    def _setSigningCertChain(self, signingCertChain):
        '''Signature set-up with "X509PKIPathv1" BinarySecurityToken 
        ValueType.  Use an X.509 Stack to store certificates that make up a 
        chain of trust to certificate used to verify a signature
        
        @type signingCertChain: list or tuple of M2Crypto.X509.X509Cert or
        ndg.security.common.X509.X509Cert types.
        @param signingCertChain: list of certificate objects making up the
        chain of trust.  The last certificate is the one associated with the
        private key used to sign the message.'''
        self.__signingCertChain = X509Stack()
        
        for cert in signingCertChain:
            if cert:
                self.__signingCertChain.push(cert)
            
    def _getSigningCertChain(self):
        return self.__signingCertChain
    
    signingCertChain = property(fset=_setSigningCertChain,
                                fget=_getSigningCertChain,
                                doc="Certificates in the chain of trust to "
                                    "verify the certificate provided in an "
                                    "incoming message.")

    def _setSigningPriKeyPwd(self, signingPriKeyPwd):
        "Set method for private key file password used to sign message"
        if (signingPriKeyPwd is not None and 
            not isinstance(signingPriKeyPwd, basestring)):
            raise AttributeError("Signing private key password must be None "
                                 "or a valid string")
        
        self.__signingPriKeyPwd = signingPriKeyPwd

    def _getSigningPriKeyPwd(self):       
        return self.__signingPriKeyPwd

    signingPriKeyPwd = property(fset=_setSigningPriKeyPwd,
                                fget=_getSigningPriKeyPwd,
                                doc="Password protecting private key file "
                                    "used to sign message")

    def _setSigningPriKey(self, signingPriKey):
        """Set method for client private key
        
        Nb. if input is a string, signingPriKeyPwd will need to be set if
        the key is password protected.
        
        @type signingPriKey: M2Crypto.RSA.RSA / string / None
        @param signingPriKey: private key used to sign message"""
        if not signingPriKey:
            self.__signingPriKey = None
            
        elif isinstance(signingPriKey, basestring):
            pwdCallback = lambda *ar, **kw: self.__signingPriKeyPwd
            self.__signingPriKey = RSA.load_key_string(signingPriKey,
                                                       callback=pwdCallback)
        elif isinstance(signingPriKey, RSA.RSA):
            self.__signingPriKey = signingPriKey
            
        else:
            raise TypeError("Signing private key must be a valid "
                            "M2Crypto.RSA.RSA type or a string")
                
    def _getSigningPriKey(self):
        return self.__signingPriKey

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
                pwdCallback = lambda *ar, **kw: self.__signingPriKeyPwd                                           
                self.__signingPriKey = RSA.load_key_bio(priKeyFile, 
                                                        callback=pwdCallback)           
            except Exception, e:
                raise AttributeError("Setting private key for signature: %s"%e)
        
        elif signingPriKeyFilePath is not None:
            raise TypeError("Private key file path must be a valid string or "
                            "None")
        
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
        for cert in caCertList:
            self.__caX509Stack.push(cert)


    def __setCAX509StackFromDir(self, caCertDir):
        '''Read CA certificates from directory and add them to the X.509
        stack
        
        @param caCertDir: string / None type
        @type caCertDir: directory from which to read CA certificate files'''
        
        if not caCertDir:
            return
        
        # Mimic OpenSSL -CApath option which expects directory of CA files
        # of form <Hash cert subject name>.0
        reg = re.compile('\d+\.0')
        try:
            caCertList = [X509Cert.Read(caFile) 
                          for caFile in os.listdir(caCertDir) 
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

        # Mimic OpenSSL -CApath option which expects directory of CA files
        # of form <Hash cert subject name>.0
        try:
            caCertList = [X509Cert.Read(caFile) for caFile in caCertFilePathList]
        except Exception:
            raise WSSecurityError('Loading CA certificate "%s" from file '
                                  'list: %s' % (caFile, traceback.format_exc()))
                    
        # Add to stack
        self.__appendCAX509Stack(caCertList)
        
    caCertFilePathList = property(fset=__setCAX509StackFromCertFileList,
                                  doc="List of CA cert. files used for "
                                      "verification")              
        
    def _get_timestampClockSkew(self):
        return self.__timestampClockSkew

    def _set_timestampClockSkew(self, val):
        if isinstance(val, basestring):
            self.__timestampClockSkew = float(val)
            
        elif isinstance(val, (float, int)):
            self.__timestampClockSkew = val
            
        else:
            raise TypeError("Expecting string, float or int type for "
                            "timestampClockSkew attribute, got %r" % 
                            type(val))
        
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
        return self.__timestampMustBeSet

    def _set_timestampMustBeSet(self, val):
        self.__timestampMustBeSet = self._setBool(val)
        
    timestampMustBeSet = property(fset=_set_timestampMustBeSet,
                                  fget=_get_timestampMustBeSet,
                                  doc="Set to True to raise an exception if a "
                                      "message to be verified doesn't have a "
                                      "timestamp element.  Set to False to "
                                      "log a warning message and continue "
                                      "processing")
    
    def _get_createdElemMustBeSet(self):
        return self.__createdElemMustBeSet

    def _set_createdElemMustBeSet(self, val):
        self.__createdElemMustBeSet = self._setBool(val)
        
    createdElemMustBeSet = property(fset=_set_createdElemMustBeSet,
                                    fget=_get_createdElemMustBeSet,
                                    doc="Set to True to raise an exception if "
                                        "a message to be verified doesn't "
                                        "have <wsu:Created/> element with its "
                                        "timestamp element.  Set to False to "
                                        "log a warning message and continue "
                                        "processing")
    
    def _get_expiresElemMustBeSet(self):
        return self.__expiresElemMustBeSet

    def _set_expiresElemMustBeSet(self, val):
        self.__expiresElemMustBeSet = self._setBool(val)
        
    expiresElemMustBeSet = property(fset=_set_expiresElemMustBeSet,
                                    fget=_get_expiresElemMustBeSet,
                                    doc="Set to True to raise an exception if "
                                        "a message to be verified doesn't "
                                        "have <wsu:Expires/> element with its "
                                        "timestamp element.  Set to False to "
                                        "log a warning message and continue "
                                        "processing")           
    
    
class SignatureHandlerFactory(object):
    """Create a new signature handler from the given class name and other 
    configuration settings
    """
    CLASS_NAME_OPTNAME = 'className'
    
    @classmethod
    def fromConfigFile(cls, filePath, sectionName='DEFAULT', prefix=''):
        """Instantiate a new signature handler from a config file"""
        
        # Expand environment variables in file path
        expandedFilePath = os.path.expandvars(filePath)
        
        # Add 'here' item to enable convenient path substitutions in the config
        # file
        defaultItems = dict(here=os.path.dirname(expandedFilePath))
        cfg = CaseSensitiveConfigParser(defaults=defaultItems)
        
        readFilePaths = cfg.read(expandedFilePath)
        
        # Check file was read in OK
        if len(readFilePaths) == 0:
            raise IOError('Missing config file: "%s"' % expandedFilePath) 
               
        optName = prefix + cls.CLASS_NAME_OPTNAME
        className = cfg.get(sectionName, optName)
        signatureHandlerClass = classfactory.importClass(className, 
                                            objectType=BaseSignatureHandler)
        
        return signatureHandlerClass.fromConfigFile(filePath,
                                                    sectionName=sectionName, 
                                                    prefix=prefix)
    
    @classmethod
    def fromKeywords(cls, prefix='', **kw):
        """Instantiate a new signature handler from keyword settings"""
        optName = prefix + cls.CLASS_NAME_OPTNAME
        className = kw.get(optName)
        if className is None:
            raise KeyError("No %r keyword setting" % cls.CLASS_NAME_OPTNAME)
        
        signatureHandlerClass = classfactory.importClass(className, 
                                            objectType=BaseSignatureHandler)
        
        return signatureHandlerClass.fromKeywords(prefix, **kw)
    