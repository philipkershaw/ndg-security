"""WS-Security test class includes digital signature handler

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/09/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

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
                                  
from ZSI.TC import ElementDeclaration,TypeDefinition
from ZSI.generate.pyclass import pyclass_type

from ZSI.wstools.Utility import DOMException
from ZSI.wstools.Utility import NamespaceError, MessageInterface, ElementProxy

# Canonicalization
from ZSI.wstools.c14n import Canonicalize

from xml.dom import Node
from xml.xpath.Context import Context
from xml import xpath

# Include for re-parsing doc ready for canonicalization in sign method - see
# associated note
from xml.dom.ext.reader.PyExpat import Reader

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
    UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

class OASIS(_OASIS):
    # wss4j 1.5.3
    WSSE11 = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
    # wss4j 1.5.1
    #WSSE11 = "http://docs.oasis-open.org/wss/2005/xx/oasis-2005xx-wss-wssecurity-secext-1.1.xsd"
       
def getElements(node, nameList):
    '''DOM Helper function for getting child elements from a given node'''
    # Avoid sub-string matches
    nameList = isinstance(nameList, basestring) and [nameList] or nameList
    return [n for n in node.childNodes if str(n.localName) in nameList]


def getChildNodes(node, nodeList=None):
    if nodeList is None:
        nodeList = [node] 
    return _getChildNodes(node, nodeList)
           
def _getChildNodes(node, nodeList):

    if node.attributes is not None:
        nodeList += node.attributes.values() 
    nodeList += node.childNodes
    for childNode in node.childNodes:
        _getChildNodes(childNode, nodeList)
    return nodeList



class WSSecurityError(Exception):
    """For WS-Security generic exceptions not covered by other exception
    classes in this module"""

class InvalidCertChain(Exception):    
    """Raised from SignatureHandler.verify if the certificate submitted to
    verify a signature is not from a known CA"""
    
class VerifyError(Exception):
    """Raised from SignatureHandler.verify if an error occurs in the signature
    verification"""
 
class TimestampError(Exception):
    """Raised from SignatureHandler._verifyTimestamp if there is a problem with
    the created or expiry times in an input message Timestamp"""
    
class InvalidSignature(Exception):
    """Raised from verify method for an invalid signature"""

class SignatureError(Exception):
    """Flag if an error occurs during signature generation"""
        
class SignatureHandler(object):
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

    
    binSecTokValType = {
        "X509PKIPathv1": OASIS.X509TOKEN.X509PKIPathv1,
        "X509":          OASIS.X509TOKEN.X509,
        "X509v3":        OASIS.X509TOKEN.X509+"v3"
    }


    #_________________________________________________________________________
    def __init__(self, cfg=None, cfgFileSection='DEFAULT',
                 cfgClass=WSSecurityConfig, **kw):
        '''
        @reqBinSecTokValType: set the ValueType for the BinarySecurityToken
        added to the WSSE header for a signed message.  See 
        __setReqBinSecTokValType method and binSecTokValType class variable
        for options.  binSecTokValType determines whether signingCert or
        signingCertChain attributes will be used.        
        @type binSecTokValType: string
        
        @param verifyingCert: X.509 certificate used by verify method to
        verify a message.  This argument can be omitted if the message to
        be verified contains the X.509 certificate in the 
        BinarySecurityToken element.  In this case, the cert read from the
        message will be assigned to the verifyingCert attribute.
        @type verifyingCert: M2Crypto.X509.X509 / 
        ndg.security.common.X509.X509Cert
        
        @param verifyingCertFilePath: alternative input to the above, pass 
        the file path to the certificate stored in a file
        @type verifyingCertFilePath: string
        
        @param signingCert: certificate associated with private key used to
        sign a message.  The sign method will add this to the 
        BinarySecurityToken element of the WSSE header.  binSecTokValType
        attribute must be set to 'X509' or 'X509v3' ValueTyep.  As an 
        alternative, use signingCertChain - see below...
        @type signingCert: M2Crypto.X509.X509 / 
        ndg.security.common.X509.X509Cert
        
        @param signingCertFilePath: alternative input to the above, pass 
        the file path to the certificate stored in a file
        @type signingCertFilePath: string
        
        @param signingCertChain: pass a list of certificates constituting a 
        chain of trust from the certificate used to verifying the signature 
        backward to the CA cert.  The CA cert need not be included.  To use 
        this option, reqBinSecTokValType must be set to the 'X509PKIPathv1'
        ValueType
        @type signingCertChain: list or tuple 
        
        @param signingPriKey: private key used to be sign method to sign
        message
        @type signingPriKey: M2Crypto.RSA.
        
        @param signingPriKeyFilePath: equivalent to the above but pass 
        private key from PEM file
        @type signingPriKeyFilePath: string
        
        @param signingPriKeyPwd: password protecting private key.  Set /
        default to None if there is no password.
        @type signingPriKeyPwd: string or None
        
        @param caCertDirPath: establish trust for signature verification. 
        This is a directory containing CA certificates.  These are used to
        verify the certificate used to verify the message signature.
        @type caCertDirPath: string
        
        @param caCertFilePathList: same as above except pass in a list of
        file paths instead of a single directory name.
        @type caCertFilePathList: list or tuple
        
        @param addTimestamp: set to true to add a timestamp to outbound 
        messages
        @type addTimestamp: bool 
        
        @param : for servers - set this flag to enable the signature value of a
        request to be recorded and included with a SignatureConfirmation 
        element in the response.
        @type : bool 
        
        @param refC14nKw: dictionary of keywords to reference 
        Canonicalization.  Use 'unsuppressedPrefixes' keyword to set 
        unsuppressedPrefixes.
        @type refC14nKw: dict
        
        @param signedInfoC14nKw: keywords to Signed Info Canonicalization.
        It uses the same format as refC14nKw above.
        @type signedInfoC14nKw: dict
        '''
        log.debug("SignatureHandler.__init__ ...")
        
        # WSSecurityConfig is the default class for reading config params but
        # alternative derivative class may be passed in instead.
        if not issubclass(cfgClass, WSSecurityConfig):
            raise TypeError("%s is not a sub-class of WSSecurityConfig" % \
                            cfgClass)
        
        # Read parameters from config file if set
        if isinstance(cfg, basestring):
            log.debug("SignatureHandler.__init__: config file path input ...")
            self.cfg = cfgClass()
            self.cfg.read(cfg)
        else:
            log.debug("SignatureHandler.__init__: config object input ...")
            self.cfg = cfgClass(cfg=cfg)
            
        if cfg: # config object or config file path was set
            log.debug("SignatureHandler.__init__: Processing config file...")
            self.cfg.parse(section=cfgFileSection)

        # Also update config from keywords set 
        log.debug("SignatureHandler.__init__: setting config from keywords...")
        self.cfg.update(kw)
        
        
        self.__setReqBinSecTokValType(self.cfg['reqBinSecTokValType'])
        
        # Set keywords for canonicalization of SignedInfo and reference 
        # elements
        # TODO: get rid of refC14nKw and signedInfoC14nKw options
        if len(self.cfg.get('refC14nInclNS', [])):
            self.__setRefC14nKw({'unsuppressedPrefixes':
                                 self.cfg['refC14nInclNS']})
        else:
            self.__setRefC14nKw(self.cfg['refC14nKw'])

   
        if len(self.cfg.get('signedInfoC14nNS', [])):
            self.__setSignedInfoC14nKw({'unsuppressedPrefixes':
                                        self.cfg['signedInfoC14nNS']})
        else:
            self.__setSignedInfoC14nKw(self.cfg['signedInfoC14nKw'])
            

        self.__setVerifyingCert(self.cfg['verifyingCert'])
        self.__setVerifyingCertFilePath(self.cfg['verifyingCertFilePath'])
        
        self.__setSigningCert(self.cfg['signingCert'])
        self.__setSigningCertFilePath(self.cfg['signingCertFilePath'])

        if self.cfg.get('signingCertChain'):
            self.__setSigningCertChain(self.cfg['signingCertChain'])
        else:
            self.__signingCertChain = None   
             
        # MUST be set before __setSigningPriKeyFilePath / __setSigningPriKey
        # are called
        self.__setSigningPriKeyPwd(self.cfg['signingPriKeyPwd'])
        
        if self.cfg.get('signingPriKey'):
            # Don't allow None for private key setting
            self.__setSigningPriKey(self.cfg['signingPriKey'])
            
        self.__setSigningPriKeyFilePath(self.cfg['signingPriKeyFilePath'])
        
        # CA certificate(s) for verification of X.509 certificate used with
        # signature.
        if self.cfg.get('caCertDirPath'):
            self.caCertDirPath = self.cfg['caCertDirPath']
            
        elif self.cfg.get('caCertFilePathList'):
            self.caCertFilePathList = self.cfg['caCertFilePathList']
            
        self.addTimestamp = self.cfg['addTimestamp']
        self.applySignatureConfirmation=self.cfg['applySignatureConfirmation']
        self.b64EncSignatureValue = None
        
        log.debug("WSSE Config = %s" % self.cfg)

                
    #_________________________________________________________________________
    def __setReqBinSecTokValType(self, value):
        """Set ValueType attribute for BinarySecurityToken used in a request
         
        @type value: string
        @param value: name space for BinarySecurityToken ValueType check
        'binSecTokValType' class variable for supported types.  Input can be 
        shortened to binSecTokValType keyword if desired.
        """
        
        if value in self.__class__.binSecTokValType:
            self.__reqBinSecTokValType = self.__class__.binSecTokValType[value]
 
        elif value in self.__class__.binSecTokValType.values():
            self.__reqBinSecTokValType = value
        else:
            raise WSSecurityError, \
                'Request BinarySecurityToken ValueType "%s" not recognised' %\
                value
            
        
    reqBinSecTokValType = property(fset=__setReqBinSecTokValType,
         doc="ValueType attribute for BinarySecurityToken used in request")
        

    #_________________________________________________________________________
    def __checkC14nKw(self, kw):
        """Check keywords for canonicalization in signing process - generic
        method for setting keywords for reference element and SignedInfo
        element c14n
        
        @type kw: dict
        @param kw: keyword used with ZSI.wstools.Utility.Canonicalization"""
        
        # Check for dict/None - Set to None in order to use inclusive 
        # canonicalization
        if kw is not None and not isinstance(kw, dict):
            # Otherwise keywords must be a dictionary
            raise AttributeError, \
                "Expecting dictionary type for reference c14n keywords"
                
        elif kw.get('unsuppressedPrefixes') and \
             not isinstance(kw['unsuppressedPrefixes'], list) and \
             not isinstance(kw['unsuppressedPrefixes'], tuple):
            raise AttributeError, \
                'Expecting list or tuple of prefix names for "%s" keyword' % \
                'unsuppressedPrefixes'
        
                
    #_________________________________________________________________________
    def __setRefC14nKw(self, kw):
        """Set keywords for canonicalization of reference elements in the 
        signing process"""
        self.__checkC14nKw(kw)                    
        self.__refC14nKw = kw
        
    refC14nKw = property(fset=__setRefC14nKw,
                         doc="Keywords for c14n of reference elements")
        
                
    #_________________________________________________________________________
    def __setSignedInfoC14nKw(self, kw):
        """Set keywords for canonicalization of SignedInfo element in the 
        signing process"""
        self.__checkC14nKw(kw)                    
        self.__signedInfoC14nKw = kw
        
    signedInfoC14nKw = property(fset=__setSignedInfoC14nKw,
                                doc="Keywords for c14n of SignedInfo element")


    #_________________________________________________________________________
    def __refC14nIsExcl(self):
        return isinstance(self.__refC14nKw, dict) and \
               isinstance(self.__refC14nKw.get('unsuppressedPrefixes'), list)
               
    refC14nIsExcl = property(fget=__refC14nIsExcl,
    doc="Return True/False c14n for reference elements set to exclusive type")
     

    #_________________________________________________________________________
    def __signedInfoC14nIsExcl(self):
        return isinstance(self.__signedInfoC14nKw, dict) and \
        isinstance(self.__signedInfoC14nKw.get('unsuppressedPrefixes'), list)
               
    signedInfoC14nIsExcl = property(fget=__signedInfoC14nIsExcl,
    doc="Return True/False c14n for SignedInfo element set to exclusive type")
    
    
    #_________________________________________________________________________
    def __setCert(self, cert):
        """filter and convert input cert to signing verifying cert set 
        property methods.  For signingCert, set to None if it is not to be
        included in the SOAP header.  For verifyingCert, set to None if this
        cert can be expected to be retrieved from the SOAP header of the 
        message to be verified
        
        @type: ndg.security.common.X509.X509Cert / M2Crypto.X509.X509 /
        string or None
        @param cert: X.509 certificate.  
        
        @rtype ndg.security.common.X509.X509Cert
        @return X.509 certificate object"""
        
        if cert is None or isinstance(cert, X509Cert):
            # ndg.security.common.X509.X509Cert type / None
            return cert
            
        elif isinstance(cert, X509.X509):
            # M2Crypto.X509.X509 type
            return X509Cert(m2CryptoX509=cert)
            
        elif isinstance(cert, basestring):
            return X509CertParse(cert)
        
        else:
            raise AttributeError, "X.509 Cert. must be type: " + \
                "ndg.security.common.X509.X509Cert, M2Crypto.X509.X509 or " +\
                "a base64 encoded string"

    
    #_________________________________________________________________________
    def __getVerifyingCert(self):
        '''Return X.509 cert object corresponding to cert used to verify the 
        signature in the last call to verify
        
         * Cert will correspond to one used in the LATEST call to verify, on
         the next call it will be replaced
         * if verify hasn't been called, the cert will be None
        
        @rtype: M2Crypto.X509.X509
        @return: certificate object
        '''
        return self.__verifyingCert


    #_________________________________________________________________________
    def __setVerifyingCert(self, verifyingCert):
        "Set property method for X.509 cert. used to verify a signature"
        self.__verifyingCert = self.__setCert(verifyingCert)
    
        # Reset file path as it may no longer apply
        self.__verifyingCertFilePath = None
        
    verifyingCert = property(fset=__setVerifyingCert,
                             fget=__getVerifyingCert,
                             doc="Set X.509 Cert. for verifying signature")


    #_________________________________________________________________________
    def __setVerifyingCertFilePath(self, verifyingCertFilePath):
        "Set method for Service X.509 cert. file path property"
        
        if isinstance(verifyingCertFilePath, basestring):
            self.__verifyingCert = X509CertRead(verifyingCertFilePath)
            
        elif verifyingCertFilePath is not None:
            raise AttributeError, \
            "Verifying X.509 Cert. file path must be None or a valid string"
        
        self.__verifyingCertFilePath = verifyingCertFilePath
        
    verifyingCertFilePath = property(fset=__setVerifyingCertFilePath,
                    doc="file path of X.509 Cert. for verifying signature")

    
    #_________________________________________________________________________
    def __getSigningCert(self):
        '''Return X.509 cert object corresponding to cert used with
        signature
        
        @rtype: M2Crypto.X509.X509
        @return: certificate object
        '''
        return self.__signingCert


    #_________________________________________________________________________
    def __setSigningCert(self, signingCert):
        "Set property method for X.509 cert. to be included with signature"
        self.__signingCert = self.__setCert(signingCert)
    
        # Reset file path as it may no longer apply
        self.__signingCertFilePath = None
        
    signingCert = property(fget=__getSigningCert,
                           fset=__setSigningCert,
                           doc="X.509 Cert. to include signature")

 
    #_________________________________________________________________________
    def __setSigningCertFilePath(self, signingCertFilePath):
        "Set signature X.509 cert property method"
        
        if isinstance(signingCertFilePath, basestring):
            self.__signingCert = X509CertRead(signingCertFilePath)
            
        elif signingCertFilePath is not None:
            raise AttributeError, \
                "Signature X.509 cert. file path must be a valid string"
        
        self.__signingCertFilePath = signingCertFilePath
        
        
    signingCertFilePath = property(fset=__setSigningCertFilePath,
                   doc="File path X.509 cert. to include with signed message")

    
    #_________________________________________________________________________
    def __setSigningCertChain(self, signingCertChain):
        '''Signature set-up with "X509PKIPathv1" BinarySecurityToken 
        ValueType.  Use an X.509 Stack to store certificates that make up a 
        chain of trust to certificate used to verify a signature
        
        @type signingCertChain: list or tuple of M2Crypto.X509.X509Cert or
        ndg.security.common.X509.X509Cert types.
        @param signingCertChain: list of certificate objects making up the
        chain of trust.  The last certificate is the one associated with the
        private key used to sign the message.'''
        
        if not isinstance(signingCertChain, list) and \
           not isinstance(signingCertChain, tuple):
            raise WSSecurityError, \
                        'Expecting a list or tuple for "signingCertChain"'
        
        self.__signingCertChain = X509Stack()
            
        for cert in signingCertChain:
            self.__signingCertChain.push(cert)
            
    signingCertChain = property(fset=__setSigningCertChain,
               doc="Cert.s in chain of trust to cert. used to verify msg.")

 
    #_________________________________________________________________________
    def __setSigningPriKeyPwd(self, signingPriKeyPwd):
        "Set method for private key file password used to sign message"
        if signingPriKeyPwd is not None and \
           not isinstance(signingPriKeyPwd, basestring):
            raise AttributeError, \
                "Signing private key password must be None or a valid string"
        
        self.__signingPriKeyPwd = signingPriKeyPwd
        
    signingPriKeyPwd = property(fset=__setSigningPriKeyPwd,
             doc="Password protecting private key file used to sign message")

 
    #_________________________________________________________________________
    def __setSigningPriKey(self, signingPriKey):
        """Set method for client private key
        
        Nb. if input is a string, signingPriKeyPwd will need to be set if
        the key is password protected.
        
        @type signingPriKey: M2Crypto.RSA.RSA / string
        @param signingPriKey: private key used to sign message"""
        
        if isinstance(signingPriKey, basestring):
            pwdCallback = lambda *ar, **kw: self.__signingPriKeyPwd
            self.__signingPriKey = RSA.load_key_string(signingPriKey,
                                                       callback=pwdCallback)

        elif isinstance(signingPriKey, RSA.RSA):
            self.__signingPriKey = signingPriKey 
                   
        else:
            raise AttributeError, "Signing private key must be a valid " + \
                                  "M2Crypto.RSA.RSA type or a string"
                
    signingPriKey = property(fset=__setSigningPriKey,
                             doc="Private key used to sign outbound message")

 
    #_________________________________________________________________________
    def __setSigningPriKeyFilePath(self, signingPriKeyFilePath):
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
                raise AttributeError, \
                                "Setting private key for signature: %s" % e
        
        elif signingPriKeyFilePath is not None:
            raise AttributeError, \
                        "Private key file path must be a valid string or None"
        
        self.__signingPriKeyFilePath = signingPriKeyFilePath
        
    signingPriKeyFilePath = property(fset=__setSigningPriKeyFilePath,
                      doc="File path for private key used to sign message")

    def __caCertIsSet(self):
        '''Check for CA certificate set (X.509 Stack has been created)'''
        return hasattr(self, '_SignatureHandler__caX509Stack')
    
    caCertIsSet = property(fget=__caCertIsSet,
           doc='Check for CA certificate set (X.509 Stack has been created)')
    
    #_________________________________________________________________________
    def __appendCAX509Stack(self, caCertList):
        '''Store CA certificates in an X.509 Stack
        
        @param caCertList: list or tuple
        @type caCertList: M2Crypto.X509.X509 certificate objects'''
        
        if not self.caCertIsSet:
            self.__caX509Stack = X509Stack()
            
        for cert in caCertList:
            self.__caX509Stack.push(cert)


    #_________________________________________________________________________
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
            raise WSSecurityError, \
                'Loading CA certificate "%s" from CA directory: %s' % \
                                                        (caFile, str(e))
                    
        # Add to stack
        self.__appendCAX509Stack(caCertList)
        
    caCertDirPath = property(fset=__setCAX509StackFromDir,
                      doc="Dir. containing CA cert.s used for verification")


    #_________________________________________________________________________
    def __setCAX509StackFromCertFileList(self, caCertFilePathList):
        '''Read CA certificates from file and add them to the X.509
        stack
        
        @type caCertFilePathList: list or tuple
        @param caCertFilePathList: list of file paths for CA certificates to
        be used to verify certificate used to sign message'''
        
        if not isinstance(caCertFilePathList, list) and \
           not isinstance(caCertFilePathList, tuple):
            raise WSSecurityError, \
                        'Expecting a list or tuple for "caCertFilePathList"'

        # Mimic OpenSSL -CApath option which expects directory of CA files
        # of form <Hash cert subject name>.0
        try:
            caCertList = [X509CertRead(caFile) \
                          for caFile in caCertFilePathList]
        except Exception, e:
            raise WSSecurityError, \
                    'Loading CA certificate "%s" from file list: %s' % \
                                                        (caFile, str(e))
                    
        # Add to stack
        self.__appendCAX509Stack(caCertList)
        
    caCertFilePathList = property(fset=__setCAX509StackFromCertFileList,
                      doc="List of CA cert. files used for verification")
                

    def _applySignatureConfirmation(self, wsseElem):
        '''Add SignatureConfirmation element - as specified in WS-Security 1.1
        - to outbound message on receipt of a signed message from a client
        
        This has been added in through tests vs. Apache Axis Rampart client
        
        @type wsseElem: 
        @param wsseElem: wsse:Security element'''
        if self.b64EncSignatureValue is None:
            log.info(\
"SignatureConfirmation element requested but no request signature was cached")
            return
        
        sigConfirmElem = wsseElem.createAppendElement(OASIS.WSSE11, 
                                                      'SignatureConfirmation')
        
        # Add ID so that the element can be included in the signature
        sigConfirmElem.node.setAttribute('wsu:Id', "signatureConfirmation")

        # Add ID so that the element can be included in the signature
        # Following line is a hck to avoid appearance of #x when serialising \n
        # chars TODO: why is this happening??
        b64EncSignatureValue = ''.join(self.b64EncSignatureValue.split('\n'))
        sigConfirmElem.node.setAttribute('Value', b64EncSignatureValue)
        
        
    def _addTimeStamp(self, wsseElem, elapsedSec=60*5):
        '''Add a timestamp to wsse:Security section of message to be signed
        e.g.
            <wsu:Timestamp wsu:Id="timestamp">
               <wsu:Created>2008-03-25T14:40:37.319Z</wsu:Created>
               <wsu:Expires>2008-03-25T14:45:37.319Z</wsu:Expires>
            </wsu:Timestamp>
        
        @type wsseElem: 
        @param wsseElem: wsse:Security element
        @type elapsedSec: int    
        @param elapsedSec: time interval in seconds between Created and Expires
        time stamp values 
        '''
        # Nb. wsu ns declaration is in the SOAP header elem
        timestampElem = wsseElem.createAppendElement(_WSU.UTILITY, 'Timestamp')

        # Add ID so that the timestamp element can be included in the signature
        timestampElem.node.setAttribute('wsu:Id', "timestamp")
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        createdElem = timestampElem.createAppendElement(_WSU.UTILITY,'Created')
        dtCreatedTime = datetime.utcnow()
        createdElem.createAppendTextNode(dtCreatedTime.isoformat('T')+'Z')
        
        dtExpiryTime = dtCreatedTime + timedelta(seconds=elapsedSec)
        expiresElem = timestampElem.createAppendElement(_WSU.UTILITY,'Expires')
        expiresElem.createAppendTextNode(dtExpiryTime.isoformat('T')+'Z')
        

    def _verifyTimeStamp(self, parsedSOAP, ctxt):
        """Call from verify to check timestamp if found.  
        
        TODO: refactor input args - maybe these should by object attributes
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender
        @type ctxt:
        @param ctxt: XPath context object"""

        try:
            timestampNode = xpath.Evaluate('//wsse:Timestamp',
                                           contextNode=parsedSOAP.dom,
                                           context=ctxt)[0]
        except:
            log.warning("Verifying message - No timestamp element found")
            return
        
        # Time now 
        dtNow = datetime.utcnow()
        
        createdNode = timestampNode.getElementsByTagName("Created")
        
        # Workaround for fractions of second
        try:
            [createdDateTime, createdSecFraction]=createdNode.nodeValue.split()
        except ValueError, e:
            raise ValueError("Parsing timestamp Created element: %s" % e)
        
        dtCreated = datetime.strptime(createdDateTime, '%Y-%m-%dT%H:%M:%S')
        dtCreated += timedelta(seconds=int(createdSecFraction))
        if dtCreated >= dtNow:
            raise TimestampError(\
        "Timestamp created time %s is equal to or after the current time %s" %\
                (dtCreated, dtNow))
        
        expiresNode = timestampNode.getElementsByTagName("Expires")
        if expiresNode is None:
            log.warning(\
                "Verifying message - No Expires element found in Timestamp")
            return

        try:
            [expiresDateTime, expiresSecFraction]=expiresNode.nodeValue.split()
        except ValueError, e:
            raise ValueError("Parsing timestamp Expires element: %s" % e)
        
        dtCreated = datetime.strptime(expiresDateTime, '%Y-%m-%dT%H:%M:%S')
        dtCreated += timedelta(seconds=int(createdSecFraction))
        if dtExpiry > dtNow:
            raise TimestampError(\
                "Timestamp expiry time %s is after the current time %s" % \
                (dtCreated, dtNow))
            
                   
    #_________________________________________________________________________
    def sign(self, soapWriter):
        '''Sign the message body and binary security token of a SOAP message
        
        @type soapWriter: ZSI.writer.SoapWriter
        @param soapWriter: ZSI object to write SOAP message
        '''
        
        # Namespaces for XPath searches
        processorNss = \
        {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }

        # Add X.509 cert as binary security token
        if self.__reqBinSecTokValType==self.binSecTokValType['X509PKIPathv1']:
            binSecTokVal = base64.encodestring(self.__signingCertChain.asDER())
        else:
            # Assume X.509 / X.509 vers 3
            binSecTokVal = base64.encodestring(self.__signingCert.asDER())

        soapWriter._header.setNamespaceAttribute('wsse', OASIS.WSSE)
        soapWriter._header.setNamespaceAttribute('wsse11', OASIS.WSSE11)
        soapWriter._header.setNamespaceAttribute('wsu', _WSU.UTILITY)
        soapWriter._header.setNamespaceAttribute('ds', DSIG.BASE)
        
        try:
            refC14nPfxSet = len(self.__refC14nKw['unsuppressedPrefixes']) > 0
        except KeyError:
            refC14nPfxSet = False

        try:
            signedInfoC14nPfxSet = \
                len(self.__signedInfoC14nKw['unsuppressedPrefixes']) > 0
        except KeyError:
            signedInfoC14nPfxSet = False
                
        if refC14nPfxSet or refC14nPfxSet:
           soapWriter._header.setNamespaceAttribute('ec', DSIG.C14N_EXCL)
        
        # Check <wsse:security> isn't already present in header
        ctxt = Context(soapWriter.dom.node, processorNss=processorNss)
        wsseNodes = xpath.Evaluate('//wsse:security', 
                                   contextNode=soapWriter.dom.node, 
                                   context=ctxt)
        if len(wsseNodes) > 1:
            raise SignatureError, 'wsse:Security element is already present'

        # Add WSSE element
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                          'Security')
        wsseElem.setNamespaceAttribute('wsse', OASIS.WSSE)
        
        # Recipient MUST parse and check this signature 
        wsseElem.node.setAttribute('SOAP-ENV:mustUnderstand', "1")
        
        # Binary Security Token element will contain the X.509 cert 
        # corresponding to the private key used to sing the message
        binSecTokElem = wsseElem.createAppendElement(OASIS.WSSE, 
                                                     'BinarySecurityToken')
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        binSecTokElem.node.setAttribute('ValueType', 
                                        self.__reqBinSecTokValType)

        encodingType = \
"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        binSecTokElem.node.setAttribute('EncodingType', encodingType)
        
        # Add ID so that the binary token can be included in the signature
        binSecTokElem.node.setAttribute('wsu:Id', "binaryToken")

        binSecTokElem.createAppendTextNode(binSecTokVal)


        # Timestamp
        if self.addTimestamp:
            self._addTimeStamp(wsseElem)
            
        # Signature Confirmation
        if self.applySignatureConfirmation: 
            self._applySignatureConfirmation(wsseElem)
        
        # Signature
        signatureElem = wsseElem.createAppendElement(DSIG.BASE, 'Signature')
        signatureElem.setNamespaceAttribute('ds', DSIG.BASE)
        
        # Signature - Signed Info
        signedInfoElem = signatureElem.createAppendElement(DSIG.BASE, 
                                                           'SignedInfo')
        
        # Signed Info - Canonicalization method
        c14nMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                    'CanonicalizationMethod')
        
        # Set based on 'signedInfoIsExcl' property
        c14nAlgOpt = (DSIG.C14N, DSIG.C14N_EXCL)
        signedInfoC14nAlg = c14nAlgOpt[int(self.signedInfoC14nIsExcl)]
        
        c14nMethodElem.node.setAttribute('Algorithm', signedInfoC14nAlg)
        
        if signedInfoC14nPfxSet:
            c14nInclNamespacesElem = c14nMethodElem.createAppendElement(\
                                                    signedInfoC14nAlg,
                                                    'InclusiveNamespaces')
            c14nInclNamespacesElem.node.setAttribute('PrefixList', 
			    ' '.join(self.__signedInfoC14nKw['unsuppressedPrefixes']))
        
        # Signed Info - Signature method
        sigMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                           'SignatureMethod')
        sigMethodElem.node.setAttribute('Algorithm', DSIG.SIG_RSA_SHA1)
        
        # Signature - Signature value
        signatureValueElem = signatureElem.createAppendElement(DSIG.BASE, 
                                                             'SignatureValue')
        
        # Key Info
        KeyInfoElem = signatureElem.createAppendElement(DSIG.BASE, 'KeyInfo')
        secTokRefElem = KeyInfoElem.createAppendElement(OASIS.WSSE, 
                                                  'SecurityTokenReference')
        
        # Reference back to the binary token included earlier
        wsseRefElem = secTokRefElem.createAppendElement(OASIS.WSSE, 
                                                        'Reference')
        wsseRefElem.node.setAttribute('URI', "#binaryToken")
        
        # Add Reference to body so that it can be included in the signature
        soapWriter.body.node.setAttribute('wsu:Id', "body")
        soapWriter.body.node.setAttribute('xmlns:wsu', _WSU.UTILITY)

        # Serialize and re-parse prior to reference generation - calculating
        # canonicalization based on soapWriter.dom.node seems to give an
        # error: the order of wsu:Id attribute is not correct
        try:
            docNode = Reader().fromString(str(soapWriter))
        except Exception, e:
            raise SignatureError("Error parsing SOAP message for signing: %s"%\
                                 e)

        ctxt = Context(docNode, processorNss=processorNss)
        refNodes = xpath.Evaluate('//*[@wsu:Id]', 
                                  contextNode=docNode, 
                                  context=ctxt)

        # Set based on 'signedInfoIsExcl' property
        refC14nAlg = c14nAlgOpt[self.refC14nIsExcl]
        
        # 1) Reference Generation
        #
        # Find references
        for refNode in refNodes:
            
            # Set URI attribute to point to reference to be signed
            #uri = u"#" + refNode.getAttribute('wsu:Id')
            uri = u"#" + refNode.attributes[(_WSU.UTILITY, 'Id')].value
            
            # Canonicalize reference
#            refC14n = Canonicalize(refNode, **self.__refC14nKw)
            
            refSubsetList = getChildNodes(refNode)
            refC14n = Canonicalize(docNode, 
                                   None, 
                                   subset=refSubsetList,
                                   **self.__refC14nKw)
            
            # Calculate digest for reference and base 64 encode
            #
            # Nb. encodestring adds a trailing newline char
            digestValue = base64.encodestring(sha(refC14n).digest()).strip()


            # Add a new reference element to SignedInfo
            refElem = signedInfoElem.createAppendElement(DSIG.BASE, 
                                                         'Reference')
            refElem.node.setAttribute('URI', uri)
            
            # Use ds:Transforms or wsse:TransformationParameters?
            transformsElem = refElem.createAppendElement(DSIG.BASE, 
                                                        'Transforms')
            transformElem = transformsElem.createAppendElement(DSIG.BASE, 
                                                               'Transform')

            # Set Canonicalization algorithm type
            transformElem.node.setAttribute('Algorithm', refC14nAlg)
            if refC14nPfxSet:
                # Exclusive C14N requires inclusive namespace elements
                inclNamespacesElem = transformElem.createAppendElement(\
							                           refC14nAlg,
                                                       'InclusiveNamespaces')
                inclNamespacesElem.node.setAttribute('PrefixList',
				        ' '.join(self.__refC14nKw['unsuppressedPrefixes']))
            
            # Digest Method 
            digestMethodElem = refElem.createAppendElement(DSIG.BASE, 
                                                           'DigestMethod')
            digestMethodElem.node.setAttribute('Algorithm', DSIG.DIGEST_SHA1)
            
            # Digest Value
            digestValueElem = refElem.createAppendElement(DSIG.BASE, 
                                                          'DigestValue')
            digestValueElem.createAppendTextNode(digestValue)

   
        # 2) Signature Generation
        #        
        # Canonicalize the signedInfo node
#        c14nSignedInfo = Canonicalize(signedInfoElem.node, 
#                                      **self.__signedInfoC14nKw)
            
#        signedInfoSubsetList = getChildNodes(signedInfoElem.node)
#        c14nSignedInfo = Canonicalize(soapWriter._header.node, 
#                                      None, 
#                                      subset=signedInfoSubsetList,
#                                      **self.__signedInfoC14nKw)

        docNode = Reader().fromString(str(soapWriter))
        ctxt = Context(docNode, processorNss=processorNss)
        signedInfoNode = xpath.Evaluate('//ds:SignedInfo', 
                                          contextNode=docNode, 
                                          context=ctxt)[0]

        signedInfoSubsetList = getChildNodes(signedInfoNode)
        c14nSignedInfo = Canonicalize(docNode, 
                                      None, 
                                      subset=signedInfoSubsetList,
                                      **self.__signedInfoC14nKw)

        # Calculate digest of SignedInfo
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Sign using the private key and base 64 encode the result
        signatureValue = self.__signingPriKey.sign(signedInfoDigestValue)
        b64EncSignatureValue = base64.encodestring(signatureValue).strip()

        # Add to <SignatureValue>
        signatureValueElem.createAppendTextNode(b64EncSignatureValue)

        log.info("Signature generation complete")


    def verify(self, parsedSOAP):
        """Verify signature
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender"""

        processorNss = \
        {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(parsedSOAP.dom, processorNss=processorNss)
        

        signatureNodes = xpath.Evaluate('//ds:Signature', 
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)
        if len(signatureNodes) > 1:
            raise VerifyError, 'Multiple ds:Signature elements found'
        
        try:
            signatureNodes = signatureNodes[0]
        except:
            # Message wasn't signed
            log.warning("Input message wasn't signed!")
            return
        
        # Two stage process: reference validation followed by signature 
        # validation 
        
        # 1) Reference Validation
        
        # Check for canonicalization set via ds:CanonicalizationMethod -
        # Use this later as a back up in case no Canonicalization was set in 
        # the transforms elements
        c14nMethodNode = xpath.Evaluate('//ds:CanonicalizationMethod', 
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)[0]
        
        refNodes = xpath.Evaluate('//ds:Reference', 
                                  contextNode=parsedSOAP.dom, 
                                  context=ctxt)

        for refNode in refNodes:
            # Get the URI for the reference
            refURI = refNode.getAttributeNode('URI').value
                         
            try:
                transformsNode = getElements(refNode, "Transforms")[0]
                transforms = getElements(transformsNode, "Transform")
    
                refAlgorithm = \
                            transforms[0].getAttributeNode("Algorithm").value
            except Exception, e:
                raise VerifyError, \
            'failed to get transform algorithm for <ds:Reference URI="%s">'%\
                        (refURI, str(e))
                
            # Add extra keyword for Exclusive canonicalization method
            refC14nKw = {}
            if refAlgorithm == DSIG.C14N_EXCL:
                try:
                    # Check for no inclusive namespaces set
                    inclusiveNS = getElements(transforms[0], 
                                              "InclusiveNamespaces")                    
                    if inclusiveNS:
                        pfxListAttNode = \
                                inclusiveNS[0].getAttributeNode('PrefixList')
                            
                        refC14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
                    else:
                        # Set to empty list to ensure Exclusive C14N is set for
                        # Canonicalize call
                        refC14nKw['unsuppressedPrefixes'] = []
                except Exception, e:
                    raise VerifyError(
            'failed to handle transform (%s) in <ds:Reference URI="%s">: %s' %\
                        (transforms[0], refURI, e))
        
            # Canonicalize the reference data and calculate the digest
            if refURI[0] != "#":
                raise VerifyError, \
                    "Expecting # identifier for Reference URI \"%s\"" % refURI
                    
            # XPath reference
            uriXPath = '//*[@wsu:Id="%s"]' % refURI[1:]
            uriNode = xpath.Evaluate(uriXPath, 
                                     contextNode=parsedSOAP.dom, 
                                     context=ctxt)[0]

#            refC14n = Canonicalize(uriNode, **refC14nKw)
            refSubsetList = getChildNodes(uriNode)
            refC14n = Canonicalize(parsedSOAP.dom,
                                   None, 
                                   subset=refSubsetList,
                                   **refC14nKw)
            digestValue = base64.encodestring(sha(refC14n).digest()).strip()
            
            # Extract the digest value that was stored            
            digestNode = getElements(refNode, "DigestValue")[0]
            nodeDigestValue = str(digestNode.childNodes[0].nodeValue).strip()   
            
            # Reference validates if the two digest values are the same
            if digestValue != nodeDigestValue:
                raise InvalidSignature, \
                        'Digest Values do not match for URI: "%s"' % refURI
            
            log.info("Verified canonicalization for element %s" % refURI[1:])
                
        # 2) Signature Validation
        signedInfoNode = xpath.Evaluate('//ds:SignedInfo',
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)[0]

        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        signedInfoC14nAlg = c14nMethodNode.getAttributeNode("Algorithm").value
        signedInfoC14nKw = {}
        if signedInfoC14nAlg == DSIG.C14N_EXCL:
            try:
                # Check for inclusive namespaces
                inclusiveNS = c14nMethodNode.getElementsByTagName(
                                                        "InclusiveNamespaces")
                if inclusiveNS:                    
                    pfxListAttNode = inclusiveNS[0].getAttributeNode(\
                                                                 'PrefixList')
                    signedInfoC14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
                else:
                    # Must default to [] otherwise exclusive C14N is not
                    # triggered
                    signedInfoC14nKw['unsuppressedPrefixes'] = []
            except Exception, e:
                raise VerifyError, \
            'failed to handle exclusive canonicalisation for SignedInfo: %s'%\
                        str(e)

        # Canonicalize the SignedInfo node and take digest
        #c14nSignedInfo = Canonicalize(signedInfoNode, **signedInfoC14nKw)
        signedInfoSubsetList = getChildNodes(signedInfoNode)
        c14nSignedInfo = Canonicalize(parsedSOAP.dom, 
                                      None, 
                                      subset=signedInfoSubsetList,
                                      **signedInfoC14nKw)
                              
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Get the signature value in order to check against the digest just
        # calculated
        signatureValueNode = xpath.Evaluate('//ds:SignatureValue',
                                            contextNode=parsedSOAP.dom, 
                                            context=ctxt)[0]

        # Remove base 64 encoding
        # This line necessary? - only decode call needed??  pyGridWare vers
        # seems to preserve whitespace
#        b64EncSignatureValue = \
#                    str(signatureValueNode.childNodes[0].nodeValue).strip()
        b64EncSignatureValue = signatureValueNode.childNodes[0].nodeValue
        signatureValue = base64.decodestring(b64EncSignatureValue)

        # Cache Signature Value here so that a response can include it
        if self.applySignatureConfirmation:
            # re-encode string to avoid possible problems with interpretation 
            # of line breaks
            self.b64EncSignatureValue = b64EncSignatureValue
        else:
            self.b64EncSignatureValue = None
         
        # Look for X.509 Cert in wsse:BinarySecurityToken node
        try:
            binSecTokNode = xpath.Evaluate('//wsse:BinarySecurityToken',
                                           contextNode=parsedSOAP.dom,
                                           context=ctxt)[0]
        except:
            # Signature may not have included the Binary Security Token in 
            # which case the verifying cert will need to have been set 
            # elsewhere
            binSecTokNode = None
        
        if binSecTokNode:
            try:
                x509CertTxt=str(binSecTokNode.childNodes[0].nodeValue)
                
                valueType = binSecTokNode.getAttributeNode("ValueType").value
                if valueType in (self.__class__.binSecTokValType['X509v3'],
                                 self.__class__.binSecTokValType['X509']):
                    # Remove base 64 encoding
                    derString = base64.decodestring(x509CertTxt)
                    
                    # Load from DER format into M2Crypto.X509
                    m2X509Cert = X509.load_cert_string(derString,
                                                       format=X509.FORMAT_DER)
                    self.__setVerifyingCert(m2X509Cert)
                    
                    x509Stack = X509Stack()

                elif valueType == \
                    self.__class__.binSecTokValType['X509PKIPathv1']:
                    
                    derString = base64.decodestring(x509CertTxt)
                    x509Stack = X509StackParseFromDER(derString)
                    
                    # TODO: Check ordering - is the last off the stack the
                    # one to use to verify the message?
                    self.__verifyingCert = x509Stack[-1]
                else:
                    raise WSSecurityError, "BinarySecurityToken ValueType " +\
                        'attribute is not recognised: "%s"' % valueType
                               
            except Exception, e:
                raise VerifyError, "Error extracting BinarySecurityToken " + \
                                   "from WSSE header: " + str(e)

        if self.__verifyingCert is None:
            raise VerifyError, "No certificate set for verification " + \
                "of the signature"
        
        # Extract RSA public key from the cert
        rsaPubKey = self.__verifyingCert.pubKey.get_rsa()

        # Apply the signature verification
        try:
            verify = rsaPubKey.verify(signedInfoDigestValue, signatureValue)
        except RSA.RSAError, e:
            raise VerifyError, "Error in Signature: " + str(e)
        
        if not verify:
            raise InvalidSignature, "Invalid signature"
        
        # Verify chain of trust 
        x509Stack.verifyCertChain(x509Cert2Verify=self.__verifyingCert,
                                  caX509Stack=self.__caX509Stack)
        
        self._verifyTimeStamp(parsedSOAP, ctxt) 
        log.info("Signature OK")        
        

class EncryptionError(Exception):
    """Flags an error in the encryption process"""

class DecryptionError(Exception):
    """Raised from EncryptionHandler.decrypt if an error occurs with the
    decryption process"""


class EncryptionHandler(object):
    """Encrypt/Decrypt SOAP messages using WS-Security""" 
    
    # Map namespace URIs to Crypto algorithm module and mode 
    cryptoAlg = \
    {
         _ENCRYPTION.WRAP_AES256:      {'module':       AES, 
                                        'mode':         AES.MODE_ECB,
                                        'blockSize':    16},
         
         # CBC (Cipher Block Chaining) modes
         _ENCRYPTION.BLOCK_AES256:     {'module':       AES, 
                                        'mode':         AES.MODE_CBC,
                                        'blockSize':    16},
                                        
         _ENCRYPTION.BLOCK_TRIPLEDES:  {'module':       DES3, 
                                        'mode':         DES3.MODE_CBC,
                                        'blockSize':    8}   
    }

     
    def __init__(self,
                 signingCertFilePath=None, 
                 signingPriKeyFilePath=None, 
                 signingPriKeyPwd=None,
                 chkSecurityTokRef=False,
                 encrNS=_ENCRYPTION.BLOCK_AES256):
        
        self.__signingCertFilePath = signingCertFilePath
        self.__signingPriKeyFilePath = signingPriKeyFilePath
        self.__signingPriKeyPwd = signingPriKeyPwd
        
        self.__chkSecurityTokRef = chkSecurityTokRef
        
        # Algorithm for shared key encryption
        try:
            self.__encrAlg = self.cryptoAlg[encrNS]
            
        except KeyError:
            raise EncryptionError, \
        'Input encryption algorithm namespace "%s" is not supported' % encrNS

        self.__encrNS = encrNS
        
        
    def encrypt(self, soapWriter):
        """Encrypt an outbound SOAP message
        
        Use Key Wrapping - message is encrypted using a shared key which 
        itself is encrypted with the public key provided by the X.509 cert.
        signingCertFilePath"""
        
        # Use X.509 Cert to encrypt
        x509Cert = X509.load_cert(self.__signingCertFilePath)
        
        soapWriter.dom.setNamespaceAttribute('wsse', OASIS.WSSE)
        soapWriter.dom.setNamespaceAttribute('xenc', _ENCRYPTION.BASE)
        soapWriter.dom.setNamespaceAttribute('ds', DSIG.BASE)
        
        # TODO: Put in a check to make sure <wsse:security> isn't already 
        # present in header
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                         'Security')
        wsseElem.node.setAttribute('SOAP-ENV:mustUnderstand', "1")
        
        encrKeyElem = wsseElem.createAppendElement(_ENCRYPTION.BASE, 
                                                   'EncryptedKey')
        
        # Encryption method used to encrypt the shared key
        keyEncrMethodElem = encrKeyElem.createAppendElement(_ENCRYPTION.BASE, 
                                                        'EncryptionMethod')
        
        keyEncrMethodElem.node.setAttribute('Algorithm', 
                                            _ENCRYPTION.KT_RSA_1_5)


        # Key Info
        KeyInfoElem = encrKeyElem.createAppendElement(DSIG.BASE, 'KeyInfo')
        
        secTokRefElem = KeyInfoElem.createAppendElement(OASIS.WSSE, 
                                                  'SecurityTokenReference')
        
        x509IssSerialElem = secTokRefElem.createAppendElement(DSIG.BASE, 
                                                          'X509IssuerSerial')

        
        x509IssNameElem = x509IssSerialElem.createAppendElement(DSIG.BASE, 
                                                          'X509IssuerName')
        x509IssNameElem.createAppendTextNode(x509Cert.get_issuer().as_text())

        
        x509IssSerialNumElem = x509IssSerialElem.createAppendElement(
                                                  DSIG.BASE, 
                                                  'X509IssuerSerialNumber')
        
        x509IssSerialNumElem.createAppendTextNode(
                                          str(x509Cert.get_serial_number()))

        # References to what has been encrypted
        encrKeyCiphDataElem = encrKeyElem.createAppendElement(
                                                          _ENCRYPTION.BASE,
                                                          'CipherData')
        
        encrKeyCiphValElem = encrKeyCiphDataElem.createAppendElement(
                                                          _ENCRYPTION.BASE,
                                                          'CipherValue')

        # References to what has been encrypted
        refListElem = encrKeyElem.createAppendElement(_ENCRYPTION.BASE,
                                                      'ReferenceList')
        
        dataRefElem = refListElem.createAppendElement(_ENCRYPTION.BASE,
                                                      'DataReference')
        dataRefElem.node.setAttribute('URI', "#encrypted")

                     
        # Add Encrypted data to SOAP body
        encrDataElem = soapWriter.body.createAppendElement(_ENCRYPTION.BASE, 
                                                           'EncryptedData')
        encrDataElem.node.setAttribute('Id', 'encrypted')
        encrDataElem.node.setAttribute('Type', _ENCRYPTION.BASE)  
              
        # Encryption method used to encrypt the target data
        dataEncrMethodElem = encrDataElem.createAppendElement(
                                                      _ENCRYPTION.BASE, 
                                                      'EncryptionMethod')
        
        dataEncrMethodElem.node.setAttribute('Algorithm', self.__encrNS)
        
        # Cipher data
        ciphDataElem = encrDataElem.createAppendElement(_ENCRYPTION.BASE,
                                                        'CipherData')
        
        ciphValueElem = ciphDataElem.createAppendElement(_ENCRYPTION.BASE,
                                                         'CipherValue')


        # Get elements from SOAP body for encryption
        dataElem = soapWriter.body.node.childNodes[0]
        data = dataElem.toxml()
     
        # Pad data to nearest multiple of encryption algorithm's block size    
        modData = len(data) % self.__encrAlg['blockSize']
        nPad = modData and self.__encrAlg['blockSize'] - modData or 0
        
        # PAd with random junk but ...
        data += os.urandom(nPad-1)
        
        # Last byte should be number of padding bytes
        # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
        data += chr(nPad)       
        
        # Generate shared key and input vector - for testing use hard-coded 
        # values to allow later comparison              
        sharedKey = os.urandom(self.__encrAlg['blockSize'])
        iv = os.urandom(self.__encrAlg['blockSize'])
        
        alg = self.__encrAlg['module'].new(sharedKey,
                                           self.__encrAlg['mode'],
                                           iv)
 
        # Encrypt required elements - prepend input vector
        encryptedData = alg.encrypt(iv + data)
        dataCiphValue = base64.encodestring(encryptedData).strip()

        ciphValueElem.createAppendTextNode(dataCiphValue)
        
        
        # ! Delete unencrypted message body elements !
        soapWriter.body.node.removeChild(dataElem)

        
        # Use X.509 cert public key to encrypt the shared key - Extract key
        # from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()
        
        # Encrypt the shared key
        encryptedSharedKey = rsaPubKey.public_encrypt(sharedKey, 
                                                      RSA.pkcs1_padding)
        
        encrKeyCiphVal = base64.encodestring(encryptedSharedKey).strip()
        
        # Add the encrypted shared key to the EncryptedKey section in the SOAP
        # header
        encrKeyCiphValElem.createAppendTextNode(encrKeyCiphVal)

#        print soapWriter.dom.node.toprettyxml()
#        import pdb;pdb.set_trace()
        
        
    def decrypt(self, parsedSOAP):
        """Decrypt an inbound SOAP message"""
        
        processorNss = \
        {
            'xenc':   _ENCRYPTION.BASE,
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(parsedSOAP.dom, processorNss=processorNss)
        
        refListNodes = xpath.Evaluate('//xenc:ReferenceList', 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)
        if len(refListNodes) > 1:
            raise DecryptionError, 'Expecting a single ReferenceList element'
        
        try:
            refListNode = refListNodes[0]
        except:
            # Message wasn't encrypted - is this OK or is a check needed for
            # encryption info in SOAP body - enveloped form?
            return


        # Check for wrapped key encryption
        encrKeyNodes = xpath.Evaluate('//xenc:EncryptedKey', 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)
        if len(encrKeyNodes) > 1:
            raise DecryptionError, 'This implementation can only handle ' + \
                                   'single EncryptedKey element'
        
        try:
            encrKeyNode = encrKeyNodes[0]
        except:
            # Shared key encryption used - leave out for the moment
            raise DecryptionError, 'This implementation can only handle ' + \
                                   'wrapped key encryption'

        
        # Check encryption method
        keyEncrMethodNode = getElements(encrKeyNode, 'EncryptionMethod')[0]     
        keyAlgorithm = keyEncrMethodNode.getAttributeNode("Algorithm").value
        if keyAlgorithm != _ENCRYPTION.KT_RSA_1_5:
            raise DecryptionError, \
            'Encryption algorithm for wrapped key is "%s", expecting "%s"' % \
                (keyAlgorithm, _ENCRYPTION.KT_RSA_1_5)

                                                            
        if self.__chkSecurityTokRef and self.__signingCertFilePath:
             
            # Check input cert. against SecurityTokenReference
            securityTokRefXPath = '/ds:KeyInfo/wsse:SecurityTokenReference'
            securityTokRefNode = xpath.Evaluate(securityTokRefXPath, 
                                                contextNode=encrKeyNode, 
                                                context=ctxt)
            # TODO: Look for ds:X509* elements to check against X.509 cert 
            # input


        # Look for cipher data for wrapped key
        keyCiphDataNode = getElements(encrKeyNode, 'CipherData')[0]
        keyCiphValNode = getElements(keyCiphDataNode, 'CipherValue')[0]

        keyCiphVal = str(keyCiphValNode.childNodes[0].nodeValue)
        encryptedKey = base64.decodestring(keyCiphVal)

        # Read RSA Private key in order to decrypt wrapped key  
        priKeyFile = BIO.File(open(self.__signingPriKeyFilePath))          
        pwdCallback = lambda *ar, **kw: self.__signingPriKeyPwd                                        
        priKey = RSA.load_key_bio(priKeyFile, callback=pwdCallback)
        
        sharedKey = priKey.private_decrypt(encryptedKey, RSA.pkcs1_padding)
        

        # Check list of data elements that have been encrypted
        for dataRefNode in refListNode.childNodes:

            # Get the URI for the reference
            dataRefURI = dataRefNode.getAttributeNode('URI').value                            
            if dataRefURI[0] != "#":
                raise VerifyError, \
                    "Expecting # identifier for DataReference URI \"%s\"" % \
                    dataRefURI

            # XPath reference - need to check for wsu namespace qualified?
            #encrNodeXPath = '//*[@wsu:Id="%s"]' % dataRefURI[1:]
            encrNodeXPath = '//*[@Id="%s"]' % dataRefURI[1:]
            encrNode = xpath.Evaluate(encrNodeXPath, 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)[0]
                
            dataEncrMethodNode = getElements(encrNode, 'EncryptionMethod')[0]     
            dataAlgorithm = \
                        dataEncrMethodNode.getAttributeNode("Algorithm").value
            try:        
                # Match algorithm name to Crypto module
                CryptoAlg = self.cryptoAlg[dataAlgorithm]
                
            except KeyError:
                raise DecryptionError, \
'Encryption algorithm for data is "%s", supported algorithms are:\n "%s"' % \
                    (keyAlgorithm, "\n".join(self.cryptoAlg.keys()))

            # Get Data
            dataCiphDataNode = getElements(encrNode, 'CipherData')[0]
            dataCiphValNode = getElements(dataCiphDataNode, 'CipherValue')[0]
        
            dataCiphVal = str(dataCiphValNode.childNodes[0].nodeValue)
            encryptedData = base64.decodestring(dataCiphVal)
            
            alg = CryptoAlg['module'].new(sharedKey, CryptoAlg['mode'])
            decryptedData = alg.decrypt(encryptedData)
            
            # Strip prefix - assume is block size
            decryptedData = decryptedData[CryptoAlg['blockSize']:]
            
            # Strip any padding suffix - Last byte should be number of padding
            # bytes
            # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
            lastChar = decryptedData[-1]
            nPad = ord(lastChar)
            
            # Sanity check - there may be no padding at all - the last byte 
            # being the end of the encrypted XML?
            #
            # TODO: are there better sanity checks than this?!
            if nPad < CryptoAlg['blockSize'] and nPad > 0 and \
               lastChar != '\n' and lastChar != '>':
                
                # Follow http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block -
                # last byte gives number of padding bytes
                decryptedData = decryptedData[:-nPad]


            # Parse the encrypted data - inherit from Reader as a fudge to 
            # enable relevant namespaces to be added prior to parse
            processorNss.update({'xsi': SCHEMA.XSI3, 'ns1': 'urn:ZSI:examples'})
            class _Reader(Reader):
                def initState(self, ownerDoc=None):
                    Reader.initState(self, ownerDoc=ownerDoc)
                    self._namespaces.update(processorNss)
                    
            rdr = _Reader()
            dataNode = rdr.fromString(decryptedData, ownerDoc=parsedSOAP.dom)
            
            # Add decrypted element to parent and remove encrypted one
            parentNode = encrNode._get_parentNode()
            parentNode.appendChild(dataNode)
            parentNode.removeChild(encrNode)
            
            from xml.dom.ext import ReleaseNode
            ReleaseNode(encrNode)
            
            # Ensure body_root attribute is up to date in case it was
            # previously encrypted
            parsedSOAP.body_root = parsedSOAP.body.childNodes[0]
            #print decryptedData
            #import pdb;pdb.set_trace()
