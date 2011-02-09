"""NDG Credential Wallet

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "30/11/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:credentialwallet.py 4378 2008-10-29 10:30:14Z pjkersha $'

import logging
log = logging.getLogger(__name__)

# Temporary store of certificates for use with CredentialWallet getAttCert()
import tempfile

# Check Attribute Certificate validity times
from datetime import datetime
from datetime import timedelta


# Access Attribute Authority's web service using ZSI - allow pass if not 
# loaded since it's possible to make AttributeAuthority instance locally
# without using the WS
aaImportError = True
try:
    # AttributeAuthority client package resides with CredentialWallet module in 
    # ndg.security.common
    from ndg.security.common.attributeauthority import \
        AttributeAuthorityClient, AttributeAuthorityClientError, \
        AttributeRequestDenied, NoMatchingRoleInTrustedHosts
    aaImportError = False
except ImportError:
    log.warning('Loading CredentialWallet without SOAP interface imports')
    pass

# Likewise - may not want to use WS and use AttributeAuthority locally in which
# case no need to import it
try:
    from ndg.security.server.attributeauthority import AttributeAuthority, \
        AttributeAuthorityError, AttributeAuthorityAccessDenied
    aaImportError = False
except:
    log.warning('Loading CredentialWallet without Attribute Authority '
                'interface imports')
    pass

if aaImportError:
    raise ImportError("Either AttributeAuthority or AttributeAuthorityClient "
                      "classes must be present to allow interoperation with "
                      "Attribute Authorities")

# Authentication X.509 Certificate
from ndg.security.common.X509 import *
from M2Crypto import X509, BIO, RSA

# Authorisation - attribute certificate 
from ndg.security.common.AttCert import *
from ndg.security.common.wssecurity.dom import SignatureHandler

# generic parser to read INI/XML properties file
from ndg.security.common.utils.configfileparsers import \
                                                INIPropertyFileWithValidation


class _CredentialWalletException(Exception):    
    """Generic Exception class for CredentialWallet module.  Overrides 
    Exception to enable writing to the log"""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)


class CredentialWalletError(_CredentialWalletException):    
    """Exception handling for NDG Credential Wallet class.  Overrides Exception
    to enable writing to the log"""


class CredentialWalletAttributeRequestDenied(CredentialWalletError):    
    """Handling exception where CredentialWallet is denied authorisation by an
    Attribute Authority.
  
    @type __extAttCertList: list
    @ivar __extAttCertList: list of candidate Attribute Certificates that
    could be used to try to get a mapped certificate from the target 
    Attribute Authority
    
    @type __trustedHostInfo: dict
    @ivar __trustedHostInfo: dictionary indexed by host name giving 
    details of Attribute Authority URI and roles for trusted hosts"""
    
    def __init__(self, *args, **kw):
        """Raise exception for attribute request denied with option to give
        caller hint to certificates that could used to try to obtain a
        mapped certificate
        
        @type extAttCertList: list
        @param extAttCertList: list of candidate Attribute Certificates that
        could be used to try to get a mapped certificate from the target 
        Attribute Authority
        
        @type trustedHostInfo: dict 
        @param trustedHostInfo: dictionary indexed by host name giving 
        details of Attribute Authority URI and roles for trusted hosts"""
        
        self.__trustedHostInfo = kw.pop('trustedHostInfo', {})
        self.__extAttCertList = kw.pop('extAttCertList', [])
            
        CredentialWalletError.__init__(self, *args, **kw)

    def _getTrustedHostInfo(self):
        """Get message text"""
        return self.__trustedHostInfo

    trustedHostInfo = property(fget=_getTrustedHostInfo, 
                               doc="URI and roles details for trusted hosts")
       
    def _getExtAttCertList(self):
        """Return list of candidate Attribute Certificates that could be used
        to try to get a mapped certificate from the target Attribute Authority
        """
        return self.__extAttCertList

    extAttCertList = property(fget=_getExtAttCertList,
                              doc="list of candidate Attribute Certificates "
                              "that could be used to try to get a mapped "
                              "certificate from the target Attribute "
                              "Authority")

          
class _MetaCredentialWallet(type):
    """Enable CredentialWallet to have read only class variables e.g.
    
    print CredentialWallet.accessDenied 
    
    ... is allowed but,
    
    CredentialWallet.accessDenied = None
    
    ... raises - AttributeError: can't set attribute"""
    
    def _getAccessDenied(cls):
        '''accessDenied get method'''
        return False
    
    accessDenied = property(fget=_getAccessDenied)
    
    def _getAccessGranted(cls):
        '''accessGranted get method'''
        return True
    
    accessGranted = property(fget=_getAccessGranted)


# CredentialWallet is a 'new-style' class inheriting from "object" and making 
# use of new Get/Set methods for hiding of attributes
class CredentialWallet(object):
    """Volatile store of user credentials associated with a user session
    
    @type userX509Cert: string / M2Crypto.X509.X509 /
    ndg.security.common.X509.X509Cert
    @ivar userX509Cert: X.509 certificate for user (property attribute)
    
    @type userPriKey: string / M2Crypto.RSA.RSA 
    @ivar userPriKey: private key for user cert (property attribute)
    
    @type issuingX509Cert: string / ndg.security.common.X509.X509Cert
    @ivar issuingX509Cert: X.509 cert for issuer of user cert (property 
    attribute)
    
    @type attributeAuthorityURI: string
    @ivar attributeAuthorityURI: URI of Attribute Authority to make 
    requests to.  Setting this ALSO creates an AttributeAuthorityClient instance 
    _attributeAuthorityClnt.  - See attributeAuthorityURI property for
    details. (property attribute)
    
    @type attributeAuthority: ndg.security.server.attributeauthority.AttributeAuthority
    @ivar attributeAuthority: Attribute Authority to make requests to.  
    attributeAuthorityURI takes precedence over this keyword i.e. if an
    attributeAuthorityURI has been set, then calls are made to the AA web 
    service at this location rather to any self.attributeAuthority running 
    locally. (property attribute)
    
    @type caCertFilePathList: string (for single file), list or tuple
    @ivar caCertFilePathList: Certificate Authority's certificates - used
    in validation of signed Attribute Certificates and WS-Security 
    signatures of incoming messages.  If not set here, it must
    be input in call to getAttCert. (property attribute)
            
    @type credentialRepository: instance of CredentialRepository derived 
    class
    @ivar credentialRepository: Credential Repository instance.   (property 
    attribute).  If not set, defaults to NullCredentialRepository type - see 
    class below...

    
    @type mapFromTrustedHosts: bool
    @ivar mapFromTrustedHosts sets behaviour for getAttCert().  If
    set True and authorisation fails with the given Attribute Authority, 
    attempt to get authorisation using Attribute Certificates issued by 
    other trusted AAs. (property attribute)
    
    @type rtnExtAttCertList: bool
    @ivar rtnExtAttCertList: behaviour for getAttCert().  If True, and 
    authorisation fails with the given Attribute Authority, return a list 
    of Attribute Certificates from other trusted AAs which could be used 
    to obtain a mapped Attribute Certificate on a subsequent authorisation
    attempt. (property attribute)
    
    @type attCertRefreshElapse: float / int
    @ivar attCertRefreshElapse: used by getAttCert to determine 
    whether to replace an existing AC in the cache with a fresh one.  If 
    the existing one has less than attCertRefreshElapse time in seconds
    left before expiry then replace it. (property attribute)
    
    @type wssCfgKw: dict
    @ivar wssCfgKw: keywords to WS-Security SignatureHandler
    used for Credential Wallet's SOAP interface to Attribute Authorities.
    (property attribute)
            
    @type _credentialRepository: ndg.security.common.CredentialRepository or 
    derivative
    @ivar _credentialRepository: reference to Credential Repository object.  
    An optional non-volatile cache for storage of wallet info which can be
    later restored. (Don't reference directly - see equivalent property 
    attribute)

    @type _mapFromTrustedHosts: bool
    @ivar _mapFromTrustedHosts: if true, allow a mapped attribute certificate
    to obtained in a getAttCert call.  Set false to prevent mappings.
    (Don't reference directly - see equivalent property attribute)

    @type _rtnExtAttCertList: bool
    @ivar _rtnExtAttCertList: if true, return a list of external attribute 
    certificates from getAttCert call. (Don't reference directly - see 
    equivalent property attribute)

    @type __dn: ndg.security.common.X509.X500DN
    @ivar __dn: distinguished name from user certificate.  (Don't reference 
    directly - see equivalent property attribute)

    @type _credentials: dict       
    @ivar _credentials: Credentials are stored as a dictionary one element per
    attribute certificate held and indexed by certificate issuer name.
    (Don't reference directly - see equivalent property attribute)

    @type _caCertFilePathList: basestring, list, tuple or None
    @ivar _caCertFilePathList: file path(s) to CA certificates.  If None
    then the input is quietly ignored.  See caCertFilePathList property.
    (Don't reference directly - see equivalent property attribute)

    @type _userX509Cert: ndg.security.common.X509.X509Cert
    @ivar _userX509Cert: X.509 user certificate instance.
    (Don't reference directly - see equivalent property attribute)

    @type _issuingX509Cert: ndg.security.common.X509.X509Cert
    @ivar _issuingX509Cert: X.509 user certificate instance.
    (Don't reference directly - see equivalent property attribute)
 
    @type _userPriKey: M2Crypto.RSA.RSA
    @ivar _userPriKey: Private key used to sign outbound message.
    (Don't reference directly - see equivalent property attribute)
    """

    __metaclass__ = _MetaCredentialWallet

    propertyDefaults = dict(
        userId=None,
        userX509Cert=None,
        userX509CertFilePath=None,
        userPriKey=None,
        userPriKeyFilePath=None,
        issuingX509Cert=None,
        issuingX509CertFilePath=None,
        caCertFilePathList=[],
        sslCACertFilePathList=[],
        attributeAuthorityURI=None,
        attributeAuthority=None,
        credentialRepository=None,
        mapFromTrustedHosts=False,
        rtnExtAttCertList=True,
        attCertRefreshElapse=7200,
        wssCfgFilePath=None,
        wssCfgSection='DEFAULT',
        wssCfgPrefix='',
        wssCfgKw={})
    
    _protectedAttrs = [
        '_userX509Cert',
        '_userX509CertFilePath',
        '_userPriKey',
        '_userPriKeyFilePath',
        '_userPriKeyPwd',
        '_issuingX509Cert',
        '_issuingX509CertFilePath',
        '_attributeAuthorityClnt',
        '_attributeAuthority',
        '_caCertFilePathList',
        '_sslCACertFilePathList',
        '_credentialRepository',
        '_mapFromTrustedHosts',
        '_rtnExtAttCertList',
        '_attCertRefreshElapse',
        '_cfg',
        '_credentials',
        '_dn',
        '_attributeAuthorityURI'
    ]
    
    __slots__ = propertyDefaults.keys() + _protectedAttrs
    
    def __init__(self, 
                 cfg=None, 
                 cfgFileSection='DEFAULT', 
                 cfgPrefix='', 
                 wssCfgKw={},
                 **kw):
        """Create store of user credentials for their current session

        @type cfg: string / ConfigParser object
        @param cfg: if a string type, this is interpreted as the file path to
        a configuration file, otherwise it will be treated as a ConfigParser 
        object 
        @type cfgSection: string
        @param cfgSection: sets the section name to retrieve config params 
        from
        @type cfgPrefix: basestring
        @param cfgPrefix: apply a prefix to all CredentialWallet config params 
        so that if placed in a file with other parameters they can be 
        distinguished
        @type cfgKw: dict
        @param cfgKw: set parameters as key value pairs."""

        log.debug("Calling CredentialWallet.__init__ ...")

        # Initialise attributes - 1st protected ones
        attr = {}.fromkeys(CredentialWallet._protectedAttrs)
        
        # ... then properties
        attr.update(CredentialWallet.propertyDefaults)
        for k, v in attr.items():
            setattr(self, k, v)
            
        # Update attributes from a config file
        if cfg:
            self.parseConfig(cfg, section=cfgFileSection, prefix=cfgPrefix)

        # Update attributes from keywords passed - set user private key
        # password first if it's present.  This is to avoid an error setting
        # the private key
        self.userPriKeyPwd = kw.pop('userPriKeyPwd', None)
        for k,v in kw.items():
            setattr(self, k, v)

        # Get the distinguished name from the user certificate
        if self._userX509Cert:
            self._dn = self._userX509Cert.dn.serialise()
        
        
        # Credentials are stored as a dictionary one element per attribute
        # certicate held and indexed by certificate issuer name
        self._credentials = {}


        # Make a connection to the Credentials Repository
        if self._credentialRepository is None:
            log.info('Applying default CredentialRepository %r for user '
                     '"%s"' % (NullCredentialRepository, self.userId))
            self._credentialRepository = NullCredentialRepository()
        else:
            log.info('Checking CredentialRepository for credentials for user '
                     '"%s"' % self.userId)
            
            if not issubclass(self._credentialRepository,CredentialRepository):
                raise CredentialWalletError("Input Credential Repository instance "
                                      "must be of a class derived from "
                                      "\"CredentialRepository\"")
    
       
            # Check for valid attribute certificates for the user
            try:
                self._credentialRepository.auditCredentials(self.userId)
                userCred=self._credentialRepository.getCredentials(self.userId)
    
            except Exception, e:
                log.error("Error updating wallet with credentials from "
                          "repository: %s" % e)
                raise
    
    
            # Update wallet with attribute certificates stored in the 
            # repository.  Store ID and certificate instantiated as an AttCert
            # type
            try:
                for cred in userCred: 
                    attCert = AttCertParse(cred.attCert)
                    issuerName = attCert['issuerName']
                    
                    self._credentials[issuerName] = {'id':cred.id, 
                                                     'attCert':attCert}    
            except Exception, e:
                try:
                    raise CredentialWalletError("Error parsing Attribute "
                        "Certificate ID '%s' retrieved from the " 
                        "Credentials Repository: %s" % (cred.id, e))            
                except:
                    raise CredentialWalletError("Error parsing Attribute "
                                          "Certificate retrieved from the "
                                          "Credentials Repository: %s:" % e)
            
            # Filter out expired or otherwise invalid certificates
            self.audit()

    def parseConfig(self, cfg, prefix='', section='DEFAULT'):
        '''Extract parameters from _cfg config object'''
        
        if isinstance(cfg, basestring):
            cfgFilePath = os.path.expandvars(cfg)
            self._cfg = None
        else:
            cfgFilePath = None
            self._cfg = cfg
            
        # Configuration file properties are held together in a dictionary
        readAndValidate = INIPropertyFileWithValidation()
        prop = readAndValidate(cfgFilePath,
                               cfg=self._cfg,
                               validKeys=CredentialWallet.propertyDefaults,
                               prefix=prefix,
                               sections=(section,))
        
        # Keep a copy of config for use by WS-Security SignatureHandler parser
        if self._cfg is None:
            self._cfg = readAndValidate.cfg
        
        # Copy prop dict into object attributes - __slots__ definition and 
        # property methods will ensure only the correct attributes are set
        # Set user private key password first if it's present.  This is to 
        # avoid an error setting the private key
        self.userPriKeyPwd = prop.pop('userPriKeyPwd', None)
        for key, val in prop.items():
            setattr(self, key, val)


    def _getAttCertRefreshElapse(self):
        """Get property method for Attribute Certificate wallet refresh time
        @rtype: float or int
        @return: "elapse time in seconds"""
        return self._attCertRefreshElapse
    
    def _setAttCertRefreshElapse(self, val):
        """Set property method for Attribute Certificate wallet refresh time
        @type val: float or int
        @param val: "elapse time in seconds"""
        if isinstance(val, (float, int)):
            self._attCertRefreshElapse = val
            
        elif isinstance(val, basestring):
            self._attCertRefreshElapse = float(val)
        else:
            raise AttributeError("Expecting int, float or string type input "
                                 "for attCertRefreshElapse")
            
    attCertRefreshElapse = property(fget=_getAttCertRefreshElapse, 
                                    fset=_setAttCertRefreshElapse,
                                    doc="If an existing one has AC less than "
                                        "attCertRefreshElapse time in seconds "
                                        "left before expiry then replace it")
    
    def _setX509Cert(self, cert):
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
            raise AttributeError("X.509 Cert. must be type: "
                                 "ndg.security.common.X509.X509Cert, "
                                 "M2Crypto.X509.X509 or a base64 encoded "
                                 "string")

    def _setUserX509Cert(self, userX509Cert):
        "Set property method for X.509 user cert."
        self._userX509Cert = self._setX509Cert(userX509Cert)
        

    def _getUserX509Cert(self):
        """Get user cert X509Cert instance"""
        return self._userX509Cert

    userX509Cert = property(fget=_getUserX509Cert,
                            fset=_setUserX509Cert,
                            doc="X.509 user certificate instance")
 
    def _setUserX509CertFilePath(self, filePath):
        "Set user X.509 cert file path property method"
        
        if isinstance(filePath, basestring):
            filePath = os.path.expandvars(filePath)
            self._userX509Cert = X509CertRead(filePath)
            
        elif filePath is not None:
            raise AttributeError("User X.509 cert. file path must be a valid "
                                 "string")
        
        self._userX509CertFilePath = filePath
                
    userX509CertFilePath = property(fset=_setUserX509CertFilePath,
                                    doc="File path to user X.509 cert.")
    
    def _setIssuingX509Cert(self, issuingX509Cert):
        "Set property method for X.509 user cert."
        self._issuingX509Cert = self._setX509Cert(issuingX509Cert)
        
    def _getIssuingX509Cert(self):
        """Get user cert X509Cert instance"""
        return self._issuingX509Cert

    issuingX509Cert = property(fget=_getIssuingX509Cert,
                               fset=_setIssuingX509Cert,
                               doc="X.509 user certificate instance")
 
    def _setIssuerX509CertFilePath(self, filePath):
        "Set user X.509 cert file path property method"
        
        if isinstance(filePath, basestring):
            filePath = os.path.expandvars(filePath)
            self._issuerX509Cert = X509CertRead(filePath)
            
        elif filePath is not None:
            raise AttributeError("User X.509 cert. file path must be a valid "
                                 "string")
        
        self._issuerX509CertFilePath = filePath
                
    issuerX509CertFilePath = property(fset=_setIssuerX509CertFilePath,
                                      doc="File path to user X.509 cert. "
                                          "issuing cert.")     

    def _getUserPriKey(self):
        "Get method for user private key"
        return self._userPriKey
    
    def _setUserPriKey(self, userPriKey):
        """Set method for user private key
        
        Nb. if input is a string, userPriKeyPwd will need to be set if
        the key is password protected.
        
        @type userPriKey: M2Crypto.RSA.RSA / string
        @param userPriKey: private key used to sign message"""
        
        if userPriKey is None:
            self._userPriKey = None
        elif isinstance(userPriKey, basestring):
            pwdCallback = lambda *ar, **kw: self._userPriKeyPwd
            self._userPriKey = RSA.load_key_string(userPriKey,
                                                   callback=pwdCallback)
        elif isinstance(userPriKey, RSA.RSA):
            self._userPriKey = userPriKey          
        else:
            raise AttributeError("user private key must be a valid "
                                 "M2Crypto.RSA.RSA type or a string")
                
    userPriKey = property(fget=_getUserPriKey,
                          fset=_setUserPriKey,
                          doc="User private key if set, used to sign outbound "
                              "messages to Attribute authority")

    def _setUserPriKeyFilePath(self, filePath):
        "Set user private key file path property method"
        
        if isinstance(filePath, basestring):
            filePath = os.path.expandvars(filePath)
            try:
                # Read Private key to sign with    
                priKeyFile = BIO.File(open(filePath)) 
                pwdCallback = lambda *ar, **kw: self._userPriKeyPwd
                self._userPriKey = RSA.load_key_bio(priKeyFile, 
                                                    callback=pwdCallback)    
            except Exception, e:
                raise AttributeError("Setting user private key: %s" % e)
        
        elif filePath is not None:
            raise AttributeError("Private key file path must be a valid "
                                 "string or None")
        
        self._userPriKeyFilePath = filePath
        
    userPriKeyFilePath = property(fset=_setUserPriKeyFilePath,
                                  doc="File path to user private key")
 
    def _setUserPriKeyPwd(self, userPriKeyPwd):
        "Set method for user private key file password"
        if userPriKeyPwd is not None and not isinstance(userPriKeyPwd, 
                                                        basestring):
            raise AttributeError("Signing private key password must be None "
                                 "or a valid string")
        
        # Explicitly convert to string as M2Crypto OpenSSL wrapper fails with
        # unicode type
        self._userPriKeyPwd = str(userPriKeyPwd)

    def _getUserPriKeyPwd(self):
        "Get property method for user private key"
        return self._userPriKeyPwd
        
    userPriKeyPwd = property(fset=_setUserPriKeyPwd,
                             fget=_getUserPriKeyPwd,
                             doc="Password protecting user private key file")
        
    def _getCredentials(self):
        """Get Property method.  Credentials are read-only
        
        @rtype: dict
        @return: cached ACs indesed by issuing organisation name"""
        return self._credentials

    # Publish attribute
    credentials = property(fget=_getCredentials,
                           doc="List of Attribute Certificates linked to "
                               "issuing authorities")


    def _getCACertFilePathList(self):
        """Get CA cert or certs used to validate AC signatures and signatures
        of peer SOAP messages.
        
        @rtype caCertFilePathList: basestring, list or tuple
        @return caCertFilePathList: file path(s) to CA certificates."""
        return self._caCertFilePathList
    
    def _setCACertFilePathList(self, caCertFilePathList):
        """Set CA cert or certs to validate AC signatures, signatures
        of Attribute Authority SOAP responses and SSL connections where 
        AA SOAP service is run over SSL.
        
        @type caCertFilePathList: basestring, list, tuple or None
        @param caCertFilePathList: file path(s) to CA certificates.  If None
        then the input is quietly ignored."""
        
        if isinstance(caCertFilePathList, basestring):
           self._caCertFilePathList = [caCertFilePathList]
           
        elif isinstance(caCertFilePathList, list):
           self._caCertFilePathList = caCertFilePathList
           
        elif isinstance(caCertFilePathList, tuple):
           self._caCertFilePathList = list(caCertFilePathList)

        elif caCertFilePathList is not None:
            raise CredentialWalletError("Input CA Certificate file path is not a "
                                  "valid string")      
        
    caCertFilePathList = property(fget=_getCACertFilePathList,
                                  fset=_setCACertFilePathList,
                                  doc="CA Certificates - used for "
                                      "verification of AC and SOAP message "
                                      "signatures")

    def _getSSLCACertFilePathList(self):
        """Get CA cert or certs used to validate AC signatures and signatures
        of peer SOAP messages.
        
        @rtype sslCACertFilePathList: basestring, list or tuple
        @return sslCACertFilePathList: file path(s) to CA certificates."""
        return self._sslCACertFilePathList
    
    def _setSSLCACertFilePathList(self, sslCACertFilePathList):
        """Set CA cert or certs to validate AC signatures, signatures
        of Attribute Authority SOAP responses and SSL connections where 
        AA SOAP service is run over SSL.
        
        @type sslCACertFilePathList: basestring, list, tuple or None
        @param sslCACertFilePathList: file path(s) to CA certificates.  If None
        then the input is quietly ignored."""
        
        if isinstance(sslCACertFilePathList, basestring):
           self._sslCACertFilePathList = [sslCACertFilePathList]
           
        elif isinstance(sslCACertFilePathList, list):
           self._sslCACertFilePathList = sslCACertFilePathList
           
        elif isinstance(sslCACertFilePathList, tuple):
           self._sslCACertFilePathList = list(sslCACertFilePathList)

        elif sslCACertFilePathList is not None:
            raise CredentialWalletError("Input CA Certificate file path is "
                                        "not a valid string")      
        
    sslCACertFilePathList = property(fget=_getSSLCACertFilePathList,
                                  fset=_setSSLCACertFilePathList,
                                  doc="CA Certificates - used for "
                                      "verification of peer certs in SSL "
                                      "connections")
        
    def _getAttributeAuthorityURI(self):
        """Get property method for Attribute Authority Web Service URI to
        connect to."""
        return self._attributeAuthorityURI
            
    def _setAttributeAuthorityURI(self, attributeAuthorityURI):
        """Set property method for Attribute Authority Web Service URI to
        connect to.  This method ALSO RESETS attributeAuthority - a local
        Attribute Authority instance - to None
        
        @type attributeAuthorityURI: basestring/None
        @param attributeAuthorityURI: Attribute Authority Web Service URI.  Set
        to None to initialise."""
        if attributeAuthorityURI is not None and \
           not isinstance(attributeAuthorityURI, basestring):
            raise AttributeError("URI must be a string or None type")
        
        self._attributeAuthorityURI = attributeAuthorityURI
        
        # Re-initialize local instance
        self._attributeAuthority = \
                    CredentialWallet.propertyDefaults['attributeAuthority']
            
    attributeAuthorityURI = property(fget=_getAttributeAuthorityURI,
                                     fset=_setAttributeAuthorityURI,
                                     doc="Attribute Authority address - "
                                         "setting also sets up "
                                         "AttributeAuthorityClient instance!")

    def _getAttributeAuthority(self):
        """Get property method for Attribute Authority Web Service client
        instance.  Use attributeAuthorityURI propert to set up 
        attributeAuthorityClnt
        
        @rtype attributeAuthority: ndg.security.server.attributeauthority.AttributeAuthority
        @return attributeAuthority: Attribute Authority instance"""
        return self._attributeAuthority

    def _setAttributeAuthority(self, attributeAuthority):
        """Set property method for Attribute Authority Web Service instance to
        connect to.  This method ALSO RESETS attributeAuthorityURI - the 
        address of a remote Attribute Authority - to None
        
        @type attributeAuthority: ndg.security.server.attributeauthority.AttributeAuthority
        @param attributeAuthority: Attribute Authority instance."""
        if attributeAuthority is not None and \
           not isinstance(attributeAuthority, AttributeAuthority):
            raise AttributeError("Expecting %r for attributeAuthority "
                                 "attribute" % AttributeAuthority)
            
        self._attributeAuthority = attributeAuthority
        
        # Re-initialize setting for remote service
        self._attributeAuthorityURI = \
                    CredentialWallet.propertyDefaults['attributeAuthorityURI']
            
    attributeAuthority = property(fget=_getAttributeAuthority,
                                  fset=_setAttributeAuthority, 
                                  doc="Attribute Authority instance")


    def _getMapFromTrustedHosts(self):
        """Get property method for boolean flag - if set to True it allows
        role mapping to be attempted when connecting to an Attribute Authority
        
        @type mapFromTrustedHosts: bool
        @param mapFromTrustedHosts: set to True to try role mapping in AC 
        requests to Attribute Authorities"""
        return self._mapFromTrustedHosts

    def _setMapFromTrustedHosts(self, mapFromTrustedHosts):
        """Set property method for boolean flag - if set to True it allows
        role mapping to be attempted when connecting to an Attribute Authority
        
        @type mapFromTrustedHosts: bool
        @param mapFromTrustedHosts: Attribute Authority Web Service."""
        if not isinstance(mapFromTrustedHosts, bool):
            raise AttributeError("Expecting %r for mapFromTrustedHosts "
                                 "attribute" % bool)
            
        self._mapFromTrustedHosts = mapFromTrustedHosts
            
    mapFromTrustedHosts = property(fget=_getMapFromTrustedHosts,
                                   fset=_setMapFromTrustedHosts, 
                                   doc="Set to True to enable mapped AC "
                                       "requests")

    def _getRtnExtAttCertList(self):
        """Get property method for Attribute Authority Web Service client
        instance.  Use rtnExtAttCertListURI propert to set up 
        rtnExtAttCertListClnt
        
        @type rtnExtAttCertList: bool
        @param rtnExtAttCertList: """
        return self._rtnExtAttCertList

    def _setRtnExtAttCertList(self, rtnExtAttCertList):
        """Set property method for boolean flag - when a AC request fails,
        return a list of candidate ACs that could be used to re-try with in
        order to get mapped AC.
        
        @type rtnExtAttCertList: bool
        @param rtnExtAttCertList: set to True to configure getAttCert to return
        a list of ACs that could be used in a re-try to get a mapped AC from 
        the target Attribute Authority."""
        if not isinstance(rtnExtAttCertList, bool):
            raise AttributeError("Expecting %r for rtnExtAttCertList "
                                 "attribute" % bool)
            
        self._rtnExtAttCertList = rtnExtAttCertList
            
    rtnExtAttCertList = property(fget=_getRtnExtAttCertList,
                                 fset=_setRtnExtAttCertList, 
                                 doc="Set to True to enable mapped AC "
                                     "requests")

    def isValid(self, **x509CertKeys):
        """Check wallet's user cert.  If expired return False
        
        @type **x509CertKeys: dict
        @param **x509CertKeys: keywords applying to 
        ndg.security.common.X509.X509Cert.isValidTime method"""
        if self._userX509Cert is not None:
            return self._userX509Cert.isValidTime(**x509CertKeys)
        else:
            log.warning("CredentialWallet.isValid: no user certificate set in "
                        "wallet")
            return True


    def addCredential(self, attCert, bUpdateCredentialRepository=True):
        """Add a new attribute certificate to the list of credentials held.

        @type attCert:
        @param attCert: new attribute Certificate to be added
        @type bUpdateCredentialRepository: bool
        @param bUpdateCredentialRepository: if set to True, and a repository 
        exists it will be updated with the new credentials also
        
        @rtype: bool
        @return: True if certificate was added otherwise False.  - If an
        existing certificate from the same issuer has a later expiry it will
        take precence and the new input certificate is ignored."""

        # Check input
        if not isinstance(attCert, AttCert):
            raise CredentialWalletError("Attribute Certificate must be an AttCert "
                                  "type object")

        # Check certificate validity
        try:
            attCert.isValid(raiseExcep=True)
            
        except AttCertError, e:
            raise CredentialWalletError("Adding Credential: %s" % e)
        

        # Check to see if there is an existing Attribute Certificate held
        # that was issued by the same host.  If so, compare the expiry time.
        # The one with the latest expiry will be retained and the other
        # ingored
        bUpdateCred = True
        issuerName = attCert['issuerName']
        
        if issuerName in self._credentials:
            # There is an existing certificate held with the same issuing
            # host name as the new certificate
            attCertOld = self._credentials[issuerName]['attCert']

            # Get expiry times in datetime format to allow comparison
            dtAttCertOldNotAfter = attCertOld.getValidityNotAfter(\
                                                            asDatetime=True)
            dtAttCertNotAfter = attCert.getValidityNotAfter(asDatetime=True)

            # If the new certificate has an earlier expiry time then ignore it
            bUpdateCred = dtAttCertNotAfter > dtAttCertOldNotAfter

                
        if bUpdateCred:
            # Update: Nb. -1 ID value flags item as new.  Items read in
            # from the CredentialRepository during creation of the wallet will
            # have +ve IDs previously allocated by the database
            self._credentials[issuerName] = {'id': -1, 'attCert': attCert}

            # Update the Credentials Repository - the permanent store of user
            # authorisation credentials.  This allows credentials for previous
            # sessions to be re-instated
            if self._credentialRepository and bUpdateCredentialRepository:
                self.updateCredentialRepository()

        # Flag to caller to indicate whether the input certificate was added
        # to the credentials or an exsiting certificate from the same issuer
        # took precedence
        return bUpdateCred
            

    def audit(self):
        """Check the credentials held in the wallet removing any that have
        expired or are otherwise invalid."""

        log.debug("CredentialWallet.audit ...")
        
        # Nb. No signature check is carried out.  To do a check, access is
        # needed to the cert of the CA that issued the Attribute Authority's
        # cert
        #
        # P J Kershaw 12/09/05
        for key, val in self._credentials.items():
            if not val['attCert'].isValid(chkSig=False):
                del self._credentials[key]


    def updateCredentialRepository(self, auditCred=True):
        """Copy over non-persistent credentials held by wallet into the
        perminent repository.
        
        @type auditCred: bool
        @param auditCred: filter existing credentials in the repository
        removing invalid ones"""

        log.debug("CredentialWallet.updateCredentialRepository ...")
        
        if not self._credentialRepository:
            raise CredentialWalletError("No Credential Repository has been created "
                                  "for this wallet")
                            
        # Filter out invalid certs unless auditCred flag is explicitly set to
        # false
        if auditCred: self.audit()

        # Update the database - only add new entries i.e. with an ID of -1
        attCertList = [i['attCert'] for i in self._credentials.values() \
                       if i['id'] == -1]

        self._credentialRepository.addCredentials(self.userId, attCertList)


    def _createAttributeAuthorityClnt(self, attributeAuthorityURI):
        """Set up a client to an Attribute Authority with the given URI
        
        @type attributeAuthorityURI: string
        @param attributeAuthorityURI: Attribute Authority Web Service URI.

        @rtype: ndg.security.common.attributeauthority.AttributeAuthorityClient
        @return: new Attribute Authority client instance"""

        log.debug('CredentialWallet._createAttributeAuthorityClnt for '
                  'service: "%s"' % attributeAuthorityURI)

        attributeAuthorityClnt = AttributeAuthorityClient(
                            uri=attributeAuthorityURI,
                            sslCACertFilePathList=self._sslCACertFilePathList,
                            cfg=self.wssCfgFilePath or self._cfg,
                            cfgFileSection=self.wssCfgSection,
                            cfgFilePrefix=self.wssCfgPrefix,
                            **(self.wssCfgKw or {}))
        
        # If a user certificate is set, use this to sign messages instead of
        # the default settings in the WS-Security config.  
        if attributeAuthorityClnt.signatureHandler is not None and \
           self.userPriKey is not None:
            if self.issuingX509Cert is not None:
                # Pass a chain of certificates - 
                # Initialise WS-Security signature handling to pass 
                # BinarySecurityToken containing user cert and cert for user 
                # cert issuer 
                attributeAuthorityClnt.signatureHandler.reqBinSecTokValType = \
                            SignatureHandler.binSecTokValType["X509PKIPathv1"]
                attributeAuthorityClnt.signatureHandler.signingCertChain = \
                                    (self.issuingX509Cert, self.userX509Cert)                

                attributeAuthorityClnt.signatureHandler.signingPriKey = \
                                                            self.userPriKey
            elif self.userX509Cert is not None:
                # Pass user cert only - no need to pass a cert chain.  
                # This type of token is more likely to be supported by the 
                # various WS-Security toolkits
                attributeAuthorityClnt.signatureHandler.reqBinSecTokValType = \
                                    SignatureHandler.binSecTokValType["X509v3"]
                attributeAuthorityClnt.signatureHandler.signingCert = \
                                                            self.userX509Cert

                attributeAuthorityClnt.signatureHandler.signingPriKey = \
                                                            self.userPriKey

        return attributeAuthorityClnt


    def _getAttCert(self, 
                    attributeAuthorityURI=None, 
                    attributeAuthority=None,
                    extAttCert=None):       
        """Wrapper to Attribute Authority attribute certificate request.  See
        getAttCert for the classes' public interface.
        
        If successful, a new attribute certificate is issued to the user
        and added into the wallet
        
        @type attributeAuthorityURI: string
        @param attributeAuthorityURI: to call as a web service, specify the URI for the 
        Attribute Authority.
        
        @type attributeAuthority: ndg.security.server.attributeauthority.AttributeAuthority
        @param attributeAuthority: Alternative to attributeAuthorityURI - to 
        run on the local machine, specify a local Attribute Authority 
        instance.

        @type extAttCert: ndg.security.common.AttCert.AttCert
        @param extAttCert: an existing Attribute Certificate which can 
        be used to making a mapping should the user not be registered with the
        Attribute Authority"""
      
        log.debug("CredentialWallet._getAttCert ...")
        
        
        # If a user cert. is present, ignore the user ID setting.  The
        # Attribute Authority will set the userId field of the 
        # Attribute Certificate based on the DN of the user certificate
        if self.userX509Cert:
            userId = str(self.userX509Cert.dn)
        else:
            userId = self.userId
            
        if attributeAuthority is not None and \
           attributeAuthorityURI is not None:
            raise KeyError("Both attributeAuthorityURI and attributeAuthority "
                           "keywords have been set")
        
        if attributeAuthority is None:
            attributeAuthority = self.attributeAuthority
            
        if attributeAuthorityURI is None:
            attributeAuthorityURI = self.attributeAuthorityURI
            
        # Set a client alias according to whether the Attribute Authority is
        # being called locally or as a remote service
        if attributeAuthorityURI is not None:
            # Call Remote Service at given URI
            aaInterface = self._createAttributeAuthorityClnt(
                                                        attributeAuthorityURI)                            
            log.debug('CredentialWallet._getAttCert for remote Attribute '
                      'Authority service: "%s" ...' % attributeAuthorityURI)
                
        elif attributeAuthority is not None:
            # Call local based Attribute Authority with settings from the 
            # configuration file attributeAuthority
            aaInterface = attributeAuthority
            log.debug('CredentialWallet._getAttCert for local Attribute '
                      'Authority: "%r" ...' % attributeAuthority)
        else:
            raise CredentialWalletError("Error requesting attribute: "
                                        "certificate a URI or Attribute "
                                        "Authority instance must be specified")
        
        try:
            # Request a new attribute certificate from the Attribute
            # Authority
            attCert = aaInterface.getAttCert(userId=userId,
                                             userAttCert=extAttCert)
            
            log.info('Granted Attribute Certificate from issuer DN = "%s"'%
                     attCert.issuerDN)
            
        except (AttributeAuthorityAccessDenied, AttributeRequestDenied), e:
            # AttributeAuthorityAccessDenied is raised if 
            # aaInterface is a local AA instance and 
            # AttributeRequestDenied is raised for a client to a remote AA
            # service
            raise CredentialWalletAttributeRequestDenied(str(e))
                    
        except Exception, e:
            raise CredentialWalletError("Requesting attribute certificate: %s"%
                                        e)

        # Update attribute Certificate instance with CA's certificate ready 
        # for signature check in addCredential()
        if self._caCertFilePathList is None:
            raise CredentialWalletError("No CA certificate has been set")
        
        attCert.certFilePathList = self._caCertFilePathList

        
        # Add credential into wallet
        #
        # Nb. if the certificates signature is invalid, it will be rejected
        log.debug("Adding credentials into wallet...")
        self.addCredential(attCert)
        
        return attCert


    def _getAAHostInfo(self, 
                       attributeAuthority=None,
                       attributeAuthorityURI=None):
        """Wrapper to Attribute Authority getHostInfo
        
        _getAAHostInfo([attributeAuthority=f|attributeAuthorityURI=u])
                   
        @type userRole: string
        @param userRole: get hosts which have a mapping to this role
        
        @type attributeAuthorityURI: string
        @param attributeAuthorityURI: to call as a web service, specify the URI for the 
        Attribute Authority.
        
        @type attributeAuthority: string
        @param attributeAuthority: Alternative to attributeAuthorityURI - to 
        run on the local machine, specify the local Attribute Authority 
        instance.
        """

        if attributeAuthority is None:
            attributeAuthority = self.attributeAuthority
            
        if attributeAuthorityURI is None:
            attributeAuthorityURI = self.attributeAuthorityURI
        
        log.debug('CredentialWallet._getAAHostInfo for service: "%s" ...' % 
                  attributeAuthorityURI or attributeAuthority)
            
        # Set a client alias according to whether the Attribute Authority is
        # being called locally or asa remote service
        if attributeAuthorityURI is not None:
            # Call Remote Service at given URI
            attributeAuthorityClnt = self._createAttributeAuthorityClnt(
                                                    attributeAuthorityURI)

        elif attributeAuthority is not None:
            # Call local based Attribute Authority with settings from the 
            # configuration file attributeAuthority
            attributeAuthorityClnt = attributeAuthority
            
        else:
            raise CredentialWalletError("Error requesting trusted hosts info: " 
                                        "a URI or Attribute Authority " 
                                        "configuration file must be specified")
            
        try:
            # Request a new attribute certificate from the Attribute
            # Authority
            return attributeAuthorityClnt.getHostInfo()
            
        except Exception, e:
            log.error("Requesting host info: %s" % e)
            raise


    def _getAATrustedHostInfo(self, 
                              userRole=None,
                              attributeAuthority=None,
                              attributeAuthorityURI=None):
        """Wrapper to Attribute Authority getTrustedHostInfo
        
        _getAATrustedHostInfo([userRole=r, ][attributeAuthority=f|
                              attributeAuthorityURI=u])
                   
        @type userRole: string
        @param userRole: get hosts which have a mapping to this role
        
        @type attributeAuthorityURI: string
        @param attributeAuthorityURI: to call as a web service, specify the URI for the 
        Attribute Authority.
        
        @type attributeAuthority: string
        @param attributeAuthority: Alternative to attributeAuthorityURI - to 
        run on the local machine, specify the local Attribute Authority 
        instance.
        """

        if attributeAuthority is None:
            attributeAuthority = self.attributeAuthority
            
        if attributeAuthorityURI is None:
            attributeAuthorityURI = self.attributeAuthorityURI
        
        log.debug('CredentialWallet._getAATrustedHostInfo for role "%s" and '
                  'service: "%s" ...' % (userRole, 
                                attributeAuthorityURI or attributeAuthority))
            
        # Set a client alias according to whether the Attribute Authority is
        # being called locally or asa remote service
        if attributeAuthorityURI is not None:
            # Call Remote Service at given URI
            attributeAuthorityClnt = self._createAttributeAuthorityClnt(
                                                    attributeAuthorityURI)

        elif attributeAuthority is not None:
            # Call local based Attribute Authority with settings from the 
            # configuration file attributeAuthority
            attributeAuthorityClnt = attributeAuthority
            
        else:
            raise CredentialWalletError("Error requesting trusted hosts info: " 
                                        "a URI or Attribute Authority " 
                                        "configuration file must be specified")
            
        try:
            # Request a new attribute certificate from the Attribute
            # Authority
            return attributeAuthorityClnt.getTrustedHostInfo(role=userRole)
            
        except Exception, e:
            log.error("Requesting trusted host info: %s" % e)
            raise


    def getAttCert(self,
                   reqRole=None,
                   attributeAuthority=None,
                   attributeAuthorityURI=None,
                   mapFromTrustedHosts=None,
                   rtnExtAttCertList=None,
                   extAttCertList=None,
                   extTrustedHostList=None,
                   refreshAttCert=False,
                   attCertRefreshElapse=None):
        
        """Get an Attribute Certificate from an Attribute Authority.  If this 
        fails try to make a mapped Attribute Certificate by using a certificate 
        from another host which has a trust relationship to the Attribute 
        Authority in question.

        getAttCert([reqRole=r, ][attributeAuthority=a|attributeAuthorityURI=u,]
                   [mapFromTrustedHosts=m, ]
                   [rtnExtAttCertList=e, ][extAttCertList=el, ]
                   [extTrustedHostList=et, ][refreshAttCert=ra])
                  
        The procedure is:

        1) Try attribute request using user certificate
        2) If the Attribute Authority (AA) doesn't recognise the certificate,
        find out any other hosts which have a trust relationship to the AA.
        3) Look for Attribute Certificates held in the wallet corresponding
        to these hosts.
        4) If no Attribute Certificates are available, call the relevant
        hosts' AAs to get certificates
        5) Finally, use these new certificates to try to obtain a mapped
        certificate from the original AA
        6) If this fails access is denied      
                    
        @type reqRole: string
        @param reqRole: the required role to get access for
        
        @type attributeAuthorityURI: string
        @param attributeAuthorityURI: to call as a web service, specify the URI for the 
        Attribute Authority.
        
        @type attributeAuthority: string
        @param attributeAuthority: Altenrative to attributeAuthorityURI - to 
        run on the local machine, specify a local Attribute Authority 
        instance.
                                
        @type mapFromTrustedHosts: bool / None     
        @param mapFromTrustedHosts: if request fails via the user's cert
        ID, then it is possible to get a mapped certificate by using 
        certificates from other AA's.  Set this flag to True, to allow this 
        second stage of generating a mapped certificate from the certificate 
        stored in the wallet credentials.

        If set to False, it is possible to return the list of certificates 
        available for mapping and then choose which one or ones to use for
        mapping by re-calling getAttCert with extAttCertList set to these 
        certificates.
        
        Defaults to None in which case self._mapFromTrustedHosts is not 
        altered

        The list is returned via CredentialWalletAttributeRequestDenied 
        exception.  If no value is set, the default value held in 
        self.mapFromTrustedHosts is used

        @type rtnExtAttCertList: bool / None
        @param rtnExtAttCertList: If request fails, make a list of 
        candidate certificates from other Attribute Authorities which the user
        could use to retry and get a mapped certificate.
                                
        If mapFromTrustedHosts is set True this flags value is overriden and 
        effectively set to True.

        If no value is set, the default value held in self._rtnExtAttCertList
        is used.
                                
        The list is returned via a CredentialWalletAttributeRequestDenied 
        exception object.
                                
        @type extAttCertList: list
        @param extAttCertList: Attribute Certificate or list of certificates
        from other Attribute Authorities.  These can be used to get a mapped 
        certificate if access fails based on the user's certificate
        credentials.  They are tried out in turn until access is granted so 
        the order of the list decides the order in which they will be tried

        @type extTrustedHostList:
        @param extTrustedHostList: same as extAttCertList keyword, but 
        instead of providing Attribute Certificates, give a list of Attribute 
        Authority hosts.  These will be matched up to Attribute Certificates 
        held in the wallet.  Matching certificates will then be used to try to
        get a mapped Attribute Certificate.
        
        @type refreshAttCert: bool
        @param refreshAttCert: if set to True, the attribute request 
        will go ahead even if the wallet already contains an Attribute 
        Certificate from the target Attribute Authority.  The existing AC in 
        the wallet will be replaced by the new one obtained from this call.
                                
        If set to False, this method will check to see if an AC issued by the 
        target AA already exists in the wallet.  If so, it will return this AC
        to the caller without proceeding to make a call to the AA.
        
        @type attCertRefreshElapse: float / int
        @param attCertRefreshElapse: determine whether to replace an 
        existing AC in the cache with a fresh one.  If the existing one has 
        less than attCertRefreshElapse time in seconds left before expiry then
        replace it.
        
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate retrieved from Attribute Authority"""
        
        log.debug("CredentialWallet.getAttCert ...")
        
        # Both these assignments are calling set property methods implicitly!
        if attributeAuthorityURI:
            self.attributeAuthorityURI = attributeAuthorityURI
            
        if attributeAuthority is not None:
            self.attributeAuthority = attributeAuthority
           
        if not refreshAttCert and self._credentials:
            # Refresh flag is not set so it's OK to check for any existing
            # Attribute Certificate in the wallet whose issuerName match the 
            # target AA's name
            
            # Find out the site ID for the target AA by calling AA's host
            # info WS method
            log.debug("CredentialWallet.getAttCert - check AA site ID ...")
            try:
                hostInfo = self._getAAHostInfo()
                aaName = hostInfo.keys()[0]
            except Exception, e:
                raise CredentialWalletError("Getting host info: %s" % e)
            
            # Look in the wallet for an AC with the same issuer name
            if aaName in self._credentials:
                # Existing Attribute Certificate found in wallet - Check that 
                # it will be valid for at least the next 2 hours
                if attCertRefreshElapse is not None:
                    self.attCertRefreshElapse = attCertRefreshElapse
                    
                dtNow = datetime.utcnow() + \
                        timedelta(seconds=self.attCertRefreshElapse)
                
                attCert = self._credentials[aaName]['attCert']
                if attCert.isValidTime(dtNow=dtNow):
                    log.info("Retrieved an existing %s AC from the wallet" % 
                             aaName)
                    return attCert
            
            
        # Check for settings from input, if not set use previous settings
        # made
        if mapFromTrustedHosts is not None:
            self.mapFromTrustedHosts = mapFromTrustedHosts

        if rtnExtAttCertList is not None:
            self.rtnExtAttCertList = rtnExtAttCertList


        # Check for list of external trusted hosts (other trusted NDG data 
        # centres)
        if extTrustedHostList:
            log.info("Checking for ACs in wallet matching list of trusted "
                     "hosts set: %s" % extTrustedHostList)
            
            if not self.mapFromTrustedHosts:
                raise CredentialWalletError("A list of trusted hosts has been " 
                                      "input but mapping from trusted hosts "
                                      "is set to disallowed")
            
            if isinstance(extTrustedHostList, basestring):
                extTrustedHostList = [extTrustedHostList]

            # Nb. Any extAttCertList is overriden by extTrustedHostList being
            # set
            extAttCertList = [self._credentials[hostName]['attCert'] \
                              for hostName in extTrustedHostList \
                              if hostName in self._credentials]

        # Set an empty list to trigger an AttributeError by initialising it to
        # None
        if extAttCertList == []:
            extAttCertList = None
            
        # Repeat authorisation attempts until succeed or means are exhausted
        while True:
            
            # Check for candidate certificates for mapping
            try:
                # If list is set get the next cert
                extAttCert = extAttCertList.pop()

            except AttributeError:
                log.debug("No external Attribute Certificates - trying "
                          "request without mapping...")
                # No List set - attempt request without
                # using mapping from trusted hosts
                extAttCert = None
                            
            except IndexError:
                
                # List has been emptied without attribute request succeeding -
                # give up
                errMsg = "Attempting to obtained a mapped certificate: " + \
                         "no external attribute certificates are available"
                    
                # Add the exception form the last call to the Attribute
                # Authority if an error exists
                try:
                    errMsg += ": %s" % attributeRequestDenied
                except NameError:
                    pass

                raise CredentialWalletAttributeRequestDenied(errMsg)
                                                    
                
            # Request Attribute Certificate from Attribute Authority
            try:
                attCert = self._getAttCert(extAttCert=extAttCert)                
                # Access granted
                return attCert
            
            except CredentialWalletAttributeRequestDenied, \
                   attributeRequestDenied:
                if not self.mapFromTrustedHosts and not self.rtnExtAttCertList:
                    log.debug("Creating a mapped certificate option is not "
                              "set - raising "
                              "CredentialWalletAttributeRequestDenied "
                              "exception saved from earlier")
                    raise attributeRequestDenied

                if isinstance(extAttCertList, list):
                    # An list of attribute certificates from trusted hosts
                    # is present continue cycling through this until one of
                    # them is accepted and a mapped certificate can be derived
                    log.debug("AC request denied - but external ACs available "
                              "to try mapped AC request ...")
                    continue
                             
                #  Use the input required role and the AA's trusted host list
                # to identify attribute certificates from other hosts which
                # could be used to make a mapped certificate
                log.debug("Getting a list of trusted hosts for mapped AC "
                          "request ...")
                try:
                    trustedHostInfo = self._getAATrustedHostInfo(reqRole)
                    
                except NoMatchingRoleInTrustedHosts, e:
                    raise CredentialWalletAttributeRequestDenied(
                        'Can\'t get a mapped Attribute Certificate for '
                        'the "%s" role' % reqRole)
                
                except Exception, e:
                    raise CredentialWalletError("Getting trusted hosts: %s"%e)

                if not trustedHostInfo:
                    raise CredentialWalletAttributeRequestDenied(
                        "Attribute Authority has no trusted hosts with "
                        "which to make a mapping")

                
                # Initialise external certificate list here - if none are
                # found IndexError will be raised on the next iteration and
                # an access denied error will be raised
                extAttCertList = []

                # Look for Attribute Certificates with matching issuer host
                # names
                log.debug("Checking wallet for ACs issued by one of the "
                          "trusted hosts...")
                for hostName in self._credentials:

                    # Nb. Candidate certificates for mappings must have
                    # original provenance and contain at least one of the
                    # required roles
                    attCert = self._credentials[hostName]['attCert']
                    
                    if hostName in trustedHostInfo and attCert.isOriginal():                        
                        for role in attCert.roles:
                            if role in trustedHostInfo[hostName]['role']:                                
                                extAttCertList.append(attCert)


                if not extAttCertList:
                    log.debug("No wallet ACs matched any of the trusted "
                              "hosts.  - Try request for an AC from a "
                              "trusted host ...")
                    
                    # No certificates in the wallet matched the trusted host
                    # and required roles
                    #
                    # Try each host in turn in order to get a certificate with
                    # the required credentials in order to do a mapping
                    for host, info in trustedHostInfo.items():
                        try:
                            # Try request to trusted host
                            extAttCert = self._getAttCert(\
                                        attributeAuthorityURI=info['aaURI'])

                            # Check the certificate contains at least one of
                            # the required roles
                            if [True for r in extAttCert.roles \
                                if r in info['role']]:
                               extAttCertList.append(extAttCert)

                               # For efficiency, stop once obtained a valid
                               # cert - but may want complete list for user to
                               # choose from
                               #break
                               
                        except Exception, e:
                            # ignore any errors and continue
                            log.warning('AC request to trusted host "%s"' 
                                        ' resulted in: %s' % (info['aaURI'],e))
                            
                    
                if not extAttCertList:                        
                    raise CredentialWalletAttributeRequestDenied(
                        "No certificates are available with which to "
                        "make a mapping to the Attribute Authority")


                if not self.mapFromTrustedHosts:
                    
                    # Exit here returning the list of candidate certificates
                    # that could be used to make a mapped certificate
                    msg = "User is not registered with Attribute " + \
                          "Authority - retry using one of the returned " + \
                          "Attribute Certificates obtained from other " + \
                          "trusted hosts"
                          
                    raise CredentialWalletAttributeRequestDenied(msg,
                                            extAttCertList=extAttCertList,
                                            trustedHostInfo=trustedHostInfo)            


class CredentialRepositoryError(_CredentialWalletException):   
    """Exception handling for NDG Credential Repository class."""


class CredentialRepository:
    """CredentialWallet's abstract interface class to a Credential Repository. 
    The Credential Repository is abstract store of user currently valid user
    credentials.  It enables retrieval of attribute certificates from a user's
    previous session(s)"""
        
    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Initialise Credential Repository abstract base class.  Derive from 
        this class to define Credentail Repository interface Credential
        Wallet 

        If the connection string or properties file is set a connection
        will be made

        @type dbPPhrase: string
        @param dbPPhrase: pass-phrase to database if applicable
        
        @type propFilePath: string
        @param propFilePath: file path to a properties file.  This could 
        contain configuration parameters for the repository e.g.  database 
        connection parameters
        
        @type **prop: dict
        @param **prop: any other keywords required
        """
        raise NotImplementedError(
            self.__init__.__doc__.replace('\n       ',''))


    def addUser(self, userId, dn=None):
        """A new user to Credentials Repository
        
        @type userId: string
        @param userId: userId for new user
        @type dn: string
        @param dn: users Distinguished Name (optional)"""
        raise NotImplementedError(
            self.addUser.__doc__.replace('\n       ',''))

                            
    def auditCredentials(self, userId=None, **attCertValidKeys):
        """Check the attribute certificates held in the repository and delete
        any that have expired

        @type userId: basestring/list or tuple
        @param userId: audit credentials for the input user ID or list of IDs
        @type attCertValidKeys: dict
        @param **attCertValidKeys: keywords which set how to check the 
        Attribute Certificate e.g. check validity time, XML signature, version
         etc.  Default is check validity time only - See AttCert class"""
        raise NotImplementedError(
            self.auditCredentials.__doc__.replace('\n       ',''))


    def getCredentials(self, userId):
        """Get the list of credentials for a given users DN
        
        @type userId: string
        @param userId: users userId, name or X.509 cert. distinguished name
        @rtype: list 
        @return: list of Attribute Certificates"""
        raise NotImplementedError(
            self.getCredentials.__doc__.replace('\n       ',''))

        
    def addCredentials(self, userId, attCertList):
        """Add new attribute certificates for a user.  The user must have
        been previously registered in the repository

        @type userId: string
        @param userId: users userId, name or X.509 cert. distinguished name
        @type attCertList: list
        @param attCertList: list of attribute certificates"""
        raise NotImplementedError(
            self.addCredentials.__doc__.replace('\n       ',''))



class NullCredentialRepository(CredentialRepository):
    """Implementation of Credential Repository interface with empty stubs.  
    Use this class in the case where no Credential Repository is required"""
    
    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        pass

    def addUser(self, userId):
        pass
                            
    def auditCredentials(self, **attCertValidKeys):
        pass

    def getCredentials(self, userId):
        return []
       
    def addCredentials(self, userId, attCertList):
        pass