"""NDG Credentials Wallet

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "30/11/05"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import logging
log = logging.getLogger(__name__)

# Temporary store of certificates for use with CredWallet getAttCert()
import tempfile

# Check Attribute Certificate validity times
from datetime import datetime
from datetime import timedelta


# Access Attribute Authority's web service using ZSI - allow pass if not 
# loaded since it's possible to make AttAuthority instance locally without 
# using the WS
aaImportError = True
try:
    # AttAuthority client package resides with CredWallet module in 
    # ndg.security.common
    from ndg.security.common.AttAuthority import AttAuthorityClient, \
        AttAuthorityClientError, AttributeRequestDenied, \
        NoMatchingRoleInTrustedHosts
    aaImportError = False
    
    # Reference 'X509PKIPathv1' BinarySecurityToken ValueType
    from wsSecurity import SignatureHandler
except ImportError:
    log.warning('Loading CredWallet without SOAP interface imports')
    pass

# Likewise - may not want to use WS and use AttAuthority locally in which case
# no need to import it
try:
    from ndg.security.server.AttAuthority import AttAuthority, \
        AttAuthorityError, AttAuthorityAccessDenied
    aaImportError = False
except:
    log.warning(\
            'Loading CredWallet for SOAP interface to Attribute Authority')
    pass

if aaImportError:
    raise ImportError, \
        "Either AttAuthority or AttAuthorityClient classes must be " + \
        "present to allow interoperation with Attribute Authorities"

# Authentication X.509 Certificate
from ndg.security.common.X509 import *
from M2Crypto import X509, BIO, RSA

# Authorisation - attribute certificate 
from ndg.security.common.AttCert import *


class _CredWalletException(Exception):    
    """Generic Exception class for CredWallet module.  Overrides Exception to 
    enable writing to the log"""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)

#_____________________________________________________________________________
class CredWalletError(_CredWalletException):    
    """Exception handling for NDG Credential Wallet class.  Overrides Exception to 
    enable writing to the log"""


#_____________________________________________________________________________
class CredWalletAttributeRequestDenied(CredWalletError):    
    """Handling exception where CredWallet is denied authorisation by an
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
        
        if 'trustedHostInfo' in kw:
            self.__trustedHostInfo = kw['trustedHostInfo']
            del kw['trustedHostInfo']
        else:
            self.__trustedHostInfo = {}
            
        if 'extAttCertList' in kw:
            self.__extAttCertList = kw['extAttCertList']
            del kw['extAttCertList']
        else:    
            self.__extAttCertList = []
            
        CredWalletError.__init__(self, *args, **kw)

    def __getTrustedHostInfo(self):
        """Get message text"""
        return self.__msg

    trustedHostInfo = property(fget=__getTrustedHostInfo, 
                               doc="URI and roles details for trusted hosts")
       
    def __getExtAttCertList(self):
        """Return list of candidate Attribute Certificates that could be used
        to try to get a mapped certificate from the target Attribute Authority
        """
        return self.__extAttCertList

    extAttCertList = property(fget=__getExtAttCertList,
                              doc="list of candidate Attribute " + \
                              "Certificates that could be used " + \
                              "to try to get a mapped certificate " + \
                              "from the target Attribute Authority")

          
#_____________________________________________________________________________
class _MetaCredWallet(type):
    """Enable CredWallet to have read only class variables e.g.
    
    print CredWallet.accessDenied 
    
    ... is allowed but,
    
    CredWallet.accessDenied = None
    
    ... raises - AttributeError: can't set attribute"""
    
    def __getAccessDenied(cls):
        '''accessDenied get method'''
        return False
    
    accessDenied = property(fget=__getAccessDenied)
    
    def __getAccessGranted(cls):
        '''accessGranted get method'''
        return True
    
    accessGranted = property(fget=__getAccessGranted)

#_____________________________________________________________________________        
# CredWallet is a 'new-style' class inheriting from "object" and making use
# of new Get/Set methods for hiding of attributes
class CredWallet(object):
    """Volatile store of user credentials associated with a user session
    
    @type __credRepos: ndg.security.common.CredRepos or derivative
    @ivar __credRepos: reference to Credential Repository object.  An optional
    non-volatile cache for storage of wallet info when 

    @type __mapFromTrustedHosts: bool
    @ivar __mapFromTrustedHosts: if true, allow a mapped attribute certificate
    to obtained in a getAttCert call.  Set false to prevent mappings.

    @type __rtnExtAttCertList: bool
    @ivar __rtnExtAttCertList: if true, return a list of external attribute 
    certificates from getAttCert call

    @type __dn: ndg.security.common.X509.X500DN
    @ivar __dn: distinguished name from user certificate

    @type __credentials: dict       
    @ivar __credentials: Credentials are stored as a dictionary one element per attribute
    certicate held and indexed by certificate issuer name

    @type __caCertFilePathList: basestring, list, tuple or None
    @ivar __caCertFilePathList: file path(s) to CA certificates.  If None
    then the input is quietly ignored.  See caCertFilePathList property

    @type __userCert: ndg.security.common.X509.X509Cert
    @ivar __userCert: X.509 user certificate instance

    @type __issuingCert: ndg.security.common.X509.X509Cert
    @ivar __issuingCert: X.509 user certificate instance
 
    @type __userPriKey: M2Crypto.RSA.RSA
    @ivar __userPriKey: Private key used to sign outbound message
    """

    __metaclass__ = _MetaCredWallet
    
    def __init__(self,
                 userCert,
                 userPriKey,
                 issuingCert=None,
                 caCertFilePathList=None,
                 aaURI=None,
                 aaPropFilePath=None,
                 credRepos=None,
                 mapFromTrustedHosts=False,
                 rtnExtAttCertList=True,
                 attCertRefreshElapse=7200,
                 wssSignatureHandlerKw={}):
        """Create store of user credentials for their current session

        @type userCert: string / M2Crypto.X509.X509 /
        ndg.security.common.X509.X509Cert
        @param userCert: X.509 certificate for user
        
        @type userPriKey: string / M2Crypto.RSA.RSA 
        @param userPriKey: private key for user cert
        
        @type issuingCert: string / ndg.security.common.X509.X509Cert
        @param issuingCert: X.509 cert for issuer of user cert
        
        @type aaURI: string
        @param aaURI: URI of Attribute Authority to make requests to.  
        Setting this ALSO creates an AttAuthorityClient instance 
        self.__aaClnt.  - See aaURI property for details.
        
        @type aaPropFilePath: string
        @param aaPropFilePath: properties file path for an Attribute 
        Authority to make requests to.  Setting this ALSO creates an 
        AttAuthority instance self.__aa running locally.   - See aa property 
        for details.  aaURI takes precedence over this keyword i.e. if an
        aaURI has been set, then calls are made to the AA web service at this
        location rather to any self.__aa running locally.
        
        @type caCertFilePathList: string (for single file), list or tuple
        @param caCertFilePathList: Certificate Authority's certificates - used
        in validation of signed Attribute Certificates and WS-Security 
        signatures of incoming messages.  If not set here, it must
        be input in call to getAttCert.
                
        @type credRepos: instance of CredRepos derived class
        @param credRepos: Credential Repository instance.  If not set, 
        defaults to NullCredRepos type - see class below...
        
        @type mapFromTrustedHosts: bool
        @param mapFromTrustedHosts sets behaviour for getAttCert().  If
        set True and authorisation fails with the given Attribute Authority, 
        attempt to get authorisation using Attribute Certificates issued by 
        other trusted AAs.
        
        @type rtnExtAttCertList: bool
        @param rtnExtAttCertList: behaviour for getAttCert().  If True, and 
        authorisation fails with the given Attribute Authority, return a list 
        of Attribute Certificates from other trusted AAs which could be used 
        to obtain a mapped Attribute Certificate on a subsequent authorisation
        attempt
        
        @type attCertRefreshElapse: float / int
        @param attCertRefreshElapse: used by getAttCert to determine 
        whether to replace an existing AC in the cache with a fresh one.  If 
        the existing one has less than attCertRefreshElapse time in seconds
        left before expiry then replace it.
        
        @type wssSignatureHandlerKw: dict
        @param wssSignatureHandlerKw: keywords to WS-Security SignatureHandler
        used for Credential Wallet's SOAP interface to Attribute Authorities
        """

        log.debug("Calling CredWallet.__init__ ...")
        
        self.attCertRefreshElapse = attCertRefreshElapse
        
        self.__setUserCert(userCert)
        self.__setUserPriKey(userPriKey)
        self.__setIssuingCert(issuingCert)
        
        self.__setAAuri(aaURI)
        self.__setCAcertFilePathList(caCertFilePathList)
                
        self.__credRepos = credRepos or NullCredRepos()
        
        # Set behaviour for authorisation requests
        self.__mapFromTrustedHosts = mapFromTrustedHosts
        self.__rtnExtAttCertList = rtnExtAttCertList
        
        self.wssSignatureHandlerKw = wssSignatureHandlerKw
        
        # Get the distinguished name from the user certificate
        self.__dn = self.__userCert.dn.serialise()
        
        
        # Credentials are stored as a dictionary one element per attribute
        # certicate held and indexed by certificate issuer name
        self.__credentials = {}


        # Make a connection to the Credentials Repository
        if self.__credRepos:
            log.info(\
            'Checking CredentialRepository for credentials for user "%s"' % \
                self.__dn)
            
            if not isinstance(self.__credRepos, CredRepos):
                raise CredWalletError, \
                    "Input Credentials Repository instance must be of a " + \
                    "class derived from \"CredRepos\""
    
       
            # Check for valid attribute certificates for the user
            try:
                self.__credRepos.auditCredentials(dn=self.__dn)
                userCred = self.__credRepos.getCredentials(self.__dn)
    
            except Exception, e:
                raise CredWalletError, \
                "Error updating wallet with credentials from repository: " + \
                    str(e)
    
    
            # Update wallet with attribute certificates stored in the 
            # repository.  Store ID and certificate instantiated as an AttCert
            # type
            try:
                for cred in userCred:
                    
                    attCert = AttCertParse(cred.attCert)
                    issuerName = attCert['issuerName']
                    
                    self.__credentials[issuerName] = \
                                             {'id':cred.id, 'attCert':attCert}    
            except Exception, e:
                try:
                    raise CredWalletError, \
                            "Error parsing Attribute Certificate ID '" + \
                                    cred.id + "' retrieved from the " + \
                                    "Credentials Repository: %s" % str(e)                
                except:
                    raise CredWalletError, "Error parsing Attribute " + \
                                          "Certificate retrieved from " + \
                                          "the Credentials Repository: %s:" \
                                          % str(e)
            
            
            # Filter out expired or otherwise invalid certificates
            self.audit()

        
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
    def __setUserCert(self, userCert):
        "Set property method for X.509 user cert."
        self.__userCert = self.__setCert(userCert)
        

    def __getUserCert(self):
        """Get user cert X509Cert instance"""
        return self.__userCert

    userCert = property(fget=__getUserCert,
                        fset=__setUserCert,
                        doc="X.509 user certificate instance")


    #_________________________________________________________________________
    def __setIssuingCert(self, issuingCert):
        "Set property method for X.509 user cert."
        self.__issuingCert = self.__setCert(issuingCert)
        

    def __getIssuingCert(self):
        """Get user cert X509Cert instance"""
        return self.__issuingCert

    issuingCert = property(fget=__getIssuingCert,
                         fset=__setIssuingCert,
                         doc="X.509 user certificate instance")
     
 
    #_________________________________________________________________________
    def __setUserPriKey(self, userPriKey):
        """Set method for client private key
        
        Nb. if input is a string, userPriKeyPwd will need to be set if
        the key is password protected.
        
        @type userPriKey: M2Crypto.RSA.RSA / string
        @param userPriKey: private key used to sign message"""
        
        if isinstance(userPriKey, basestring):
            self.__userPriKey = RSA.load_key_string(userPriKey,
                                             callback=lambda *ar, **kw: None)
        elif isinstance(userPriKey, RSA.RSA):
            self.__userPriKey = userPriKey          
        else:
            raise AttributeError, "user private key must be a valid " + \
                                  "M2Crypto.RSA.RSA type or a string"
                
    userPriKey = property(fset=__setUserPriKey,
                          doc="Private key used to sign outbound message")

   
    def __getCredentials(self):
        """Get Property method.  Credentials are read-only
        
        @rtype: dict
        @return: cached ACs indesed by issuing organisation name"""
        return self.__credentials

    # Publish attribute
    credentials = property(fget=__getCredentials,
                           doc="List of Attribute Certificates")   


    #_________________________________________________________________________
    def __getCAcertFilePathList(self):
        """Get CA cert or certs used to validate AC signatures and signatures
        of peer SOAP messages.
        
        @rtype caCertFilePathList: basestring, list or tuple
        @return caCertFilePathList: file path(s) to CA certificates."""
        return self.__caCertFilePathList
    
    #_________________________________________________________________________
    def __setCAcertFilePathList(self, caCertFilePathList):
        """Set CA cert or certs to validate AC signatures, signatures
        of Attribute Authority SOAP responses and SSL connections where 
        AA SOAP service is run over SSL.
        
        @type caCertFilePathList: basestring, list, tuple or None
        @param caCertFilePathList: file path(s) to CA certificates.  If None
        then the input is quietly ignored."""
        
        if isinstance(caCertFilePathList, basestring):
           self.__caCertFilePathList = [caCertFilePathList]
           
        elif isinstance(caCertFilePathList, list):
           self.__caCertFilePathList = caCertFilePathList
           
        elif isinstance(caCertFilePathList, tuple):
           self.__caCertFilePathList = list(caCertFilePathList)

        elif caCertFilePathList is not None:
            raise CredWalletError, \
                        "Input CA Certificate file path is not a valid string"      
        
    caCertFilePathList = property(fget=__getCAcertFilePathList,
                                  fset=__setCAcertFilePathList,
                                  doc="CA Certificates - used for " + \
                                      "verification of AC and SOAP " + \
                                      "message signatures and SSL " + \
                                      "connections")


    #_________________________________________________________________________
    def __createAAClnt(self, aaURI):
        """Set up a client to an Attribute Authority with the given URI
        
        @type aaURI: string
        @param aaURI: Attribute Authority Web Service URI.

        @rtype: ndg.security.common.AttAuthorityClient
        @return: new Attribute Authority client instance"""

        log.debug('CredWallet.__createAAClnt for service: "%s"' % aaURI)
        
        # Check for WS-Security settings made in self.wssSignatureHandlerKw 
        # dict. If not set, then pick up defaults from wallet credentials
        if 'signingCert' and 'signingCertFilePath' and 'signingCertChain' \
           not in self.wssSignatureHandlerKw:
            
            # Use user certificate for signing messages
            if self.__issuingCert is not None:
                # Initialise WS-Security signature handling to pass 
                # BinarySecurityToken containing user cert and cert for user cert 
                # issuer 
                self.wssSignatureHandlerKw['reqBinSecTokValType'] = \
                            SignatureHandler.binSecTokValType["X509PKIPathv1"]
                self.wssSignatureHandlerKw['signingCertChain'] = \
                                        (self.__issuingCert, self.__userCert)
                
            else:
                # Pass user cert only - no need to pass a cert chain.  
                # This type of token is more likely to be supported by the 
                # various WS-Security toolkits
                self.wssSignatureHandlerKw['reqBinSecTokValType'] = \
                                    SignatureHandler.binSecTokValType["X509v3"]
                self.wssSignatureHandlerKw['signingCert'] = self.__userCert

            self.wssSignatureHandlerKw['signingPriKey'] = self.__userPriKey

        if 'caCertFilePathList' not in self.wssSignatureHandlerKw:
            self.wssSignatureHandlerKw['caCertFilePathList'] = \
                                                    self.__caCertFilePathList

        aaClnt = AttAuthorityClient(uri=aaURI,
                            sslCACertFilePathList=self.__caCertFilePathList,
                            **self.wssSignatureHandlerKw)
        return aaClnt


    #_________________________________________________________________________
    def __setAAuri(self, aaURI):
        """Set property method for Attribute Authority Web Service URI to
        connect to.  This method ALSO SETS UP THE CLIENT INTERFACE
        
        @type aaURI: string
        @param aaURI: Attribute Authority Web Service URI.  Set to None to
        initialise.  Set to a URI to instantiate a new AA client"""
        if aaURI is None:
            self.__aaClnt = None
            return
        else:
            self.__aaClnt = self.__createAAClnt(aaURI)
            
    aaURI = property(fset=__setAAuri,
             doc="AA URI - setting also sets up AttAuthorityClient instance!")


    #_________________________________________________________________________
    def __getAAclnt(self):
        """Get property method for Attribute Authority Web Service client
        instance.  Use aaURI propert to set up aaClnt
        
        @type aaClnt: AttAuthorityClient
        @param aaClnt: Attribute Authority Web Service client instance"""
        return self.__aaClnt
            
    aaClnt = property(fget=__getAAclnt, doc="AA web service client instance")


    #_________________________________________________________________________
    def __setAApropFilePath(self, aaPropFilePath):
        """Set property method for the properties file of a local
        Attribute Authority.  This method ALSO SETS UP THE LOCAL Attribute 
        Authority object to retrieve ACs from.  the property aaURI takes
        precedence: if an aaURI is set then it assumed that an Attribute
        Authority will be connected to via a web service call
        
        @type aaPropFilePath: string
        @param aaPropFilePath: Attribute Authority properties file.  Setting 
        this instantiates a new AA locally"""
        if aaPropFilePath is None:
            self.__aa = None
            return

        # Make a new attribute authority instance 
        self.__aa = AttAuthority(propFilePath=aaPropFilePath)

    aaPropFilePath = property(fset=__setAApropFilePath,
    doc="AA properties file path - setting this also sets up an AA locally!")


    #_________________________________________________________________________
    def __getAA(self):
        """Get property method for Attribute Authority Web Service client
        instance.  Use aaURI propert to set up aaClnt
        
        @type aaClnt: AttAuthorityClient
        @param aaClnt: Attribute Authority Web Service client instance"""
        return self.__aaClnt
            
    aa = property(fget=__getAA, doc="Attribute Authority instance")


    #_________________________________________________________________________
    def isValid(self, **x509CertKeys):
        """Check wallet's user cert.  If expired return False
        
        @type **x509CertKeys: dict
        @param **x509CertKeys: keywords applying to 
        ndg.security.common.X509.X509Cert.isValidTime method"""
        return self.__userCert.isValidTime(**x509CertKeys)

    
    #_________________________________________________________________________
    def addCredential(self, attCert, bUpdateCredRepos=True):
        """Add a new attribute certificate to the list of credentials held.

        @type attCert:
        @param attCert: new attribute Certificate to be added
        @type bUpdateCredRepos: bool
        @param bUpdateCredRepos: if set to True, and a repository exists it 
        will be updated with the new credentials also
        
        @rtype: bool
        @return: True if certificate was added otherwise False.  - If an
        existing certificate from the same issuer has a later expiry it will
        take precence and the new input certificate is ignored."""

        # Check input
        if not isinstance(attCert, AttCert):
            raise CredWalletError,\
                "Attribute Certificate must be an AttCert type object"

        # Check certificate validity
        try:
            attCert.isValid(raiseExcep=True)
            
        except AttCertError, e:
            raise CredWalletError, "Adding Credential: %s" % e
        

        # Check to see if there is an existing Attribute Certificate held
        # that was issued by the same host.  If so, compare the expiry time.
        # The one with the latest expiry will be retained and the other
        # ingored
        bUpdateCred = True
        issuerName = attCert['issuerName']
        
        if issuerName in self.__credentials:
            # There is an existing certificate held with the same issuing
            # host name as the new certificate
            attCertOld = self.__credentials[issuerName]['attCert']

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
            self.__credentials[issuerName] = {'id': -1, 'attCert': attCert}

            # Update the Credentials Repository - the permanent store of user
            # authorisation credentials.  This allows credentials for previous
            # sessions to be re-instated
            if self.__credRepos and bUpdateCredRepos:
                self.updateCredRepos()

        # Flag to caller to indicate whether the input certificate was added
        # to the credentials or an exsiting certificate from the same issuer
        # took precedence
        return bUpdateCred
            

    #_________________________________________________________________________
    def audit(self):
        """Check the credentials held in the wallet removing any that have
        expired or are otherwise invalid."""

        log.debug("CredWallet.audit ...")
        
        # Nb. No signature check is carried out.  To do a check, access is
        # needed to the cert of the CA that issued the Attribute Authority's
        # cert
        #
        # P J Kershaw 12/09/05
        for key, val in self.__credentials.items():
            if not val['attCert'].isValid(chkSig=False):
                del self.__credentials[key]


    #_________________________________________________________________________            
    def updateCredRepos(self, auditCred=True):
        """Copy over non-persistent credentials held by wallet into the
        perminent repository.
        
        @type auditCred: bool
        @param auditCred: filter existing credentials in the repository
        removing invalid ones"""

        log.debug("CredWallet.updateCredRepos ...")
        
        if not self.__credRepos:
            raise CredWalletError, \
                  "No Credential Repository has been created for this wallet"
                            
        # Filter out invalid certs unless auditCred flag is explicitly set to
        # false
        if auditCred: self.audit()

        # Update the database - only add new entries i.e. with an ID of -1
        attCertList = [i['attCert'] for i in self.__credentials.values() \
                        if i['id'] == -1]

        self.__credRepos.addCredentials(self.__dn, attCertList)


    #_________________________________________________________________________                    
    def __getAttCert(self, aaClnt=None, extAttCert=None):       
        """Wrapper to Attribute Authority attribute certificate request.  See
        getAttCert for the classes' public interface.

        To call the Attribute Authority as a Web Service, specify a URI
        otherwise set the properties file path.
        
        If successful, a new attribute certificate is issued to the user
        and added into the wallet

        @type aaClnt: ndg.security.common.AttAuthorityClient
        @param aaClnt: client object to Attribute Authority to make a request 
        to.  If omitted, it is set to self.__aaClnt.  This attribute may 
        itself be None.   In this case, a local AA client will be expected
        set from a properties file.
        
        @type extAttCert: ndg.security.common.AttCert.AttCert
        @param extAttCert: an existing Attribute Certificate which can 
        be used to making a mapping should the user not be registered with the
        Attribute Authority"""
      
        log.debug("CredWallet.__getAttCert ...")
        
        if aaClnt is None:
            aaClnt = self.__aaClnt
            
        if aaClnt is not None:
            try:
                attCert = aaClnt.getAttCert(userAttCert=extAttCert)
                               
                log.info(\
             'Granted Attribute Certificate from issuer DN = "%s" at "%s"' % \
             (attCert.issuerDN, aaClnt.uri))
                
            except AttributeRequestDenied, e:
                raise CredWalletAttributeRequestDenied, str(e)
                            
        elif self.aaPropFilePath is not None:

            # Call local based Attribute Authority with settings from the 
            # configuration file aaPropFilePath
            try:
                # Request a new attribute certificate from the Attribute
                # Authority
                attCert = self.__aa.getAttCert(userAttCert=extAttCert)
                
                log.info(\
                     'Granted Attribute Certificate from issuer DN = "%s"' % \
                     attCert.issuerDN)
                
            except AttAuthorityAccessDenied, e:
                raise CredWalletAttributeRequestDenied, str(e)
                        
            except Exception, e:
                raise CredWalletError,"Requesting attribute certificate: %s"%e

        else:
            raise CredWalletError, "Error requesting attribute: " + \
                "certificate a URI or Attribute Authority configuration " + \
                "file must be specified"
        

        # Update attribute Certificate instance with CA's certificate ready 
        # for signature check in addCredential()
        if self.__caCertFilePathList is None:
            raise CredWalletError, "No CA certificate has been set"
        
        attCert.certFilePathList = self.__caCertFilePathList

        
        # Add credential into wallet
        #
        # Nb. if the certificates signature is invalid, it will be rejected
        self.addCredential(attCert)
        
        return attCert


    #_________________________________________________________________________
    def getAATrustedHostInfo(self, 
                             userRole=None,
                             aaPropFilePath=None,
                             aaURI=None):
        """Wrapper to Attribute Authority getTrustedHostInfo
        
        getAATrustedHostInfo([userRole=r, ][aaPropFilePath=f|aaURI=u])
                   
        @type userRole: string
        @param userRole: get hosts which have a mapping to this role
        
        @type aaURI: string
        @param aaURI: to call as a web service, specify the URI for the 
        Attribute Authority.
        
        @type aaPropFilePath: string
        @param aaPropFilePath: Altenrative to aaURI - to run on the local 
        machine, specify the local Attribute Authority configuration file.
        """
        
        log.debug(\
        'CredWallet.getAATrustedHostInfo for role "%s" and service: "%s"' % \
                   (userRole, aaURI or aaPropFilePath))
        if aaURI:
            self.__setAAuri(aaURI)
        elif aaPropFilePath:
            self.__setAAPropFilePath 

            
        if self.__aaClnt is not None:
            # Call Attribute Authority WS
#            try:
                return self.__aaClnt.getTrustedHostInfo(role=userRole)                
#                           
#            except Exception, e:
#                raise CredWalletError, \
#                            "Requesting trusted host information: %s" % str(e)                

        elif self.__aa is not None:

            # Call local based Attribute Authority with settings from the 
            # configuration file aaPropFilePath
            try:
                # Request a new attribute certificate from the Attribute
                # Authority
                return self.__aa.getTrustedHostInfo(role=userRole)
                
            except Exception, e:
                raise CredWalletError, "Requesting trusted host info: %s" % e

        else:
            raise CredWalletError, "Error requesting trusted hosts info: " + \
                                   "a URI or Attribute Authority " + \
                                   "configuration file must be specified"


    #_________________________________________________________________________
    def getAttCert(self,
                   reqRole=None,
                   aaPropFilePath=None,
                   aaURI=None,
                   mapFromTrustedHosts=None,
                   rtnExtAttCertList=None,
                   extAttCertList=None,
                   extTrustedHostList=None,
                   refreshAttCert=False,
                   attCertRefreshElapse=None):
        
        """For a given role, get an Attribute Certificate from an Attribute 
        Authority using a user's X.509 certificate.  If this fails try to make
        a mapped Attribute Certificate by using a certificate from another 
        host which has a trust relationship to the Attribute Authority in 
        question.

        getAttCert([reqRole=r, ][aaPropFilePath=f|aaURI=u,]
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
        
        @type aaURI: string
        @param aaURI: to call as a web service, specify the URI for the 
        Attribute Authority.
        
        @type aaPropFilePath: string
        @param aaPropFilePath: Altenrative to aaURI - to run on the local 
        machine, specify the local Attribute Authority configuration file.
                                
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
        
        Defaults to None in which case self.__mapFromTrustedHosts is not 
        altered

        The list is returned via CredWalletAttributeRequestDenied exception
        If no value is set, the default value held in 
        self.__mapFromTrustedHosts is used

        @type rtnExtAttCertList: bool / None
        @param rtnExtAttCertList: If request fails, make a list of 
        candidate certificates from other Attribute Authorities which the user
        could use to retry and get a mapped certificate.
                                
        If mapFromTrustedHosts is set True this flags value is overriden and 
        effectively set to True.

        If no value is set, the default value held in self.__rtnExtAttCertList
        is used.
                                
        The list is returned via a CredWalletAttributeRequestDenied exception 
        object.
                                
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
        replace it."""
        
        log.debug("CredWallet.getAttCert ...")
        
        if aaURI:
            self.__setAAuri(aaURI)
        elif aaPropFilePath:
            self.__setAAPropFilePath 
           
        if not refreshAttCert and self.__credentials:
            # Refresh flag is not set so it's OK to check for any existing
            # Attribute Certificate in the wallet whose issuerName match the 
            # target AA's name
            
            # Find out the site ID for the target AA by calling AA's host
            # info WS method
            log.debug("CredWallet.getAttCert - check AA site ID ...")
            
            try:
                hostInfo = self.__aaClnt.getHostInfo()
                aaName = hostInfo.keys()[0]
            except Exception, e:
                raise CredWalletError, "Getting host info: %s" % e
            
            # Look in the wallet for an AC with the same issuer name
            if aaName in self.__credentials:
                # Existing Attribute Certificate found in wallet - Check that 
                # it will be valid for at least the next 2 hours
                if attCertRefreshElapse is not None:
                    self.attCertRefreshElapse = attCertRefreshElapse
                    
                dtNow = datetime.utcnow() + \
                        timedelta(seconds=self.attCertRefreshElapse)
                
                attCert = self.__credentials[aaName]['attCert']
                if attCert.isValidTime(dtNow=dtNow):
                    log.info("Retrieved an existing %s AC from the wallet" % \
                             aaName)
                    return attCert
            
            
        # Check for settings from input, if not set use previous settings
        # made
        if mapFromTrustedHosts is not None:
            self.__mapFromTrustedHosts = mapFromTrustedHosts

        if rtnExtAttCertList is not None:
            self.__rtnExtAttCertList = rtnExtAttCertList


        # Check for list of external trusted hosts (other trusted NDG data 
        # centres)
        if extTrustedHostList:
            log.info(\
        "Checking for ACs in wallet matching list of trusted hosts set: %s" % 
                 extTrustedHostList)
            
            if not self.__mapFromTrustedHosts:
                raise CredWalletError, "A list of trusted hosts has been " + \
                "input but mapping from trusted hosts is set to disallowed"
            
            if isinstance(extTrustedHostList, basestring):
                extTrustedHostList = [extTrustedHostList]

            # Nb. Any extAttCertList is overriden by extTrustedHostList being
            # set
            extAttCertList = [self.__credentials[hostName]['attCert'] \
                              for hostName in extTrustedHostList \
                              if hostName in self.__credentials]

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
                log.debug(\
  "No external Attribute Certificates - trying request without mapping...")
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

                raise CredWalletAttributeRequestDenied, errMsg
                                                    
                
            # Request Attribute Certificate from Attribute Authority
            try:
                attCert = self.__getAttCert(extAttCert=extAttCert)                
                # Access granted
                return attCert
            
            except CredWalletAttributeRequestDenied, attributeRequestDenied:
                if not mapFromTrustedHosts and not rtnExtAttCertList:
                    # Creating a mapped certificate is not allowed - raise
                    # authorisation denied exception saved from earlier
                    raise attributeRequestDenied

                if isinstance(extAttCertList, list):
                    # An list of attribute certificates from trusted hosts
                    # is present continue cycling through this until one of
                    # them is accepted and a mapped certificate can be derived
                    log.debug(\
"AC request denied - but external ACs available to try mapped AC request ...")
                    continue
                             
                #  Use the input required role and the AA's trusted host list
                # to identify attribute certificates from other hosts which
                # could be used to make a mapped certificate
                log.debug(\
                    "Getting a list of trusted hosts for mapped AC request ...")
                try:
                    trustedHostInfo = self.getAATrustedHostInfo(reqRole,
                                            aaPropFilePath=aaPropFilePath)
                except NoMatchingRoleInTrustedHosts, e:
                    raise CredWalletAttributeRequestDenied, \
                        'Can\'t get a mapped Attribute Certificate for ' + \
                        'the "%s" role' % reqRole
                
                except Exception, e:
                    raise CredWalletError, "Getting trusted hosts: %s" % e

                if not trustedHostInfo:
                    raise CredWalletAttributeRequestDenied, \
                        "Attribute Authority has no trusted hosts with " + \
                        "which to make a mapping"

                
                # Initialise external certificate list here - if none are
                # found IndexError will be raised on the next iteration and
                # an access denied error will be raised
                extAttCertList = []

                # Look for Attribute Certificates with matching issuer host
                # names
                log.debug(\
            "Checking wallet for ACs issued by one of the trusted hosts...")
                for hostName in self.__credentials:

                    # Nb. Candidate certificates for mappings must have
                    # original provenance and contain at least one of the
                    # required roles
                    attCert = self.__credentials[hostName]['attCert']
                    
                    if hostName in trustedHostInfo and attCert.isOriginal():                        
                        for role in attCert.roles:
                            if role in trustedHostInfo[hostName]['role']:                                
                                extAttCertList.append(attCert)


                if not extAttCertList:
                    log.debug("No wallet ACs matched any of the trusted " + \
                              "hosts.  - Try request for an AC from a " + \
                              "trusted host ...")
                    
                    # No certificates in the wallet matched the trusted host
                    # and required roles
                    #
                    # Try each host in turn in order to get a certificate with
                    # the required credentials in order to do a mapping
                    for host, info in trustedHostInfo.items():
                        try:
                            # Try request to trusted host
                            trustedAAClnt = self.__createAAClnt(info['aaURI'])
                            extAttCert=self.__getAttCert(aaClnt=trustedAAClnt)

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
                            log.warning('AC request to trusted host "%s"' % \
                                        info['aaURI'] + ' resulted in: %s'%e)
                            
                    
                if not extAttCertList:                        
                    raise CredWalletAttributeRequestDenied, \
                        "No certificates are available with which to " + \
                        "make a mapping to the Attribute Authority"


                if not mapFromTrustedHosts:
                    
                    # Exit here returning the list of candidate certificates
                    # that could be used to make a mapped certificate
                    msg = "User is not registered with Attribute " + \
                          "Authority - retry using one of the returned " + \
                          "Attribute Certificates obtained from other " + \
                          "trusted hosts"
                          
                    raise CredWalletAttributeRequestDenied(msg,
                                            extAttCertList=extAttCertList,
                                            trustedHostInfo=trustedHostInfo)            
             
        
#_____________________________________________________________________________
class CredReposError(_CredWalletException):   
    """Exception handling for NDG Credential Repository class."""


#_____________________________________________________________________________
class CredRepos:
    """CredWallet's interface class to a Credential Repository"""
    

    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Initialise Credential Repository abstract base class derive from 
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
        raise NotImplementedError, \
            self.__init__.__doc__.replace('\n       ','')


    def addUser(self, username, dn):
        """A new user to Credentials Repository
        
        @type username: string
        @param username: username for new user
        @type dn: string
        @param dn: users Distinguished Name"""
        raise NotImplementedError, \
            self.addUser.__doc__.replace('\n       ','')

                            
    def auditCredentials(self, **attCertValidKeys):
        """Check the attribute certificates held in the repository and delete
        any that have expired

        @type attCertValidKeys: dict
        @param **attCertValidKeys: keywords which set how to check the 
        Attribute Certificate e.g. check validity time, XML signature, version
         etc.  Default is check validity time only - See AttCert class"""
        raise NotImplementedError, \
            self.auditCredentials.__doc__.replace('\n       ','')


    def getCredentials(self, dn):
        """Get the list of credentials for a given users DN
        
        @type dn: string
        @param dn: users distinguished name
        @rtype: list 
        @return: list of Attribute Certificates"""
        raise NotImplementedError, \
            self.getCredentials.__doc__.replace('\n       ','')

        
    def addCredentials(self, dn, attCertList):
        """Add new attribute certificates for a user.  The user must have
        been previously registered in the repository

        @type dn: string
        @param dn: users Distinguished name
        @type attCertList: list
        @param attCertList: list of attribute certificates"""
        raise NotImplementedError, \
            self.addCredentials.__doc__.replace('\n       ','')



#_____________________________________________________________________________
class NullCredRepos(CredRepos):
    """Implementation of Credential Repository interface with empty stubs.  
    This allows for where no Credential Repository is required"""
    
    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        pass

    def addUser(self, userName, dn):
        pass
                            
    def auditCredentials(self, **attCertValidKeys):
        pass

    def getCredentials(self, dn):
        return []
       
    def addCredentials(self, dn, attCertList):
        pass