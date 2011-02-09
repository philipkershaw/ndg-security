"""NDG Credentials Wallet

NERC Data Grid Project

P J Kershaw 30/11/05

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

reposID = '$Id$'


# Temporary store of certificates for use with CredWallet reqAuthorisation()
import tempfile

# Check Attribute Certificate validity times
from datetime import datetime
from datetime import timedelta


# Access Attribute Authority's web service using ZSI - allow pass if not 
# loaded since it's possible to make AttAuthority instance locally without 
# using the WS
aaImportError = True
try:
    from SecurityClient import AttAuthorityClient, AttAuthorityClientError
    aaImportError = False
    
except ImportError:
    pass

# Likewise - may want to use WS and not use AttAuthority locally in which case
# no need to import it
try:
    from AttAuthority import *
    aaImportError = False
except:
    pass

if aaImportError:
    raise ImportError("Either AttAuthority or ZSI modules must be " + \
                      "present to allow interoperation with Attribute " +\
                      "Authorities")

# Authentication X.509 Certificate
from X509 import *

# Authorisation - attribute certificate 
from AttCert import *


#_____________________________________________________________________________
class CredWalletError(Exception):    
    """Exception handling for NDG CredentialWallet class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
class CredWalletAuthorisationDenied(Exception):    
    """Handling exception where CredWallet is denied authorisation by an
    Attribute Authority."""
    
    def __init__(self, msg=None, extAttCertList=[], trustedHostInfo={}):
        """Raise exception for authorisation denied with option to give
        caller hint to certificates that could used to try to obtain a
        mapped certificate
        
        msg:                error message
        extAttCertList:     list of candidate Attribute Certificates that
                            could be used to try to get a mapped certificate
                            from the target Attribute Authority
        trustedHostInfo:    dictionary indexed by host name giving details
                            of WSDL URI and roles for trusted hosts"""

        self.__msg = msg
        self.__trustedHostInfo = trustedHostInfo
        
        # Prevent None type setting
        if extAttCertList is None:
            extAttCertList = []
            
        self.__extAttCertList = extAttCertList

        
    def __str__(self):
        return self.__msg


    def __getMsg(self):
        """Get message text"""
        return self.__msg

    msg = property(fget=__getMsg, doc="Error message text")


    def __getTrustedHostInfo(self):
        """Get message text"""
        return self.__msg

    trustedHostInfo = property(fget=__getTrustedHostInfo, 
                               doc="WSDL and roles details for trusted hosts")
    
    
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
# CredWallet is a 'new-style' class inheriting from "object" and making use
# of new Get/Set methods for hiding of attributes
class CredWallet(object):
    """Volatile store of user credentials associated with a user session"""

    def __init__(self,
                 proxyCertTxt,
                 caPubKeyFilePath=None,
                 clntPubKeyFilePath=None,
                 clntPriKeyFilePath=None,
                 clntPriKeyPwd=None,
                 credRepos=None,
                 mapFromTrustedHosts=False,
                 rtnExtAttCertList=True):
        """Create store of user credentials for their current session

        proxy certificate:      users proxy certificate as string text
        caPubKeyFilePath:       Certificate Authority's certificate - used in
                                validation of signed Attribute Certificates.
                                If not set here, it must be input in call
                                to reqAuthorisation.
        clntPubKeyFilePath:     Public key certificate for this client. 
                                Setting this enables return message from AA 
                                WSDL to be encrypted by the AA.
        clntPriKeyFilePath:     Client's Private key used to decrypt response
                                from AA.
        clntPriKeyPwd:          Password protecting the client private key.
        credRepos:              Credential Repository instance
        mapFromTrustedHosts:    sets behaviour for reqAuthorisation().  If
                                set True and authorisation fails with the
                                given Attribute Authority, attempt to get
                                authorisation using Attribute Certificates
                                issued by other trusted AAs
        rtnExtAttCertList:     behaviour for reqAuthorisation().  If True,
                                and authorisation fails with the given
                                Attribute Authority, return a list of
                                Attribute Certificates from other trusted AAs
                                which could be used to obtain a mapped
                                Attribute Certificate on a subsequent
                                authorisation attempt"""


        # Makes implicit call to __setProxyCert - Checks the proxy certificate
        # and make an NDG.X509Cert instance
        self.proxyCertTxt = proxyCertTxt
        
        self.__setCApubKeyFilePath(caPubKeyFilePath)
        self.__setClntPubKeyFilePath(clntPubKeyFilePath)
        self.__setClntPriKeyFilePath(clntPriKeyFilePath)
        self.__setClntPriKeyPwd(clntPriKeyPwd)
                
        self.__credRepos = credRepos
        
        # Set behaviour for authorisation requests
        self.__mapFromTrustedHosts = mapFromTrustedHosts
        self.__rtnExtAttCertList = rtnExtAttCertList
        
        
        # Get the distinguished name from the proxy certificate
        self.__dn = self.__proxyCert.dn.serialise()
        
        
        # Credentials are stored as a dictionary one element per attribute
        # certicate held and indexed by certificate issuer name
        self.__credentials = {}


        # Make a connection to the Credentials Repository
        if self.__credRepos:
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
        



    def __str__(self):
        return "<Credential Wallet instance>"


    #_________________________________________________________________________    
    def __setProxyCert(self, proxyCertTxt):
        """Set a new proxy certificate for the wallet

        proxyCertTxt: input certificate as a string"""
        
        try:
            if not isinstance(proxyCertTxt, basestring):
                raise CredWalletError(\
                                "Proxy Certificate must be input as a string")
        except Exception, e:
            raise CredWalletError("Input proxy certificate: %s" % e)

        self.__proxyCertTxt = proxyCertTxt
        self.__proxyCert = X509Cert()
        self.__proxyCert.parse(proxyCertTxt)
    

    #_________________________________________________________________________
    # Set Proxy Certificate text also updates the proxyCert X509Cert
    # instance
    def __setProxyCertTxt(self, value):
        """Set proxy cert string and from it update equivalent X509Cert 
        instance"""
        self.__setProxyCert(value)

            
    def __getProxyCertTxt(self):
        """Get proxy cert as a string"""
        return self.__proxyCertTxt
 
        
    def __delProxyCertTxt(self):
        """Prevent deletion of proxy cert string"""
        raise AttributeError("\"proxyCertTxt\" cannot be deleted")

  
    # Publish attribute as read/write
    proxyCertTxt = property(fget=__getProxyCertTxt,
                            fset=__setProxyCertTxt,
                            fdel=__delProxyCertTxt,
                            doc="String text of proxy certificate")

    def __getProxyCert(self):
        """Get proxy cert X509Cert instance"""
        return self.__proxyCert


    # Proxy Cert instance is read-only - to set it, set proxyCertTxt
    proxyCert = property(fget=__getProxyCert,
                         doc="X.509 proxy certificate instance")
    
    
    #_________________________________________________________________________
    # Credentials are read-only
    def __getCredentials(self):
        return self.__credentials

    # Publish attribute
    credentials = property(fget=__getCredentials,
                           doc="List of Attribute Certificates")   


    #_________________________________________________________________________
    def __setCApubKeyFilePath(self, caPubKeyFilePath):
        
        if not isinstance(caPubKeyFilePath, basestring) and \
           caPubKeyFilePath is not None:
            raise CredWalletError(\
                "Input CA Certificate file path is not a valid string")
                
        self.__caPubKeyFilePath = caPubKeyFilePath
       
        
    caPubKeyFilePath = property(fset=__setCApubKeyFilePath,
                              doc="CA Certificate  - use to check AC XML Sig")


    #_________________________________________________________________________
    def __setClntPubKeyFilePath(self, clntPubKeyFilePath):
        
        if not isinstance(clntPubKeyFilePath, basestring) and \
           clntPubKeyFilePath is not None:
            raise CredWalletError(\
                "Input Client Certificate file path is not a valid string")
                
        self.__clntPubKeyFilePath = clntPubKeyFilePath
        
        # Read the file into string ready to be passed over WS interface as
        # required
        if self.__clntPubKeyFilePath:
            try:
                self.__clntPubKey = open(self.__clntPubKeyFilePath).read()
                
            except IOError, (errNo, errMsg):
                raise CredWalletError(\
                            "Reading client public key file \"%s\": %s" %\
                            (self.__clntPubKeyFilePath, errMsg))
                                   
            except Exception, e:
                raise CredWalletError(\
                            "Reading client public key file \"%s\": %s" %\
                            (self.__clntPubKeyFilePath, str(e)))                
       
        
    clntPubKeyFilePath = property(fset=__setClntPubKeyFilePath,
                        doc="Client Public Key - use to encrypt resp from AA")


    #_________________________________________________________________________
    def __setClntPriKeyFilePath(self, clntPriKeyFilePath):
        
        if not isinstance(clntPriKeyFilePath, basestring) and \
           clntPriKeyFilePath is not None:
            raise CredWalletError(\
                "Input Client Private Key file path is not a valid string")
                
        self.__clntPriKeyFilePath = clntPriKeyFilePath
       
        
    clntPriKeyFilePath = property(fset=__setClntPriKeyFilePath,
                    doc="Client Private Key - use to decrypt resp from AA")


    #_________________________________________________________________________
    def __setClntPriKeyPwd(self, clntPriKeyPwd):
        
        if not isinstance(clntPriKeyPwd, basestring) and \
           clntPriKeyPwd is not None:
            raise CredWalletError(\
                "Input Client Private Key password is not a valid string")
                
        self.__clntPriKeyPwd = clntPriKeyPwd
       
        
    clntPriKeyPwd = property(fset=__setClntPriKeyPwd,
                             doc="Password for Client Private Key")


    #_________________________________________________________________________
    def isValid(self, **x509CertKeys):
        """Check wallet's proxy cert.  If expired return False"""
        try:
            return self.__proxyCert.isValidTime(**x509CertKeys)

        except Exception, e:
            raise CredWalletError("Credential Wallet: %s" % e)

    
    #_________________________________________________________________________
    def addCredential(self, attCert, bUpdateCredRepos=True):
        """Add a new attribute certificate to the list of credentials held.
        Return True if certificate was added otherwise False.  - If an
        existing certificate from the same issuer has a later expiry it will
        take precence and the new input certificate is ignored.

        attCert:            new attribute Certificate to be added
        bUpdateCredRepos:   if set to True, and a repository exisits it will
                            be updated with the new credentials also"""

        # Check input
        try:
            if not isinstance(attCert, AttCert):
                raise CredWalletError(\
                    "Attribute Certificate must be an AttCert type object")
                    
        except Exception, e:
            raise CredWalletError("Attribute Certificate input: %s" % e)


        # Check certificate validity
        try:
            attCert.isValid(raiseExcep=True)
            
        except AttCertError, e:
            raise CredWalletError("Adding Credential: %s" % e)
        

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
            


    def audit(self):
        """Check the credentials held in the wallet removing any that have
        expired or are otherwise invalid."""

        # Nb. No signature check is carried out.  To do a check, access is
        # needed to the cert of the CA that issued the Attribute Authority's
        # cert
        #
        # P J Kershaw 12/09/05
        for key, val in self.__credentials.items():
            if not val['attCert'].isValid(chkSig=False):
                del self.__credentials[key]



                
    def updateCredRepos(self, auditCred=True):
        """Copy over non-persistent credentials held by wallet into the
        perminent repository."""

        if not self.__credRepos:
            raise CredWalletError(
                  "No Credential Repository has been created for this wallet")
                            
        # Filter out invalid certs unless auditCred flag is explicitly set to
        # false
        if auditCred: self.audit()

        # Update the database - only add new entries i.e. with an ID of -1
        attCertList = [i['attCert'] for i in self.__credentials.values() \
                        if i['id'] == -1]

        self.__credRepos.addCredentials(self.__dn, attCertList)

        
    def __reqAuthorisation(self,
                           aaPropFilePath=None,
                           aaWSDL=None,
                           aaPubKeyFilePath=None,
                           extAttCert=None,
                           bDebug=False):
        
        """Wrapper to Attribute Authority authorisation request.  See
        reqAuthorisation for the classes' public interface.

        To call the Attribute Authority as a Web Service, specify a WSDL
        otherwise set the properties file path.
        
        If successful, a new attribute certificate is issued to the user
        and added into the wallet

        aaWSDL|aaPropFilePath:  to call as a web service, specify the file
                                path or URI for the Attribute Authority's
                                WSDL.  Otherwise, to run on the local machine,
                                specify a local Attribute Authority
                                configuration file.
        extAttCert:             an existing Attribute Certificate which can be
                                used to making a mapping should the user not
                                be registered with the Attribute Authority"""
            
        if aaWSDL is not None:
            try:
                aaClnt = AttAuthorityClient(aaWSDL=aaWSDL,
                                aaPubKeyFilePath=aaPubKeyFilePath,
                                clntPubKeyFilePath=self.__clntPubKeyFilePath,
                                clntPriKeyFilePath=self.__clntPriKeyFilePath)
                                    
                authzResp = aaClnt.reqAuthorisation(self.__proxyCertTxt, 
                                        userAttCert=extAttCert, 
                                        clntPriKeyPwd=self.__clntPriKeyPwd)                
            except Exception, e:
                raise CredWalletError, "Requesting authorisation: %s" % str(e)


            if authzResp['statCode'] == authzResp.accessDenied:
                raise CredWalletAuthorisationDenied, \
                            "Authorisation denied: %s" % authzResp['errMsg']

            elif authzResp['statCode'] == authzResp.accessGranted:
                # TODO: Temporary fudge - convert output into string and then 
                # re-convert into AttCert type to try to avoid strange error 
                # XML sig check
                #
                # P J Kershaw 24/07/06
                attCert = AttCertParse(str(authzResp['credential']))
                
            else:
                raise CredWalletError, "Attribute Authority authorisation " +\
                                       "status code not recognised"
            
        elif aaPropFilePath is not None:

            # Call local based Attribute Authority with settings from the 
            # configuration file aaPropFilePath

            if not isinstance(aaPropFilePath, basestring):
                raise CredWalletError, "Attribute Authority Configuration " +\
                                      "file path must be a valid string"
                                    
            try:
                # Make a new attribute authority instance 
                aa = AttAuthority(aaPropFilePath)

                # Request a new attribute certificate from the Attribute
                # Authority
                attCert = aa.authorise(proxyCert=self.__proxyCertTxt,
                                       userAttCert=extAttCert)
                
            except AttAuthorityAccessDenied, e:
                raise CredWalletAuthorisationDenied, \
                                                "Authorisation denied: %s" % e
            
            except Exception, e:
                raise CredWalletError, "Requesting authorisation: %s" % e

        else:
            raise CredWalletError, "Error requesting authorisation: " + \
                                   "a WSDL file or Attribute Authority " + \
                                   "configuration file must be specified"
        

        # Update attribute Certificate instance with CA's certificate ready 
        # for signature check in addCredential()
        if self.__caPubKeyFilePath is None:
            raise CredWalletError, "No CA certificate has been set"
        
        attCert.certFilePathList = self.__caPubKeyFilePath

        
        # Add credential into wallet
        #
        # Nb. if the certificates signature is invalid, it will be rejected
        self.addCredential(attCert)


        return attCert




    def getAATrustedHostInfo(self,
                             userRole=None,
                             aaWSDL=None,
                             aaPubKeyFilePath=None,
                             aaPropFilePath=None,
                             bDebug=False):
        """Wrapper to Attribute Authority getTrustedHostInfo
        
        userRole:               get hosts which have a mapping to this role
        aaWSDL|aaPropFilePath:  to call as a web service, specify the file
                                path or URI for the Attribute Authority's
                                WSDL.  Otherwise, to run on the local machine,
                                specify a local Attribute Authority
                                configuration file."""
        
        if aaWSDL is not None:
            # Call Attribute Authority WS
            try:
                aaClnt = AttAuthorityClient(aaWSDL=aaWSDL,
                                aaPubKeyFilePath=aaPubKeyFilePath,
                                clntPubKeyFilePath=self.__clntPubKeyFilePath,
                                clntPriKeyFilePath=self.__clntPriKeyFilePath)
                                    
                trustedHostInfo = aaClnt.getTrustedHostInfo(role=userRole,
                                        clntPriKeyPwd=self.__clntPriKeyPwd)                
                return trustedHostInfo
                           
            except Exception, e:
                raise CredWalletError, \
                            "Requesting trusted host information: %s" % str(e)                

        elif aaPropFilePath is not None:

            # Call local based Attribute Authority with settings from the 
            # configuration file aaPropFilePath
            if not instance(aaWSDL, basestring):
                raise CredWalletError, "Attribute Authority Configuration " +\
                                      "file path must be a valid string"
                                    
            try:
                # Make a new attribute authority instance 
                aa = AttAuthority(aaPropFilePath)

                # Request a new attribute certificate from the Attribute
                # Authority
                return aa.getTrustedHostInfo(role=userRole)
                
            except Exception, e:
                raise CredWalletError, "Requesting trusted host info: %s" % e

        else:
            raise CredWalletError, "Error requesting trusted hosts info: " + \
                                   "a WSDL file or Attribute Authority " + \
                                   "configuration file must be specified"


    #_________________________________________________________________________
    def reqAuthorisation(self,
                         reqRole=None,
                         aaPropFilePath=None,
                         aaWSDL=None,
                         aaPubKeyFilePath=None,
                         mapFromTrustedHosts=None,
                         rtnExtAttCertList=None,
                         extAttCertList=None,
                         extTrustedHostList=None,
                         refreshAttCert=False):
        
        """For a given role, get authorisation from an Attribute Authority
        using a user's proxy certificate.  If this fails try to make a mapped
        Attribute Certificate by using a certificate from another host which
        has a trust relationship to the Attribute Authority in question.

        reqRole:                the required role to get access for
        aaWSDL|aaPropFilePath:  to call as a web service, specify the file
                                path or URI for the Attribute Authority's
                                WSDL.  Otherwise, to run on the local machine,
                                specify a local Attribute Authority
                                configuration file.
                                
        aaPubKeyFilePath:       Public key of AA used to encrypt client 
                                requests to the AA.

        mapFromTrustedHosts:    if authorisation fails via the user's proxy
                                certificate, then it is possible to get a
                                mapped certificate by using certificates from
                                other AA's.  Set this flag to True, to allow
                                this second stage of generating a mapped
                                certificate from the certificate stored in the
                                wallet credentials.

                                If set to False, it is possible to return the
                                list of certificates available for mapping and
                                then choose which one or ones to use for
                                mapping by re-calling reqAuthorisation with
                                extAttCertList set to these certificates

                                The list is returned via
                                CredWalletAuthorisationDenied exception

                                If no value is set, the default value held
                                in self.__mapFromTrustedHosts is used

        rtnExtAttCertList:      If authorisation fails, make a list of 
                                candidate certificates from other Attribute 
                                Authorities which the user could use to retry
                                and get a mapped certificate.
                                
                                If mapFromTrustedHosts is set True this flags 
                                value is overriden and effectively set to 
                                True.

                                If no value is set, the default value held
                                in self.__rtnExtAttCertList is used
                                
                                The list is returned via a
                                CredWalletAuthorisationDenied exception object
                                
        extAttCertList:         Attribute Certificate or list of certificates
                                from other Attribute Authorities.  These can
                                be used to get a mapped certificate if access
                                fails based on the user's proxy certificate
                                credentials.  They are tried out in turn until
                                access is granted so the order of the list
                                decides the order in which they will be tried

        extTrustedHostList:     same as extAttCertList keyword, but instead
                                providing Attribute Certificates, give a list
                                of Attribute Authority hosts.  These will be
                                matched up to Attribute Certificates held in
                                the wallet.  Matching certificates will then
                                be used to try to get mapped authorisation.
        
        refreshAttCert:         if set to True, the authorisation request will
                                will go ahead even if the wallet already 
                                contains an Attribute Certificate from
                                the target Attribute Authority.  The existing
                                AC in the wallet will be replaced by the new
                                one obtained from this call.
                                
                                If set to False, this method will check to see
                                if an AC issued by the target AA already 
                                exists in the wallet.  If so, it will return
                                this AC to the caller without proceeding to 
                                make a call to the AA.
                                
        The procedure is:

        1) Try authorisation using proxy certificate
        2) If the Attribute Authority (AA) doesn't recognise the certificate,
        find out any other hosts which have a trust relationship to the AA.
        3) Look for Attribute Certificates held in the wallet corresponding
        to these hosts.
        4) If no Attribute Certificates are available, call the relevant
        hosts' AAs to get certificates
        5) Finally, use these new certificates to try to obtain a mapped
        certificate from the original AA
        6) If this fails access is denied"""
                              
                              
        if aaPubKeyFilePath is None:
            # Try retrieving public key from the web service and making a 
            # temporary file to hold it
            try:
                pubKeyReq = PubKeyReq()
                resp = aaSrv.getPubKey(pubKeyReq=pubKeyReq())
                pubKeyResp = PubKeyResp(xmlTxt=resp['pubKeyResp'])
        
                if 'errMsg' in pubKeyResp and pubKeyResp['errMsg']:
                    raise Exception(pubKeyResp['errMsg'])
                
                aaPubKeyTmpFile = tempfile.NamedTemporaryFile()
                open(aaPubKeyTmpFile.name,"w").write(pubKeyResp['pubKey'])
    
                aaPubKeyFilePath = aaPubKeyTmpFile.name
                
            except IOError, (errNo, errMsg):
                raise CredWalletError(\
                    "Writing public key to temporary file: %s" % errMsg)
                                                      
            except Exception, e:
                raise CredWalletError(\
                    "Retrieving Attribute Authority public key: "+ str(e))


        if not refreshAttCert and self.__credentials:
            # Refresh flag is not set so it's OK to check for any existing
            # Attribute Certificate in the wallet whose issuerName match the 
            # target AA's name
            
            # Find out the site ID for the target AA by calling AA's host
            # info WS method
            aaClnt = AttAuthorityClient(aaWSDL=aaWSDL, 
                                 aaPubKeyFilePath=aaPubKeyFilePath,
                                 clntPubKeyFilePath=self.__clntPubKeyFilePath,
                                 clntPriKeyFilePath=self.__clntPriKeyFilePath)
            
            hostInfo = aaClnt.getHostInfo(clntPriKeyPwd=self.__clntPriKeyPwd)
            aaName = hostInfo.keys()[0]
            
            # Look in the wallet for an AC with the same issuer name
            if aaName in self.__credentials:
                # Existing Attribute Certificate found in wallet - Check that 
                # it will be valid for at least the next 2 hours
                #
                # TODO: Make this 2 hour offset a configurable parameter
                #
                # P J Kershaw 14/06/06
                dtNow = datetime.utcnow() + timedelta(seconds=7200)
                
                attCert = self.__credentials[aaName]['attCert']
                if attCert.isValidTime(dtNow=dtNow):                                   
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
            if not self.__mapFromTrustedHosts:
                raise CredWalletError("A list of trusted hosts has been " + \
                                      "input but mapping from trusted " + \
                                      "hosts is set to disallowed")
            
            if isinstance(extTrustedHostList, basestring):
                extTrustedHostList = [extTrustedHostList]

            # Nb. Any extAttCertList is overriden by extTrustedHostList being
            # set
            extAttCertList = []
            for hostName in extTrustedHostList:

                if hostName in self.__credentials:
                    extAttCertList.append(\
                                    self.__credentials[hostName]['attCert'])


        # Repeat authorisation attempts until succeed or means are exhausted
        while True:
            
            # Check for candidate certificates for mapping
            try:
                # If list is set get the next cert
                extAttCert = extAttCertList.pop()

            except AttributeError:
                
                # No List set - attempt authorisation without
                # using mapping from trusted hosts
                extAttCert = None
                                
            except IndexError:
                
                # List has been emptied without authorisation succeeding -
                # give up
                errMsg = "Attempting to obtained a mapped certificate: " + \
                    "no external attribute certificates are available"
                    
                # Add the exception form the last call to the Attribute
                # Authority if an error exists
                try:
                    errMsg += ": %s" % authorisationDenied
                except NameError:
                    pass

                raise CredWalletAuthorisationDenied, errMsg
                                                    
                
            # Request Authorisation from Attribute Authority
            try:
                attCert = self.__reqAuthorisation(aaWSDL=aaWSDL,
                                            aaPubKeyFilePath=aaPubKeyFilePath,
                                            aaPropFilePath=aaPropFilePath,
                                            extAttCert=extAttCert)                
                # Access granted
                return attCert
            
            except CredWalletAuthorisationDenied, authorisationDenied:

                # If a required role was set then it's possible to go
                # to get certificates with mapped roles from trusted hosts
                # Shouldn't need to set a role - setting a role makes it more
                # efficient but it's not essential
                #
                # P J Kershaw 29/03/06
#                if not reqRole:
#                    raise CredWalletAuthorisationDenied(\
#                        "No user role was input in order to map to " + \
#                        "a role in a trusted host")


                if not mapFromTrustedHosts and not rtnExtAttCertList:
                    # Creating a mapped certificate is not allowed - raise
                    # authorisation denied exception saved from earlier
                    raise authorisationDenied


                if isinstance(extAttCertList, list):
                    # An list of attribute certificates from trusted hosts
                    # is present continue cycling through this until one of
                    # them is accepted and a mapped certificate can be derived
                    continue
                
                
                #  Use the input required role and the AA's trusted host list
                # to identify attribute certificates from other hosts which
                # could be used to make a mapped certificate
                try:
                    trustedHostInfo = self.getAATrustedHostInfo(reqRole,
                                            aaWSDL=aaWSDL,
                                            aaPubKeyFilePath=aaPubKeyFilePath,
                                            aaPropFilePath=aaPropFilePath)
                except Exception, e:
                    raise CredWalletError("Getting trusted hosts: %s" % e)

                if not trustedHostInfo:
                    raise CredWalletAuthorisationDenied(\
                        "Attribute Authority has no trusted hosts with " + \
                        "which to make a mapping")

                
                # Initialise external certificate list here - if none are
                # found IndexError will be raised on the next iteration and
                # an access denied error will be raised
                extAttCertList = []

                # Look for Attribute Certificates with matching issuer host
                # names
                for hostName in self.__credentials:

                    # Nb. Candidate certificates for mappings must have
                    # original provenance and contain at least one of the
                    # required roles
                    attCert = self.__credentials[hostName]['attCert']
                    
                    if hostName in trustedHostInfo and attCert.isOriginal():                        
                        for role in attCert.getRoles():
                            if role in trustedHostInfo[hostName]['role']:                                
                                extAttCertList.append(attCert)


                if not extAttCertList:
                    # No certificates in the wallet matched the trusted host
                    # and required roles
                    #
                    # Try each host in turn in order to get a certificate with
                    # the required credentials in order to do a mapping
                    for key, val in trustedHostInfo.items():

                        try:
                            extAttCert = self.__reqAuthorisation(\
                                                           aaWSDL=val['wsdl'])

                            # Check the certificate contains at least one of
                            # the required roles
                            roles = extAttCert.getRoles()
                            if [True for r in roles if r in val['role']]:
                               extAttCertList.append(extAttCert)

                               # For efficiency, stop once obtained a valid
                               # cert - but may want complete list for user to
                               # choose from
                               #break
                               
                        except Exception, e:
                            pass    # ignore any errors and continue
                    
                if not extAttCertList:                        
                    raise CredWalletAuthorisationDenied(\
                        "No certificates are available with which to " + \
                        "make a mapping to the Attribute Authority")


                if not mapFromTrustedHosts:
                    
                    # Exit here returning the list of candidate certificates
                    # that could be used to make a mapped certificate
                    msg = "User is not registered with Attribute " + \
                          "Authority - retry using one of the returned " + \
                          "Attribute Certificates obtained from other " + \
                          "trusted hosts"
                          
                    raise CredWalletAuthorisationDenied(msg=msg,
                                            extAttCertList=extAttCertList,
                                            trustedHostInfo=trustedHostInfo)
                
            except Exception, authorisationError:
                # Authorisation request raised an error other than access
                # denied
                raise authorisationError
            

    #_________________________________________________________________________
    def __retrieveURI(self, uri):
        """Retrieve content from a URI - use to get public key from a 
        remote Attribute Authority
        
        Nb. If tempFile goes out of scope the temporary file containing the 
        URI content will be deleted also"""
        
        try:
            tempFile = tempfile.NamedTemporaryFile()
            (fileName, httpResp) = urllib.urlretrieve(uri,
                                                      tempFile.name)
        except Exception, e:
            raise CredWalletError("Error retrieving from URI " + \
                                  "\"%s\": %s" % (uri, str(e)))
    
        # Expecting plain text format for returned public key file
        # 404 error would come back as 'text/html'
        if 'text/plain' not in httpResp['Content-type']:
            raise CredWalletError("Error retrieving from URI " + \
                                  "\"%s\": expecting \"plain/text\"" % uri)
            
        return tempFile
 
        
#_____________________________________________________________________________
class CredReposError(Exception):   
    """Exception handling for NDG Credential Repository class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg 
 



#_____________________________________________________________________________
class CredRepos:
    """CredWallet's interface class to a Credential Repository"""
    

    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Initialise Credential Repository abstract base class derive from 
        this class to define Credentail Repository interface Credential
        Wallet 

        If the connection string or properties file is set a connection
        will be made

        dbPPhrase:     pass-phrase to database if applicable
        propFilePath:  file path to a properties file.  This could contain
                       configuration parameters for the repository e.g.
                       database connection parameters
        **prop:        any other keywords required
        """
        raise NotImplementedError(\
            self.__init__.__doc__.replace('\n       ',''))


    def addUser(self, userName, dn):
        """A new user to Credentials Repository"""
        raise NotImplementedError(
            self.addUser.__doc__.replace('\n       ',''))

                            
    def auditCredentials(self, **attCertValidKeys):
        """Check the attribute certificates held in the repository and delete
        any that have expired

        attCertValidKeys:  keywords which set how to check the Attribute
                           Certificate e.g. check validity time, XML
                           signature, version etc.  Default is check
                           validity time only"""
        raise NotImplementedError(
            self.auditCredentials.__doc__.replace('\n       ',''))


    def getCredentials(self, dn):
        """Get the list of credentials for a given user's DN"""
        raise NotImplementedError(
            self.getCredentials.__doc__.replace('\n       ',''))

        
    def addCredentials(self, dn, attCertList):
        """Add new attribute certificates for a user.  The user must have
        been previously registered in the repository

        dn:            users Distinguished name
        attCertList:   list of attribute certificates"""
        raise NotImplementedError(
            self.addCredentials.__doc__.replace('\n       ',''))



           
if __name__ == "__main__":
    proxyCertTxt = open('../x509up_u25157').read()
    credWallet = CredWallet(proxyCertTxt)
