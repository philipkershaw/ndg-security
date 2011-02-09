"""NDG Credentials Wallet

NERC Data Grid Project

P J Kershaw 30/11/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'


# Temporary store of certificates for use with CredWallet reqAuthorisation()
import tempfile

# Keyword formatting/XML message creation for Attribute Authority WS
from AttAuthorityIO import *

# Access Attribute Authority's web service using ZSI - allow pass if not loaded
# since it's possible to make AttAuthority instance locally without using
# the WS
aaImportError = True
try:
    from ZSI import ServiceProxy
    import socket # handle socket errors from WS
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
                 caCertFilePath=None,
                 clntCertFilePath=None,
                 credRepos=None,
                 mapFromTrustedHosts=False,
                 rtnExtAttCertList=True):
        """Create store of user credentials for their current session

        proxy certificate:      users proxy certificate as string text
        caCertFilePath:         Certificate Authority's certificate - used in
                                validation of signed Attribute Certificates.
                                If not set here, it must be input in call
                                to reqAuthorisation
        clntCertFilePath:       Public key certificate for this client. 
                                Setting this enables return message from AA 
                                WSDL to be encrypted by the AA.
        credRepos:              Credential Repository instance
        mapFromTrustedHosts:   sets behaviour for reqAuthorisation().  If
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
        
        if caCertFilePath:
            self.__setCAcertFilePath(caCertFilePath)
        else:
            self.__caCertFilePath = None
            
        if clntCertFilePath:
            self.__setClntCertFilePath(clntCertFilePath)
        else:
            self.__clntCertFilePath = None
                 
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
                raise CredWalletError(\
                    "Input Credentials Repository instance must be of a "+\
                    "class derived from \"CredRepos\"")
    
       
            # Check for valid attribute certificates for the user
            try:
                userCred = self.__credRepos.getCredentials(self.__dn)
    
            except Exception, e:
                raise CredWalletError(
                "Error updating wallet with credentials from repository: " + \
                    str(e))
    
    
            # Update wallet with attribute certificates stored in the repository
            # Store ID and certificate instantiated as an AttCert type
            try:
                for cred in userCred:
                    
                    attCert = AttCertParse(cred.attCert)
                    issuerName = attCert['issuerName']
                    
                    self.__credentials[issuerName] = \
                                             {'id':cred.id, 'attCert':attCert}
            except Exception, e:
                try:
                    raise CredWalletError(
                            "Error parsing Attribute Certificate ID '" + \
                                    cred.id + "' retrieved from the " + \
                                    "Credentials Repository: %s" % str(e))                
                except:
                    raise CredWalletError("Error parsing Attribute " + \
                                          "Certificate retrieved from " + \
                                          "the Credentials Repository: %s:" \
                                          % e)
            
            
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
    def __setCAcertFilePath(self, caCertFilePath):
        
        if not isinstance(caCertFilePath, basestring):
            raise CredWalletError(\
                "Input CA Certificate file path is not valid")
                
        self.__caCertFilePath = caCertFilePath
       
        
    caCertFilePath = property(fset=__setCAcertFilePath,
                              doc="CA Certificate  - use to check AC XML Sig")


    #_________________________________________________________________________
    def __setClntCertFilePath(self, clntCertFilePath):
        
        if not isinstance(clntCertFilePath, basestring):
            raise CredWalletError(\
                "Input Client Certificate file path is not valid")
                
        self.__clntCertFilePath = clntCertFilePath
       
        
    clntCertFilePath = property(fset=__setClntCertFilePath,
                    doc="Client Certificate  - use to encrypt resp from AA")



    def isValid(self, **x509CertKeys):
        """Check wallet's proxy cert.  If expired return False"""
        try:
            return self.__proxyCert.isValidTime(**x509CertKeys)

        except Exception, e:
            raise CredWalletError("Credential Wallet: %s" % e)


    
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
                           aaCertFilePath=None,
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
 
        aaCertFilePath:         Public key certificate for Attribute 
                                Authority.  Pass this to enable message level
                                encryption of outgoing message to AA WS.
                                Applies only where aaWSDL is set.  If omitted,
                                outgoing message is not enrypted.  In this
                                case SSL could be used instead to encrypt the 
                                message.
        extAttCert:             an existing Attribute Certificate which can be
                                used to making a mapping should the user not
                                be registered with the Attribute Authority"""

        if extAttCert is not None:
            if not isinstance(extAttCert, AttCert):
                raise CredWalletError(\
                    "Input Attribute Certificate must be AttCert type")

            extAttCertTxt = extAttCert.asString()
        else:
            extAttCertTxt = '' # None

            
        if aaWSDL is not None:

            if not isinstance(aaWSDL, basestring):
                raise CredWalletError("Attribute Authority WSDL file " + \
                                      "path must be a valid string")

            if self.__clntCertFilePath:
                clntCertTxt = \
                    X509Cert(filePath=self.__clntCertFilePath).asString()
            else:
                clntCertTxt = None
                
                
            try:                
                # Get Attribute Authority web service interface
                if bDebug:
                    traceFile = sys.stderr
                else:
                    traceFile = None
                    
                aaSrv = ServiceProxy(aaWSDL,
                                     use_wsdl=True,
                                     tracefile=traceFile)
                
                # Format XML request message
                #
                # Message will be encrypted if aaCertFilePath was set
                authorisationReq = AuthorisationReq(\
                                            proxyCert=self.__proxyCertTxt,
                                            userAttCert=extAttCertTxt,
                                            clntCert=clntCertTxt,
                                            encrPubKeyFilePath=aaCertFilePath)
                              
                # Call Attribute Authority's Web service
                resp = aaSrv.reqAuthorisation(\
                                         authorisationReq=authorisationReq())

            except socket.error, (dummy, e):
                raise CredWalletError("Requesting authorisation: %s" % str(e))
                
            except Exception, e:
                raise CredWalletError("Requesting authorisation: %s" % e)


            # Parse the response
            authorisationResp = AuthorisationResp(\
                                    xmlTxt=str(resp['authorisationResp']))
                                    
            # Check the status code returned from the authorisation request
            if authorisationResp['statCode'] == authorisationResp.accessError:
                raise CredWalletError(authorisationResp['errMsg'])
            
            elif authorisationResp['statCode'] == \
                                            authorisationResp.accessDenied:
                raise CredWalletAuthorisationDenied(\
                    "Authorisation denied: %s" % authorisationResp['errMsg'])

            elif authorisationResp['statCode'] == \
                                            authorisationResp.accessGranted:
                attCert = authorisationResp['credential']

            else:
                raise CredWalletError("Attribute Authority authorisation " + \
                                      "status code not recognised")
            
        elif aaPropFilePath is not None:

            # Call local based Attribute Authority with settings from the 
            # configuration file aaPropFilePath

            if not isinstance(aaPropFilePath, basestring):
                raise CredWalletError("Attribute Authority Configuration " + \
                                      "file path must be a valid string")
                                    
            try:
                # Make a new attribute authority instance 
                aa = AttAuthority(aaPropFilePath)

                # Request a new attribute certificate from the Attribute
                # Authority
                attCert = aa.authorise(proxyCert=self.__proxyCertTxt,
                                       userAttCertTxt=extAttCertTxt)
                
            except AttAuthorityAccessDenied, e:
                raise CredWalletAuthorisationDenied(\
                                    "Authorisation denied: %s" % e)
            
            except Exception, e:
                raise CredWalletError("Requesting authorisation: %s" % e)

        else:
            raise CredWalletError("Error requesting authorisation: " + \
                                  "a WSDL file or Attribute Authority " + \
                                  "configuration file must be specified")
        

        # Update attribute Certificate instance with CA's certificate ready 
        # for signature check in addCredential()
        if self.__caCertFilePath is None:
            raise CredWalletError("No CA certificate has been set")
        
        attCert.certFilePathList = self.__caCertFilePath

        
        # Add credential into wallet
        #
        # Nb. if the certificates signature is invalid, it will be rejected
        self.addCredential(attCert)


        return attCert




    def getAATrustedHostInfo(self,
                             userRole,
                             aaWSDL=None,
                             aaPropFilePath=None):
        """Wrapper to Attribute Authority getTrustedHostInfo
        
        userRole:               get hosts which have a mpping to this role
        aaWSDL|aaPropFilePath:  to call as a web service, specify the file
                                path or URI for the Attribute Authority's
                                WSDL.  Otherwise, to run on the local machine,
                                specify a local Attribute Authority
                                configuration file."""

        if not isinstance(userRole, basestring) or not userRole:
            raise CredWalletError("User Role must be a valid string")

        
        if aaWSDL is not None:

            if not isinstance(aaWSDL, basestring):
                raise CredWalletError("Attribute Authority WSDL file " + \
                                      "path must be a valid string")

            try:                
                # Get Attribute Authority web service interface
                aaSrv = ServiceProxy(aaWSDL, use_wsdl=True)
                
                # Call Attribute Authority's Web service
                resp = aaSrv.getTrustedHostInfo(usrRole=userRole)
                if resp['errMsg']:
                    raise Exception(resp['errMsg'])

                # De-serialise output into a dictionary of roles indexed by
                # host name
                hostList = []
                for host in resp['trustedHostInfo']:
                    hostSplit = re.split("\s*:\s*", str(host))
                    roleList = re.split("\s*,\s*", hostSplit[2])
                    
                    hostList.append((hostSplit[0], \
                                    {'wsdl': hostSplit[1], 'role': roleList}))

                return dict(hostList)
            
            except socket.error, e:
                raise CredWalletError("Requesting trusted host info: %s" % \
                                      e[1])                
            except Exception, e:
                raise CredWalletError("Requesting trusted host info: %s" % e)

            
        elif aaPropFilePath is not None:

            # Call local based Attribute Authority with settings from the 
            # configuration file aaPropFilePath

            if not instance(aaWSDL, basestring):
                raise CredWalletError("Attribute Authority Configuration " + \
                                      "file path must be a valid string")
                                    
            try:
                # Make a new attribute authority instance 
                aa = AttAuthority(aaPropFilePath)

                # Request a new attribute certificate from the Attribute
                # Authority
                return aa.getTrustedHosts(userRole)
                
            except Exception, e:
                raise CredWalletError("Requesting trusted host info: %s" % e)

        else:
            raise CredWalletError("Error requesting trusted hosts info: " + \
                                  "a WSDL file or Attribute Authority " + \
                                  "configuration file must be specified")


    #_________________________________________________________________________
    def reqAuthorisation(self,
                         reqRole=None,
                         aaPropFilePath=None,
                         aaWSDL=None,
                         aaCertFilePath=None,
                         clntCertFilePath=None,
                         caCertFilePath=None,
                         mapFromTrustedHosts=None,
                         rtnExtAttCertList=None,
                         extAttCertList=None,
                         extTrustedHostList=None):
        
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

        aaCertFilePath:         Public key certificate for Attribute 
                                Authority.  Pass this to enable message level
                                encryption of outgoing message to AA WS.
                                Applies only where aaWSDL is set.  If omitted,
                                outgoing message is not enrypted.  In this
                                case SSL could be used instead to encrypt the 
                                message.
                                
        clntCertFilePath:       Public key certificate for this client. 
                                Setting this enables return message from AA 
                                WSDL to be encrypted by the AA.

        caCertFilePath:         Certificate Authority's certificate used to
                                validate the signature of any Attribute
                                Certificate returned from the Attribute
                                Authority

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


        if caCertFilePath is not None:
            self.caCertFilePath = caCertFilePath
            
        if clntCertFilePath is not None:
            self.clntCertFilePath = clntCertFilePath

            
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
                raise CredWalletAuthorisationDenied(\
                    "Attempting to obtained a mapped certificate: " + \
                    "no external attribute certificates are available")


            # Request Authorisation from Attribute Authority
            try:
                attCert = self.__reqAuthorisation(aaWSDL=aaWSDL,
                                                aaPropFilePath=aaPropFilePath,
                                                aaCertFilePath=aaCertFilePath,
                                                extAttCert=extAttCert)                
                # Access granted
                return attCert
            
            except CredWalletAuthorisationDenied, authorisationDenied:

                # If a required role was set then it's possible to go
                # to get certificates with mapped roles from trusted hosts
                if not reqRole:
                    raise CredWalletAuthorisationDenied(\
                        "No user role was input in order to map to " + \
                        "a role in a trusted host")


                #  Use the input required role and the AA's trusted host list
                # to identify attribute certificates from other hosts which
                # could be used to make a mapped certificate
                try:
                    trustedHostInfo = self.getAATrustedHostInfo(reqRole,
                                                aaWSDL=aaWSDL,
                                                aaPropFilePath=aaPropFilePath)
                except Exception, e:
                    raise CredWalletError("Getting trusted hosts: %s" % e)

                if not trustedHostInfo:
                    raise CredWalletAuthorisationDenied(\
                        "Attribute Authority has no trusted hosts with " + \
                        "which to make a mapping")


                if not mapFromTrustedHosts and not rtnExtAttCertList:
                    # Creating a mapped certificate is not allowed - raise
                    # authorisation denied exception saved from earlier
                    raise authorisationDenied

                
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
