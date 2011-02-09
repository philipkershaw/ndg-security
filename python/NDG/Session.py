"""NDG Session Management and security includes SessionMgr, UserSession,
Credentials Wallet and Credentials Repository classes.

NERC Data Grid Project

P J Kershaw 02/06/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'


# Temporary store of certificates for use with CredWallet reqAuthorisation()
import tempfile

# SQLObject Database interface
from sqlobject import *

# MYSQL exceptions have no error message associated with them so include here
# to allow an explicit trap around database calls
import _mysql_exceptions

# Placing of session ID on client
from Cookie import SimpleCookie

# For parsing of properties file
import cElementTree as ElementTree

# Base 64 encode session IDs if returned in strings - urandom's output may
# not be suitable for printing!
import base64

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
    from NDG.AttAuthority import *
    aaImportError = False
except:
    pass

if aaImportError:
    raise ImportError("Either AttAuthority or ZSI modules must be " + \
                      "present to allow interoperation with Attribute " +\
                      "Authorities")

# Authentication X.509 Certificate
from NDG.X509 import *

# Authorisation - attribute certificate 
from NDG.AttCert import *

# MyProxy server interface
from NDG.MyProxy import *


#_____________________________________________________________________________
class CredWalletError(Exception):    
    """Exception handling for NDG CredentialWallet class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
class CredWalletAuthorisationDenied(Exception, UserDict):    
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
        trustedHostInfo:    dictionary of indexed by host name giving details
                            of WSDL URI and roles for trusted hosts"""

        # Base class initialisation
        UserDict.__init__(self)

        self.__dat = {}
        self.__dat['msg'] = msg
        self.__dat['trustedHostInfo'] = trustedHostInfo
        self.__dat['extAttCertList'] = extAttCertList

        
    def __str__(self):
        return self.__dat['msg']

    
    def __delitem__(self, key):
        "keys cannot be removed"        
        raise CredWalletError('Keys cannot be deleted from ' + \
                              CredWalletAuthorisationDenied.__name__)


    def __setitem__(self, key, value):
        """Dictionary items can't be set"""
        raise CredWalletError("Dictionary items can't be set")


    def __getitem__(self, key):
        """Enable access using dictionary like behaviour"""
        if key not in self.__dat:
            raise CredWalletError('Key "%s" not recognised' % key)

        return self.__dat[key]

    
    def clear(self):
        """Override UserDict default behaviour"""
        raise CredWalletError("Data cannot be cleared from " + \
                              CredWalletAuthorisationDenied.__name__)

    
    def copy(self):
        """Override UserDict default behaviour"""
        return self.__dat

    
    def keys(self):
        return self.__dat.keys()


    def items(self):
        return self.__dat.items()


    def values(self):
        return self.__dat.values()


    def has_key(self):
        return self.__dat.has_key()

    
    def getExtAttCertList(self):
        """Return list of candidate Attribute Certificates that could be used
        to try to get a mapped certificate from the target Attribute Authority
        """
        return self.__extAttCertList




#_____________________________________________________________________________        
class CredWallet(UserDict):
    """Volatile store of user credentials associated with a user session"""

    def __init__(self,
                 proxyCertTxt,
                 credRepos=None,
                 credReposPropFilePath=None,
                 bMapFromTrustedHosts=False,
                 bSetExtAttCertList=True):
        """Create store of user credentials for their current session

        proxy certificate:      users proxy certificate as string text
        credReposDbURI:         Credential Repository Database URI
        bMapFromTrustedHosts:   sets behaviour for reqAuthorisation().  If
                                set True and authorisation fails with the
                                given Attribute Authority, attempt to get
                                authorisation using Attribute Certificates
                                issued by other trusted AAs
        bSetExtAttCertList:     behaviour for reqAuthorisation().  If True,
                                and authorisation fails with the given
                                Attribute Authority, return a list of
                                Attribute Certificates from other trusted AAs
                                which could be used to obtain a mapped
                                Attribute Certificate on a subsequent
                                authorisation attempt"""


        # Base class initialisation
        UserDict.__init__(self)


        # Check the proxy certificate and make an NDG.X509Cert instance
        self.setProxyCert(proxyCertTxt)


        # Set behaviour for authorisation requests
        self.__bMapFromTrustedHosts = bMapFromTrustedHosts
        self.__bSetExtAttCertList = bSetExtAttCertList
        
        
        # Get the distinguished name from the proxy certificate
        self.__dn = self.__proxyCert.getDN().serialise()


        # Make a connection to the Credentials Repository
        #
        # Fudge file setting for now
        # P J Kershaw 10/06/05
        if credRepos is not None:
            if not isinstance(credRepos, CredRepos):
                raise CredWalletError(\
                    "Input Credentials Repository instance is not invalid")

            self.__credRepos = credRepos
        else:
            try:
                self.__credRepos = CredRepos(credReposPropFilePath)
                
            except Exception, e:
                raise CredWalletError(\
                            "Error accessing credentials repository: %s" % e)
        
        
        # Credentials are stored as a dictionary one element per attribute
        # certicate held and indexed by certificate issuer name
        self.__credentials = {}


        # Check for valid attribute certificates for the user
        try:
            userCred = self.__credRepos.getCredentials(self.__dn)

        except Exception, e:
            raise CredWalletError(
                "Error updating wallet with credentials from repository: %s"%\
                e)


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
                                "Credentials Repository: %s" % e)                
            except:
                raise CredWalletError("Error parsing Attribute " + \
                                      "Certificate retrieved from the " + \
                                      "Credentials Repository: %s:" % e)
        
        
        # Filter out expired or otherwise invalid certificates
        self.audit()
        



    def __str__(self):
        return "<Credential Wallet instance>"

    
    def __delitem__(self, key):
        "CredWallet keys cannot be removed"        
        raise CredWalletError('Keys cannot be deleted from ' + \
                              CredWallet.__name__)


    def __setitem__(self, key, value):
        """Enable access to __proxyCertTxt using dictionary like
        behaviour"""
        if key == 'proxyCertTxt':
            self.setProxyCert(value)
        else:
            raise CredWalletError('Key "%s" not recognised' % key)


    def __getitem__(self, key):
        """Enable access to __proxyCertTxt using dictionary like
        behaviour"""
        if key == 'proxyCertTxt':
            return self.__proxyCertTxt
        
        elif key == 'proxyCert':
            return self.__proxyCert
        
        elif key == 'credentials':
            return self.__credentials
        else:
            raise CredWalletError('Key "%s" not recognised' % key)


    def clear(self):
        """Override UserDict default behaviour"""
        raise CredWalletError("Data cannot be cleared from " + \
                              CredWallet.__name__)

    
    def copy(self):
        """Override UserDict default behaviour"""
        raise CredWalletError("A copy cannot be made of "+CredWallet.__name__)

    
    def keys(self):
        return ['proxyCertTxt', 'proxyCert', 'credentials']


    def items(self):
        return [('proxyCertTxt', self.__proxyCertTxt)]


    def values(self):
        return [self.__proxyCertTxt]


    def has_key(self):
        return self.__dat.has_key()



        
    def setProxyCert(self, proxyCertTxt):
        """Set a new proxy certificate for the wallet

        proxyCert: input certificate as a string"""
        
        try:
            if not isinstance(proxyCertTxt, basestring):
                raise CredWalletError(\
                                "Proxy Certificate must be input as a string")
        except Exception, e:
            raise CredWalletError("Input proxy certificate: %s" % e)

        self.__proxyCertTxt = proxyCertTxt
        self.__proxyCert = X509Cert()
        self.__proxyCert.parse(proxyCertTxt)




    def isValid(self, **x509CertKeys):
        """Check wallet's proxy cert.  If epxired return False"""
        try:
            return self.__proxyCert.isValidTime(**x509CertKeys)

        except Exception, e:
            raise CredWalletError("Credential Wallet: %s" % e)


    
    def addCredential(self, attCert, bUpdateCredRepos=True):
        """Add a new attribute certificate to the list of credentials held.
        Return True if certificate was added otherwise False.  - If an
        existing certificate from the same issuer has a later expiry it will
        take precence and the new input certificate is ignored.

        attCert:           new attribute Certificate to be added
        bUpdateCredRepos:   if set to True, the repository will be updated
                            with the new credentials also"""

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
            if bUpdateCredRepos:
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
        for item in self.__credentials.items():
            if not item[1]['attCert'].isValid(chkSig=False):
                del self.__credentials[item[0]]



                
    def updateCredRepos(self, auditCred=True):
        """Copy over non-persistent credentials held by wallet into the
        perminent repository."""

        # Filter out invalid certs unless auditCred flag is explicitly set to
        # false
        if auditCred: self.audit()

        # Update the database - only add new entries i.e. with an ID of -1
        attCertList = [i['attCert'] for i in self.__credentials.values() \
                        if i['id'] == -1]

        self.__credRepos.addCredentials(self.__dn, attCertList)


        
    def __reqAuthorisation(self,
                           aaWSDL=None,
                           aaPropFilePath=None,
                           extAttCert=None,
                           bDebug=False):
        
        """Wrapper to Attribute Authority authorisation request.  See
        reqAuthorisation for the classes' public interface.

        To call the Attibute Authority as a Web Service, specify a WSDL
        otherwise set the properties file path.
        
        If successful, a new attribute certificate is issued to the user
        and added into the wallet

        aaWSDL|aaPropFilePath:  to call as a web service, specify the file
                                path or URI for the Attribute Authority's
                                WSDL.  Otherwise, to run on the local machine,
                                specify a local Attribute Authority
                                configuration file.
                                
        extAttCert:            an existing Attribute Certificate which can be
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

            try:                
                # Get Attribute Authority web service interface
                if bDebug:
                    traceFile = sys.stderr
                else:
                    traceFile = None
                    
                aaSrv = ServiceProxy(aaWSDL,
                                     use_wsdl=True,
                                     tracefile=traceFile)
                
                # Call Attribute Authority's Web service
                resp=aaSrv.reqAuthorisation(usrProxyCert=self.__proxyCertTxt,
                                            usrAttCert=extAttCertTxt)

            except socket.error, e:
                raise CredWalletError("Requesting authorisation: %s" % e[1])
                
            except Exception, e:
                raise CredWalletError("Requesting authorisation: %s" % e)


            # Check the status code returned from the authorisation request
            if resp['statCode'] == 'AccessError':
                raise CredWalletError(str(resp['errMsg']))
            
            elif resp['statCode'] == 'AccessDenied':
                raise CredWalletAuthorisationDenied(\
                            "Authorisation denied: %s" % str(resp['errMsg']))

            elif resp['statCode'] == 'AccessGranted':
                attCertTxt = resp['attCert']

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
                attCertTxt = aa.authorise(\
                                    usrProxyCertFileTxt=self.__proxyCertTxt,
                                    extAttCertFileTxt=extAttCertTxt)
                
            except AttAuthorityAccessDenied, e:
                raise CredWalletAuthorisationDenied(\
                                    "Authorisation denied: %s" % e)
            
            except Exception, e:
                raise CredWalletError("Requesting authorisation: %s" % e)

        else:
            raise CredWalletError("Error requesting authorisation: " + \
                                  "a WSDL file or Attribute Authority " + \
                                  "configuration file must be specified")

        
        # Convert text into Attribute Certificate object
        try:
            attCert = AttCertParse(attCertTxt)
            
        except Exception, e:
            raise CredWalletError("Parsing Attribute Certificate returned " +\
                                  "from authorisation request: %s" % e)
        

        # The Attribute Authority's certificate and it's CA certificate
        # are required in order to verify that the signature is valid.
        # This check is carried out by addCredential()
        try:
            aaCertRec = \
                self.__credRepos.AACertificate.selectBy(dn=attCert['issuer'])
            
        except Exception, e:
            raise CredWalletError("Accessing certificate for %s: %s",
                                                (attCert['issuer'], str(e)))

        if not aaCertRec.count():
            raise CredWalletError("No certificate found in repository " + \
                                  "matching '" + attCert['issuer'] + "'")
        

        # Parse Attribute Authority certificate read from database record
        try:
            aaCert = X509CertParse(aaCertRec[0].cert)

        except Exception, e:
            raise CredWalletError("Attribute Authority Certificate " + \
                                  "returned from authorisation request: " + \
                                  "%s" % e)


        # Search for CA certificate of Attribute Authority
        try:
            # CA Certificates DN is present in Attribute Authority Certificate
            # issuer field
            caCertDN = aaCert.getIssuer().serialise()
            caCertRec = self.__credRepos.AACertificate.selectBy(dn=caCertDN)
            
        except Exception, e:
            raise CredWalletError("Accessing certificate for %s: %s",
                                                (aaCert.getDN(), str(e)))

        if not caCertRec.count():
            raise CredWalletError("No certificate found in repository " + \
                                  "matching '" + aaCert.getDN() + "'")


        # Make temporary store for certificate extracted from database -
        # AttCert class handles certificates via files
        caCertFile = tempfile.NamedTemporaryFile('w', -1, '.pem', 'caCert-')
        open(caCertFile.name, 'w').write(caCertRec[0].cert)

        # Update attribute Certificate ready for validation in addCredential()
        attCert.setCertFilePathList(caCertFile.name)

        
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


    

    def reqAuthorisation(self,
                         reqRole=None,
                         aaWSDL=None,
                         aaPropFilePath=None,
                         bMapFromTrustedHosts=None,
                         bSetExtAttCertList=None,
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

        bMapFromTrustedHosts:   if authorisation fails via the user's proxy
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
                                in self.__bMapFromTrustedHosts is used

        bSetExtAttCertList:     make a list of of certificates
                                from other Attribute Authorities.  If
                                bMapFromTrustedHosts is set True this flag is
                                overriden and effectively set to True.

                                If no value is set, the default value held
                                in self.__bSetExtAttCertList is used
                                
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


        # Check for settings from input, if not set use previous settings
        # made
        if bMapFromTrustedHosts is not None:
            self.__bMapFromTrustedHosts = bMapFromTrustedHosts

        if bSetExtAttCertList is not None:
            self.__bSetExtAttCertList = bSetExtAttCertList


        # Check for external Attribute Certificates
        if extTrustedHostList:
            if not self.__bMapFromTrustedHosts:
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


                if not bMapFromTrustedHosts and not bSetExtAttCertList:
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
                    for i in trustedHostInfo.items():

                        try:
                            extAttCert = self.__reqAuthorisation(\
                                                       aaWSDL=i[1]['wsdl'])

                            # Check the certificate contains at least one of
                            # the required roles
                            roles = extAttCert.getRoles()
                            if [True for r in roles if r in i[1]['role']]:
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


                if not bMapFromTrustedHosts:
                    
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
    """Interface to Credentials Repository Database"""

    # valid configuration property keywords
    __validKeys = ['dbURI']
    

    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Initialise Credentials Repository Database object.

        If the connection string or properties file is set a connection
        will be made

        dbURI:              <db type>://<username>:<passwd>@<hostname>/dbname
        propFilePath: file path to properties file

        Nb. propFilePath setting overrides input dbURI
        """
            
        self.__con = None
        self.__prop = {}
        
        if propFilePath is not None:
            
            # Read database URI set in file
            self.readProperties(propFilePath, dbPPhrase=dbPPhrase)
            
        elif prop != {}:
            
            # Database URI may have been set as an input keyword argument
            self.setProperties(dbPPhrase=dbPPhrase, **prop)




    def __setConnection(self,
                        dbType=None,
                        dbUserName=None,
                        dbPPhrase=None,
                        dbHostname=None,
                        dbName=None,
                        dbURI=None,
                        chkConnection=True):
        """Establish a database connection from a database URI

        pass a URI OR the parameters to construct the URI
            
        dbURI: "<db type>://<username>:<passwd>:<hostname>/dbname"

        or

        dbURI: "<db type>://<username>:%PPHRASE%:<hostname>/dbname"
        + passPhrase

        - %PPHRASE% is substituted with the input passPhrase keyword
        
        or
        
        dbType:         database type e.g. 'mysql'
        dbUserName:     username
        dbPPhrase:      pass-phrase
        dbHostname:     name of host where database resides
        dbName:         name of the database


        chkConnection:  check that the URI is able to connect to the 
        """

        try:
            if dbURI:
                # Check for pass-phrase variable set in URI '%PPHRASE%'
                dbURIspl = dbURI.split('%')
                if len(dbURIspl) == 3:
                    
                    if dbPPhrase is None:
                        raise CredReposError("No database pass-phrase set")
                    
                    dbURI = dbURIspl[0] + dbPPhrase + dbURIspl[2]
                
            else:
                # Construct URI from individual inputs
                dbURI = dbType + '://' + dbUserName + ':' + dbPPhrase + \
                        ':' + dbHostname + '/' + dbName
        except Exception, e:
            # Checking form missing keywords
            raise CredReposError("Error creating database URI: %s" % e)

        try:
            self.__con = connectionForURI(dbURI)
        except Exception, e:
            raise CredReposError("Error creating database connection: %s" % e)

        if chkConnection:
            try:
                self.__con.makeConnection()
            except _mysql_exceptions.OperationalError, (errNum, errMsg):
                raise CredReposError(\
                    "Error connecting to Credential Repository: %s" % errMsg)
                
            except Exception, e:
                raise CredReposError(\
                    "Error connecting to Credential Repository: %s" % e)

            
        # Copy the connection object into the table classes
        CredRepos.User._connection = self.__con
        CredRepos.UserCredential._connection = self.__con
        CredRepos.AACertificate._connection = self.__con
          



    def setProperties(self, dbPPhrase=None, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise CredReposError("Property name \"%s\" is invalid" % key)
                
        self.__prop.update(prop)


        # Update connection setting
        if 'dbURI' in prop:
            self.__setConnection(dbURI=prop['dbURI'],
                                 dbPPhrase=dbPPhrase)
                


        
    def readProperties(self,
                       propFilePath=None,
                       propElem=None,
                       dbPPhrase=None):
        """Read the configuration properties for the CredentialRepository

        propFilePath|propElem

        propFilePath: set to read from the specified file
        propElem:     set to read beginning from a cElementTree node"""

        if propFilePath is not None:

            try:
                tree = ElementTree.parse(propFilePath)
                propElem = tree.getroot()
                
            except IOError, e:
                raise CredReposError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror))

            except Exception, e:
                raise CredReposError("Error parsing properties file: %s" % \
                                    str(e))

        if propElem is None:
            raise CredReposError("Root element for parsing is not defined")


        # Read properties into a dictionary
        prop = dict([(elem.tag, elem.text) for elem in propElem])
        self.setProperties(dbPPhrase=dbPPhrase, **prop)

            

    def addUser(self, userName, dn):
        """A new user to Credentials Repository"""
        try:
            self.User(userName=userName, dn=dn)

        except Exception, e:
            raise CredReposError("Error adding new user '%s': %s" % \
                                                        (userName, e))



                            
    def auditCredentials(self, **attCertValidKeys):
        """Check the attribute certificates held in the repository and delete
        any that have expired

        attCertValidKeys:  keywords which set how to check the Attribute
                            Certificate e.g. check validity time, XML
                            signature, version etc.  Default is check
                            validity time only"""

        if attCertValidKeys == {}:
            # Default to check only the validity time
            attCertValidKeys = {    'chkTime':          True,
                                    'chkVersion':       False,
                                    'chkProvenance':    False,
                                    'chkSig':           False }
            
        try:
            credList = self.UserCredential.select()
            
        except Exception, e:
            raise CredReposError("Selecting credentials from repository: %s",\
                                 e)

        # Iterate through list of credentials deleting records where the
        # certificate is invalid
        try:
            for cred in credList:
                attCert = AttCertParse(cred.attCert)
                
                if not attCert.isValid(**attCertValidKeys):
                    self.UserCredential.delete(cred.id)
                    
        except Exception, e:
            try:
                raise CredReposError("Deleting credentials for '%s': %s",
                                                       (cred.dn, e))
            except:
                raise CredReposError("Deleting credentials: %s", e)




    def getCredentials(self, dn):
        """Get the list of credentials for a given user's DN"""

        try:
            return self.UserCredential.selectBy(dn=dn)
            
        except Exception, e:
            raise CredReposError("Selecting credentials for %s: %s" % (dn, e))



        
    def addCredentials(self, dn, attCertList):
        """Add new attribute certificates for a user.  The user must have
        been previously registered in the repository

        dn:             users Distinguished name
        attCertList:   list of attribute certificates"""
        
        try:
            userCred = self.User.selectBy(dn=dn)
            
            if userCred.count() == 0:
                raise CredReposError("User \"%s\" is not registered" % dn)

        # Make explicit trap for MySQL interface error since it has no error
        # message associated with it
        except _mysql_exceptions.InterfaceError, e:
            raise CredReposError("Checking for user \"%s\": %s" % \
                                 (dn, "MySQL interface error"))
        
        except Exception, e:
            raise CredReposError("Checking for user \"%s\":" % (dn, e))

        
        # Carry out check? - filter out certs in db where a new cert
        # supercedes it - i.e. expires later and has the same roles
        # assigned - May be too complicated to implement
        #uniqAttCertList = [attCert for attCert in attCertList \
        #    if min([attCert == cred.attCert for cred in userCred])]
        
                
        # Update database with new entries
        try:
            for attCert in attCertList:
                self.UserCredential(dn=dn, attCert=attCert.asString())

        except _mysql_exceptions.InterfaceError, e:
            raise CredReposError("Adding new user credentials for " + \
                                 "user %s: %s" % (dn,"MySQL interface error"))
        except Exception, e:
            raise CredReposError("Adding new user credentials for " + \
                                 "user %s: %s" % (dn, e))




    #_________________________________________________________________________
    # Database tables defined using SQLObject derived classes
    # Nb. These are class variables of the CredRepos class
    class User(SQLObject):
        """SQLObject derived class to define Credentials Repository db table
        to store user information"""

        # to be assigned to connectionForURI(<db URI>)
        _connection = None

        # Force table name
        _table = "User"

        userName = StringCol(dbName='userName', length=30)
        dn = StringCol(dbName='dn', length=128)


    class UserCredential(SQLObject):
        """SQLObject derived class to define Credentials Repository db table
        to store user credentials information"""

        # to be assigned to connectionForURI(<db URI>)
        _connection = None

        # Force table name
        _table = "UserCredential"

        
        # User name field binds with UserCredential table
        dn = StringCol(dbName='dn', length=128)

        # Store complete attribute certificate text
        attCert = StringCol(dbName='attCert')


    class AACertificate(SQLObject):
        """SQLObject derived class to define Credentials Repository db table
        to store certificates of recognised Attribute Authorities and their
        CAs as required

        These certificates are needed to check the validity of Attribute
        Certificates when they are granted from Attribute Authorities"""

        # to be assigned to connectionForURI(<db URI>)
        _connection = None

        # Force table name
        _table = "AACertificate"

        
        # Distinguished Name for Attribute Authority
        dn = StringCol(dbName='dn', length=128)

        # Name identifier as it appears in Attribute Certificate issuerName
        # field
        name = StringCol(dbName='name', length=30)

        # Store complete attribute certificate text
        cert = StringCol(dbName='cert')




#_____________________________________________________________________________
class UserSessionError(Exception):    
    """Exception handling for NDG User Session class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
class UserSession(UserDict):
    """Session details - created when a user logs into NDG"""

    # Session ID
    __sessIDlen = 128
    __sessIDtagName = "Hash"

    # Follow standard format for cookie path expiry attributes
    __sessCookieExpiryTagName = "expires"
    __sessCookiePathTagName = "path"
    
    __sessCookiePath = "/"
    __sessCookieExpiryFmt = "%a, %d-%b-%Y %H:%M:%S GMT"


    def __init__(self, *credWalletArgs, **credWalletKeys):

        # Base class initialisation
        UserDict.__init__(self)

        # Each User Session has one or more browser sessions associated with
        # it.  These are stored in a list
        self.__sessID = []
        self.createSessID()
        self.credWallet = CredWallet(*credWalletArgs, **credWalletKeys)



                
    def __repr__(self):
        "Represent User Session"        
        return "<UserSession instance>"

                
    def __delitem__(self, key):
        "UserSession keys cannot be removed"        
        raise UserSessionError('Keys cannot be deleted from ' + \
                               UserSession.__name__)


    def __getitem__(self, key):
        """Enable access to list of session IDs using dictionary like
        behaviour"""
        if key == 'sessID':
            return self.__sessID
        else:
            raise UserSessionError('Key "%s" not recognised' % key)


    def clear(self):
        """Override UserDict default behaviour"""
        raise UserSessionError("Data cannot be cleared from " + \
                               UserSession.__name__)

    
    def copy(self):
        """Override UserDict default behaviour"""
        raise UserSessionError("A copy cannot be made of " + \
                               UserSession.__name__)

    
    def keys(self):
        return ['sessID']


    def items(self):
        return [('sessID', self.__sessID)]


    def values(self):
        return [self.__sessID]


    def createSessID(self):
        """Add a new session ID to be associated with this UserSession
        instance"""

        # base 64 encode output from urandom - raw output from urandom is
        # causes problems when passed over SOAP.  A consequence of this is
        # that the string length of the session ID will almost certainly be
        # longer than SessionMgr.__sessIDlen
        self.__newSessID = base64.b64encode(os.urandom(self.__sessIDlen))
        self.__sessID.append(self.__newSessID)
        

    def newSessID(self):
        """Get the session ID most recently allocated"""
        return self.__newSessID


    def getExpiryStr(self):
        """Return session expiry date/time as would formatted for a cookie"""

        try:
            # Proxy certificate's not after time determines the expiry
            dtNotAfter = self.credWallet['proxyCert'].getNotAfter()

            return dtNotAfter.strftime(self.__sessCookieExpiryFmt)
        except Exception, e:
            UserSessionError("getExpiry: %s" % e)
            
    
    def createCookie(self, sessID=None, asString=True):
        """Create cookie containing session ID and expiry

        sessID:     if no session ID is provided, return the latest one to
                    be allocated.
        asString:   Set to True to return the cookie as string text.  If
                    False, it is returned as a SimpleCookie type."""

        try:
            if sessID is None:
                sessID = self.__sessID[-1]
                
            sessCookie = SimpleCookie()
            sessCookie[self.__sessIDtagName] = sessID

            # Use standard format for cookie path and expiry
            sessCookie[self.__sessIDtagName][self.__sessCookiePathTagName] = \
                                                        self.__sessCookiePath
            
            sessCookie[self.__sessIDtagName][self.__sessCookieExpiryTagName]=\
                                                            self.getExpiryStr()
                                        
            # Make cookie as generic as possible for domains - Nb. '.uk'
            # alone won't work
            sessCookie[self.__sessIDtagName]['domain'] = 'glue.badc.rl.ac.uk'
            
            
            # Caller should set the cookie e.g. in a CGI script
            # print "Content-type: text/html"
            # print cookie.output() + os.linesep
            if asString:
                return sessCookie.output()
            else:
                return sessCookie
            
        except Exception, e:
            UserSessionError("createCookie: %s" % e)




#_____________________________________________________________________________
class SessionMgrError(Exception):    
    """Exception handling for NDG Session Manager class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
class SessionMgrAuthorisationDenied(CredWalletAuthorisationDenied):    
    """Handling exception where authorisation is denied to a session by an
    Attribute Authority."""

    # This class can be an exact copy of the CredWallet equivalent
    pass




#_____________________________________________________________________________
class SessionMgr:
    """NDG authentication and session handling"""

    # valid configuration property keywords
    __validKeys = ['myProxyProp', 'credReposProp']

    
    def __init__(self, propFilePath=None, credReposPPhrase=None, **prop):       
        """Create a new session manager to manager NDG User Sessions"""        

        # MyProxy interface
        try:
            self.__myPx = MyProxy()
            
        except Exception, e:
            raise SessionMgrError("Creating MyProxy interface: %s" % e)

        
        # Credentials repository - permanent stroe of user credentials
        try:
            self.__credRepos = CredRepos()
            
        except Exception, e:
            raise SessionMgrError(\
                    "Creating credentials repository interface: %s" % e)

        self.__sessList = []


        if propFilePath is not None:
            self.readProperties(propFilePath,
                                credReposPPhrase=credReposPPhrase)


            

    def readProperties(self,
                       propFilePath=None,
                       propElem=None,
                       credReposPPhrase=None):
        """Read Session Manager properties from an XML file or cElementTree
        node"""

        if propFilePath is not None:

            try:
                tree = ElementTree.parse(propFilePath)
                propElem = tree.getroot()

            except IOError, e:
                raise SessionMgrError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror))
                
            except Exception, e:
                raise SessionMgrError("Error parsing properties file: %s" % e)

        if propElem is None:
            raise SessionMgrError("Root element for parsing is not defined")

        # Get properties for MyProxy and CredentialRepository
        for elem in propElem:
            if elem.tag == 'myProxyProp':
                self.__myPx.readProperties(propElem=elem)

            if elem.tag == 'credReposProp':
                self.__credRepos.readProperties(propElem=elem,
                                                dbPPhrase=credReposPPhrase)
           



    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise SessionMgrError("Property name \"%s\" is invalid" % key)

        if 'myProxyProp' in prop:
            self.__myPx.setProperties(prop['myProxyProp'])

        if 'credReposProp' in prop:
            self.__credRepos.setProperties(prop['credReposProp'])
            

        
    def addUser(self,
                userName,
                userPassPhrase,
                caConfigFilePath=None,
                caPassPhrase=None):
        
        """Register a new user with NDG"

        userName:                       user name for new user
        
        userPassPhrase:                 selected passphrase for new user
        
        caConfigFilePath|caPassPhrase:  pass phrase for SimpleCA's
                                        certificate.  Set via file or direct
                                        string input respectively.  Set here
                                        to override setting [if any] made at
                                        object creation.
        
                                        Passphrase is only required if
                                        SimpleCA is instantiated on the local
                                        machine.  If SimpleCA WS is called no
                                        passphrase is required."""
        
        try:
            # Add new user certificate to MyProxy Repository
            user = self.__myPx.addUser(userName,
                                       userPassPhrase,
                                       caConfigFilePath=caConfigFilePath,
                                       caPassPhrase=caPassPhrase,
                                       retDN=True)
            
            # Add to user database
            self.__credRepos.addUser(userName, user['dn'])
            
        except Exception, e:
            raise SessionMgrError("Error registering new user: %s" % e)



        
    def connect(self, userName=None, passPhrase=None, sessID=None):        
        """Create and return a new user session or connect to an existing
        one:

        connect([userName, passPhrase]|[sessID])

        userName, passPhrase:   set username and pass-phrase to create a new
                                user session
        sessID:                 give the browser session ID corresponding to
                                an existing session"""
        

        if sessID is not None:
            # Connect to session identified by session ID
            return self.__connect2UserSession(sessID)
        else:
            # Create a fresh session
            return self.__createUserSession(userName, passPhrase)




    def __createUserSession(self, userName, passPhrase):
        """Create a new user session from input user credentials"""
        
        if not userName:
            raise SessionMgrError("Username is null")
        
        if not passPhrase:
            raise SessionMgrError("Passphrase is null")

        
        try:            
            # Get a proxy certificate to represent users ID for the new
            # session
            proxyCert = self.__myPx.getDelegation(userName, passPhrase)

        except Exception, e:
            raise SessionMgrError("MyProxy: %s" % e)

        try:   
            # Search for an existing session for the same user
            userSess = None
            for u in self.__sessList:
                if u.credWallet['proxyCert'].getDN()['CN'] == userName:

                    # Existing session found
                    userSess = u

                    # Replace it's Proxy Certificate with a more up to date
                    # one
                    userSess.credWallet.setProxyCert(proxyCert)
                    break
                

            if userSess is None:
                # Create a new user session using the new proxy certificate
                # and session ID
                userSess = UserSession(proxyCert, credRepos=self.__credRepos)
                
                newSessID = userSess.newSessID()
                
                # Check for unique session ID
                for existingUserSess in self.__sessList:
                    if newSessID in existingUserSess['sessID']:
                        raise SessionMgrError(\
                            "Session ID is not unique:\n\n %s" % newSessID)

                # Add new session to list                 
                self.__sessList.append(userSess)

            return userSess

        except Exception, e:
            raise SessionMgrError("Creating User Session: %s" % e)




    def __connect2UserSession(self, sessID):
        """Connect to an existing session by providing a valid session ID

        sessID: ID corresponding to session to connect to."""
        
            
        # Look for a session corresponding to this ID
        try:
            for userSess in self.__sessList:
                if sessID in userSess['sessID']:

                    # Check matched session has not expired
                    userSess.credWallet.isValid(raiseExcep=True)
                    return userSess
                    
        except Exception, e:
            raise SessionMgrError("User Session: %s" % e)
                        


        # User session not found
        raise SessionMgrError("No user session found with ID: " + sessID)




    def reqAuthorisation(self,
                         userName=None,
                         passPhrase=None,
                         sessID=None,
                         **reqAuthorisationKeys):
        """For given sessID, request authorisation from an Attribute Authority
        given by aaWSDL.  If sucessful, an attribute certificate is
        returned.

        userName, passPhrase:   set username and pass-phrase to create a new
                                user session
        sessID:                 give the browser session ID corresponding to
                                an existing session
        **reqAuthorisationKeys: keywords used by CredWallet.reqAuthorisation
        """

        # Connection keys will make a new session ID or retrieve an existing
        # one
        userSess = self.connect(userName=userName,
                                passPhrase=passPhrase,
                                sessID=sessID)

        # Session's wallet requests authorisation
        try:
            attCert = userSess.credWallet.reqAuthorisation(\
                                                    **reqAuthorisationKeys)        
            return attCert
            
        except CredWalletAuthorisationDenied, e:
            # Raise exception containing list of attribute certificates
            # which could be used to re-try to get authorisation via a mapped
            # certificate
            raise SessionMgrAuthorisationDenied(str(e), e['extAttCertList'])
        
        except Exception, e:
            raise e
    



    def getUserCredentials(self, **connectKeys):
        """Return the Attribute Certificates held by a particular user

        **connectKeys:  userName, passPhrase|sessID for UserSession"""
        return self.connect(**connectKeys)['credentials']



    
    def auditCredRepos(self):
        """Remove expired Attribute Certificates from the Credential
        Repository"""
        self.__credRepos.auditCredentials()



        
def reqAuthorisationTest(userName, passPhrase=None, passPhraseFilePath='tmp'):

    import pdb
    pdb.set_trace()

    try:
        if passPhrase is None:
            passPhrase = open(passPhraseFilePath).read().strip()
            
        # Start session manager
        sessMgr = SessionMgr("./sessionMgrProperties.xml")

        # Create a new session
        userSess = sessMgr.connect(userName, passPhrase)

        # Request authorisation from a data centre
        return sessMgr.reqAuthorisation(\
                            aaWSDL='./attAuthority.wsdl', 
                            #aaPropFilePath='./attAuthorityProperties.xml',
                            sessID=userSess['sessID'][0])

    except Exception, e:
        print str(e)
        



def addUserTest(userName,
                userPassPhrase,
                caConfigFilePath="tmp.txt",
                caPassPhrase=None):

    import pdb
    pdb.set_trace()

    try:
        # Add a new user using the session manager
        sessMgr = SessionMgr("./sessionMgrProperties.xml")
        sessMgr.addUser(userName,
                        userPassPhrase,
                        caConfigFilePath=caConfigFilePath)
        
    except Exception, e:
        print str(e)
