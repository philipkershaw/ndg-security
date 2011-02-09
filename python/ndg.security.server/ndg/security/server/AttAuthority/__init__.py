"""NDG Attribute Authority server side code

handles security user attribute (role) allocation

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/04/05"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import types


# Create unique names for attribute certificates
import tempfile
import os

# Alter system path for dynamic import of user roles class
import sys

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

import logging
log = logging.getLogger(__name__)

# X509 Certificate handling
from ndg.security.common.X509 import *

# NDG Attribute Certificate
from ndg.security.common.AttCert import *


#_____________________________________________________________________________
class AttAuthorityError(Exception):
    """Exception handling for NDG Attribute Authority class."""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)
        

#_____________________________________________________________________________
class AttAuthorityAccessDenied(AttAuthorityError):
    """NDG Attribute Authority - access denied exception.

    Raise from getAttCert method where no roles are available for the user
    but that the request is otherwise valid.  In all other error cases raise
    AttAuthorityError"""   

class AttAuthorityNoTrustedHosts(AttAuthorityError):
    """Raise from getTrustedHosts if there are no trusted hosts defined in
    the map configuration"""

class AttAuthorityNoMatchingRoleInTrustedHosts(AttAuthorityError):
    """Raise from getTrustedHosts if there is no mapping to any of the 
    trusted hosts for the given input role name"""


#_____________________________________________________________________________
class AttAuthority(dict):
    """NDG Attribute Authority - server for allocation of user authorization
    tokens - attribute certificates.
    
    @type __validKeys: dict
    @cvar __validKeys: valid configuration property keywords - properties file
    must contain these
    
    @type __confDir: string
    @cvar __confDir: configuration directory under $NDGSEC_DIR - default location
    for properties file 
    
    @type __propFileName: string
    @cvar __propFileName: default file name for properties file under 
    __confDir
    """

    # Code designed from NERC Data Grid Enterprise and Information Viewpoint
    # documents.
    #
    # Also, draws from Neil Bennett's ACServer class used in the Java
    # implementation of NDG Security

    __confDir = "conf"
    __propFileName = "attAuthorityProperties.xml"
    
    # valid configuration property keywords
    __validKeys = { 'name':                '',
                    'portNum':             -1,
                    'useSSL':              False,
                    'sslCertFile':         '',
                    'sslKeyFile':          '',
                    'sslKeyPwd':           '',
                    'sslCACertDir':        '',
                    'useSignatureHandler': True,
                    'certFile':            '',
                    'keyFile':             '',
                    'keyPwd':              '',
                    'wssRefInclNS':        [],
                    'wssSignedInfoInclNS': [],
                    'caCertFileList':      [],
                    'clntCertFile':        '',
                    'attCertLifetime':     -1,
                    'attCertNotBeforeOff': 0,
                    'attCertFileName':     '',
                    'attCertFileLogCnt':   0,
                    'mapConfigFile':       '',
                    'attCertDir':          '',
                    'dnSeparator':         '',
                    'userRolesModFilePath':'',
                    'userRolesModName':    '',
                    'userRolesClassName':  '',
                    'userRolesPropFile':   ''}
    
    def __init__(self, propFilePath=None, bReadMapConfig=True):
        """Create new NDG Attribute Authority instance

        @type propFilePath: string
        @param propFilePath: path to file containing Attribute Authority
        configuration parameters.  It defaults to $NDGSEC_AA_PROPFILEPATH or
        if not set, $NDGSEC_DIR/conf/attAuthorityProperties.xml
        @type bReadMapConfig: boolean
        @param bReadMapConfig: by default the Map Configuration file is 
        read.  Set this flag to False to override.
        """
        log.info("Initialising service ... ")
        
        # Base class initialisation
        dict.__init__(self)

        # Set from input or use defaults based or environment variables
        self.setPropFilePath(propFilePath)

        # Initialise role mapping look-ups - These are set in readMapConfig()
        self.__mapConfig = None
        self.__localRole2RemoteRole = None
        self.__remoteRole2LocalRole = None


        # Configuration file properties are held together in a dictionary
        self.__prop = {}

        # Read Attribute Authority Properties file
        self.readProperties()

        # Read the Map Configuration file
        if bReadMapConfig:
            self.readMapConfig()

        # Instantiate Certificate object
        log.debug("Reading and checking Attribute Authority X.509 cert. ...")
        self.__cert = X509Cert(self.__prop['certFile'])
        self.__cert.read()

        # Check it's valid
        try:
            self.__cert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttAuthorityError, \
                    "Attribute Authority's certificate is invalid: " + str(e)
        
        # Check CA certificate
        log.debug("Reading and checking X.509 CA certificate ...")
        for caCertFile in self.__prop['caCertFileList']:
            caCert = X509Cert(caCertFile)
            caCert.read()
            
            try:
                caCert.isValidTime(raiseExcep=True)
                
            except Exception, e:
                raise AttAuthorityError,'CA certificate "%s" is invalid: %s'%\
                                        (caCert.dn, e)
        
        # Issuer details - serialise using the separator string set in the
        # properties file
        self.__issuer = \
            self.__cert.dn.serialise(separator=self.__prop['dnSeparator'])

        self.__issuerSerialNumber = self.__cert.serialNumber
        
        
        # Load host sites custom user roles interface to enable the AA to
        # assign roles in an attribute certificate on a getAttCert request
        self.loadUserRolesInterface()


        attCertFilePath = os.path.join(self.__prop['attCertDir'],
                                       self.__prop['attCertFileName'])
                
        # Rotating file handler used for logging attribute certificates 
        # issued.
        self.__attCertLog = AttCertLog(attCertFilePath)
        

    #_________________________________________________________________________
    def loadUserRolesInterface(self):
        """Set-up user roles interface - load host sites custom AAUserRoles
        derived class.  This class interfaces with the sites mechanism for
        mapping user ID to the roles to which they are entitled.  This
        could be via a user database"""

        log.debug("Loading User roles interface ...")
        try:
            try:
                # Module file path may be None if the new module to be loaded
                # can be found in the existing system path            
                if self.__prop['userRolesModFilePath'] is not None:
                    if not os.path.exists(\
                              self.__prop['userRolesModFilePath']):
                        raise Exception, "File path '%s' doesn't exist" % \
                              self.__prop['userRolesModFilePath']
                              
                    # Temporarily extend system path ready for import
                    sysPathBak = sys.path[:]
                              
                    sys.path.append(self.__prop['userRolesModFilePath'])
                
                # Import module name specified in properties file
                userRolesMod = __import__(self.__prop['userRolesModName'],
                                          globals(),
                                          locals(),
                                          [self.__prop['userRolesClassName']])
    
                userRolesClass = eval('userRolesMod.' + \
                                     self.__prop['userRolesClassName'])
            finally:
                try:
                    sys.path[:] = sysPathBak
                except NameError:
                    # sysPathBak may not have been defined
                    pass
                                
        except Exception, e:
            raise AttAuthorityError,'Importing User Roles module: %s' % str(e)

        # Check class inherits from AAUserRoles abstract base class
        if not issubclass(userRolesClass, AAUserRoles):
            raise AttAuthorityError, \
                "User Roles class %s must be derived from AAUserRoles" % \
                self.__prop['userRolesClassName']


        # Instantiate custom class
        try:
            self.__userRoles=userRolesClass(self.__prop['userRolesPropFile'])
            
        except Exception, e:
            raise AttAuthorityError, \
                "Error instantiating User Roles interface: " + str(e)
                
        log.info(\
             'Instantiated "%s" class from user roles module: "%s" in "%s"' %\
                 (self.__prop['userRolesClassName'],
                  self.__prop['userRolesModName'],
                  self.__prop['userRolesModFilePath']))

        
    #_________________________________________________________________________
    # Methods for Attribute Authority dictionary like behaviour        
    def __repr__(self):
        """Return file properties dictionary as representation"""
        return repr(self.__prop)
    
    def __delitem__(self, key):
        self.__class__.__name__ + " keys cannot be removed"        
        raise KeyError, 'Keys cannot be deleted from '+self.__class__.__name__


    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of Attribute
        Authority properties
        """
        if key not in self.__prop:
            raise KeyError, "Invalid key '%s'" % key
        
        return self.__prop[key]
        
    def get(self, kw):
        return self.__prop.get(kw)
    
    def clear(self):
        raise KeyError, "Data cannot be cleared from "+self.__class__.__name__
   
    def keys(self):
        return self.__prop.keys()

    def items(self):
        return self.__prop.items()

    def values(self):
        return self.__prop.values()

    def has_key(self, key):
        return self.__prop.has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return key in self.__prop


    def setPropFilePath(self, val=None):
        """Set properties file from input or based on environment variable
        settings"""
        if not val:
            if 'NDGSEC_AA_PROPFILEPATH' in os.environ:
                val = os.environ['NDGSEC_AA_PROPFILEPATH']
                
            elif 'NDGSEC_DIR' in os.environ:
                val = os.path.join(os.environ['NDGSEC_DIR'], 
                                   self.__class__.__confDir,
                                   self.__class__.__propFileName)
            else:
                raise AttributeError, 'Unable to set default Attribute ' + \
                    'Authority properties file path: neither ' + \
                    '"NDGSEC_AA_PROPFILEPATH" or "NDGSEC_DIR" environment ' + \
                    'variables are set'
                
        if not isinstance(val, basestring):
            raise AttributeError, "Input Properties file path " + \
                                  "must be a valid string."
      
        self.__propFilePath = val
        
    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            doc="Set the path to the properties file")   
    
    
    #_________________________________________________________________________
    def getAttCert(self,
                   userId=None,
                   holderCert=None,
                   holderCertFilePath=None,
                   userAttCert=None,
                   userAttCertFilePath=None):

        """Request a new Attribute Certificate for use in authorisation

        getAttCert([userId=uid][holderCert=px|holderCertFilePath=pxFile, ]
                   [userAttCert=cert|userAttCertFilePath=certFile])
         
        @type userId: string
        @param userId: identifier for the user who is entitled to the roles
        in the certificate that is issued.  If this keyword is omitted, then
        the userId will be set to the DN of the holder.
        
        holder = the holder of the certificate - an inidividual user or an
        organisation to which the user belongs who vouches for that user's ID
        
        userId = the identifier for the user who is entitled to the roles
        specified in the Attribute Certificate that is issued.
                  
        @type holderCert: string / ndg.security.common.X509.X509Cert type
        @param holderCert: base64 encoded string containing proxy cert./
        X.509 cert object corresponding to the ID who will be the HOLDER of
        the Attribute Certificate that will be issued.  - Normally, using
        proxy certificates, the holder and user ID are the same but there
        may be cases where the holder will be an organisation ID.  This is the
        case for NDG security with the DEWS project
        
        @param holderCertFilePath: string
        @param holderCertFilePath: file path to proxy/X.509 certificate of 
        candidate holder
      
        @type userAttCert: string or AttCert type
        @param userAttCert: externally provided attribute certificate from 
        another data centre.  This is only necessary if the user is not 
        registered with this attribute authority. 
                       
        @type userAttCertFilePath: string 
        @param userAttCertFilePath: alternative to userAttCert except pass 
        in as a file path to an attribute certificate instead.
        
        @rtype: AttCert
        @return: new attribute certificate"""

        log.debug("Calling getAttCert ...")
        
        # Read X.509 certificate
        try:            
            if holderCertFilePath is not None:
                                    
                # Certificate input as a file 
                holderCert = X509Cert()
                holderCert.read(holderCertFilePath)
                
            elif isinstance(holderCert, basestring):

                # Certificate input as string text
                holderCert = X509CertParse(holderCert)
                
            elif not isinstance(holderCert, X509Cert):
                raise AttAuthorityError, \
                                "No input file path or cert text/object set"
            
        except Exception, e:
            raise AttAuthorityError, "User X.509 certificate: %s" % e


        # Check certificate hasn't expired
        log.debug("Checking client request X.509 certificate ...")
        try:
            holderCert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttAuthorityError, "User X.509 certificate is invalid: " + \
                                    str(e)

            
        # Get Distinguished name from certificate as an X500DN type
        if not userId:
            try:
                userId = holderCert.dn.serialise(\
                                         separator=self.__prop['dnSeparator']) 
            except Exception, e:
                raise AttAuthorityError, \
                    "Setting user Id from holder certificate DN: %s" % e
       
        # Make a new Attribute Certificate instance passing in certificate
        # details for later signing
        attCert = AttCert()

        # First cert in list corresponds to the private key
        attCert.certFilePathList = [self.__prop['certFile']] + \
                                    self.__prop['caCertFileList']
        
        attCert.signingKeyFilePath = self.__prop['keyFile']
        attCert.signingKeyPwd = self.__prop['keyPwd']
        
        
        # Set holder's (user's) Distinguished Name
        try:
            attCert['holder'] = \
                holderCert.dn.serialise(separator=self.__prop['dnSeparator'])            
        except Exception, e:
            raise AttAuthorityError, "Holder DN: %s" % e

        
        # Set Issuer details from Attribute Authority
        issuerDN = self.__cert.dn
        try:
            attCert['issuer'] = \
                    issuerDN.serialise(separator=self.__prop['dnSeparator'])            
        except Exception, e:
            raise AttAuthorityError, "Issuer DN: %s" % e
        
        attCert['issuerName'] = self.__prop['name']
        attCert['issuerSerialNumber'] = self.__issuerSerialNumber

        attCert['userId'] = userId
        
        # Set validity time
        try:
            attCert.setValidityTime(\
                        lifetime=self.__prop['attCertLifetime'],
                        notBeforeOffset=self.__prop['attCertNotBeforeOff'])

            # Check against the certificate's expiry
            dtHolderCertNotAfter = holderCert.notAfter
            
            if attCert.getValidityNotAfter(asDatetime=True) > \
               dtHolderCertNotAfter:

                # Adjust the attribute certificate's expiry date time
                # so that it agrees with that of the certificate
                # ... but also make ensure that the not before skew is still
                # applied
                attCert.setValidityTime(dtNotAfter=dtHolderCertNotAfter,
                        notBeforeOffset=self.__prop['attCertNotBeforeOff'])
            
        except Exception, e:
            raise AttAuthorityError, "Error setting validity time: %s" % e
        

        # Check name is registered with this Attribute Authority - if no
        # user roles are found, the user is not registered
        userRoles = self.getRoles(userId)
        if userRoles:            
            # Set as an Original Certificate
            #
            # User roles found - user is registered with this data centre
            # Add roles for this user for this data centre
            attCert.addRoles(userRoles)

            # Mark new Attribute Certificate as an original
            attCert['provenance'] = AttCert.origProvenance

        else:            
            # Set as a Mapped Certificate
            #
            # No roles found - user is not registered with this data centre
            # Check for an externally provided certificate from another
            # trusted data centre
            if userAttCertFilePath:
                
                # Read externally provided certificate
                try:
                    userAttCert = AttCertRead(userAttCertFilePath)
                    
                except Exception, e:
                    raise AttAuthorityError, \
                            "Reading external Attribute Certificate: %s" % e                            
            elif userAttCert:
                # Allow input as a string but convert to 
                if isinstance(userAttCert, basestring):
                    userAttCert = AttCertParse(userAttCert)
                    
                elif not isinstance(userAttCert, AttCert):
                    raise AttAuthorityError, \
                        "Expecting userAttCert as a string or AttCert type"          
            else:
                raise AttAuthorityAccessDenied, \
                    "User \"%s\" is not registered and no " % userId + \
                    "external attribute certificate is available to make " + \
                    "a mapping."


            # Check it's an original certificate - mapped certificates can't
            # be used to make further mappings
            if userAttCert.isMapped():
                raise AttAuthorityError, \
                    "External Attribute Certificate must have an " + \
                    "original provenance in order to make further mappings."


            # Check it's valid and signed
            try:
                # Give path to CA cert to allow check
                userAttCert.certFilePathList = self.__prop['caCertFileList']
                userAttCert.isValid(raiseExcep=True)
                
            except Exception, e:
                raise AttAuthorityError, \
                            "Invalid Remote Attribute Certificate: " + str(e)        


            # Check that's it's holder matches the candidate holder 
            # certificate DN
            if userAttCert.holderDN != holderCert.dn:
                raise AttAuthorityError, \
                    "User certificate and Attribute Certificate DNs " + \
                    'don\'t match: "%s" and "%s"' % (holderCert.dn, 
                                                     userAttCert.holderDN)
            
  
            # Get roles from external Attribute Certificate
            trustedHostRoles = userAttCert.roles


            # Map external roles to local ones
            localRoles = self.mapRemoteRoles2LocalRoles(\
                                                    userAttCert['issuerName'],
                                                    trustedHostRoles)
            if not localRoles:
                raise AttAuthorityAccessDenied, \
                    "No local roles mapped to the %s roles: %s" % \
                    (userAttCert['issuerName'], ', '.join(trustedHostRoles))

            attCert.addRoles(localRoles)
            
            
            # Mark new Attribute Certificate as mapped
            attCert.provenance = AttCert.mappedProvenance

            # Copy the user Id from the external AC
            attCert.userId = userAttCert.userId
            
            # End set mapped certificate block

        try:
            # Digitally sign certificate using Attribute Authority's
            # certificate and private key
            attCert.applyEnvelopedSignature()
            
            # Check the certificate is valid
            attCert.isValid(raiseExcep=True)
            
            # Write out certificate to keep a record of it for auditing
            #attCert.write()
            self.__attCertLog.info(attCert)
            
            log.info(\
                 'Issued an Attribute Certificate to "%s" with roles: "%s"' %\
                 (userId, '", "'.join(attCert.roles)))

            # Return the cert to caller
            return attCert
        
        except Exception, e:
            raise AttAuthorityError, "New Attribute Certificate \"%s\": %s" %\
                                    (attCert.filePath, e)
       
        
    #_________________________________________________________________________     
    def readProperties(self):

        """Read the configuration properties for the Attribute Authority.
        Nb. if parameters for the user roles interface change 
        loadUserRolesInterface() must be called explicitly in order for the
        changes to take effect

        @type propFilePath: string
        @param propFilePath: file path to properties file
        """

        log.debug("Calling readProperties ...")
        try:
            tree = ElementTree.parse(self.__propFilePath)
            
        except IOError, ioErr:
            raise AttAuthorityError, \
                                "Error parsing properties file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror)

        
        aaProp = tree.getroot()
        if aaProp is None:
            raise AttAuthorityError, \
            "Parsing properties file \"%s\": root element is not defined" % \
            self.__propFilePath


        # Copy properties from file into a dictionary
        self.__prop = {}
        invalidKeys = []
        try:
            for elem in aaProp:
                if elem.tag in AttAuthority.__validKeys:
                
                    # Make sure to leave password element contents unchanged
                    if isinstance(AttAuthority.__validKeys[elem.tag], list):
                        if len(elem) == 0 and elem.text is not None:
                            # Treat as a list of space separated elements
                            self.__prop[elem.tag] = elem.text.split()
                        else:
                            # Parse from a list of sub-elements
                            self.__prop[elem.tag] = \
                                [os.path.expandvars(subElem.text.strip()) \
                                 for subElem in elem]
                            
                    elif 'eyPwd' not in elem.tag and elem.text: 
                        self.__prop[elem.tag] = \
                                        os.path.expandvars(elem.text.strip())
                    else:
                        self.__prop[elem.tag] = elem.text
                else:
                    invalidKeys.append(elem.tag)
                
        except Exception, e:
            raise AttAuthorityError, \
                "Error parsing tag \"%s\" in properties file \"%s\": %s" % \
                (elem.tag, self.__propFilePath, e)

        if invalidKeys != []:
            raise AttAuthorityError, "The following properties file " + \
                                     "elements are invalid: " + \
                                     ', '.join(invalidKeys)
 
        # Ensure Certificate time parameters are converted to numeric type
        self.__prop['attCertLifetime'] = float(self.__prop['attCertLifetime'])
        self.__prop['attCertNotBeforeOff'] = \
                                    float(self.__prop['attCertNotBeforeOff'])

        # Likewise ...
        self.__prop['portNum'] = int(self.__prop['portNum'])
        self.__prop['attCertFileLogCnt']=int(self.__prop['attCertFileLogCnt'])

        # Check directory path
        try:
            dirList = os.listdir(self.__prop['attCertDir'])

        except OSError, osError:
            raise AttAuthorityError, \
            'Invalid directory path Attribute Certificates store "%s": %s' % \
                (self.__prop['attCertDir'], osError.strerror)

        log.info('Loaded properties from "%s"' % self.__propFilePath)
        
        
    #_________________________________________________________________________     
    def readMapConfig(self, mapConfigFilePath=None):
        """Parse Map Configuration file.

        @type mapConfigFilePath: string
        @param mapConfigFilePath: file path for map configuration file.  If 
        omitted, it uses member variable __prop['mapConfigFile'].
        """
        
        log.debug("Reading map configuration file ...")
        
        if mapConfigFilePath is not None:
            if not isinstance(mapConfigFilePath, basestring):
                raise AttAuthorityError, \
                "Input Map Configuration file path must be a valid string."
            
            self.__prop['mapConfigFile'] = mapConfigFilePath


        try:
            tree = ElementTree.parse(self.__prop['mapConfigFile'])
            rootElem = tree.getroot()
            
        except IOError, e:
            raise AttAuthorityError, \
                            "Error parsing properties file \"%s\": %s" % \
                            (e.filename, e.strerror)           
        except Exception, e:
            raise AttAuthorityError, \
                "Error parsing Map Configuration file: \"%s\": %s" % \
                (self.__prop['mapConfigFile'], e)

            
        trustedElem = rootElem.findall('trusted')
        if not trustedElem: 
            # Make an empty list so that for loop block below is skipped 
            # without an error  
            trustedElem = ()

        # Dictionaries:
        # 1) to hold all the data
        self.__mapConfig = {'thisHost': {}, 'trustedHosts': {}}

        # ... look-up
        # 2) hosts corresponding to a given role and
        # 3) roles of external data centre to this data centre
        self.__localRole2TrustedHost = {}
        self.__localRole2RemoteRole = {}
        self.__remoteRole2LocalRole = {}


        # Information about this host
        try:
            thisHostElem = rootElem.findall('thisHost')[0]
            
        except Exception, e:
            raise AttAuthorityError, \
            "\"thisHost\" tag not found in Map Configuration file \"%s\"" % \
            self.__prop['mapConfigFile']

        try:
            hostName = thisHostElem.attrib.values()[0]
            
        except Exception, e:
            raise AttAuthorityError, "\"name\" attribute of \"thisHost\" " + \
                    "element not found in Map Configuration file \"%s\"" % \
                    self.__prop['mapConfigFile']


        # hostname is also stored in the AA's config file in the 'name' tag.  
        # Check the two match as the latter is copied into Attribute 
        # Certificates issued by this AA
        #
        # TODO: would be better to rationalise this so that the hostname is 
        # stored in one place only.
        #
        # P J Kershaw 14/06/06
        if hostName != self.__prop['name']:
            raise AttAuthorityError, "\"name\" attribute of \"thisHost\" " + \
                "element in Map Configuration file doesn't match " + \
                "\"name\" element in properties file."
        
        # Information for THIS Attribute Authority
        hostDict = {}.fromkeys(('aaURI',
                                'aaDN',
                                'loginURI',
                                'loginServerDN',
                                'loginRequestServerDN'))
        self.__mapConfig['thisHost'][hostName] = hostDict.copy()
        for k in self.__mapConfig['thisHost'][hostName]:
            self.__mapConfig['thisHost'][hostName][k]=thisHostElem.findtext(k)
        
        # Information about trusted hosts
        for elem in trustedElem:
            try:
                trustedHost = elem.attrib.values()[0]
                
            except Exception, e:
                raise AttAuthorityError, \
                                    "Error reading trusted host name: %s" % e

            
            # Add signatureFile and list of roles
            #
            # (Currently Optional) additional tag allows query of the URI
            # where a user would normally login at the trusted host.  Added
            # this feature to allow users to be forwarded to their home site
            # if they are accessing a secure resource and are not 
            # authenticated
            #
            # P J Kershaw 25/05/06
            self.__mapConfig['trustedHosts'][trustedHost] = hostDict.copy()
            for k in self.__mapConfig['trustedHosts'][trustedHost]:
                self.__mapConfig['trustedHosts'][trustedHost][k] = \
                                                        elem.findtext(k)   

            roleElem = elem.findall('role')
            if roleElem:
                # Role keyword value requires special parsing before 
                # assignment
                self.__mapConfig['trustedHosts'][trustedHost]['role'] = \
                                        [dict(i.items()) for i in roleElem]
            else:
                # It's possible for trust relationships to not contain any 
                # role mapping.  e.g. a site's login service trusting other
                # sites login requests
                self.__mapConfig['trustedHosts'][trustedHost]['role'] = []
                       
            self.__localRole2RemoteRole[trustedHost] = {}
            self.__remoteRole2LocalRole[trustedHost] = {}
            
            for role in self.__mapConfig['trustedHosts'][trustedHost]['role']:
                try:
                    localRole = role['local']
                    remoteRole = role['remote']
                except KeyError, e:
                    raise AttAuthorityError, \
            'Reading map config file "%s": no element "%s" for host "%s"' % \
                        (self.__prop['mapConfigFile'], e, trustedHost)
                    
                # Role to host look-up
                if localRole in self.__localRole2TrustedHost:
                    
                    if trustedHost not in \
                       self.__localRole2TrustedHost[localRole]:
                        self.__localRole2TrustedHost[localRole].\
                                                        append(trustedHost)                        
                else:
                    self.__localRole2TrustedHost[localRole] = [trustedHost]


                # Trusted Host to local role and trusted host to trusted role
                # map look-ups
                try:
                    self.__remoteRole2LocalRole[trustedHost][remoteRole].\
                                                            append(localRole)                  
                except KeyError:
                    self.__remoteRole2LocalRole[trustedHost][remoteRole] = \
                                                                [localRole]
                    
                try:
                    self.__localRole2RemoteRole[trustedHost][localRole].\
                                                            append(remoteRole)                  
                except KeyError:
                    self.__localRole2RemoteRole[trustedHost][localRole] = \
                                                                [remoteRole]                  
        log.info('Loaded map configuration file "%s"' % \
                 self.__prop['mapConfigFile'])

       
    #_________________________________________________________________________     
    def userIsRegistered(self, userId):
        """Check a particular user is registered with the Data Centre that the
        Attribute Authority represents
        
        Nb. this method is not used internally by AttAuthority class and is
        not a required part of the AAUserRoles API
        
        @type userId: string 
        @param userId: user identity - could be a X500 Distinguished Name
        @rtype: bool
        @return: True if user is registered, False otherwise"""
        log.debug("Calling userIsRegistered ...")
        return self.__userRoles.userIsRegistered(userId)
       
        
    #_________________________________________________________________________     
    def getRoles(self, userId):
        """Get the roles available to the registered user identified userId.

        @type dn: string 
        @param dn: user identifier - could be a X500 Distinguished Name
        @return: list of roles for the given user ID"""

        log.debug('Calling getRoles for user "%s" ...' % userId)
        
        # Call to AAUserRoles derived class.  Each Attribute Authority
        # should define it's own roles class derived from AAUserRoles to
        # define how roles are accessed
        try:
            return self.__userRoles.getRoles(userId)

        except Exception, e:
            raise AttAuthorityError, "Getting user roles: %s" % e
       
        
    #_________________________________________________________________________     
    def __getHostInfo(self):
        """Return the host that this Attribute Authority represents: its ID,
        the user login URI and WSDL address.  Call this method via the
        'hostInfo' property
        
        @rtype: dict
        @return: dictionary of host information derived from the map 
        configuration"""
        
        return self.__mapConfig['thisHost']
        
    hostInfo = property(fget=__getHostInfo, 
                        doc="Return information about this host")
       
        
    #_________________________________________________________________________     
    def getTrustedHostInfo(self, role=None):
        """Return a dictionary of the hosts that have trust relationships
        with this AA.  The dictionary is indexed by the trusted host name
        and contains AA service, login URIs and the roles that map to the
        given input local role.

        @type role: string
        @param role: if set, return trusted hosts that having a mapping set 
        for this role.  If no role is input, return all the AA's trusted hosts 
        with all their possible roles

        @rtype: dict
        @return: dictionary of the hosts that have trust relationships
        with this AA.  It returns an empty dictionary if role isn't 
        recognised"""
               
        log.debug('Calling getTrustedHostInfo with role = "%s" ...' % role) 
                                 
        if not self.__mapConfig or not self.__localRole2RemoteRole:
            # This Attribute Authority has no trusted hosts
            raise AttAuthorityNoTrustedHosts, \
                "The %s Attribute Authority has no trusted hosts" % \
                self.__prop['name']


        if role is None:
            # No role input - return all trusted hosts with their WSDL URIs
            # and the remote roles they map to
            #
            # Nb. {}.fromkeys([...]).keys() is a fudge to get unique elements
            # from a list i.e. convert the list elements to a dict eliminating
            # duplicated elements and convert the keys back into a list.
            trustedHostInfo = dict(\
            [\
                (\
                    k, \
                    {
                        'aaURI':                v['aaURI'], \
                        'aaDN':                 v['aaDN'], \
                        'loginURI':             v['loginURI'], \
                        'loginServerDN':        v['loginServerDN'], \
                        'loginRequestServerDN': v['loginRequestServerDN'], \
                        'role':        {}.fromkeys(\
                            [role['remote'] for role in v['role']]\
                        ).keys()
                    }
                ) for k, v in self.__mapConfig['trustedHosts'].items()
            ])

        else:           
            # Get trusted hosts for given input local role        
            try:
                trustedHosts = self.__localRole2TrustedHost[role]
            except:
                raise AttAuthorityNoMatchingRoleInTrustedHosts, \
                    'None of the trusted hosts have a mapping to the ' + \
                    'input role "%s"' % role
    
    
            # Get associated WSDL URI and roles for the trusted hosts 
            # identified and return as a dictionary indexed by host name
            trustedHostInfo = dict(\
   [(\
        host, \
        {
            'aaURI': self.__mapConfig['trustedHosts'][host]['aaURI'],
            'aaDN': self.__mapConfig['trustedHosts'][host]['aaDN'],
            'loginURI': self.__mapConfig['trustedHosts'][host]['loginURI'],
            'loginServerDN': \
            self.__mapConfig['trustedHosts'][host]['loginServerDN'],
            'loginRequestServerDN': \
            self.__mapConfig['trustedHosts'][host]['loginRequestServerDN'],
            'role': self.__localRole2RemoteRole[host][role]
        }\
    ) for host in trustedHosts])
                         
        return trustedHostInfo
       
        
    #_________________________________________________________________________     
    def mapRemoteRoles2LocalRoles(self, trustedHost, trustedHostRoles):
        """Map roles of trusted hosts to roles for this data centre

        @type trustedHost: string
        @param trustedHost: name of external trusted data centre
        @type trustedHostRoles: list
        @param trustedHostRoles:   list of external roles to map
        @return: list of mapped roles"""

        if not self.__remoteRole2LocalRole:
            raise AttAuthorityError, "Roles map is not set - ensure " + \
                                     "readMapConfig() has been called."


        # Check the host name is a trusted one recorded in the map
        # configuration
        if not self.__remoteRole2LocalRole.has_key(trustedHost):
            return []

        # Add local roles, skipping if no mapping is found
        localRoles = []
        for trustedRole in trustedHostRoles:
            if trustedRole in self.__remoteRole2LocalRole[trustedHost]:
                localRoles.extend(\
                        self.__remoteRole2LocalRole[trustedHost][trustedRole])
                
        return localRoles


#_____________________________________________________________________________
from logging.handlers import RotatingFileHandler

#_________________________________________________________________________
# Inherit directly from Logger
_loggerClass = logging.getLoggerClass()
class AttCertLog(_loggerClass, object):
    """Log each Attribute Certificate issued using a rotating file handler
    so that the number of files held can be managed"""
    
    def __init__(self, attCertFilePath, backUpCnt=1024):
        """Set up a rotating file handler to log ACs issued.
        @type attCertFilePath: string
        @param attCertFilePath: set where to store ACs.  Set from AttAuthority
        properties file.
        
        @type backUpCnt: int
        @param backUpCnt: set the number of files to store before rotating
        and overwriting old files."""
        
        # Inherit from Logger class
        super(AttCertLog, self).__init__(name='', level=logging.INFO)
                            
        # Set a format for messages so that only the content of the AC is
        # logged, nothing else.
        formatter = logging.Formatter(fmt="", datefmt="")

        # maxBytes is set to one so that only one AC will be written before 
        # rotation to the next file
        fileLog = RotatingFileHandler(attCertFilePath, 
                                      maxBytes=1, 
                                      backupCount=backUpCnt)
        fileLog.setFormatter(formatter)            
        self.addHandler(fileLog)
                       
#_____________________________________________________________________________
class AAUserRolesError(Exception):
    """Exception handling for NDG Attribute Authority User Roles interface
    class."""


#_____________________________________________________________________________
class AAUserRoles:
    """An abstract base class to define the user roles interface to an
    Attribute Authority.

    Each NDG data centre should implement a derived class which implements
    the way user roles are provided to its representative Attribute Authority.
    
    Roles are expected to indexed by user Distinguished Name (DN).  They
    could be stored in a database or file."""

    # User defined class may wish to specify a URI for a database interface or
    # path for a user roles configuration file
    def __init__(self, dbURI=None, filePath=None):
        """User Roles base class - derive from this class to define
        roles interface to Attribute Authority
        
        @type dbURI: string
        @param dbURI: database connection URI
        @type filePath: string
        @param filePath: file path for properties file containing settings
        """
        pass


    def userIsRegistered(self, userId):
        """Virtual method - Derived method should return True if user is known
        otherwise False
        
        Nb. this method is not used by AttAuthority class and so does NOT need 
        to be implemented in a derived class.
        
        @type userId: string 
        @param userId: user Distinguished Name to look up.
        @rtype: bool
        @return: True if user is registered, False otherwise"""
        raise NotImplementedError, \
            self.userIsRegistered.__doc__.replace('\n       ','')


    def getRoles(self, userId):
        """Virtual method - Derived method should return the roles for the 
        given user's Id or else raise an exception
        
        @type userId: string 
        @param userId: user identity e.g. user Distinguished Name
        @rtype: list
        @return: list of roles for the given user ID"""
        raise NotImplementedError, \
            self.getRoles.__doc__.replace('\n       ','')
                         