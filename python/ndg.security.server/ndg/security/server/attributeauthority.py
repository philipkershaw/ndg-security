"""NDG Attribute Authority server side code

handles security user attribute (role) allocation

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/04/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:attributeauthority.py 4367 2008-10-29 09:27:59Z pjkersha $'

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
from ndg.security.common.X509 import X509Cert

# NDG Attribute Certificate
from ndg.security.common.AttCert import AttCert, AttCertRead, AttCertParse

from ndg.security.common.utils.configfileparsers import \
    readAndValidateProperties
from ndg.security.common.utils.classfactory import instantiateClass

class AttributeAuthorityError(Exception):
    """Exception handling for NDG Attribute Authority class."""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)

class AttributeAuthorityConfigError(Exception):
    """NDG Attribute Authority error with configuration. e.g. properties file
    directory permissions or role mapping file"""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)
        
class AttributeAuthorityAccessDenied(AttributeAuthorityError):
    """NDG Attribute Authority - access denied exception.

    Raise from getAttCert method where no roles are available for the user
    but that the request is otherwise valid.  In all other error cases raise
    AttributeAuthorityError"""   

class AttributeAuthorityNoTrustedHosts(AttributeAuthorityError):
    """Raise from getTrustedHosts if there are no trusted hosts defined in
    the map configuration"""

class AttributeAuthorityNoMatchingRoleInTrustedHosts(AttributeAuthorityError):
    """Raise from getTrustedHosts if there is no mapping to any of the 
    trusted hosts for the given input role name"""


class AttributeAuthority(dict):
    """NDG Attribute Authority - service for allocation of user authorization
    tokens - attribute certificates.
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: valid configuration property keywords - properties file
    must contain these
    
    @type _confDir: string
    @cvar _confDir: configuration directory under $NDGSEC_DIR - default 
    location for properties file 
    
    @type _propFileName: string
    @cvar _propFileName: default file name for properties file under 
    _confDir
    """

    # Code designed from NERC Data Grid Enterprise and Information Viewpoint
    # documents.
    #
    # Also, draws from Neil Bennett's ACServer class used in the Java
    # implementation of NDG Security

    _confDir = "conf"
    _propFileName = "attributeAuthority.cfg"
    
    # valid configuration property keywords with accepted default values.  
    # Values set to not NotImplemented here denote keys which must be specified
    # in the config
    propertyDefaults = { 
        'name':                '',
        'portNum':             -1,
        'useSSL':              False,
        'sslCertFile':         '',
        'sslKeyFile':          '',
        'sslKeyPwd':           '',
        'sslCACertDir':        '',
        'signingCertFilePath': NotImplemented,
        'signingPriKeyFilePath':NotImplemented,
        'signingPriKeyPwd':    None,
        'caCertFilePathList':  [NotImplemented],
        'attCertLifetime':     -1,
        'attCertNotBeforeOff': 0,
        'attCertFileName':     NotImplemented,
        'attCertFileLogCnt':   0,
        'mapConfigFile':       NotImplemented,
        'attCertDir':          NotImplemented,
        'dnSeparator':         '/',
        'userRolesModFilePath':'',
        'userRolesModName':    NotImplemented,
        'userRolesClassName':  NotImplemented,
        'userRolesPropFile':   ''
    }
    
    mapConfigHostDefaults = {
        'siteName':                 None,
        'aaURI':                    NotImplemented,
        'aaDN':                     NotImplemented,
        'loginURI':                 NotImplemented,
        'loginServerDN':            NotImplemented,
        'loginRequestServerDN':     NotImplemented
    }

    def __init__(self, 
                 propFilePath=None, 
                 propFileSection='DEFAULT',
                 propPrefix='',
                 bReadMapConfig=True):
        """Create new NDG Attribute Authority instance

        @type propFilePath: string
        @param propFilePath: path to file containing Attribute Authority
        configuration parameters.  It defaults to $NDGSEC_AA_PROPFILEPATH or
        if not set, $NDGSEC_DIR/conf/attributeAuthority.cfg
        - if the filename ends with 'xml', it is assumed to be in the xml 
        format
        - otherwise it is assumed to be a flat text 'ini' type file
        @type propFileSection: basestring
        @param propFileSection: section of properties file to read from.  This
        applies to ini format files only and is ignored for XML format
        properties files
        @type bReadMapConfig: boolean
        @param bReadMapConfig: by default the Map Configuration file is 
        read.  Set this flag to False to override.
        """
        log.info("Initialising service ...")
        
        # Base class initialisation
        dict.__init__(self)

        # Set from input or use defaults based or environment variables
        self.propFilePath = propFilePath
        
        self.propFileSection = propFileSection
        self.propPrefix = propPrefix
        
        # Initialise role mapping look-ups - These are set in readMapConfig()
        self._mapConfig = None
        self._localRole2RemoteRole = None
        self._remoteRole2LocalRole = None

        self.readProperties()

        # Read the Map Configuration file
        if bReadMapConfig:
            self.readMapConfig()

        # Instantiate Certificate object
        log.debug("Reading and checking Attribute Authority X.509 cert. ...")
        self.__cert = X509Cert.Read(self._prop['signingCertFilePath'])

        # Check it's valid
        try:
            self.__cert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttributeAuthorityError("Attribute Authority's certificate "
                                          "is invalid: %s" % e)
        
        # Check CA certificate
        log.debug("Reading and checking X.509 CA certificate ...")
        for caCertFile in self._prop['caCertFilePathList']:
            caCert = X509Cert(caCertFile)
            caCert.read()
            
            try:
                caCert.isValidTime(raiseExcep=True)
                
            except Exception, e:
                raise AttributeAuthorityError('CA certificate "%s" is invalid: %s'%\
                                        (caCert.dn, e))
        
        # Issuer details - serialise using the separator string set in the
        # properties file
        self.__issuer = \
            self.__cert.dn.serialise(separator=self._prop['dnSeparator'])

        self.__issuerSerialNumber = self.__cert.serialNumber
        
        # Load host sites custom user roles interface to enable the AA to
        # assign roles in an attribute certificate on a getAttCert request
        self.__userRoles = instantiateClass(self._prop['userRolesModName'],
                     self._prop['userRolesClassName'],
                     moduleFilePath=self._prop.get('userRolesModFilePath'),
                     objectType=AAUserRoles,
                     classProperties=self._prop.get('userRolesPropFile'))

        attCertFilePath = os.path.join(self._prop['attCertDir'],
                                       self._prop['attCertFileName'])
                
        # Rotating file handler used for logging attribute certificates 
        # issued.
        self._attCertLog=AttCertLog(attCertFilePath,
                                    backUpCnt=self._prop['attCertFileLogCnt'])


    def readProperties(self, section=None, prefix=None):
        '''Read the properties files and do some checking/converting of input 
        values
        
        @type section: basestring
        @param section: ini file section to read properties from - doesn't 
        apply to XML format properties files.  section setting defaults to 
        current propFileSection attribute
        
        @type prefix: basestring
        @param prefix: apply prefix to ini file properties - doesn't 
        apply to XML format properties files.  This enables filtering of
        properties so that only those relevant to this class are read in
        '''
        if section is None:
            section = self.propFileSection
        
        if prefix is None:
            prefix = self.propPrefix
              
        # Configuration file properties are held together in a dictionary
        fileProp = readAndValidateProperties(self.propFilePath, 
                                 validKeys=AttributeAuthority.propertyDefaults,
                                 prefix=prefix,
                                 sections=(section,))
        
        # Allow for section and prefix names which will nest the Attribute
        # Authority properties in a hierarchy
        propBranch = fileProp
        if section != 'DEFAULT':
            propBranch = propBranch[section]
            
        self._prop = propBranch
        
        # Ensure Certificate time parameters are converted to numeric type
        self._prop['attCertLifetime'] = float(self._prop['attCertLifetime'])
        self._prop['attCertNotBeforeOff'] = \
                                    float(self._prop['attCertNotBeforeOff'])

        # Check directory path
        try:
            dirList = os.listdir(self._prop['attCertDir'])

        except OSError, osError:
            raise AttributeAuthorityConfigError('Invalid directory path for '
                                                'Attribute Certificates store '
                                                '"%s": %s' % 
                                                (self._prop['attCertDir'], 
                                                 osError.strerror))

        
    # Methods for Attribute Authority dictionary like behaviour        
    def __repr__(self):
        """Return file properties dictionary as string"""
        return repr(self._prop)
    
    def __delitem__(self, key):
        AttributeAuthority.__name__ + " keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from '+AttributeAuthority.__name__)


    def __getitem__(self, key):
        AttributeAuthority.__name__ + """ behaves as data dictionary of Attribute
        Authority properties
        """
        if key not in self._prop:
            raise KeyError("Invalid key '%s'" % key)
        
        return self._prop[key]
        
    def get(self, kw):
        return self._prop.get(kw)
    
    def clear(self):
        raise KeyError("Data cannot be cleared from "+AttributeAuthority.__name__)
   
    def keys(self):
        return self._prop.keys()

    def items(self):
        return self._prop.items()

    def values(self):
        return self._prop.values()

    def has_key(self, key):
        return self._prop.has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return key in self._prop


    def setPropFilePath(self, val=None):
        """Set properties file from input or based on environment variable
        settings
        
        @type val: basestring
        @param val: properties file path"""
        log.debug("Setting property file path")
        if not val:
            if 'NDGSEC_AA_PROPFILEPATH' in os.environ:
                val = os.environ['NDGSEC_AA_PROPFILEPATH']
                
            elif 'NDGSEC_DIR' in os.environ:
                val = os.path.join(os.environ['NDGSEC_DIR'], 
                                   AttributeAuthority._confDir,
                                   AttributeAuthority._propFileName)
            else:
                raise AttributeError('Unable to set default Attribute '
                                     'Authority properties file path: neither '
                                     '"NDGSEC_AA_PROPFILEPATH" or "NDGSEC_DIR"'
                                     ' environment variables are set')
                
        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file path "
                                 "must be a valid string.")
      
        self._propFilePath = os.path.expandvars(val)
        log.debug("Path set to: %s" % val)
        
    def getPropFilePath(self):
        '''Get the properties file path
        
        @rtype: basestring
        @return: properties file path'''
        log.debug("Getting property file path")
        if hasattr(self, '_propFilePath'):
            return self._propFilePath
        else:
            return ""
        
    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            fget=getPropFilePath,
                            doc="Set the path to the properties file")   
    
    def setPropFileSection(self, val=None):
        """Set section name to read properties from ini file.  This is set from
        input or based on environment variable setting 
        NDGSEC_AA_PROPFILESECTION
        
        @type val: basestring
        @param val: section name"""
        log.debug("Setting property file section name")
        if not val:
            val = os.environ.get('NDGSEC_AA_PROPFILESECTION', 'DEFAULT')
                
        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file section name "
                                 "must be a valid string.")
      
        self._propFileSection = val
        log.debug("Properties file section set to: %s" % val)
        
    def getPropFileSection(self):
        '''Get the section name to extract properties from an ini file -
        DOES NOT apply to XML file properties
        
        @rtype: basestring
        @return: section name'''
        log.debug("Getting property file section name")
        if hasattr(self, '_propFileSection'):
            return self._propFileSection
        else:
            return ""    
        
    # Also set up as a property
    propFileSection = property(fset=setPropFileSection,
                    fget=getPropFileSection,
                    doc="Set the file section name for ini file properties")   
    
    def setPropPrefix(self, val=None):
        """Set prefix for properties read from ini file.  This is set from
        input or based on environment variable setting 
        NDGSEC_AA_PROPFILEPREFIX
        
        DOES NOT apply to XML file properties
        
        @type val: basestring
        @param val: section name"""
        log.debug("Setting property file section name")
        if val is None:
            val = os.environ.get('NDGSEC_AA_PROPFILEPREFIX', 'DEFAULT')
                
        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file section name "
                                 "must be a valid string.")
      
        self._propPrefix = val
        log.debug("Properties file section set to: %s" % val)
        
    def getPropPrefix(self):
        '''Get the prefix name used for properties in an ini file -
        DOES NOT apply to XML file properties
        
        @rtype: basestring
        @return: section name'''
        log.debug("Getting property file prefix")
        if hasattr(self, '_propPrefix'):
            return self._propPrefix
        else:
            return ""    
        
    # Also set up as a property
    propPrefix = property(fset=setPropPrefix,
                          fget=getPropPrefix,
                          doc="Set a prefix for ini file properties")   

    def getAttCert(self,
                   userId=None,
                   holderX509Cert=None,
                   holderX509CertFilePath=None,
                   userAttCert=None,
                   userAttCertFilePath=None):

        """Request a new Attribute Certificate for use in authorisation

        getAttCert([userId=uid][holderX509Cert=x509Cert|
                    holderX509CertFilePath=x509CertFile, ]
                   [userAttCert=cert|userAttCertFilePath=certFile])
         
        @type userId: string
        @param userId: identifier for the user who is entitled to the roles
        in the certificate that is issued.  If this keyword is omitted, then
        the userId will be set to the DN of the holder.
        
        holder = the holder of the certificate - an inidividual user or an
        organisation to which the user belongs who vouches for that user's ID
        
        userId = the identifier for the user who is entitled to the roles
        specified in the Attribute Certificate that is issued.
                  
        @type holderX509Cert: string / ndg.security.common.X509.X509Cert type
        @param holderX509Cert: base64 encoded string containing proxy cert./
        X.509 cert object corresponding to the ID who will be the HOLDER of
        the Attribute Certificate that will be issued.  - Normally, using
        proxy certificates, the holder and user ID are the same but there
        may be cases where the holder will be an organisation ID.  This is the
        case for NDG security with the DEWS project
        
        @param holderX509CertFilePath: string
        @param holderX509CertFilePath: file path to proxy/X.509 certificate of 
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
        
        # Read candidate Attribute Certificate holder's X.509 certificate
        try:
            if holderX509CertFilePath is not None:
                                    
                # Certificate input as a file 
                holderX509Cert = X509Cert()
                holderX509Cert.read(holderX509CertFilePath)
                
            elif isinstance(holderX509Cert, basestring):

                # Certificate input as string text
                holderX509Cert = X509Cert.Parse(holderX509Cert)
                
            elif not isinstance(holderX509Cert, (X509Cert, None.__class__)):
                raise AttributeAuthorityError("Holder X.509 Certificate must "
                                              "be set to valid type: a file "
                                              "path, string, X509 object or "
                                              "None")            
        except Exception, e:
            log.error("Holder X.509 certificate: %s" % e)
            raise


        # Check certificate hasn't expired
        if holderX509Cert:
            log.debug("Checking candidate holder X.509 certificate ...")
            try:
                holderX509Cert.isValidTime(raiseExcep=True)
                
            except Exception, e:
                log.error("User X.509 certificate is invalid: " + e)
                raise

            
        # If no user ID is input, set id from holder X.509 certificate DN
        # instead
        if not userId:
            if not holderX509Cert:
                raise AttributeAuthorityError("If no user ID is set a holder "
                                              "X.509 certificate must be "
                                              "present")
            try:
                userId = holderX509Cert.dn.serialise(\
                                         separator=self._prop['dnSeparator']) 
            except Exception, e:
                log.error("Setting user Id from holder certificate DN: %s" % e)
                raise
       
        # Make a new Attribute Certificate instance passing in certificate
        # details for later signing
        attCert = AttCert()

        # First certificate in list contains the public key corresponding to 
        # the private key
        attCert.certFilePathList = [self._prop['signingCertFilePath']] + \
         							self._prop['caCertFilePathList']
             
        # Check for expiry of each certificate                   
        for x509Cert in attCert.certFilePathList:
            X509Cert.Read(x509Cert).isValidTime(raiseExcep=True)
         							
        attCert.signingKeyFilePath = self._prop['signingPriKeyFilePath']
        attCert.signingKeyPwd = self._prop['signingPriKeyPwd']
        
        
        # Set holder's Distinguished Name if a holder X.509 certificate was 
        # input 
        if holderX509Cert:
            try:
                attCert['holder'] = holderX509Cert.dn.serialise(
                                        separator=self._prop['dnSeparator'])            
            except Exception, e:
                 log.error("Holder X.509 Certificate DN: %s" % e)
                 raise
            
        # Set Issuer details from Attribute Authority
        issuerDN = self.__cert.dn
        try:
            attCert['issuer'] = \
                    issuerDN.serialise(separator=self._prop['dnSeparator'])            
        except Exception, e:
            log.error("Issuer X.509 Certificate DN: %s" % e)
            raise 
           
        attCert['issuerName'] = self._prop['name']
        attCert['issuerSerialNumber'] = self.__issuerSerialNumber

        attCert['userId'] = userId
        
        # Set validity time
        try:
            attCert.setValidityTime(
                        lifetime=self._prop['attCertLifetime'],
                        notBeforeOffset=self._prop['attCertNotBeforeOff'])

            # Check against the holder X.509 certificate's expiry if set
            if holderX509Cert:
                dtHolderCertNotAfter = holderX509Cert.notAfter
                
                if attCert.getValidityNotAfter(asDatetime=True) > \
                   dtHolderCertNotAfter:
    
                    # Adjust the attribute certificate's expiry date time
                    # so that it agrees with that of the certificate
                    # ... but also make ensure that the not before skew is 
                    # still applied
                    attCert.setValidityTime(dtNotAfter=dtHolderCertNotAfter,
                            notBeforeOffset=self._prop['attCertNotBeforeOff'])
            
        except Exception, e:
            log.error("Error setting attribute certificate validity time: %s" %
                      e)
            raise 

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
                    raise AttributeAuthorityError("Reading external Attribute "
                                                  "Certificate: %s" % e)                           
            elif userAttCert:
                # Allow input as a string but convert to 
                if isinstance(userAttCert, basestring):
                    userAttCert = AttCertParse(userAttCert)
                    
                elif not isinstance(userAttCert, AttCert):
                    raise AttributeAuthorityError(
                        "Expecting userAttCert as a string or AttCert type")        
            else:
                raise AttributeAuthorityAccessDenied('User "%s" is not '
                    'registered and no external attribute certificate is '
                    'available to make a mapping.' % userId)


            # Check it's an original certificate - mapped certificates can't
            # be used to make further mappings
            if userAttCert.isMapped():
                raise AttributeAuthorityError("External Attribute Certificate "
                                              "must have an original "
                                              "provenance in order "
                                              "to make further mappings.")


            # Check it's valid and signed
            try:
                # Give path to CA cert to allow check
                userAttCert.certFilePathList=self._prop['caCertFilePathList']
                userAttCert.isValid(raiseExcep=True)
                
            except Exception, e:
                raise AttributeAuthorityError("Invalid Remote Attribute "
                                        "Certificate: " + str(e))       


            # Check that's it's holder matches the candidate holder 
            # certificate DN
            if holderX509Cert and userAttCert.holderDN != holderX509Cert.dn:
                raise AttributeAuthorityError("User certificate and Attribute "
                                        'Certificate DNs don\'t match: "%s"'
                                        ' and "%s"' % (holderX509Cert.dn, 
                                                       userAttCert.holderDN))
            
  
            # Get roles from external Attribute Certificate
            trustedHostRoles = userAttCert.roles


            # Map external roles to local ones
            localRoles = self.mapRemoteRoles2LocalRoles(
                                                    userAttCert['issuerName'],
                                                    trustedHostRoles)
            if not localRoles:
                raise AttributeAuthorityAccessDenied("No local roles mapped "
                                               "to the %s roles: %s" % 
                                               (userAttCert['issuerName'], 
                                                ', '.join(trustedHostRoles)))

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
            self._attCertLog.info(attCert)
            
            log.info('Issued an Attribute Certificate to "%s" with roles: '
                     '"%s"' % (userId, '", "'.join(attCert.roles)))

            # Return the cert to caller
            return attCert
        
        except Exception, e:
            raise AttributeAuthorityError('New Attribute Certificate "%s": %s'%
                                          (attCert.filePath, e))
       
        
    def readMapConfig(self, mapConfigFilePath=None):
        """Parse Map Configuration file.

        @type mapConfigFilePath: string
        @param mapConfigFilePath: file path for map configuration file.  If 
        omitted, it uses member variable _prop['mapConfigFile'].
        """
        
        log.debug("Reading map configuration file ...")
        
        if mapConfigFilePath is not None:
            if not isinstance(mapConfigFilePath, basestring):
                raise AttributeAuthorityConfigError("Input Map Configuration "
                                                    "file path must be a "
                                                    "valid string.")
            
            self._prop['mapConfigFile'] = mapConfigFilePath


        try:
            tree = ElementTree.parse(self._prop['mapConfigFile'])
            rootElem = tree.getroot()
            
        except IOError, e:
            raise AttributeAuthorityConfigError('Error parsing properties '
                                                'file "%s": %s' % 
                                                (e.filename,e.strerror))          
        except Exception, e:
            raise AttributeAuthorityConfigError('Error parsing Map '
                                                'Configuration file: "%s": %s'% 
                                                (self._prop['mapConfigFile'], 
                                                 e))

            
        trustedElem = rootElem.findall('trusted')
        if not trustedElem: 
            # Make an empty list so that for loop block below is skipped 
            # without an error  
            trustedElem = ()

        # Dictionaries:
        # 1) to hold all the data
        self._mapConfig = {'thisHost': {}, 'trustedHosts': {}}

        # ... look-up
        # 2) hosts corresponding to a given role and
        # 3) roles of external data centre to this data centre
        self._localRole2TrustedHost = {}
        self._localRole2RemoteRole = {}
        self._remoteRole2LocalRole = {}


        # Information about this host
        try:
            thisHostElem = rootElem.findall('thisHost')[0]
            
        except Exception, e:
            raise AttributeAuthorityConfigError('"thisHost" tag not found in '
                                                'Map Configuration file "%s"' % 
                                                self._prop['mapConfigFile'])

        try:
            hostName = thisHostElem.attrib.values()[0]
            
        except Exception, e:
            raise AttributeAuthorityConfigError('"name" attribute of '
                                                '"thisHost" element not found '
                                                'in Map Configuration file '
                                                '"%s"' % 
                                                self._prop['mapConfigFile'])


        # hostname is also stored in the AA's config file in the 'name' tag.  
        # Check the two match as the latter is copied into Attribute 
        # Certificates issued by this AA
        #
        # TODO: would be better to rationalise this so that the hostname is 
        # stored in one place only.
        #
        # P J Kershaw 14/06/06
        if hostName != self._prop['name']:
            raise AttributeAuthorityError('"name" attribute of "thisHost" '
                                          'element in Map Configuration file '
                                          'doesn\'t match "name" element in '
                                          'properties file.')
        
        # Information for THIS Attribute Authority
        self._mapConfig['thisHost'][hostName] = {}

        for k, v in AttributeAuthority.mapConfigHostDefaults.items():
            val = thisHostElem.findtext(k)
            if val is None and v == NotImplemented:
                raise AttributeAuthorityConfigError('<thisHost> option <%s> '
                                                    'must be set.' % k)
            self._mapConfig['thisHost'][hostName][k] = val
                
        
        # Information about trusted hosts
        for elem in trustedElem:
            try:
                trustedHost = elem.attrib.values()[0]
                
            except Exception, e:
                raise AttributeAuthorityConfigError('Error reading trusted '
                                                    'host name: %s' % e)

            
            # Add signatureFile and list of roles
            #
            # (Currently Optional) additional tag allows query of the URI
            # where a user would normally login at the trusted host.  Added
            # this feature to allow users to be forwarded to their home site
            # if they are accessing a secure resource and are not 
            # authenticated
            #
            # P J Kershaw 25/05/06
            self._mapConfig['trustedHosts'][trustedHost] = {}
            for k, v in AttributeAuthority.mapConfigHostDefaults.items():
                val = thisHostElem.findtext(k)
                if val is None and v == NotImplemented:
                    raise AttributeAuthorityConfigError('<trustedHost> option '
                                                        '<%s> must be set.'%k)
                    
                self._mapConfig['trustedHosts'][trustedHost][k] = \
                                                        elem.findtext(k)   

            roleElem = elem.findall('role')
            if roleElem:
                # Role keyword value requires special parsing before 
                # assignment
                self._mapConfig['trustedHosts'][trustedHost]['role'] = \
                                        [dict(i.items()) for i in roleElem]
            else:
                # It's possible for trust relationships to not contain any 
                # role mapping.  e.g. a site's login service trusting other
                # sites login requests
                self._mapConfig['trustedHosts'][trustedHost]['role'] = []
                       
            self._localRole2RemoteRole[trustedHost] = {}
            self._remoteRole2LocalRole[trustedHost] = {}
            
            for role in self._mapConfig['trustedHosts'][trustedHost]['role']:
                try:
                    localRole = role['local']
                    remoteRole = role['remote']
                except KeyError, e:
                    raise AttributeAuthorityError('Reading map configuration '
                                                  ' file "%s": no element '
                                                  '"%s" for host "%s"' % 
                                                (self._prop['mapConfigFile'], 
                                                 e, 
                                                 trustedHost))
                    
                # Role to host look-up
                if localRole in self._localRole2TrustedHost:
                    
                    if trustedHost not in \
                       self._localRole2TrustedHost[localRole]:
                        self._localRole2TrustedHost[localRole].\
                                                        append(trustedHost)                        
                else:
                    self._localRole2TrustedHost[localRole] = [trustedHost]


                # Trusted Host to local role and trusted host to trusted role
                # map look-ups
                try:
                    self._remoteRole2LocalRole[trustedHost][remoteRole].\
                                                            append(localRole)                  
                except KeyError:
                    self._remoteRole2LocalRole[trustedHost][remoteRole] = \
                                                                [localRole]
                    
                try:
                    self._localRole2RemoteRole[trustedHost][localRole].\
                                                            append(remoteRole)                  
                except KeyError:
                    self._localRole2RemoteRole[trustedHost][localRole] = \
                                                                [remoteRole]
        
        # Store trusted host info look-up for retrieval by getTrustedHostInfo
        # method                                                                         
        #
        # Nb. {}.fromkeys([...]).keys() is a fudge to get unique elements
        # from a list i.e. convert the list elements to a dict eliminating
        # duplicated elements and convert the keys back into a list.
        self._trustedHostInfo = dict(
        [
            (
                k, 
                {
                    'siteName':             v['siteName'],
                    'aaURI':                v['aaURI'], 
                    'aaDN':                 v['aaDN'], 
                    'loginURI':             v['loginURI'], 
                    'loginServerDN':        v['loginServerDN'], 
                    'loginRequestServerDN': v['loginRequestServerDN'], 
                    'role':                 {}.fromkeys([role['remote'] 
                                                         for role in v['role']]
                                                       ).keys()
                }
            ) for k, v in self._mapConfig['trustedHosts'].items()
        ])

        log.info('Loaded map configuration file "%s"' % 
                 self._prop['mapConfigFile'])
       
        
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
            raise AttributeAuthorityError("Getting user roles: %s" % e)
       
        
    def _getHostInfo(self):
        """Return the host that this Attribute Authority represents: its ID,
        the user login URI and WSDL address.  Call this method via the
        'hostInfo' property
        
        @rtype: dict
        @return: dictionary of host information derived from the map 
        configuration"""
        
        return self._mapConfig['thisHost']
        
    hostInfo = property(fget=_getHostInfo, 
                        doc="Return information about this host")
       
        
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
                                 
        if not self._mapConfig or not self._localRole2RemoteRole:
            # This Attribute Authority has no trusted hosts
            raise AttributeAuthorityNoTrustedHosts("The %s Attribute "
                                                   "Authority has no trusted "
                                                   "hosts" % 
                                                   self._prop['name'])


        if role is None:
            # No role input - return all trusted hosts with their service URIs
            # and the remote roles they map to
            return self._trustedHostInfo

        else:           
            # Get trusted hosts for given input local role        
            try:
                trustedHosts = self._localRole2TrustedHost[role]
            except:
                raise AttributeAuthorityNoMatchingRoleInTrustedHosts(
                    'None of the trusted hosts have a mapping to the '
                    'input role "%s"' % role)
    
    
            # Get associated Web service URI and roles for the trusted hosts 
            # identified and return as a dictionary indexed by host name
            trustedHostInfo = dict(
       [(
            host, 
            {
                'siteName': self._mapConfig['trustedHosts'][host]['siteName'],
                'aaURI':    self._mapConfig['trustedHosts'][host]['aaURI'],
                'aaDN':     self._mapConfig['trustedHosts'][host]['aaDN'],
                'loginURI': self._mapConfig['trustedHosts'][host]['loginURI'],
                'loginServerDN': 
                        self._mapConfig['trustedHosts'][host]['loginServerDN'],
                'loginRequestServerDN': 
                self._mapConfig['trustedHosts'][host]['loginRequestServerDN'],
                'role':     self._localRole2RemoteRole[host][role]
            }
        ) for host in trustedHosts])
                         
            return trustedHostInfo
       
        
    def mapRemoteRoles2LocalRoles(self, trustedHost, trustedHostRoles):
        """Map roles of trusted hosts to roles for this data centre

        @type trustedHost: string
        @param trustedHost: name of external trusted data centre
        @type trustedHostRoles: list
        @param trustedHostRoles:   list of external roles to map
        @return: list of mapped roles"""

        if not self._remoteRole2LocalRole:
            raise AttributeAuthorityError("Roles map is not set - ensure " 
                                    "readMapConfig() has been called.")


        # Check the host name is a trusted one recorded in the map
        # configuration
        if not self._remoteRole2LocalRole.has_key(trustedHost):
            return []

        # Add local roles, skipping if no mapping is found
        localRoles = []
        for trustedRole in trustedHostRoles:
            if trustedRole in self._remoteRole2LocalRole[trustedHost]:
                localRoles.extend(\
                        self._remoteRole2LocalRole[trustedHost][trustedRole])
                
        return localRoles


from logging.handlers import RotatingFileHandler

# Inherit directly from Logger
_loggerClass = logging.getLoggerClass()
class AttCertLog(_loggerClass, object):
    """Log each Attribute Certificate issued using a rotating file handler
    so that the number of files held can be managed"""
    
    def __init__(self, attCertFilePath, backUpCnt=1024):
        """Set up a rotating file handler to log ACs issued.
        @type attCertFilePath: string
        @param attCertFilePath: set where to store ACs.  Set from 
        AttributeAuthority properties file.
        
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
                       
class AAUserRolesError(Exception):
    """Exception handling for NDG Attribute Authority User Roles interface
    class."""


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
        
        Nb. this method is not used by AttributeAuthority class and so does NOT need 
        to be implemented in a derived class.
        
        @type userId: string 
        @param userId: user Distinguished Name to look up.
        @rtype: bool
        @return: True if user is registered, False otherwise"""
        raise NotImplementedError(
            self.userIsRegistered.__doc__.replace('\n       ',''))


    def getRoles(self, userId):
        """Virtual method - Derived method should return the roles for the 
        given user's Id or else raise an exception
        
        @type userId: string 
        @param userId: user identity e.g. user Distinguished Name
        @rtype: list
        @return: list of roles for the given user ID"""
        raise NotImplementedError(
            self.getRoles.__doc__.replace('\n       ',''))
                         