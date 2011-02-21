"""NDG Attribute Authority server side code

handles security user attribute (role) allocation

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/04/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:attributeauthority.py 4367 2008-10-29 09:27:59Z pjkersha $'
import logging
log = logging.getLogger(__name__)

import os
import re
import traceback

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

# SAML 2.0 Attribute Query Support - added 20/08/2009
from uuid import uuid4
from datetime import datetime, timedelta

from saml.utils import SAMLDateTime
from saml.saml2.core import (Response, Assertion, Attribute, AttributeStatement,
                             SAMLVersion, Subject, NameID, Issuer, Conditions,
                             AttributeQuery, XSStringAttributeValue, Status, 
                             StatusCode, StatusMessage)

from ndg.security.common.saml_utils.esg import EsgSamlNamespaces
from ndg.security.common.utils import TypedList
from ndg.security.common.utils.classfactory import instantiateClass
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)
    
# X.509 Certificate handling
from ndg.security.common.X509 import X509Cert, X500DN

# NDG Attribute Certificate
from ndg.security.common.AttCert import AttCert


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


class AttributeAuthority(object):
    """NDG Attribute Authority - service for allocation of user authorization
    tokens - attribute certificates.
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: valid configuration property keywords
    
    @type attributeInterfacePropertyDefaults: dict
    @cvar attributeInterfacePropertyDefaults: valid configuration property 
    keywords for the Attribute Interface plugin
    
    @type mapConfigHostDefaults: dict
    @cvar mapConfigHostDefaults: valid configuration property 
    keywords for the Map Configuration XML Host element
    
    @type DEFAULT_CONFIG_DIRNAME: string
    @cvar DEFAULT_CONFIG_DIRNAME: configuration directory under $NDGSEC_DIR - 
    default location for properties file 
    
    @type DEFAULT_PROPERTY_FILENAME: string
    @cvar DEFAULT_PROPERTY_FILENAME: default file name for properties file 
    under DEFAULT_CONFIG_DIRNAME
    
    @type ATTRIBUTE_INTERFACE_KEYNAME: basestring
    @param ATTRIBUTE_INTERFACE_KEYNAME: attribute interface parameters key 
    name - see initAttributeInterface for details
    """

    # Code designed from NERC Data Grid Enterprise and Information Viewpoint
    # documents.
    #
    # Also, draws from Neil Bennett's ACServer class used in the Java
    # implementation of NDG Security

    DEFAULT_CONFIG_DIRNAME = "conf"
    DEFAULT_PROPERTY_FILENAME = "attributeAuthority.cfg"
    ATTRIBUTE_INTERFACE_KEYNAME = 'attributeInterface'
    CONFIG_LIST_SEP_PAT = re.compile(',\s*')
    
    attributeInterfacePropertyDefaults = {
        'modFilePath':  '',
        'modName':      '',
        'className':    ''
    }
    
    # valid configuration property keywords with accepted default values.  
    # Values set to not NotImplemented here denote keys which must be specified
    # in the config
    propertyDefaults = { 
        'name':                         '',
        'signingCertFilePath':          '',
        'signingPriKeyFilePath':        '',
        'signingPriKeyPwd':             None,
        'caCertFilePathList':           [],
        'attCertLifetime':              -1,
        'attCertNotBeforeOff':          0.,
        'clockSkew':                    timedelta(seconds=0.),
        'attCertFileName':              '',
        'attCertFileLogCnt':            0,
        'mapConfigFilePath':            '',
        'attCertDir':                   '',
        'dnSeparator':                  '/',
        ATTRIBUTE_INTERFACE_KEYNAME:    attributeInterfacePropertyDefaults
    }
    
    mapConfigHostDefaults = {
        'siteName':                 None,
        'aaURI':                    NotImplemented,
        'aaDN':                     NotImplemented,
        'loginURI':                 NotImplemented,
        'loginServerDN':            NotImplemented,
        'loginRequestServerDN':     NotImplemented
    }

    def __init__(self):
        """Create new Attribute Authority instance"""
        log.info("Initialising service ...")
        
        # Initial config file property based attributes
        for name, val in AttributeAuthority.propertyDefaults.items():
            setattr(self, '_AttributeAuthority__%s' % name, val)
        
        self.__caCertFilePathList = TypedList(basestring)
        
        self.__propFilePath = None        
        self.__propFileSection = 'DEFAULT'
        self.__propPrefix = ''
        
        # Initialise role mapping look-ups - These are set in readMapConfig()
        self.__mapConfig = None
        self.__localRole2RemoteRole = None
        self.__remoteRole2LocalRole = None
        
        self.__cert = None
        
        # Issuer details - serialise using the separator string set in the
        # properties file
        self.__issuer = None
        self.__issuerSerialNumber = None
        self.__attCertLog = None
        self.__name = None
        
        self.__attributeInterfaceCfg = {}

    def _getMapConfig(self):
        return self.__mapConfig

    def _getCert(self):
        return self.__cert

    def _getIssuer(self):
        return self.__issuer

    def _getIssuerSerialNumber(self):
        return self.__issuerSerialNumber

    def _getAttCertLog(self):
        return self.__attCertLog

    def _getName(self):
        return self.__name

    def _getAttCertLifetime(self):
        return self.__attCertLifetime

    def _getAttCertNotBeforeOff(self):
        return self.__attCertNotBeforeOff

    def _getClockSkew(self):
        return self.__clockSkew

    def _getAttCertDir(self):
        return self.__attCertDir

    def _getAttributeInterface(self):
        return self.__attributeInterface

    def _getTrustedHostInfo(self):
        return self.__trustedHostInfo

    def _setCert(self, value):
        if not isinstance(value, X509Cert):
            raise TypeError('Expecting %r type for "cert"; got %r' %
                            (X509Cert, type(value)))
            
        self.__cert = value

    def _setIssuer(self, value):
        self.__issuer = value

    def _setIssuerSerialNumber(self, value):
        if not isinstance(value, (long, int)):
            raise TypeError('Expecting long or int type for "name"; got %r' %
                            type(value))
        self.__issuerSerialNumber = value

    def _setAttCertLog(self, value):
        if not isinstance(value, AttCertLog):
            raise TypeError('Expecting %r type for "attCertLog"; got %r' %
                            (AttCertLog, type(value)))
        self.__attCertLog = value

    def _setName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "name"; got %r' %
                            type(value))
        self.__name = value

    def _setAttCertLifetime(self, value):
        if isinstance(value, float):
            self.__attCertLifetime = value
            
        elif isinstance(value, (basestring, int, long)):
            self.__attCertLifetime = float(value)
        else:
            raise TypeError('Expecting float, int, long or string type for '
                            '"attCertLifetime"; got %r' % type(value))

    def _setAttCertNotBeforeOff(self, value):
        if isinstance(value, float):
            self.__attCertNotBeforeOff = value
            
        elif isinstance(value, (basestring, int, long)):
            self.__attCertNotBeforeOff = float(value)
        else:
            raise TypeError('Expecting float, int, long or string type for '
                            '"attCertNotBeforeOff"; got %r' % type(value))

    def _setClockSkew(self, value):
        if isinstance(value, (float, int, long)):
            self.__clockSkew = timedelta(seconds=value)
            
        elif isinstance(value, basestring):
            self.__clockSkew = timedelta(seconds=float(value))
        else:
            raise TypeError('Expecting float, int, long or string type for '
                            '"clockSkew"; got %r' % type(value))

    def _setAttCertDir(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "attCertDir"; got %r' % 
                            type(value))

        # Check directory path
        try:
            dirList = os.listdir(value)

        except OSError, osError:
            raise AttributeAuthorityConfigError('Invalid directory path for '
                                                'Attribute Certificates store '
                                                '"%s": %s' % 
                                                (value, osError.strerror))
        self.__attCertDir = value

    def _setAttributeInterface(self, value):
        if not isinstance(value, AttributeInterface):
            raise TypeError('Expecting %r type for "attributeInterface" '
                            'attribute; got %r' %
                            (AttributeInterface, type(value)))
            
        self.__attributeInterface = value

    def _setTrustedHostInfo(self, value):
        self.__trustedHostInfo = value

    def _get_caCertFilePathList(self):
        return self.__caCertFilePathList

    def _set_caCertFilePathList(self, val):
        if not isinstance(val, (list, tuple)):
            raise TypeError('Expecting list or tuple type for '
                            '"caCertFilePathList"; got %r' % type(val))
            
        # Overwrite any original settings
        self.__caCertFilePathList = TypedList(basestring)
        
        # Update with new items
        self.__caCertFilePathList += val
   
    caCertFilePathList = property(fget=_get_caCertFilePathList,
                                  fset=_set_caCertFilePathList,
                                  doc="list of file paths for CA certificates "
                                      "used to validate an Attribute "
                                      "Certificate")
    
    def _get_signingCertFilePath(self):
        return self.__signingCertFilePath
    
    def _set_signingCertFilePath(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "signingCertFilePath"; '
                            'got %r' % type(value))
        self.__signingCertFilePath = value
         
    signingCertFilePath = property(fget=_get_signingCertFilePath, 
                                   fset=_set_signingCertFilePath,
                                   doc="X.509 certificate used for Attribute "
                                       "certificate signature")
    
    def _get_signingPriKeyFilePath(self):
        return self.__signingPriKeyFilePath
    
    def _set_signingPriKeyFilePath(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"signingPriKeyFilePath"; got %r' % type(value))
        self.__signingPriKeyFilePath = value
         
    signingPriKeyFilePath = property(fget=_get_signingPriKeyFilePath, 
                                     fset=_set_signingPriKeyFilePath,
                                     doc="File Path for private key used to "
                                         "sign Attribute certificate")
    
    def _get_signingPriKeyPwd(self):
        return self.__signingPriKeyPwd
    
    def _set_signingPriKeyPwd(self, value):
        if not isinstance(value, (type(None), basestring)):
            raise TypeError('Expecting string or None type for '
                            '"signingPriKeyPwd"; got %r' % type(value))
        self.__signingPriKeyPwd = value
         
    signingPriKeyPwd = property(fget=_get_signingPriKeyPwd, 
                                fset=_set_signingPriKeyPwd,
                                doc="Password for private key file used to "
                                    "for Attribute certificate signature")

    def _get_attributeInterfaceCfg(self):
        return self.__attributeInterfaceCfg
    
    attributeInterfaceCfg = property(fget=_get_attributeInterfaceCfg,
                                     doc="Settings for Attribute Interface "
                                         "initialisation")
    
    def _get_attCertFileName(self):
        return self.__attCertFileName
    
    def _set_attCertFileName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "attCertFileName"; got '
                            '%r' % type(value))
            
        self.__attCertFileName = value
         
    attCertFileName = property(fget=_get_attCertFileName, 
                                fset=_set_attCertFileName,
                                doc="Attribute certificate file name for log "
                                    "initialisation")
    
    def _get_attCertFileLogCnt(self):
        return self.__attCertFileLogCnt
    
    def _set_attCertFileLogCnt(self, value):
        if isinstance(value, int):
            self.__attCertFileLogCnt = value
        elif isinstance(value, basestring):
            self.__attCertFileLogCnt = int(value)
        else:
            raise TypeError('Expecting int or string type for '
                            '"attCertFileLogCnt"; got %r' % type(value))
         
    attCertFileLogCnt = property(fget=_get_attCertFileLogCnt, 
                                 fset=_set_attCertFileLogCnt,
                                 doc="Counter for Attribute Certificate log "
                                     "rotating file handler")
    
    def _get_dnSeparator(self):
        return self.__dnSeparator
    
    def _set_dnSeparator(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "dnSeparator"; got '
                            '%r' % type(value))
        self.__dnSeparator = value
         
    dnSeparator = property(fget=_get_dnSeparator, 
                           fset=_set_dnSeparator,
                           doc="Distinguished Name separator character used "
                               "with X.509 Certificate issuer certificate")
            
    def _getMapConfigFilePath(self):
        return self.__mapConfigFilePath
    
    def _setMapConfigFilePath(self, val):
        if not isinstance(val, basestring):
            raise AttributeAuthorityConfigError("Input Map Configuration "
                                                "file path must be a "
                                                "valid string.")
        self.__mapConfigFilePath = val
          
    mapConfigFilePath = property(fget=_getMapConfigFilePath,
                                 fset=_setMapConfigFilePath,
                                 doc="File path for Role Mapping "
                                     "configuration") 

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
                                   AttributeAuthority.DEFAULT_CONFIG_DIRNAME,
                                   AttributeAuthority.DEFAULT_PROPERTY_FILENAME)
            else:
                raise AttributeError('Unable to set default Attribute '
                                     'Authority properties file path: neither '
                                     '"NDGSEC_AA_PROPFILEPATH" or "NDGSEC_DIR"'
                                     ' environment variables are set')
                
        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file path "
                                 "must be a valid string.")
      
        self.__propFilePath = os.path.expandvars(val)
        log.debug("Path set to: %s" % val)
        
    def getPropFilePath(self):
        '''Get the properties file path
        
        @rtype: basestring
        @return: properties file path'''
        return self.__propFilePath
        
    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            fget=getPropFilePath,
                            doc="path to file containing Attribute Authority "
                                "configuration parameters.  It defaults to "
                                "$NDGSEC_AA_PROPFILEPATH or if not set, "
                                "$NDGSEC_DIR/conf/attributeAuthority.cfg")   
    
    def setPropFileSection(self, val=None):
        """Set section name to read properties from ini file.  This is set from
        input or based on environment variable setting 
        NDGSEC_AA_PROPFILESECTION
        
        @type val: basestring
        @param val: section name"""
        if not val:
            val = os.environ.get('NDGSEC_AA_PROPFILESECTION', 'DEFAULT')
                
        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file section name "
                                 "must be a valid string.")
      
        self.__propFileSection = val
        log.debug("Properties file section set to: \"%s\"" % val)
        
    def getPropFileSection(self):
        '''Get the section name to extract properties from an ini file -
        DOES NOT apply to XML file properties
        
        @rtype: basestring
        @return: section name'''
        return self.__propFileSection
        
    # Also set up as a property
    propFileSection = property(fset=setPropFileSection,
                               fget=getPropFileSection,
                               doc="Set the file section name for ini file "
                                   "properties")   
    
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
      
        self.__propPrefix = val
        log.debug("Properties file section set to: %s" % val)
        
    def getPropPrefix(self):
        '''Get the prefix name used for properties in an ini file -
        DOES NOT apply to XML file properties
        
        @rtype: basestring
        @return: section name'''
        return self.__propPrefix
   
        
    # Also set up as a property
    propPrefix = property(fset=setPropPrefix,
                          fget=getPropPrefix,
                          doc="Set a prefix for ini file properties")   
    
    mapConfig = property(fget=_getMapConfig, 
                         doc="MapConfig object")

    cert = property(fget=_getCert, 
                    fset=_setCert, 
                    doc="X.509 Issuer Certificate")

    issuer = property(fget=_getIssuer, 
                      fset=_setIssuer, 
                      doc="Issuer name")

    issuerSerialNumber = property(fget=_getIssuerSerialNumber, 
                                  fset=_setIssuerSerialNumber, 
                                  doc="Issuer Serial Number")

    attCertLog = property(fget=_getAttCertLog,
                          fset=_setAttCertLog, 
                          doc="Attribute certificate logging object")

    name = property(fget=_getName, 
                    fset=_setName, 
                    doc="Issuer organisation name")

    attCertLifetime = property(fget=_getAttCertLifetime, 
                               fset=_setAttCertLifetime, 
                               doc="Attribute certificate lifetime")

    attCertNotBeforeOff = property(fget=_getAttCertNotBeforeOff, 
                                   fset=_setAttCertNotBeforeOff, 
                                   doc="Attribute certificate clock skew in "
                                       "seconds")

    clockSkew = property(fget=_getClockSkew, 
                         fset=_setClockSkew, 
                         doc="Allow a clock skew in seconds for SAML Attribute"
                             " Query issueInstant parameter check")

    attCertDir = property(fget=_getAttCertDir, 
                          fset=_setAttCertDir, 
                          doc="Attribute certificate log directory")

    attributeInterface = property(fget=_getAttributeInterface, 
                                  fset=_setAttributeInterface,
                                  doc="Attribute Interface object")

    name = property(fget=_getName, fset=_setName, doc="Organisation Name")

    trustedHostInfo = property(fget=_getTrustedHostInfo, 
                               fset=_setTrustedHostInfo, 
                               doc="Dictionary of trusted organisations")
        
    @classmethod
    def fromPropertyFile(cls, propFilePath=None, propFileSection='DEFAULT',
                         propPrefix='attributeauthority.', 
                         bReadMapConfig=True):
        """Create new NDG Attribute Authority instance from the property file
        settings

        @type propFilePath: string
        @param propFilePath: path to file containing Attribute Authority
        configuration parameters.  It defaults to $NDGSEC_AA_PROPFILEPATH or
        if not set, $NDGSEC_DIR/conf/attributeAuthority.cfg
        @type propFileSection: basestring
        @param propFileSection: section of properties file to read from.
        properties files
        @type propPrefix: basestring
        @param propPrefix: set a prefix for filtering attribute authority
        property names - useful where properties are being parsed from a file
        section containing parameter names for more than one application
        @type bReadMapConfig: boolean
        @param bReadMapConfig: by default the Map Configuration file is 
        read.  Set this flag to False to override.
        """
            
        attributeAuthority = AttributeAuthority()
        if propFileSection:
            attributeAuthority.propFileSection = propFileSection
            
        if propPrefix:
            attributeAuthority.propPrefix = propPrefix

        attributeAuthority.propFilePath = propFilePath            
        attributeAuthority.readProperties()
        attributeAuthority.initialise(bReadMapConfig=bReadMapConfig)
    
        return attributeAuthority

        
    @classmethod
    def fromProperties(cls, propPrefix='attributeauthority.', 
                       bReadMapConfig=True, **prop):
        """Create new NDG Attribute Authority instance from input property
        keywords

        @type propPrefix: basestring
        @param propPrefix: set a prefix for filtering attribute authority
        property names - useful where properties are being parsed from a file
        section containing parameter names for more than one application
        @type bReadMapConfig: boolean
        @param bReadMapConfig: by default the Map Configuration file is 
        read.  Set this flag to False to override.
        """
        attributeAuthority = AttributeAuthority()
        if propPrefix:
            attributeAuthority.propPrefix = propPrefix
               
        attributeAuthority.setProperties(**prop)
        attributeAuthority.initialise(bReadMapConfig=bReadMapConfig)
        
        return attributeAuthority
    
    def initialise(self, bReadMapConfig=True):
        """Convenience method for set up of Attribute Interface, map
        configuration and PKI"""
        
        # Read the Map Configuration file
        if bReadMapConfig:
            self.readMapConfig()

        # Instantiate Certificate object
        log.debug("Reading and checking Attribute Authority X.509 cert. ...")
        self.cert = X509Cert.Read(self.signingCertFilePath)

        # Check it's valid
        try:
            self.cert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttributeAuthorityError("Attribute Authority's certificate "
                                          "is invalid: %s" % e)
        
        # Check CA certificate
        log.debug("Reading and checking X.509 CA certificate ...")
        for caCertFile in self.caCertFilePathList:
            caCert = X509Cert(caCertFile)
            caCert.read()
            
            try:
                caCert.isValidTime(raiseExcep=True)
                
            except Exception, e:
                raise AttributeAuthorityError('CA certificate "%s" is '
                                              'invalid: %s'% (caCert.dn, e))
        
        # Issuer details - serialise using the separator string set in the
        # properties file
        self.issuer = self.cert.dn.serialise(separator=self.dnSeparator)

        self.issuerSerialNumber = self.cert.serialNumber
        
        # Load user - user attribute look-up plugin 
        self.initAttributeInterface()
        
        attCertFilePath = os.path.join(self.attCertDir, self.attCertFileName)
                
        # Rotating file handler used for logging attribute certificates 
        # issued.
        self.attCertLog = AttCertLog(attCertFilePath,
                                     backUpCnt=self.attCertFileLogCnt)

    def setProperties(self, **prop):
        """Set configuration from an input property dictionary
        @type prop: dict
        @param prop: properties dictionary containing configuration items
        to be set
        """
        lenPropPrefix = len(self.propPrefix)
        
        # '+ 1' allows for the dot separator 
        lenAttributeInterfacePrefix = len(
                            AttributeAuthority.ATTRIBUTE_INTERFACE_KEYNAME) + 1
        
        for name, val in prop.items():
            if name.startswith(self.propPrefix):
                name = name[lenPropPrefix:]
            
            if name.startswith(AttributeAuthority.ATTRIBUTE_INTERFACE_KEYNAME):
                name = name[lenAttributeInterfacePrefix:]
                self.attributeInterfaceCfg[name] = val
                continue
            
            if name not in AttributeAuthority.propertyDefaults:
                raise AttributeError('Invalid attribute name "%s"' % name)
            
            if isinstance(val, basestring):
                val = os.path.expandvars(val)
            
            if isinstance(AttributeAuthority.propertyDefaults[name], list):
                val = AttributeAuthority.CONFIG_LIST_SEP_PAT.split(val)
                
            # This makes an implicit call to the appropriate property method
            try:
                setattr(self, name, val)
            except AttributeError:
                raise AttributeError("Can't set attribute \"%s\"" % name)          
            
    def readProperties(self):
        '''Read the properties files and do some checking/converting of input 
        values
        '''
        if not os.path.isfile(self.propFilePath):
            raise IOError('Error parsing properties file "%s": No such file' % 
                          self.propFilePath)
            
        defaultItems = {'here': os.path.dirname(self.propFilePath)}
        
        cfg = CaseSensitiveConfigParser(defaults=defaultItems)
        cfg.read(self.propFilePath)
        
        cfgItems = dict([(name, val) 
                         for name, val in cfg.items(self.propFileSection)
                         if name != 'here'])
        self.setProperties(**cfgItems)

    def initAttributeInterface(self):
        '''Load host sites custom user roles interface to enable the AA to
        # assign roles in an attribute certificate on a getAttCert request'''
        classProperties = {}
        classProperties.update(self.attributeInterfaceCfg)
        
        modName = classProperties.pop('modName')
        className = classProperties.pop('className')  
        
        # file path may be omitted    
        modFilePath = classProperties.pop('modFilePath', None) 
                      
        self.__attributeInterface = instantiateClass(modName,
                                             className,
                                             moduleFilePath=modFilePath,
                                             objectType=AttributeInterface,
                                             classProperties=classProperties)

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
                                         separator=self.dnSeparator) 
            except Exception, e:
                log.error("Setting user Id from holder certificate DN: %s" % e)
                raise
       
        # Make a new Attribute Certificate instance passing in certificate
        # details for later signing
        attCert = AttCert()

        # First certificate in list contains the public key corresponding to 
        # the private key
        attCert.certFilePathList = [self.signingCertFilePath] + \
         							self.caCertFilePathList
             
        # Check for expiry of each certificate                   
        for x509Cert in attCert.certFilePathList:
            X509Cert.Read(x509Cert).isValidTime(raiseExcep=True)
         							
        attCert.signingKeyFilePath = self.signingPriKeyFilePath
        attCert.signingKeyPwd = self.signingPriKeyPwd
        
        
        # Set holder's Distinguished Name if a holder X.509 certificate was 
        # input 
        if holderX509Cert:
            try:
                attCert['holder'] = holderX509Cert.dn.serialise(
                                        separator=self.dnSeparator)            
            except Exception, e:
                log.error("Holder X.509 Certificate DN: %s" % e)
                raise
        else:
            log.debug("No holder X.509 Certificate set, setting Attribute "
                      "Certificate holder to userId=%r", userId)
            attCert['holder'] = userId
            
        # Set Issuer details from Attribute Authority
        issuerDN = self.cert.dn
        try:
            attCert['issuer'] = \
                    issuerDN.serialise(separator=self.dnSeparator)            
        except Exception, e:
            log.error("Issuer X.509 Certificate DN: %s" % e)
            raise 
           
        attCert['issuerName'] = self.name
        attCert['issuerSerialNumber'] = self.issuerSerialNumber

        attCert['userId'] = userId
        
        # Set validity time
        try:
            attCert.setValidityTime(
                        lifetime=self.attCertLifetime,
                        notBeforeOffset=self.attCertNotBeforeOff)

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
                            notBeforeOffset=self.attCertNotBeforeOff)
            
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
                    userAttCert = AttCert.Read(userAttCertFilePath)
                    
                except Exception, e:
                    raise AttributeAuthorityError("Reading external Attribute "
                                                  "Certificate: %s" % e)                           
            elif userAttCert:
                # Allow input as a string but convert to 
                if isinstance(userAttCert, basestring):
                    userAttCert = AttCert.Parse(userAttCert)
                    
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
                userAttCert.certFilePathList = self.caCertFilePathList
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
            self.__attCertLog.info(attCert)
            
            log.info('Issued an Attribute Certificate to "%s" with roles: '
                     '"%s"' % (userId, '", "'.join(attCert.roles)))

            # Return the cert to caller
            return attCert
        
        except Exception:
            raise AttributeAuthorityError('New Attribute Certificate "%s": %s'%
                                          (attCert.filePath, 
                                           traceback.format_exc()))

    def samlAttributeQuery(self, attributeQuery):
        """Respond to SAML 2.0 Attribute Query
        """
        if not isinstance(attributeQuery, AttributeQuery):
            raise TypeError('Expecting %r for attribute query; got %r' %
                            (AttributeQuery, type(attributeQuery)))
           
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()
        if self.attCertNotBeforeOff != 0:
            samlResponse.issueInstant += timedelta(
                                            seconds=self.attCertNotBeforeOff)
            
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusMessage = StatusMessage()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI
        
        # Nb. SAML 2.0 spec says issuer format must be omitted
        samlResponse.issuer.value = self.issuer
        
        samlResponse.inResponseTo = attributeQuery.id
        
        # Attribute Query validation ...
        utcNow = datetime.utcnow()
        if attributeQuery.issueInstant >= utcNow + self.clockSkew:
            msg = ('SAML Attribute Query issueInstant [%s] is at or after '
                   'the current clock time [%s]') % \
                   (attributeQuery.issueInstant, SAMLDateTime.toString(utcNow))
            log.error(msg)
                      
            samlResponse.status.statusCode.value = StatusCode.REQUESTER_URI
            samlResponse.status.statusMessage = StatusMessage()
            samlResponse.status.statusMessage.value = msg
            return samlResponse
            
        elif attributeQuery.version < SAMLVersion.VERSION_20:
            samlResponse.status.statusCode.value = \
                                        StatusCode.REQUEST_VERSION_TOO_LOW_URI
            return samlResponse
        
        elif attributeQuery.version > SAMLVersion.VERSION_20:
            samlResponse.status.statusCode.value = \
                                        StatusCode.REQUEST_VERSION_TOO_HIGH_URI
            return samlResponse
        
        elif (attributeQuery.subject.nameID.format != 
              EsgSamlNamespaces.NAMEID_FORMAT):
            log.error('SAML Attribute Query subject format is %r; expecting '
                      '%r' % (attributeQuery.subject.nameID.format,
                                EsgSamlNamespaces.NAMEID_FORMAT))
            samlResponse.status.statusCode.value = StatusCode.REQUESTER_URI
            samlResponse.status.statusMessage.value = \
                                "Subject Name ID format is not recognised"
            return samlResponse
        
        elif attributeQuery.issuer.format not in Issuer.X509_SUBJECT:
            log.error('SAML Attribute Query issuer format is %r; expecting '
                      '%r' % (attributeQuery.issuer.format,
                                Issuer.X509_SUBJECT))
            samlResponse.status.statusCode.value = StatusCode.REQUESTER_URI
            samlResponse.status.statusMessage.value = \
                                            "Issuer format is not recognised"
            return samlResponse
        
        try:
            # Return a dictionary of name, value pairs
            self.attributeInterface.getAttributes(attributeQuery, samlResponse)
            
        except InvalidUserId, e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.UNKNOWN_PRINCIPAL_URI
            return samlResponse
            
        except UserIdNotKnown, e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.UNKNOWN_PRINCIPAL_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse
            
        except InvalidRequestorId, e:
            log.exception(e)
            samlResponse.status.statusCode.value = StatusCode.REQUEST_DENIED_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse
            
        except AttributeReleaseDenied, e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.INVALID_ATTR_NAME_VALUE_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse
            
        except AttributeNotKnownError, e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.INVALID_ATTR_NAME_VALUE_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse
            
        except Exception, e:
            log.exception("Unexpected error calling Attribute Interface "
                          "for subject [%s] and query issuer [%s]" %
                          (attributeQuery.subject.nameID.value,
                           attributeQuery.issuer.value))
            
            # SAML spec says application server should set a HTTP 500 Internal
            # Server error in this case
            raise 

        return samlResponse
    
    def readMapConfig(self):
        """Parse Map Configuration file.
        """
        log.debug("Reading map configuration file ...")
        
        try:
            tree = ElementTree.parse(self.mapConfigFilePath)
            rootElem = tree.getroot()
            
        except IOError, e:
            raise AttributeAuthorityConfigError('Error parsing Map '
                                                'Configuration file "%s": %s' % 
                                                (e.filename, e.strerror))          
        except Exception, e:
            raise AttributeAuthorityConfigError('Error parsing Map '
                                                'Configuration file: "%s": %s'% 
                                                (self.mapConfigFilePath, e))
       
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
            raise AttributeAuthorityConfigError('"thisHost" tag not found in '
                                                'Map Configuration file "%s"' % 
                                                self.mapConfigFilePath)

        try:
            hostName = thisHostElem.attrib.values()[0]
            
        except Exception, e:
            raise AttributeAuthorityConfigError('"name" attribute of '
                                                '"thisHost" element not found '
                                                'in Map Configuration file '
                                                '"%s"' % 
                                                self.mapConfigFilePath)

        # hostname is also stored in the AA's config file in the 'name' tag.  
        # Check the two match as the latter is copied into Attribute 
        # Certificates issued by this AA
        #
        # TODO: would be better to rationalise this so that the hostname is 
        # stored in one place only.
        #
        # P J Kershaw 14/06/06
        if hostName != self.name:
            raise AttributeAuthorityError('"name" attribute of "thisHost" '
                                          'element in Map Configuration file '
                                          'doesn\'t match "name" element in '
                                          'properties file.')
        
        # Information for THIS Attribute Authority
        self.__mapConfig['thisHost'][hostName] = {}

        for k, v in AttributeAuthority.mapConfigHostDefaults.items():
            val = thisHostElem.findtext(k)
            if val is None and v == NotImplemented:
                raise AttributeAuthorityConfigError('<thisHost> option <%s> '
                                                    'must be set.' % k)
            self.__mapConfig['thisHost'][hostName][k] = val     
        
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
            self.__mapConfig['trustedHosts'][trustedHost] = {}
            for k, v in AttributeAuthority.mapConfigHostDefaults.items():
                val = thisHostElem.findtext(k)
                if val is None and v == NotImplemented:
                    raise AttributeAuthorityConfigError('<trustedHost> option '
                                                        '<%s> must be set.'%k)
                    
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
                    raise AttributeAuthorityError('Reading map configuration '
                                                  ' file "%s": no element '
                                                  '"%s" for host "%s"' % 
                                                (self.mapConfigFilePath, 
                                                 e, 
                                                 trustedHost))
                    
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
            ) for k, v in self.__mapConfig['trustedHosts'].items()
        ])

        log.info('Loaded map configuration file "%s"' % self.mapConfigFilePath)
       
        
    def getRoles(self, userId):
        """Get the roles available to the registered user identified userId.

        @type dn: string 
        @param dn: user identifier - could be a X500 Distinguished Name
        @return: list of roles for the given user ID"""

        log.debug('Calling getRoles for user "%s" ...' % userId)
        
        # Call to AttributeInterface derived class.  Each Attribute Authority
        # should define it's own roles class derived from AttributeInterface to
        # define how roles are accessed
        try:
            return self.__attributeInterface.getRoles(userId)

        except Exception, e:
            raise AttributeAuthorityError("Getting user roles: %s" % e)
       
        
    def _getHostInfo(self):
        """Return the host that this Attribute Authority represents: its ID,
        the user login URI and WSDL address.  Call this method via the
        'hostInfo' property
        
        @rtype: dict
        @return: dictionary of host information derived from the map 
        configuration"""
        
        return self.__mapConfig['thisHost']
        
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
                                 
        if not self.__mapConfig or not self.__localRole2RemoteRole:
            # This Attribute Authority has no trusted hosts
            raise AttributeAuthorityNoTrustedHosts("The %s Attribute "
                                                   "Authority has no trusted "
                                                   "hosts" % 
                                                   self.name)


        if role is None:
            # No role input - return all trusted hosts with their service URIs
            # and the remote roles they map to
            return self._trustedHostInfo

        else:           
            # Get trusted hosts for given input local role        
            try:
                trustedHosts = self.__localRole2TrustedHost[role]
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
                'siteName': self.__mapConfig['trustedHosts'][host]['siteName'],
                'aaURI':    self.__mapConfig['trustedHosts'][host]['aaURI'],
                'aaDN':     self.__mapConfig['trustedHosts'][host]['aaDN'],
                'loginURI': self.__mapConfig['trustedHosts'][host]['loginURI'],
                'loginServerDN': 
                        self.__mapConfig['trustedHosts'][host]['loginServerDN'],
                'loginRequestServerDN': 
                self.__mapConfig['trustedHosts'][host]['loginRequestServerDN'],
                'role':     self.__localRole2RemoteRole[host][role]
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

        if not self.__remoteRole2LocalRole:
            raise AttributeAuthorityError("Roles map is not set - ensure " 
                                    "readMapConfig() has been called.")


        # Check the host name is a trusted one recorded in the map
        # configuration
        if not self.__remoteRole2LocalRole.has_key(trustedHost):
            return []

        # Add local roles, skipping if no mapping is found
        localRoles = []
        for trustedRole in trustedHostRoles:
            if trustedRole in self.__remoteRole2LocalRole[trustedHost]:
                localRoles.extend(
                        self.__remoteRole2LocalRole[trustedHost][trustedRole])
                
        return localRoles

    def getAttCertFactory(self):
        """Factory method to create SAML Attribute Qeury wrapper function
        @rtype: function
        @return getAttCert method function wrapper
        """
        def getAttCertWrapper(*arg, **kw):
            """
            @type *arg: tuple
            @param *arg: getAttCert arguments
            @type **kw: dict
            @param **kw: getAttCert keyword arguments
            @rtype: ndg.security.common.AttCert.AttCert
            @return: new attribute certificate
            """
            return self.getAttCert(*arg, **kw)
        
        return getAttCertWrapper

    def samlAttributeQueryFactory(self):
        """Factory method to create SAML Attribute Qeury wrapper function
        @rtype: function
        @return: samlAttributeQuery method function wrapper
        """
        def samlAttributeQueryWrapper(attributeQuery):
            """
            @type attributeQuery: saml.saml2.core.AttributeQuery
            @param attributeQuery: SAML Attribute Query
            @rtype: saml.saml2.core.Response
            @return: SAML response
            """
            return self.samlAttributeQuery(attributeQuery)
        
        return samlAttributeQueryWrapper
    

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
        
        if not isinstance(backUpCnt, int):
            raise TypeError('Expecting int type for "backUpCnt" keyword')
        
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
 
                      
class AttributeInterfaceError(Exception):
    """Exception handling for NDG Attribute Authority User Roles interface
    class."""
 
                      
class AttributeInterfaceConfigError(AttributeInterfaceError):
    """Invalid configuration set for Attribute interface"""
 
                      
class AttributeInterfaceRetrieveError(AttributeInterfaceError):
    """Error retrieving attributes for Attribute interface class"""

                       
class AttributeReleaseDenied(AttributeInterfaceError):
    """Requestor was denied release of the requested attributes"""

                       
class AttributeNotKnownError(AttributeInterfaceError):
    """Requested attribute names are not known to this authority"""


class InvalidRequestorId(AttributeInterfaceError):
    """Requestor is not known or not allowed to request attributes"""
    

class UserIdNotKnown(AttributeInterfaceError): 
    """User ID passed to getAttributes is not known to the authority"""
    
    
class InvalidUserId(AttributeInterfaceError):
    """User Id passed to getAttributes is invalid"""
    
    
class InvalidAttributeFormat(AttributeInterfaceError):
    """Format for Attribute requested is invalid or not supported"""
    
      
class AttributeInterface(object):
    """An abstract base class to define the user roles interface to an
    Attribute Authority.

    Each NDG data centre should implement a derived class which implements
    the way user roles are provided to its representative Attribute Authority.
    
    Roles are expected to indexed by user Distinguished Name (DN).  They
    could be stored in a database or file."""
    
    # Enable derived classes to use slots if desired
    __slots__ = ()
    
    # User defined class may wish to specify a URI for a database interface or
    # path for a user roles configuration file
    def __init__(self, **prop):
        """User Roles base class - derive from this class to define
        roles interface to Attribute Authority
        
        @type prop: dict
        @param prop: custom properties to pass to this class
        """

    def getRoles(self, userId):
        """Virtual method - Derived method should return the roles for the 
        given user's Id or else raise an exception
        
        @type userId: string 
        @param userId: user identity e.g. user Distinguished Name
        @rtype: list
        @return: list of roles for the given user ID
        @raise AttributeInterfaceError: an error occured requesting 
        attributes
        """
        raise NotImplementedError(self.getRoles.__doc__)
 
    def getAttributes(self, attributeQuery, response):
        """Virtual method should be implemented in a derived class to enable
        AttributeAuthority.samlAttributeQuery - The derived method should 
        return the attributes requested for the given user's Id or else raise 
        an exception
        
        @type attributeQuery: saml.saml2.core.AttributeQuery 
        @param userId: query containing requested attributes
        @type: saml.saml2.core.Response
        @param: Response - add an assertion with the list of attributes 
        for the given subject ID in the query or set an error Status code and
        message
        @raise AttributeInterfaceError: an error occured requesting 
        attributes
        @raise AttributeReleaseDeniedError: Requestor was denied release of the
        requested attributes
        @raise AttributeNotKnownError: Requested attribute names are not known 
        to this authority
        """
        raise NotImplementedError(self.getAttributes.__doc__)


class CSVFileAttributeInterface(AttributeInterface):
    """Attribute Interface based on a Comma Separated Variable file containing
    user identities and associated attributes.  For test/development purposes
    only.  The SAML getAttributes method is NOT implemented here
    
    The expected file format is:
    
    <userID>, <role1>, <role2>, ... <roleN>
    """
    def __init__(self, propertiesFilePath=None):
        """
        @param propertiesFilePath: file path to Comma Separated file 
        containing user ids and roles
        @type propertiesFilePath: basestring
        """
        if propertiesFilePath is None:
            raise AttributeError("Expecting propertiesFilePath setting")
        
        propertiesFile = open(propertiesFilePath)
        lines = propertiesFile.readlines()
        
        self.attributeMap = {}
        for line in lines:
            fields = re.split(',\s*', line.strip())
            self.attributeMap[fields[0]] = fields[1:]
    
    def getRoles(self, userId):
        """
        @param userId: user identity to key into attributeMap
        @type userId: basestring
        """  
        log.debug('CSVFileAttributeInterface.getRoles for user "%s" ...', 
                  userId)
        return self.attributeMap.get(userId, [])


# Properties file
from ConfigParser import SafeConfigParser, NoOptionError

try:
    # PostgreSQL interface
    from psycopg2 import connect
except ImportError:
    pass

class PostgresAttributeInterface(AttributeInterface):
    """User Roles interface to Postgres database
    
    The SAML getAttributes method is NOT implemented
    
    The configuration file follows the form,
    
    [Connection]
    # name of database
    dbName: user.db
    
    # database host machine
    host: mydbhost.ac.uk
    
    # database account username
    username: mydbaccount
    
    # Password - comment out to prompt from stdin instead
    pwd: mydbpassword
    
    [getRoles]
    query0: select distinct grp from users_table, where user = '%%s'
    defaultRoles = publicRole
    """

    CONNECTION_SECTION_NAME = "Connection"
    GETROLES_SECTION_NAME = "getRoles"
    HOST_OPTION_NAME = "host"
    DBNAME_OPTION_NAME = "dbName"
    USERNAME_OPTION_NAME = "username"
    PWD_OPTION_NAME = "pwd"
    QUERYN_OPTION_NAME = "query%d"
    DEFAULT_ROLES_OPTION_NAME = "defaultRoles"
    
    def __init__(self, propertiesFilePath=None):
        """Connect to Postgres database"""
        self.__con = None
        self.__host = None
        self.__dbName = None
        self.__username = None
        self.__pwd = None

        if propertiesFilePath is None:
            raise AttributeError("No Configuration file was set")

        self.readConfigFile(propertiesFilePath)

    def __del__(self):
        """Close database connection"""
        self.close()

    def readConfigFile(self, propertiesFilePath):
        """Read the configuration for the database connection

        @type propertiesFilePath: string
        @param propertiesFilePath: file path to config file"""

        if not isinstance(propertiesFilePath, basestring):
            raise TypeError("Input Properties file path must be a valid "
                            "string; got %r" % type(propertiesFilePath))

        cfg = SafeConfigParser()
        cfg.read(propertiesFilePath)

        self.__host = cfg.get(
                        PostgresAttributeInterface.CONNECTION_SECTION_NAME, 
                        PostgresAttributeInterface.HOST_OPTION_NAME)
        self.__dbName = cfg.get(
                        PostgresAttributeInterface.CONNECTION_SECTION_NAME, 
                        PostgresAttributeInterface.DBNAME_OPTION_NAME)
        self.__username = cfg.get(
                        PostgresAttributeInterface.CONNECTION_SECTION_NAME, 
                        PostgresAttributeInterface.USERNAME_OPTION_NAME)
        self.__pwd = cfg.get(
                        PostgresAttributeInterface.CONNECTION_SECTION_NAME, 
                        PostgresAttributeInterface.PWD_OPTION_NAME)

        try:
            self.__getRolesQuery = []
            for i in range(10):
                queryStr = cfg.get(
                        PostgresAttributeInterface.GETROLES_SECTION_NAME, 
                        PostgresAttributeInterface.QUERYN_OPTION_NAME % i)
                self.__getRolesQuery += [queryStr]
        except NoOptionError:
             # Continue until no more query<n> items left
             pass

        # This option may be omitted in the config file
        try:
            self.__defaultRoles = cfg.get(
                PostgresAttributeInterface.GETROLES_SECTION_NAME, 
                PostgresAttributeInterface.DEFAULT_ROLES_OPTION_NAME).split()
        except NoOptionError:
            self.__defaultRoles = []

    def connect(self,
                username=None,
                dbName=None,
                host=None,
                pwd=None,
                prompt="Database password: "):
        """Connect to database

        Values for keywords omitted are derived from the config file.  If pwd
        is not in the config file it will be prompted for from stdin

        @type username: string
        @keyword username: database account username
        @type dbName: string
        @keyword dbName: name of database
        @type host: string
        @keyword host: database host machine
        @type pwd: string
        @keyword pwd: password for database account.  If omitted and not in
        the config file it will be prompted for from stdin
        @type prompt: string
        @keyword prompt: override default password prompt"""

        if not host:
            host = self.__host

        if not dbName:
            dbName = self.__dbName

        if not username:
            username = self.__username

        if not pwd:
            pwd = self.__pwd

            if not pwd:
                import getpass
                pwd = getpass.getpass(prompt=prompt)

        try:
            self.__db = connect("host=%s dbname=%s user=%s password=%s" % \
                                (host, dbName, username, pwd))
            self.__cursor = self.__db.cursor()

        except NameError, e:
            raise AttributeInterfaceError("psycopg2 Postgres package not "
                                          "installed? %s" % e)
        except Exception, e:
            raise AttributeInterfaceError("Error connecting to database "
                                          "\"%s\": %s" % (dbName, e))

    def close(self):
        """Close database connection"""
        if self.__con:
            self.__con.close()

    def getRoles(self, userId):
        """Return valid roles for the given userId

        @type userId: basestring
        @param userId: user identity"""

        try:
            self.connect()

            # Process each query in turn appending role names
            roles = self.__defaultRoles[:]
            for query in self.__getRolesQuery:
                try:
                    self.__cursor.execute(query % userId)
                    queryRes = self.__cursor.fetchall()

                except Exception, e:
                    raise AttributeInterfaceError("Query for %s: %s" %
                                                  (userId, e))

                roles += [res[0] for res in queryRes if res[0]]
        finally:
            self.close()

        return roles

    def __getCursor(self):
        """Return a database cursor instance"""
        return self.__cursor

    cursor = property(fget=__getCursor, doc="database cursor")


from string import Template
try:
    from sqlalchemy import create_engine, exc
    sqlAlchemyInstalled = True
except ImportError:
    sqlAlchemyInstalled = False
    

class SQLAlchemyAttributeInterface(AttributeInterface):
    '''SQLAlchemy based Attribute interface enables the Attribute Authority
    to interface to any database type supported by it
    
    @type SQLQUERY_USERID_KEYNAME: basestring
    @cvar SQLQUERY_USERID_KEYNAME: key corresponding to string to be 
    substituted into attribute query for user identifier e.g.
    
    select attr from user_table where username = $userId
    
    @type SAML_VALID_REQUESTOR_DNS_PAT: _sre.SRE_Pattern
    @param SAML_VALID_REQUESTOR_DNS_PAT: regular expression to split list of
    SAML requestor DNs.  These must comma separated.  Each comma may be 
    separated by any white space including new line characters
    '''  
    DEFAULT_SAML_ASSERTION_LIFETIME = timedelta(seconds=60*60*8) 
     
    SQLQUERY_USERID_KEYNAME = 'userId'
    
    ISSUER_NAME_FORMAT = Issuer.X509_SUBJECT
    ISSUER_NAME_OPTNAME = 'issuerName'
    CONNECTION_STRING_OPTNAME = 'connectionString'
    ATTRIBUTE_SQLQUERY_OPTNAME = 'attributeSqlQuery'
    SAML_SUBJECT_SQLQUERY_OPTNAME = 'samlSubjectSqlQuery'
    SAML_VALID_REQUESTOR_DNS_OPTNAME = 'samlValidRequestorDNs'
    SAML_ASSERTION_LIFETIME_OPTNAME = 'samlAssertionLifetime'
    SAML_ATTRIBUTE2SQLQUERY_OPTNAME = 'samlAttribute2SqlQuery'
    SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN = len(SAML_ATTRIBUTE2SQLQUERY_OPTNAME)
    
    SAML_ATTRIBUTE2SQLQUERY_ATTRNAME_DELIMITERS = ('.', '_')
    
    __slots__ = (
        ISSUER_NAME_OPTNAME,
        CONNECTION_STRING_OPTNAME,
        ATTRIBUTE_SQLQUERY_OPTNAME,
        SAML_SUBJECT_SQLQUERY_OPTNAME,
        SAML_VALID_REQUESTOR_DNS_OPTNAME,
        SAML_ASSERTION_LIFETIME_OPTNAME,
        SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
        
    )
    __PRIVATE_ATTR_PREFIX = '_SQLAlchemyAttributeInterface__'
    __slots__ += tuple([__PRIVATE_ATTR_PREFIX + i for i in __slots__
                        ] + [__PRIVATE_ATTR_PREFIX + 'dbEngine'])
    del i
    
#    For Reference - split based on space separated ' or " quoted items
#    SAML_VALID_REQUESTOR_DNS_PAT = re.compile("['\"]?\s*['\"]")
    
    SAML_VALID_REQUESTOR_DNS_PAT = re.compile(',\s*')
    
    def __init__(self, **properties):
        '''Instantiate object taking in settings from the input properties'''
        log.debug('Initialising SQLAlchemyAttributeInterface instance ...')
        
        if not sqlAlchemyInstalled:
            raise AttributeInterfaceConfigError("SQLAlchemy is not installed")
        
        self.__issuerName = None
        self.__connectionString = None
        self.__attributeSqlQuery = None
        self.__samlSubjectSqlQuery = None
        self.__samlValidRequestorDNs = []
        self.__samlAssertionLifetime = \
            SQLAlchemyAttributeInterface.DEFAULT_SAML_ASSERTION_LIFETIME
        self.__samlAttribute2SqlQuery = {}
        
        self.setProperties(**properties)

    def __setattr__(self, name, value):
        """Provide a way to set the attribute map by dynamically handling
        attribute names containing the SAML attribute name as a suffix e.g.
        
        attributeInterface.samlAttribute2SqlQuery_firstName = 'Philip'
        
        will update __samlAttribute2SqlQuery with the 'firstName', 'Philip'
        key value pair.  Similarly,
        
        setattr('samlAttribute2SqlQuery.emailAddress', 'pjk@somewhere.ac.uk')
        
        sets __samlAttribute2SqlQuery with the 'emailAddress',
        'pjk@somewhere.ac.uk' key value pair
        
        This is useful in enabling settings to be made direct from a dict of
        option name and values parsed from an ini file.
        """
        cls = SQLAlchemyAttributeInterface
        
        if name in cls.__slots__:
            object.__setattr__(self, name, value)
            
        elif (name[cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN] in 
              cls.SAML_ATTRIBUTE2SQLQUERY_ATTRNAME_DELIMITERS):
            # A special 'samlAttribute2SqlQuery[._]+' attribute name has been 
            # found.  The first item is the attribute name and the second, the
            # corresponding SQL query to get the values corresponding to that
            # name.            
            samlAttributeName, samlAttributeSqlQuery = value.split(None, 1)
            
            # Items may be quoted with " quotes
            self.__samlAttribute2SqlQuery[samlAttributeName.strip('"')
                                          ] = samlAttributeSqlQuery.strip('"')
        else:
            raise AttributeError("'SQLAlchemyAttributeInterface' has no "
                                 "attribute %r" % name)

    def setProperties(self, prefix='', **properties):
        for name, val in properties.items():
            if prefix:
                if name.startswith(prefix):
                    name = name.replace(prefix, '', 1)
                    setattr(self, name, val)
            else:
                setattr(self, name, val)

    def _getIssuerName(self):
        return self.__issuerName

    def _setIssuerName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                            (SQLAlchemyAttributeInterface.ISSUER_NAME_OPTNAME,
                             type(value)))

        self.__issuerName = value

    issuerName = property(_getIssuerName, 
                          _setIssuerName, 
                          doc="The name of the issuing organisation.  This is "
                              "expected to be an X.509 Distinguished Name")
            
    def _getSamlAssertionLifetime(self):
        return self.__samlAssertionLifetime

    def _setSamlAssertionLifetime(self, value):
        if isinstance(value, timedelta):
            self.__samlAssertionLifetime = value
            
        if isinstance(value, (float, int, long)):
            self.__samlAssertionLifetime = timedelta(seconds=value)
            
        elif isinstance(value, basestring):
            self.__samlAssertionLifetime = timedelta(seconds=float(value))
        else:
            raise TypeError('Expecting float, int, long, string or timedelta '
                'type for "%s"; got %r' % 
                (SQLAlchemyAttributeInterface.SAML_ASSERTION_LIFETIME_OPTNAME,
                 type(value)))

    samlAssertionLifetime = property(_getSamlAssertionLifetime, 
                                     _setSamlAssertionLifetime, 
                                     doc="Time validity for SAML Assertion "
                                         "set in SAML Response returned from "
                                         "getAttributes")

    def _getSamlSubjectSqlQuery(self):
        return self.__samlSubjectSqlQuery

    def _setSamlSubjectSqlQuery(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                    (SQLAlchemyAttributeInterface.SAML_SUBJECT_SQLQUERY_OPTNAME,
                     type(value)))
            
        self.__samlSubjectSqlQuery = value

    samlSubjectSqlQuery = property(_getSamlSubjectSqlQuery, 
                                   _setSamlSubjectSqlQuery, 
                                   doc="SAML Subject SQL Query")

    def _getSamlAttribute2SqlQuery(self):
        return self.__samlAttribute2SqlQuery

    def _setSamlAttribute2SqlQuery(self, value):
        if isinstance(value, dict):
            # Validate string type for keys and values
            invalidItems = [(k, v) for k, v in value.items() 
                            if (not isinstance(k, basestring) or 
                                not isinstance(v, basestring))]
            if invalidItems:
                raise TypeError('Expecting string type for "%s" dict items; '
                                'got these/this invalid item(s) %r' % 
                (SQLAlchemyAttributeInterface.SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
                 invalidItems))
                
            self.__samlAttribute2SqlQuery = value
            
        elif isinstance(value, (tuple, list)):
            for query in value:
                if not isinstance(query, basestring):
                    raise TypeError('Expecting string type for "%s" '
                                    'attribute items; got %r' %
                (SQLAlchemyAttributeInterface.SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
                 type(value)))
                    
            self.__samlAttribute2SqlQuery = value                 
        else:
            raise TypeError('Expecting dict type for "%s" attribute; got %r' %
                (SQLAlchemyAttributeInterface.SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
                 type(value)))
            
    samlAttribute2SqlQuery = property(_getSamlAttribute2SqlQuery, 
                                      _setSamlAttribute2SqlQuery, 
                                      doc="SQL Query or queries to obtain the "
                                          "attribute information to respond "
                                          "a SAML attribute query.  The "
                                          "attributes returned from each "
                                          "query concatenated together, must "
                                          "exactly match the SAML attribute "
                                          "names set in the samlAttributeNames "
                                          "property")

    def _getSamlValidRequestorDNs(self):
        return self.__samlValidRequestorDNs

    def _setSamlValidRequestorDNs(self, value):
        if isinstance(value, basestring):
            
            pat = SQLAlchemyAttributeInterface.SAML_VALID_REQUESTOR_DNS_PAT
            self.__samlValidRequestorDNs = [
                X500DN.fromString(dn) for dn in pat.split(value)
            ]
            
        elif isinstance(value, (tuple, list)):
            self.__samlValidRequestorDNs = [X500DN.fromString(dn) 
                                            for dn in value]
        else:
            raise TypeError('Expecting list/tuple or basestring type for "%s" '
                'attribute; got %r' %
                (SQLAlchemyAttributeInterface.SAML_VALID_REQUESTOR_DNS_OPTNAME,
                 type(value)))
    
    samlValidRequestorDNs = property(_getSamlValidRequestorDNs, 
                                     _setSamlValidRequestorDNs, 
                                     doc="list of certificate Distinguished "
                                         "Names referring to the client "
                                         "identities permitted to query the "
                                         "Attribute Authority via the SAML "
                                         "Attribute Query interface")
    
    def _getConnectionString(self):
        return self.__connectionString

    def _setConnectionString(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                        (SQLAlchemyAttributeInterface.CONNECTION_STRING_OPTNAME,
                         type(value)))
        self.__connectionString = value
        
        # Beware of setting multiple times
        self.__dbEngine = create_engine(self.__connectionString)


    connectionString = property(fget=_getConnectionString, 
                                fset=_setConnectionString, 
                                doc="Database connection string.  Nb. this "
                                "attention: also creates the database engine!  "
                                "Should be called once only for a given new "
                                "connection string")

    def _getAttributeSqlQuery(self):
        return self.__attributeSqlQuery

    def _setAttributeSqlQuery(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" attribute; got %r'% 
                    (SQLAlchemyAttributeInterface.ATTRIBUTE_SQLQUERY_OPTNAME,
                     type(value)))
        self.__attributeSqlQuery = value

    attributeSqlQuery = property(fget=_getAttributeSqlQuery, 
                                 fset=_setAttributeSqlQuery, 
                                 doc="SQL Query for attribute query")
    
    def getRoles(self, userId):     
        """Return valid roles for the given userId

        @type userId: basestring
        @param userId: user identity
        @rtype: list
        @return: list of roles for the given user
        """

        connection = self.__dbEngine.connect()
        
        try:
            queryInputs = {
                SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME:
                userId
            }
            query = Template(self.attributeSqlQuery).substitute(queryInputs)
            result = connection.execute(query)

        except exc.ProgrammingError:
            raise AttributeInterfaceRetrieveError("Error with SQL Syntax: %s" %
                                                  traceback.format_exc())
        finally:
            connection.close()

        try:
            attributes = [attr for attr in result][0][0]
        
        except (IndexError, TypeError):
            raise AttributeInterfaceRetrieveError("Error with result set: %s" %
                                                  traceback.format_exc())
        
        log.debug('Attributes=%r retrieved for user=%r' % (attributes, 
                                                           userId))
        
        return attributes

    def getAttributes(self, attributeQuery, response):
        """Attribute Authority SAML AttributeQuery
        
        @type attributeQuery: saml.saml2.core.AttributeQuery 
        @param userId: query containing requested attributes
        @type: saml.saml2.core.Response
        @param: Response - add an assertion with the list of attributes 
        for the given subject ID in the query or set an error Status code and
        message
        @raise AttributeInterfaceError: an error occured requesting 
        attributes
        @raise AttributeReleaseDeniedError: Requestor was denied release of the
        requested attributes
        @raise AttributeNotKnownError: Requested attribute names are not known 
        to this authority
        """
        userId = attributeQuery.subject.nameID.value
        requestedAttributeNames = [attribute.name
                                   for attribute in attributeQuery.attributes]
        
        requestorDN = X500DN.fromString(attributeQuery.issuer.value)

        if not self._queryDbForSamlSubject(userId):
            raise UserIdNotKnown('Subject Id "%s" is not known to this '
                                 'authority' % userId)

        if requestorDN not in self.samlValidRequestorDNs:
            raise InvalidRequestorId('Requestor identity "%s" is invalid' %
                                     requestorDN)

        unknownAttrNames = [attrName for attrName in requestedAttributeNames
                            if attrName not in self.samlAttribute2SqlQuery]

        if len(unknownAttrNames) > 0:
            raise AttributeNotKnownError("Unknown attributes requested: %r" %
                                         unknownAttrNames)
        
        # Create a new assertion to hold the attributes to be returned
        assertion = Assertion()

        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = response.issueInstant
    
        assertion.issuer = Issuer()
        assertion.issuer.value = self.issuerName
        assertion.issuer.format = Issuer.X509_SUBJECT

        assertion.conditions = Conditions()
        assertion.conditions.notBefore = assertion.issueInstant
        assertion.conditions.notOnOrAfter = (assertion.conditions.notBefore + 
                                             self.samlAssertionLifetime)

        assertion.subject = Subject()
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = attributeQuery.subject.nameID.format
        assertion.subject.nameID.value = attributeQuery.subject.nameID.value

        attributeStatement = AttributeStatement()

        # Query the database for the requested attributes and return them
        # mapped to their attribute names as specified by the attributeNames
        # property
        for requestedAttribute in attributeQuery.attributes:
            attributeVals = self._queryDbForSamlAttributes(
                                                    requestedAttribute.name, 
                                                    userId)

            # Make a new SAML attribute object to hold the values obtained
            attribute = Attribute()
            attribute.name = requestedAttribute.name
            
            # Check name format requested - only XSString is currently
            # supported
            if (requestedAttribute.nameFormat != 
                XSStringAttributeValue.DEFAULT_FORMAT):
                raise InvalidAttributeFormat('Requested attribute type %r but '
                                     'only %r type is supported' %
                                     (requestedAttribute.nameFormat,
                                      XSStringAttributeValue.DEFAULT_FORMAT))
            
            attribute.nameFormat = requestedAttribute.nameFormat

            if requestedAttribute.friendlyName is not None:
                attribute.friendlyName = requestedAttribute.friendlyName

            for val in attributeVals:
                attribute.attributeValues.append(XSStringAttributeValue())
                attribute.attributeValues[-1].value = val

            attributeStatement.attributes.append(attribute)

        assertion.attributeStatements.append(attributeStatement)
        response.assertions.append(assertion)
        
    def _queryDbForSamlSubject(self, userId):     
        """Check a given SAML subject (user) is registered in the database.
        This method is called from the getAttributes() method

        @type userId: basestring
        @param userId: user identity
        @rtype: bool
        @return: True/False is user registered?
        """
        if self.samlSubjectSqlQuery is None:
            log.debug('No "self.samlSubjectSqlQuery" property has been set, '
                      'skipping SAML subject query step')
            return True
        
        if self.__dbEngine is None:
            raise AttributeInterfaceConfigError('No connection '
                                                'has been initialised')
        
        try:
            queryInputs = {
                SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME: userId
            }
            query = Template(self.samlSubjectSqlQuery).substitute(queryInputs)
            
        except KeyError, e:
            raise AttributeInterfaceConfigError("Invalid key for SAML subject "
                        "query string.  The valid key is %r" % 
                        SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME)    

        log.debug('Checking for SAML subject with SQL Query = "%s"', query)
        try:
            connection = self.__dbEngine.connect()
            result = connection.execute(query)

        except (exc.ProgrammingError, exc.OperationalError):
            raise AttributeInterfaceRetrieveError('SQL error: %s' %
                                                  traceback.format_exc()) 
        finally:
            connection.close()

        try:
            found = [entry for entry in result][0][0] > 0
        
        except (IndexError, TypeError):
            raise AttributeInterfaceRetrieveError("Error with result set: %s" %
                                                  traceback.format_exc())
        
        log.debug('user=%r found=%r' % (userId, found))
        
        return found
     
    def _queryDbForSamlAttributes(self, attributeName, userId):     
        """Query the database in response to a SAML attribute query
        
        This method is called from the getAttributes() method

        @type userId: basestring
        @param userId: user identity
        @rtype: bool
        @return: True/False is user registered?
        """
        
        if self.__dbEngine is None:
            raise AttributeInterfaceConfigError('No connection has been '
                                                'initialised')
        
        queryTmpl = self.samlAttribute2SqlQuery.get(attributeName)
        if queryTmpl is None:
            raise AttributeInterfaceConfigError('No SQL query set for '
                                                'attribute %r' % attributeName)
        
        try:
            queryInputs = {
                SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME: userId
            }
            query = Template(queryTmpl).substitute(queryInputs)
            
        except KeyError, e:
            raise AttributeInterfaceConfigError("Invalid key %s for SAML "
                        "attribute query string.  The valid key is %r" % 
                        (e,
                         SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME))
            
        log.debug('Checking for SAML attributes with SQL Query = "%s"', query)
                
        try:
            connection = self.__dbEngine.connect()
            result = connection.execute(query)
            
        except (exc.ProgrammingError, exc.OperationalError):
            raise AttributeInterfaceRetrieveError('SQL error: %s' %
                                                  traceback.format_exc())
        finally:
            connection.close()

        try:
            attributeValues = [entry[0] for entry in result]
            
        except (IndexError, TypeError):
            raise AttributeInterfaceRetrieveError("Error with result set: "
                                                  "%s" % traceback.format_exc())
        
        log.debug('Database results for SAML Attribute query user=%r '
                  'attribute values=%r' % (userId, attributeValues))
        
        return attributeValues
      
    def __getstate__(self):
        '''Explicit pickling required with __slots__'''
        return dict([(attrName, getattr(self, attrName)) 
                      for attrName in SQLAlchemyAttributeInterface.__slots__])
        
    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        for attr, val in attrDict.items():
            setattr(self, attr, val)            

        
    
        