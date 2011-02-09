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

from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (Response, Assertion, Attribute, 
                                 AttributeStatement, SAMLVersion, Subject, 
                                 NameID, Issuer, Conditions, AttributeQuery, 
                                 XSStringAttributeValue, Status, 
                                 StatusCode, StatusMessage)

from ndg.security.common.saml_utils.esgf import ESGFSamlNamespaces
from ndg.security.common.X509 import X500DN
from ndg.security.common.utils import TypedList
from ndg.security.common.utils.classfactory import instantiateClass
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)


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


class AttributeAuthority(object):
    """NDG Attribute Authority - rewritten with a SAML 2.0 Attribute Query 
    interface for Earth System Grid
    
    @type PROPERTY_DEFAULTS: dict
    @cvar PROPERTY_DEFAULTS: valid configuration property keywords
    
    @type ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS: dict
    @cvar ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS: valid configuration property 
    keywords for the Attribute Interface plugin
    
    @type DEFAULT_CONFIG_DIRNAME: string
    @cvar DEFAULT_CONFIG_DIRNAME: configuration directory under $NDGSEC_DIR - 
    default location for properties file 
    
    @type DEFAULT_PROPERTY_FILENAME: string
    @cvar DEFAULT_PROPERTY_FILENAME: default file name for properties file 
    under DEFAULT_CONFIG_DIRNAME
    
    @type ATTRIBUTE_INTERFACE_OPTPREFIX: basestring
    @param ATTRIBUTE_INTERFACE_OPTPREFIX: attribute interface parameters key 
    name - see initAttributeInterface for details
    """

    DEFAULT_CONFIG_DIRNAME = "conf"
    DEFAULT_PROPERTY_FILENAME = "attributeAuthority.cfg"
    
    # Config file special parameters
    HERE_OPTNAME = 'here'
    PREFIX_OPTNAME = 'prefix'
    
    # Config file option names
    ISSUER_NAME_OPTNAME = 'issuerName'
    ASSERTION_LIFETIME_OPTNAME = 'assertionLifetime'
    
    ATTRIBUTE_INTERFACE_OPTPREFIX = 'attributeInterface'
    ATTRIBUTE_INTERFACE_MOD_FILEPATH_OPTNAME = 'modFilePath'
    ATTRIBUTE_INTERFACE_CLASSNAME_OPTNAME = 'className'
    
    CONFIG_LIST_SEP_PAT = re.compile(',\s*')
    
    
    ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS = {
        ATTRIBUTE_INTERFACE_MOD_FILEPATH_OPTNAME:  '',
        ATTRIBUTE_INTERFACE_CLASSNAME_OPTNAME:    ''
    }
    
    # valid configuration property keywords with accepted default values.  
    # Values set to not NotImplemented here denote keys which must be specified
    # in the config
    PROPERTY_DEFAULTS = { 
        ISSUER_NAME_OPTNAME:            '',
        ASSERTION_LIFETIME_OPTNAME:     -1,
        ATTRIBUTE_INTERFACE_OPTPREFIX:  ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS
    }

    __slots__ = (
        '__assertionLifetime', 
        '__propFilePath',
        '__propFileSection',
        '__propPrefix',
        '__attributeInterface',
        '__attributeInterfaceCfg'
    )
    
    def __init__(self):
        """Create new Attribute Authority instance"""
        log.info("Initialising service ...")
        
        # Initial config file property based attributes
        self.__assertionLifetime = None
        
        self.__propFilePath = None        
        self.__propFileSection = 'DEFAULT'
        self.__propPrefix = ''
        
        self.__attributeInterfaceCfg = \
                AttributeAuthority.ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS.copy()
        
    def __getstate__(self):
        '''Enable pickling with __slots__'''
        _dict = {}
        for attrName in AttributeAuthority.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_AttributeAuthority" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
  
    def __setstate__(self, attrDict):
        '''Enable pickling with __slots__'''
        for attrName, val in attrDict.items():
            setattr(self, attrName, val)
    
    def _getAssertionLifetime(self):
        return self.__assertionLifetime

    def _setAssertionLifetime(self, value):
        if isinstance(value, float):
            self.__assertionLifetime = value
            
        elif isinstance(value, (basestring, int, long)):
            self.__assertionLifetime = float(value)
        else:
            raise TypeError('Expecting float, int, long or string type for '
                            '"assertionLifetime"; got %r' % type(value))

    def _getAttributeInterface(self):
        return self.__attributeInterface

    def _setAttributeInterface(self, value):
        if not isinstance(value, AttributeInterface):
            raise TypeError('Expecting %r type for "attributeInterface" '
                            'attribute; got %r' %
                            (AttributeInterface, type(value)))
            
        self.__attributeInterface = value

    def _get_attributeInterfaceCfg(self):
        return self.__attributeInterfaceCfg
    
    attributeInterfaceCfg = property(fget=_get_attributeInterfaceCfg,
                                     doc="Settings for Attribute Interface "
                                         "initialisation")

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

    assertionLifetime = property(fget=_getAssertionLifetime, 
                                 fset=_setAssertionLifetime, 
                                 doc="validity lifetime (s) for Attribute "
                                     "assertions issued")

    attributeInterface = property(fget=_getAttributeInterface, 
                                  fset=_setAttributeInterface,
                                  doc="Attribute Interface object")
        
    @classmethod
    def fromPropertyFile(cls, propFilePath=None, section='DEFAULT',
                         prefix='attributeauthority.'):
        """Create new NDG Attribute Authority instance from the property file
        settings

        @type propFilePath: string
        @param propFilePath: path to file containing Attribute Authority
        configuration parameters.  It defaults to $NDGSEC_AA_PROPFILEPATH or
        if not set, $NDGSEC_DIR/conf/attributeAuthority.cfg
        @type section: basestring
        @param section: section of properties file to read from.
        properties files
        @type prefix: basestring
        @param prefix: set a prefix for filtering attribute authority
        property names - useful where properties are being parsed from a file
        section containing parameter names for more than one application
        """
            
        attributeAuthority = AttributeAuthority()
        if section:
            attributeAuthority.propFileSection = section
            
        if prefix:
            attributeAuthority.propPrefix = prefix

        # If path is None it will default to setting derived from environment
        # variable - see setPropFilePath()
        attributeAuthority.propFilePath = propFilePath
                     
        attributeAuthority.readProperties()
        attributeAuthority.initialise()
    
        return attributeAuthority

    @classmethod
    def fromProperties(cls, prefix='attributeauthority.', **prop):
        """Create new NDG Attribute Authority instance from input property
        keywords

        @type propPrefix: basestring
        @param propPrefix: set a prefix for filtering attribute authority
        property names - useful where properties are being parsed from a file
        section containing parameter names for more than one application
        """
        attributeAuthority = AttributeAuthority()
        if prefix:
            attributeAuthority.propPrefix = prefix
               
        attributeAuthority.setProperties(**prop)
        attributeAuthority.initialise()
        
        return attributeAuthority
    
    def initialise(self):
        """Convenience method for set up of Attribute Interface, map
        configuration and PKI"""

        # Instantiate Certificate object
        log.debug("Reading and checking Attribute Authority X.509 cert. ...")
        
        # Load user - user attribute look-up plugin 
        self.initAttributeInterface()

    def setProperties(self, **prop):
        """Set configuration from an input property dictionary
        @type prop: dict
        @param prop: properties dictionary containing configuration items
        to be set
        """
        lenPropPrefix = len(self.propPrefix)
        
        # '+ 1' allows for the dot separator 
        lenAttributeInterfacePrefix = len(
                        AttributeAuthority.ATTRIBUTE_INTERFACE_OPTPREFIX) + 1
        
        for name, val in prop.items():
            if name.startswith(self.propPrefix):
                name = name[lenPropPrefix:]
            
            if name.startswith(
                            AttributeAuthority.ATTRIBUTE_INTERFACE_OPTPREFIX):
                name = name[lenAttributeInterfacePrefix:]
                self.attributeInterfaceCfg[name] = val
                continue
            
            if name not in AttributeAuthority.PROPERTY_DEFAULTS:
                raise AttributeError('Invalid attribute name "%s"' % name)
            
            if isinstance(val, basestring):
                val = os.path.expandvars(val)
            
            if isinstance(AttributeAuthority.PROPERTY_DEFAULTS[name], list):
                val = AttributeAuthority.CONFIG_LIST_SEP_PAT.split(val)
                
            # This makes an implicit call to the appropriate property method
            try:
                setattr(self, name, val)
            except AttributeError:
                raise AttributeError("Can't set attribute \"%s\": %s" % 
                                     (name, traceback.format_exc()))
            
    def readProperties(self):
        '''Read the properties files and do some checking/converting of input 
        values
        '''
        if not os.path.isfile(self.propFilePath):
            raise IOError('Error parsing properties file "%s": No such file' % 
                          self.propFilePath)
            
        defaultItems = {
            AttributeAuthority.HERE_OPTNAME: os.path.dirname(self.propFilePath)
        }
        
        cfg = CaseSensitiveConfigParser(defaults=defaultItems)
        cfg.read(self.propFilePath)
        
        if cfg.has_option(self.propFileSection, 
                          AttributeAuthority.PREFIX_OPTNAME):
            self.propPrefix = cfg.get(self.propFileSection, 
                                      AttributeAuthority.PREFIX_OPTNAME)
            
        cfgItems = dict([(name, val) 
                         for name, val in cfg.items(self.propFileSection)
                         if (name != AttributeAuthority.HERE_OPTNAME and 
                             name != AttributeAuthority.PREFIX_OPTNAME)])
        self.setProperties(**cfgItems)

    def initAttributeInterface(self):
        '''Load host sites custom user roles interface to enable the AA to
        # assign roles in an attribute certificate on a getAttCert request'''
        classProperties = {}
        classProperties.update(self.attributeInterfaceCfg)
        
        className = classProperties.pop('className', None)  
        if className is None:
            raise AttributeAuthorityConfigError('No Attribute Interface '
                                                '"className" property set')
        
        # file path may be omitted    
        modFilePath = classProperties.pop('modFilePath', None) 
                      
        self.__attributeInterface = instantiateClass(className,
                                             moduleFilePath=modFilePath,
                                             objectType=AttributeInterface,
                                             classProperties=classProperties)

    def samlAttributeQuery(self, attributeQuery, samlResponse):
        """Respond to SAML 2.0 Attribute Query
        """
        if not isinstance(attributeQuery, AttributeQuery):
            raise TypeError('Expecting %r for attribute query; got %r' %
                            (AttributeQuery, type(attributeQuery)))
        
        # Attribute Query validation ...
        utcNow = datetime.utcnow()
        if (attributeQuery.subject.nameID.format != 
            ESGFSamlNamespaces.NAMEID_FORMAT):
            log.error('SAML Attribute Query subject format is %r; expecting '
                      '%r' % (attributeQuery.subject.nameID.format,
                                ESGFSamlNamespaces.NAMEID_FORMAT))
            samlResponse.status.statusCode.value = StatusCode.REQUESTER_URI
            samlResponse.status.statusMessage.value = \
                                "Subject Name ID format is not recognised"
            return samlResponse
        
        elif attributeQuery.issuer.format != Issuer.X509_SUBJECT:
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

    def samlAttributeQueryFactory(self):
        """Factory method to create SAML Attribute Query wrapper function
        @rtype: function
        @return: samlAttributeQuery method function wrapper
        """
        def samlAttributeQueryWrapper(attributeQuery, response):
            """Attribute Query method.  This must adhere to the function
            signature specified by 
            ndg.security.server.wsgi.saml.SOAPQueryInterfaceMiddleware
            @type attributeQuery: ndg.saml.saml2.core.AttributeQuery
            @param attributeQuery: SAML Attribute Query
            @rtype: ndg.saml.saml2.core.Response
            @return: SAML response
            """
            return self.samlAttributeQuery(attributeQuery, response)
        
        return samlAttributeQueryWrapper
    
               
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


import traceback
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
    CONNECTION_STRING_OPTNAME = 'connectionString'
    ATTRIBUTE_SQLQUERY_OPTNAME = 'attributeSqlQuery'
    SAML_SUBJECT_SQLQUERY_OPTNAME = 'samlSubjectSqlQuery'
    SAML_VALID_REQUESTOR_DNS_OPTNAME = 'samlValidRequestorDNs'
    SAML_ASSERTION_LIFETIME_OPTNAME = 'samlAssertionLifetime'
    SAML_ATTRIBUTE2SQLQUERY_OPTNAME = 'samlAttribute2SqlQuery'
    SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN = len(SAML_ATTRIBUTE2SQLQUERY_OPTNAME)
    
    SAML_ATTRIBUTE2SQLQUERY_ATTRNAME_DELIMITERS = ('.', '_')
    
    __slots__ = (
        CONNECTION_STRING_OPTNAME,
        ATTRIBUTE_SQLQUERY_OPTNAME,
        SAML_SUBJECT_SQLQUERY_OPTNAME,
        SAML_VALID_REQUESTOR_DNS_OPTNAME,
        SAML_ASSERTION_LIFETIME_OPTNAME,
        SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
    )
    __PRIVATE_ATTR_PREFIX = '_SQLAlchemyAttributeInterface__'
    __slots__ += tuple([__PRIVATE_ATTR_PREFIX + i for i in __slots__])
    del i
    
#    For Reference - split based on space separated ' or " quoted items
#    SAML_VALID_REQUESTOR_DNS_PAT = re.compile("['\"]?\s*['\"]")
    
    SAML_VALID_REQUESTOR_DNS_PAT = re.compile(',\s*')
    
    def __init__(self, **properties):
        '''Instantiate object taking in settings from the input properties'''
        log.debug('Initialising SQLAlchemyAttributeInterface instance ...')
        
        if not sqlAlchemyInstalled:
            raise AttributeInterfaceConfigError("SQLAlchemy is not installed")

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
            
        elif (len(name) > cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN and
              name[cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN] in 
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

    connectionString = property(fget=_getConnectionString, 
                                fset=_setConnectionString, 
                                doc="Database connection string")

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

        dbEngine = create_engine(self.connectionString)
        connection = dbEngine.connect()
        
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
    
        # Assumes SAML response issuer name set independently - 
        # ndg.security.server.wsgi.saml.SOAPQueryInterfaceMiddleware
        assertion.issuer = Issuer()
        assertion.issuer.value = response.issuer.value
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
        
        if self.connectionString is None:
            raise AttributeInterfaceConfigError('No "connectionString" setting '
                                                'has been made')
            
        dbEngine = create_engine(self.connectionString)
        
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
            connection = dbEngine.connect()
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
        
        if self.connectionString is None:
            raise AttributeInterfaceConfigError('No "connectionString" setting '
                                                'has been made')

        dbEngine = create_engine(self.connectionString)
        
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
            connection = dbEngine.connect()
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

        
    
        