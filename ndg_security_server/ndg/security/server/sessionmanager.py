"""NDG Security server side session management and security includes 
UserSession and SessionManager classes.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/06/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:sessionmanager.py 4367 2008-10-29 09:27:59Z pjkersha $'
import logging
log = logging.getLogger(__name__)

import os

# Base 64 encode session IDs if returned in strings - urandom's output may
# not be suitable for printing!
import base64

# Time module for use with cookie expiry
from datetime import datetime, timedelta

# Credential Wallet
from ndg.security.common.credentialwallet import (NDGCredentialWallet, 
    CredentialRepository, CredentialWalletError, 
    CredentialWalletAttributeRequestDenied, NullCredentialRepository)
    
from ndg.security.common.wssecurity import WSSecurityConfig
from ndg.security.common.X509 import (X500DN, X509Cert, X509CertParse, 
    X509CertExpired, X509CertInvalidNotBeforeTime) 

# generic parser to read INI/XML properties file
from ndg.security.common.utils.configfileparsers import (
                                                INIPropertyFileWithValidation)

# utility to instantiate classes dynamically
from ndg.security.common.utils.classfactory import instantiateClass


class _SessionException(Exception):
    """Base class for all Exceptions in this module.  Overrides Exception to 
    enable writing to the log"""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)

class UserSessionError(_SessionException):    
    """Exception handling for NDG User Session class."""

class InvalidUserSession(UserSessionError):    
    """Problem with a session's validity"""

class UserSessionExpired(UserSessionError):    
    """Raise when session's X.509 cert. has expired"""

class UserSessionNotBeforeTimeError(UserSessionError):    
    """Raise when session's X.509 cert. not before time is before the current
    system time"""
   

# Inheriting from 'object' allows Python 'new-style' class with Get/Set
# access methods
class UserSession(object):
    """Session details - created when a user logs into NDG"""
    sessIdLen = 32
    
    def __init__(self, lifetime=28800, **credentialWalletKeys):
        """Initialise UserSession with keywords to NDGCredentialWallet
        
        @type lifetime: int / float
        @param lifetime: lifetime of session in seconds before it is scheduled
        to time out and becomes invalid - see isValid()
        """
                
        log.debug("UserSession.__init__ ...")
        
        # Set time stamp to enable auditing to remove stale sessions.  The
        # user's credential wallet may contain a user certificate which may
        # also be checked for expiry using NDGCredentialWallet.isValid() but there
        # may be no user certificate set.  This code is an extra provision to
        # to allow for this
        self.__dtCreationTime = datetime.utcnow()
        self.lifetime = lifetime
        
        # Each User Session has one or more browser sessions associated with
        # it.  These are stored in a list
        self.__sessIdList = []
        self.addNewSessID()
        self.__credentialWallet = NDGCredentialWallet(**credentialWalletKeys)

        log.info("Created a session with ID = %s" % self.__sessIdList[-1])

    def __getDtCreationTime(self):
        return self.__dtCreationTime
    
    dtCreationTime = property(fget=__getDtCreationTime,
                              doc="time at which the session was created as a "
                                  "datetime.datetime instance")
    
    def __setLifetime(self, lifetime):
        if not isinstance(lifetime, (int, float)):
            raise TypeError("Expecting int or float type for session lifetime "
                            "attribute; got %s instead" % type(lifetime))
        self.__lifetime = lifetime
        
    def __getLifetime(self):
        return self.__lifetime
       
    lifetime = property(fget=__getLifetime,
                        fset=__setLifetime,
                        doc="lifetime of session in seconds before it is "
                            "scheduled to time out and becomes invalid")
    
    def isValidTime(self, raiseExcep=False):
        """Return True if the session is within it's validity time
        
        @type raiseExcep: bool
        @param raiseExcep: set to True to raise an exception if the session
        has an invalid time
       
        @raise UserSessionNotBeforeTimeError: current time is BEFORE the 
        creation time for this session i/e/ something is seriously wrong
        @raise UserSessionExpired: this session has expired
        """
        dtNow = datetime.utcnow()
        dtNotAfter = self.dtCreationTime + timedelta(seconds=self.lifetime)
        
        if raiseExcep:
            if dtNow < self.__dtCreationTime:
                raise UserSessionNotBeforeTimeError("Current time %s is "
                        "before session's not before time of %s" % 
                        (dtNow.strftime("%d/%m/%Y %H:%M:%S"),
                         self.__dtCreationTime.strftime("%d/%m/%Y %H:%M:%S")))
            
            if dtNow > dtNotAfter:
                raise UserSessionExpired("Current time %s is after session's "
                        "expiry time of %s" % 
                        (dtNow.strftime("%d/%m/%Y %H:%M:%S"),
                         self.__dtCreationTime.strftime("%d/%m/%Y %H:%M:%S")))                
        else:   
            return dtNow > self.dtCreationTime and dtNow < dtNotAfter        
    
    def isValid(self, raiseExcep=False):
        """Return True if this session is valid.  This checks the 
        validity time calling isValidTime and the validity of the Credential
        Wallet held
        
        @type raiseExcep: bool
        @param raiseExcep: set to True to raise an exception if the session
        is invalid
        @raise UserSessionNotBeforeTimeError: current time is before session 
        creation time
        @raise UserSessionExpired: session has expired
        @raise X509CertInvalidNotBeforeTime: X.509 certificate held by the
        NDGCredentialWallet is set after the current time
        @raise X509CertExpired: X.509 certificate held by the
        NDGCredentialWallet has expired
        """
        if not self.isValidTime(raiseExcep=raiseExcep):
            return False
        
        if not self.credentialWallet.isValid(raiseExcep=raiseExcep):
            return False
        
        return True
    
    
    def __getCredentialWallet(self):
        """Get Credential Wallet instance"""
        return self.__credentialWallet
    
    credentialWallet = property(fget=__getCredentialWallet,
                                doc="Read-only access to NDGCredentialWallet "
                                    "instance")

    def __getSessIdList(self):
        """Get Session ID list - last item is latest allocated for this
        session"""
        return self.__sessIdList
    
    sessIdList = property(fget=__getSessIdList,
                          doc="Read-only access to Session ID list")

    def __latestSessID(self):
        """Get the session ID most recently allocated"""
        return self.__sessIdList[-1]
    
    # Publish as an attribute
    latestSessID = property(fget=__latestSessID,
                            doc="Latest Session ID allocated")

    def addNewSessID(self):
        """Add a new session ID to be associated with this UserSession
        instance"""

        # base 64 encode output from urandom - raw output from urandom is
        # causes problems when passed over SOAP.  A consequence of this is
        # that the string length of the session ID will almost certainly be
        # longer than UserSession.sessIdLen
        sessID = base64.urlsafe_b64encode(os.urandom(UserSession.sessIdLen))
        self.__sessIdList.append(sessID)
        
class SessionManagerError(_SessionException):    
    """Exception handling for NDG Session Manager class."""

class SessionNotFound(SessionManagerError):
    """Raise from SessionManager._connect2UserSession when session ID is not 
    found in the Session dictionary"""


class SessionManager(dict):
    """NDG authentication and session handling
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: list of the valid properties file element names and
    sub-elements where appropriate
    
    @type _confDir: string
    @cvar _confDir: configuration directory under $NDGSEC_DIR - default 
    location for properties file 
    
    @type _propFileName: string
    @cvar _propFileName: default file name for properties file under 
    _confDir
    
    @type credentialRepositoryPropertyDefaults: dict
    @cvar credentialRepositoryPropertyDefaults: permitted properties file 
    elements for configuring the Crendential Repository.  Those set to 
    NotImplemented indicate properties that must be set.  For the others, the 
    value indicates the default if not present in the file"""

    # Valid configuration property keywords
    AUTHN_KEYNAME = 'authNService'   
    CREDREPOS_KEYNAME = 'credentialRepository'    
    CREDWALLET_KEYNAME = 'credentialWallet'
    defaultSectionName = 'sessionManager'
    
    authNServicePropertyDefaults = {
        'moduleFilePath': None,
        'moduleName': None,
        'className': None,
    }
    
    credentialRepositoryPropertyDefaults = {
        'moduleFilePath': None,
        'moduleName': None,
        'className': 'NullCredentialRepository',
    }

    propertyDefaults = {
        'portNum':                None,
        'useSSL':                 False,
        'sslCertFile':            None,
        'sslKeyFile':             None,
        'sslCACertDir':           None,
        AUTHN_KEYNAME:            authNServicePropertyDefaults, 
        CREDREPOS_KEYNAME:        credentialRepositoryPropertyDefaults
    }

    _confDir = "conf"
    _propFileName = "sessionMgrProperties.xml"
    
    def __init__(self, 
                 propFilePath=None, 
                 propFileSection='DEFAULT',
                 propPrefix='',
                 **prop):       
        """Create a new session manager to manager NDG User Sessions
        
        @type propFilePath: basestring
        @param propFilePath: path to properties file
        @type propFileSection: basestring
        @param propFileSection: applies to ini format config files only - the 
        section to read the Session Managers settings from
        set in properties file
        @type prop: dict
        @param **prop: set any other properties corresponding to the tags in 
        the properties file as keywords"""        

        log.info("Initialising service ...")
        
        # Base class initialisation
        dict.__init__(self)

        # Key user sessions by session ID
        self.__sessDict = {}

        # Key user sessions by user DN
        self.__dnDict = {}

        # Finally, also key by username
        self.__usernameDict = {}
        
        self._propFileSection = ''
        self._propPrefix = ''
        
        # Credential Repository interface only set if properties file is set
        # otherwise explicit calls are necessary to set 
        # credentialRepositoryProp via setProperties/readProperties and then 
        # loadCredentialRepositoryInterface
        self._credentialRepository = None
    
        # Set from input or use defaults based or environment variables
        self.propFilePath = propFilePath
        
        self.propFileSection = propFileSection
        self.propPrefix = propPrefix
        self._cfg = None
        
        # Set properties from file
        self.readProperties()

        
        # Set any properties that were provided by keyword input
        # NB If any are duplicated with tags in the properties file they
        # will overwrite the latter
        self.setProperties(**prop)

        # Instantiate the authentication service to use with the session 
        # manager
        self.initAuthNService()
        
        # Call here as we can safely expect that all Credential Repository
        # parameters have been set above
        self.initCredentialRepository()    
        
        
    def initAuthNService(self):
        '''Load Authentication Service Interface from property settings'''
        authNProp = self.__prop[SessionManager.AUTHN_KEYNAME]
        authNModFilePath = authNProp.pop('moduleFilePath', None)
        
        self.__authNService = instantiateClass(authNProp.pop('moduleName'),
                                               authNProp.pop('className'),
                                               moduleFilePath=authNModFilePath,
                                               objectType=AbstractAuthNService, 
                                               classProperties=authNProp)            
        
    def initCredentialRepository(self):
        '''Load Credential Repository instance from property settings
        If non module or class name were set a null interface is loaded by
        default'''
        
        credReposProp = self.__prop.get(SessionManager.CREDREPOS_KEYNAME, {})

        credentialRepositoryModule = credReposProp.get('moduleName')
        credentialRepositoryClassName = credReposProp.get('className')
            
        if credentialRepositoryModule is None or \
           credentialRepositoryClassName is None:
            # Default to NullCredentialRepository if no settings have been made
            self._credentialRepository = NullCredentialRepository()
        else:
            credReposModuleFilePath = credReposProp.get('moduleFilePath')
                
            self._credentialRepository = instantiateClass(
                                        credentialRepositoryModule,
                                        credentialRepositoryClassName,
                                        moduleFilePath=credReposModuleFilePath,
                                        objectType=CredentialRepository,
                                        classProperties=credReposProp)

    def __delitem__(self, key):
        "Session Manager keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from '+self.__class__.__name__)
    
    def __getitem__(self, key):
        """Enables behaviour as data dictionary of Session Manager properties
        """
        if key not in self.__prop:
            raise KeyError("Invalid key '%s'" % key)
        
        return self.__prop[key]
    
    def __setitem__(self, key, item):
        self.__class__.__name__ + """ behaves as data dictionary of Session
        Manager properties"""
        self.setProperties(**{key: item})
           
    def get(self, kw):
        return self.__prop.get(kw)

    def clear(self):
        raise KeyError("Data cannot be cleared from "+SessionManager.__name__)
   
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
        log.debug("Setting property file path")
        if not val:
            if 'NDGSEC_SM_PROPFILEPATH' in os.environ:
                val = os.environ['NDGSEC_SM_PROPFILEPATH']
                
                log.debug('Set properties file path "%s" from '
                          '"NDGSEC_SM_PROPFILEPATH"' % val)

            elif 'NDGSEC_DIR' in os.environ:
                val = os.path.join(os.environ['NDGSEC_DIR'], 
                                   self.__class__._confDir,
                                   self.__class__._propFileName)

                log.debug('Set properties file path %s from "NDGSEC_DIR"'%val)
            else:
                raise AttributeError('Unable to set default Session '
                                     'Manager properties file path: neither ' 
                                     '"NDGSEC_SM_PROPFILEPATH" or "NDGSEC_DIR"'
                                     ' environment variables are set')
        else:
             log.debug('Set properties file path %s from user input' % val)       

        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file path must be a valid "
                                 "string.")
      
        self._propFilePath = os.path.expandvars(val)
        log.debug("Path set to: %s" % val)
        
    def getPropFilePath(self):
        log.debug("Getting property file path")
        if hasattr(self, '_propFilePath'):
            return self._propFilePath
        else:
            return ""
        
    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            fget=getPropFilePath,
                            doc="Set the path to the properties file")   
        
    def getPropFileSection(self):
        '''Get the section name to extract properties from an ini file -
        DOES NOT apply to XML file properties
        
        @rtype: basestring
        @return: section name'''
        log.debug("Getting property file section name")
        return self._propFileSection  
    
    def setPropFileSection(self, val=None):
        """Set section name to read properties from ini file.  This is set from
        input or based on environment variable setting 
        NDGSEC_SM_PROPFILESECTION
        
        @type val: basestring
        @param val: section name"""
        log.debug("Setting property file section name")
        if not val:
            val = os.environ.get('NDGSEC_SM_PROPFILESECTION', 'DEFAULT')
                
        if not isinstance(val, basestring):
            raise AttributeError("Input Properties file section name "
                                 "must be a valid string.")
      
        self._propFileSection = val
        log.debug("Properties file section set to: %s" % val)
        
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
        return self._propPrefix
        
    # Also set up as a property
    propPrefix = property(fset=setPropPrefix,
                          fget=getPropPrefix,
                          doc="Set a prefix for ini file properties")   

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
        readPropertiesFile = INIPropertyFileWithValidation()
        fileProp=readPropertiesFile(self.propFilePath,
                                    validKeys=SessionManager.propertyDefaults,
                                    prefix=prefix,
                                    sections=(section,))
        
        # Keep a copy of the config file for the NDGCredentialWallet to reference 
        # so that it can retrieve WS-Security settings
        self._cfg = readPropertiesFile.cfg
        
        # Allow for section and prefix names which will nest the Attribute
        # Authority properties in a hierarchy
        propBranch = fileProp
        if section != 'DEFAULT':
            propBranch = propBranch[section]
            
        self.__prop = propBranch

        log.info('Loaded properties from "%s"' % self.propFilePath)

    @staticmethod
    def _setProperty(value):
        if value and isinstance(value, basestring):
            return os.path.expandvars(value).strip()
        else:
            return value              
        
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        log.debug("Calling SessionManager.setProperties with kw = %s" % prop)
        
        for key in prop.keys():
            if key not in self.propertyDefaults:
                raise SessionManagerError('Property name "%s" is invalid'%key)
            
        for key, value in prop.iteritems():
                       
            if key == SessionManager.AUTHN_KEYNAME:
                for subKey, subVal in prop[key].iteritems():
#                    if subKey not in \
#                       SessionManager.authNServicePropertyDefaults:
#                        raise SessionManagerError('Key "%s" is not a valid '
#                                            'Session Manager AuthNService '
#                                            'property' % subKey)
#                        
                    if subVal:
                        self.__prop[key][subKey] = SessionManager._setProperty(
                                                                        subVal)
    
            elif key == SessionManager.CREDREPOS_KEYNAME:
                for subKey, subVal in self.__prop[key].iteritems():
#                    if subKey not in \
#                       SessionManager.credentialRepositoryPropertyDefaults:
#                        raise SessionManagerError('Key "%s" is not a valid '
#                                        'Session Manager credentialRepository '
#                                        'property' % subKey)
#                        
                    if subVal:
                        self.__prop[key][subKey] = SessionManager._setProperty(
                                                                        subVal)

            elif key in SessionManager.propertyDefaults:
                # Only update other keys if they are not None or ""
                if value:
                    self.__prop[key] = SessionManager._setProperty(value)             
            else:
                raise SessionManagerError('Key "%s" is not a valid Session '
                                          'Manager property' % key)
        
    def getSessionStatus(self, sessID=None, userDN=None):
        """Check the status of a given session identified by sessID or 
        user Distinguished Name
        
        @type sessID: string
        @param sessID: session identifier as returned from a call to connect()
        @type userDN: string
        @param userDN: user Distinguished Name of session to check
        @rtype: bool
        @return: True if session is active, False if no session found"""

        log.debug("Calling SessionManager.getSessionStatus ...")
        
        # Look for a session corresponding to this ID
        if sessID and userDN:
            raise SessionManagerError('Only "SessID" or "userDN" keywords may '
                                      'be set')
        elif sessID:
            if sessID in self.__sessDict:               
                log.info("Session found with ID = %s" % sessID)
                return True
            else:
                # User session not found with given ID
                log.info("No user session found matching input ID = %s"%sessID)
                return False
                          
        elif userDN:
            try:
                # Enables re-ordering of DN fields for following dict search
                userDN = str(X500DN(userDN))
                
            except Exception, e:
                log.error("Parsing input user certificate DN for "
                          "getSessionStatus: %s" % e)
                raise
            
            if userDN in self.__dnDict:
                log.info("Session found with DN = %s" % userDN)
                return True                        
            else:
                # User session not found with given proxy cert
                log.info("No user session found matching input userDN = %s" %
                         userDN)
                return False

    def connect(self, 
                createServerSess=True,
                username=None,
                passphrase=None, 
                userX509Cert=None, 
                sessID=None):        
        """Create a new user session or connect to an existing one:

        connect([createServerSess=True/False, ]|[, username=u, passphrase=p]|
                [, userX509Cert=px]|[, sessID=id])

        @type createUserSess: bool
        @param createServerSess: If set to True, the SessionManager will create
        and manage a session for the user.  For command line case, it's 
        possible to choose to have a client or server side session using this 
        keyword.
        
        @type username: string
        @param username: username of account to connect to

        @type passphrase: string
        @param passphrase: pass-phrase - user with username arg
        
        @type userX509Cert: string
        @param userX509Cert: connect to existing session with proxy certificate
        corresponding to user.  username/pass-phrase not required
        
        @type sessID: string
        @param sessID: connect to existing session corresponding to this ID.
        username/pass-phrase not required.
        
        @rtype: tuple
        @return user certificate, private key, issuing certificate and 
        session ID respectively.  Session ID will be none if createUserSess 
        keyword is set to False
        
        @raise AuthNServiceError: error with response from Authentication
        service.  An instance of this class or derived class instance may be
        raised.
        """
        
        log.debug("Calling SessionManager.connect ...")
        
        # Initialise proxy cert to be returned
        userX509Cert = None
        
        if sessID is not None:            
            # Connect to an existing session identified by a session ID and 
            # return equivalent proxy cert
            userSess = self._connect2UserSession(sessID=sessID)
            userX509Cert = userSess.credentialWallet.userX509Cert
            
        elif userX509Cert is not None:
            # Connect to an existing session identified by a proxy 
            # certificate 
            userSess = self._connect2UserSession(userX509Cert=userX509Cert)
            sessID = userSess.latestSessID
            
        else:
            # Create a fresh session
            try:
                # Get a proxy certificate to represent users ID for the new
                # session
                userCreds = self.__authNService.logon(username, passphrase)
            except AuthNServiceError:
                # Filter out known AuthNService exceptions
                raise
            except Exception, e:
                # Catch all here for AuthNService but the particular 
                # implementation should make full use of AuthN* exception
                # types
                raise AuthNServiceError("Authentication Service: %s" % e)
                            
            # Unpack output
            if userCreds is None:
                nUserCreds = 0
            else:
                nUserCreds = len(userCreds)
                
            if nUserCreds > 1:
                userX509Cert = userCreds[0]
                userPriKey = userCreds[1]
            else:
                userX509Cert = userPriKey = None
                
            # Issuing cert is needed only if userX509Cert is a proxy
            issuingCert = nUserCreds > 2 and userCreds[2] or None        

            if createServerSess:
                # Session Manager creates and manages user's session
                userSess = self.createUserSession(username, 
                                                  passphrase,
                                                userCreds)
                sessID = userSess.latestSessID
            else:
                sessID = None
                                
        # Return proxy details and cookie
        return userX509Cert, userPriKey, issuingCert, sessID        
        
       
    def createUserSession(self, username, userPriKeyPwd=None, userCreds=None):
        """Create a new user session from input user credentials       
        and return it.  This is an alternative to connect() useful in cases
        where a session needs to be created for an existing authenticated user
        
        @type username: basestring
        @param username: username user logged in with
        @type userPriKeyPwd: basestring
        @param userPriKeyPwd: password protecting the private key if set.
        @type userCreds: tuple
        @param userCreds: tuple containing user certificate, private key
        and optionally an issuing certificate.  An issuing certificate is
        present if user certificate is a proxy and therefore it's issuer is
        other than the CA. userCreds may default to None if no user certificate
        is available.  In this case, the Session Manager server certificate
        is used to secure connections to Attribute Authorities and other 
        services where required
        
        @raise SessionManagerError: session ID added already exists in session
        list
        @raise ndg.security.common.X509.X509CertError: from parsing X.509 cert
        set in the userCreds keyword"""
        
        log.debug("Calling SessionManager.createUserSession ...")
        
        # Check for an existing session for the same user
        if username in self.__usernameDict:
            # Update existing session with user cert and add a new 
            # session ID to access it - a single session can be accessed
            # via multiple session IDs e.g. a user may wish to access the
            # same session from the their desktop PC and their laptop.
            # Different session IDs are allocated in each case.
            userSess = self.__usernameDict[username]
            userSess.addNewSessID()            
        else:
            # Create a new user session using the username, session ID and
            # X.509 credentials

            # Copy global Credential Wallet settings into specific set for this
            # user
            if self.propPrefix:
                credentialWalletPropPfx = '.'.join((self.propPrefix, 
                                            SessionManager.CREDWALLET_KEYNAME))
            else:
                credentialWalletPropPfx = SessionManager.CREDWALLET_KEYNAME
                
            # Include cfg setting to enable WS-Security Signature handler to 
            # pick up settings
            credentialWalletProp = {
                'cfg': self._cfg,
                'userId': username,
                'userPriKeyPwd': userPriKeyPwd,
                'credentialRepository': self._credentialRepository,
                'cfgPrefix': credentialWalletPropPfx
            }
                                                    
    
            # Update user PKI settings if any are present
            if userCreds is None:
                nUserCreds = 0
            else:
                nUserCreds = len(userCreds)
                
            if nUserCreds > 1:
                credentialWalletProp['userX509Cert'] = userCreds[0]
                credentialWalletProp['userPriKey'] = userCreds[1]
            
            if nUserCreds == 3:
                credentialWalletProp['issuingX509Cert'] = userCreds[2]
                
            try:   
                userSess = UserSession(**credentialWalletProp)     
            except Exception, e:
                log.error("Creating User Session: %s" % e)
                raise 
            
            # Also allow access by user DN if individual user PKI credentials 
            # have been passed in
            if userCreds is not None:
                try:
                    userDN = str(X509CertParse(userCreds[0]).dn)
                    
                except Exception, e:
                    log.error("Parsing input certificate DN for session "
                              "create: %s" % e)
                    raise

                self.__dnDict[userDN] = userSess
        
        newSessID = userSess.latestSessID
        
        # Check for unique session ID
        if newSessID in self.__sessDict:
            raise SessionManagerError("New Session ID is already in use:\n\n "
                                      "%s" % newSessID)

        # Add new session to list                 
        self.__sessDict[newSessID] = userSess
                        
        # Return new session
        return userSess


    def _connect2UserSession(self,username=None,userX509Cert=None,sessID=None):
        """Connect to an existing session by providing a valid session ID or
        proxy certificate

        _connect2UserSession([username|userX509Cert]|[sessID])

        @type username: string
        @param username: username
        
        @type userX509Cert: string
        @param userX509Cert: user's X.509 certificate corresponding to an 
        existing session to connect to.
        
        @type sessID: string
        @param sessID: similiarly, a web browser session ID linking to an
        an existing session.
        
        @raise SessionNotFound: no matching session to the inputs
        @raise UserSessionExpired: existing session has expired
        @raise InvalidUserSession: user credential wallet is invalid
        @raise UserSessionNotBeforeTimeError: """
        
        log.debug("Calling SessionManager._connect2UserSession ...")
            
        # Look for a session corresponding to this ID
        if username:
            userSess = self.__usernameDict.get(username)
            if userSess is None:
                log.error("Session not found for username=%s" % username)
                raise SessionNotFound("No user session found matching the "
                                      "input username")

            if userSess.credentialWallet.userX509Cert:
                userDN = userSess.credentialWallet.userX509Cert.dn
            else:
                userDN = None
                
            log.info("Connecting to session userDN=%s; sessID=%s using "
                     "username=%s" % (userDN, userSess.sessIdList, username))            
        elif sessID:
            userSess = self.__sessDict.get(sessID)
            if userSess is None:  
                log.error("Session not found for sessID=%s" % sessID)
                raise SessionNotFound("No user session found matching input "
                                      "session ID")
                
            if userSess.credentialWallet.userX509Cert:
                userDN = userSess.credentialWallet.userX509Cert.dn
            else:
                userDN = None
                
            log.info("Connecting to session userDN=%s; username=%s using "
                     "sessID=%s" % (userDN, username, userSess.sessIdList))

        elif userX509Cert is not None:
            if isinstance(userX509Cert, basestring):
                try:
                    userDN = str(X509CertParse(userX509Cert).dn)
                    
                except Exception, e:
                    log.error("Parsing input user certificate DN for session "
                              "connect: %s" %e)
                    raise
            else:
                try:
                    userDN = str(userX509Cert.dn)
                    
                except Exception, e:
                    log.error("Parsing input user certificate DN for session "
                              "connect: %s" % e)
                    raise
                
            userSess = self.__dnDict.get(userDN)
            if userSess is None:
                log.error("Session not found for userDN=%s" % userDN)
                raise SessionNotFound("No user session found matching input "
                                      "user X.509 certificate")
            
            log.info("Connecting to session sessID=%s; username=%s using "
                     "userDN=%s" % (userSess.sessIdList, 
                                    userSess.credentialWallet.userId, 
                                    userDN))
        else:
            raise KeyError('"username", "sessID" or "userX509Cert" keywords '
                           'must be set')
            
        # Check that the Credentials held in the wallet are still valid            
        try:
            userSess.isValid(raiseExcep=True)
            return userSess
        
        except (UserSessionNotBeforeTimeError,X509CertInvalidNotBeforeTime), e:
            # ! Delete user session since it's user certificate is invalid
            self.deleteUserSession(userSess=userSess)
            raise       
    
        except (UserSessionExpired, X509CertExpired), e:
            # ! Delete user session since it's user certificate is invalid
            self.deleteUserSession(userSess=userSess)
            raise      
        
        except Exception, e:
            raise InvalidUserSession("User session is invalid: %s" % e)
                

    def deleteUserSession(self, sessID=None, userX509Cert=None, userSess=None):
        """Delete an existing session by providing a valid session ID or
        proxy certificate - use for user logout

        deleteUserSession([userX509Cert]|[sessID]|[userSess])
        
        @type userX509Cert: ndg.security.common.X509.X509Cert 
        @param userX509Cert: proxy certificate corresponding to an existing 
        session to connect to.
        
        @type sessID: string
        @param sessID: similiarly, a web browser session ID linking to an
        an existing session.
        
        @type userSess: UserSession
        @param userSess: user session object to be deleted
        """
        
        log.debug("Calling SessionManager.deleteUserSession ...")
        
        # Look for a session corresponding to the session ID/proxy cert.
        if sessID:
            try:
                userSess = self.__sessDict[sessID]
                
            except KeyError:
                raise SessionManagerError("Deleting user session - "
                                          "no matching session ID exists")

            # Get associated user Distinguished Name if a certificate has been
            # set
            if userSess.credentialWallet.userX509Cert is None:
                userDN = None
            else:
                userDN = str(userSess.credentialWallet.userX509Cert.dn)
            
        elif userX509Cert:
            try:
                userDN = str(userX509Cert.dn)
                
            except Exception, e:
                raise SessionManagerError("Parsing input user certificate "
                                          "DN for session connect: %s" % e)
            try:
                userSess = self.__dnDict[userDN]
                        
            except KeyError:
                # User session not found with given proxy cert
                raise SessionManagerError("No user session found matching "
                                          "input user certificate")        
        elif userSess:
            if userSess.credentialWallet.userX509Cert is None:
                userDN = None
            else:
                userDN = str(userSess.credentialWallet.userX509Cert.dn)
        else:
            # User session not found with given ID
            raise SessionManagerError('"sessID", "userX509Cert" or "userSess" '
                                      'keywords must be set')
 
        # Delete associated sessions
        try:
            # Each session may have a number of session IDs allocated to
            # it.  
            #
            # Use pop rather than del so that key errors are ignored
            for userSessID in userSess.sessIdList:
                self.__sessDict.pop(userSessID, None)

            self.__dnDict.pop(userDN, None)
        
        except Exception, e:
            raise SessionManagerError("Deleting user session: %s" % e)  

        log.info("Deleted user session: user DN = %s, sessID = %s" %
                 (userDN, userSess.sessIdList))

    def auditSessions(self):
        """Remove invalid sessions i.e. ones which have expired"""
        
        log.debug("Auditing user sessions ...")
        for session in self.__sessDict.values():
            if not session.isValid():
                self.deleteUserSession(userSess=session)
            
    def getAttCert(self,
                   username=None,
                   userX509Cert=None,
                   sessID=None,
                   **credentialWalletKw):
        """For a given user, request Attribute Certificate from an Attribute 
        Authority given by service URI.  If sucessful, an attribute 
        certificate is added to the user session credential wallet and also 
        returned from this method
        
        A user identifier must be provided in the form of a user ID, user X.509
        certificate or a user session ID

        @type username: string
        @param username: username to key into their session

        @type userX509Cert: string
        @param userX509Cert: user's X.509 certificate to key into their session
        
        @type sessID: string
        @param sessID: user's ID to key into their session
        
        @type credentialWalletKw: dict
        @param **credentialWalletKw: keywords to NDGCredentialWallet.getAttCert
        """
        
        log.debug("Calling SessionManager.getAttCert ...")
        
        # Retrieve session corresponding to user's session ID using relevant
        # input credential
        userSess = self._connect2UserSession(username=username, sessID=sessID, 
                                             userX509Cert=userX509Cert)
        
        # The user's Credential Wallet carries out an attribute request to the
        # Attribute Authority
        attCert = userSess.credentialWallet.getAttCert(**credentialWalletKw)
        return attCert

        
    def auditCredentialRepository(self):
        """Remove expired Attribute Certificates from the Credential
        Repository"""
        log.debug("Calling SessionManager.auditCredentialRepository ...")
        self._credentialRepository.auditCredentials()
        

class AuthNServiceError(Exception):
    """Base class for AbstractAuthNService exceptions
    
    A standard message is raised set by the msg class variable but the actual
    exception details are logged to the error log.  The use of a standard 
    message enbales callers to use its content for user error messages.
    
    @type msg: basestring
    @cvar msg: standard message to be raised for this exception"""
    msg = "An error occurred with login"
    def __init__(self, *arg, **kw):
        Exception.__init__(self, AuthNServiceError.msg, *arg, **kw)
        if len(arg) > 0:
            msg = arg[0]
        else:
            msg = AuthNServiceError.msg
            
        log.error(msg)
        
class AuthNServiceInvalidCredentials(AuthNServiceError):
    """User has provided incorrect username/password.  Raise from logon"""
    msg = "Invalid username/password provided"
    
class AuthNServiceRetrieveError(AuthNServiceError):
    """Error with retrieval of information to authenticate user e.g. error with
    database look-up.  Raise from logon"""
    msg = \
    "An error occurred retrieving information to check the login credentials"

class AuthNServiceInitError(AuthNServiceError):
    """Error with initialisation of AuthNService.  Raise from __init__"""
    msg = "An error occurred with the initialisation of the Session " + \
        "Manager's Authentication Service"
    
class AuthNServiceConfigError(AuthNServiceError):
    """Error with Authentication configuration.  Raise from __init__"""
    msg = "An error occurred with the Session Manager's Authentication " + \
        "Service configuration"


class AbstractAuthNService(object):
    """
    An abstract base class to define the authentication service interface for 
    use with a SessionManager service
    """

    def __init__(self, propertiesFile=None, **prop):
        """Make any initial settings
        
        Settings are held in a dictionary which can be set from **prop,
        a call to setProperties() or by passing settings in an XML file
        given by propFilePath
        
        @type propertiesFile: basestring
        @param propertiesFile: set properties via a configuration file
        @type **prop: dict
        @param **prop: set properties via keywords - see __validKeys
        class variable for a list of these
        @raise AuthNServiceInitError: error with initialisation
        @raise AuthNServiceConfigError: error with configuration
        @raise AuthNServiceError: generic exception not described by the other
        specific exception types.
        """
    
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        raise NotImplementedError(
                            self.setProperties.__doc__.replace('\n       ',''))
        
    def logon(self, username, passphrase):
        """Interface login method
        
        @type username: basestring
        @param username: username of credential
        
        @type passphrase: basestring
        @param passphrase: passphrase corresponding to username 
        @raise AuthNServiceInvalidCredentials: invalid username/passphrase
        @raise AuthNServiceError: error 
        @raise AuthNServiceRetrieveError: error with retrieval of information
        to authenticate user e.g. error with database look-up.
        @raise AuthNServiceError: generic exception not described by the other
        specific exception types.
        @rtype: tuple
        @return: this may be either user PKI credentials or an empty tuple
        depending on the nature of the authentication service.  The UserSession
        object in the Session Manager instance can receive an individual user
        certificate and private key as returned by for example MyProxy.  In 
        this case, the tuple consists of strings in PEM format: 
         - the user certificate
         - corresponding private key
         - the issuing certificate.  
        The issuing certificate is optional.  It is only set if the user 
        certificate is a proxy certificate
        """
        raise NotImplementedError(self.logon.__doc__.replace('\n       ',''))
            
