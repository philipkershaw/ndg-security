"""NDG Security server side session management and security includes 
UserSession and SessionMgr classes.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/06/05"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

# Modify sys.path when carrying out dynamic import for Credential Repository
import sys

# Time module for use with cookie expiry
from time import strftime
from datetime import datetime

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

# Base 64 encode session IDs if returned in strings - urandom's output may
# not be suitable for printing!
import base64

# Session Manager URI in cookie
from Crypto.Cipher import AES

# Check Session Manager URI is encrypted
from urllib import urlopen

# Credential Wallet
from ndg.security.common.CredWallet import CredWallet, CredRepos, \
    CredWalletError, CredWalletAttributeRequestDenied

from ndg.security.common.X509 import X500DN, X509Cert, X509CertParse, \
                                X509CertExpired, X509CertInvalidNotBeforeTime 

# MyProxy server interface
from ndg.security.server.MyProxy import *

# Use client package to allow redirection of authorisation requests and 
# to retrieve Attribute Authority public key
from ndg.security.common.SessionMgr import SessionMgrClient

# Placing of session ID on client
from ndg.security.common.sessionCookie import SessionCookie

# Use in SessionMgr __redirectAttCertReq to retrieve and store Public 
# key
import tempfile
import urllib
import logging
log = logging.getLogger(__name__)

#_____________________________________________________________________________
class _SessionMgrException(Exception):
    """Base class for all Exceptions in this module.  Overrides Exception to 
    enable writing to the log"""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)

#_____________________________________________________________________________
class UserSessionError(_SessionMgrException):    
    """Exception handling for NDG User Session class."""

#_____________________________________________________________________________
class InvalidUserSession(UserSessionError):    
    """Problem with a session's validity"""

#_____________________________________________________________________________
class UserSessionExpired(UserSessionError):    
    """Raise when session's X.509 cert. has expired"""

#_____________________________________________________________________________
class UserSessionX509CertNotBeforeTimeError(UserSessionError):    
    """Raise when session's X.509 cert. not before time is before the current
    system time"""
   

#_____________________________________________________________________________
# Inheriting from 'object' allows Python 'new-style' class with Get/Set
# access methods
class UserSession(object):
    """Session details - created when a user logs into NDG"""

    #_________________________________________________________________________
    def __init__(self, *credWalletArgs, **credWalletKeys):
        """Initialise UserSession with args and keywords to CredWallet"""
                
        log.debug("UserSession.__init__ ...")
        
        # Each User Session has one or more browser sessions associated with
        # it.  These are stored in a list
        self.__sessIDlist = []
        self.addNewSessID()
        self.__credWallet = CredWallet(*credWalletArgs, **credWalletKeys)

        log.info("Created a session with ID = %s" % self.__sessIDlist[-1])

    #_________________________________________________________________________
    # CredWallet access 
    def __getCredWallet(self):
        """Get Credential Wallet instance"""
        return self.__credWallet
    
    credWallet = property(fget=__getCredWallet,
                          doc="Read-only access to CredWallet instance")


    #_________________________________________________________________________
    # CredWallet access 
    def __getSessIDlist(self):
        """Get Session ID list - last item is latest allocated for this
        session"""
        return self.__sessIDlist
    
    sessIDlist = property(fget=__getSessIDlist,
                          doc="Read-only access to Session ID list")


    #_________________________________________________________________________        
    def __latestSessID(self):
        """Get the session ID most recently allocated"""
        return self.__sessIDlist[-1]
    
    # Publish as an attribute
    latestSessID = property(fget=__latestSessID,
                            doc="Latest Session ID allocated")


    #_________________________________________________________________________
    def addNewSessID(self):
        """Add a new session ID to be associated with this UserSession
        instance"""

        # base 64 encode output from urandom - raw output from urandom is
        # causes problems when passed over SOAP.  A consequence of this is
        # that the string length of the session ID will almost certainly be
        # longer than SessionMgr.__sessIDlen
        sessID = base64.urlsafe_b64encode(os.urandom(SessionCookie.sessIDlen))
        self.__sessIDlist.append(sessID)


    #_________________________________________________________________________
    def __getExpiryStr(self):
        """Return session expiry date/time as would be formatted for a cookie
        """

        try:
            # Proxy certificate's not after time determines the expiry
            dtNotAfter = self.credWallet.userCert.notAfter

            return dtNotAfter.strftime(self.__sessCookieExpiryFmt)
        except Exception, e:
            UserSessionError, "getExpiry: %s" % e


    #_________________________________________________________________________
    @staticmethod
    def encodeSessionMgrURI(txt, encrKey=None):
        """Encode Session Manager URI to allow inclusion in a web browser 
        session cookie
        
        The address is optionally encrypted and then base 64 encoded use a 
        URL safe encoding
        
        @type encrKey: string
        @param encrKey: 16 char encryption key used to encrypt the URI.  If
        omitted or set None, the URI is not encrypted but merely base 64
        encoded"""
        
        if encrKey is not None:
            # Text length must be a multiple of 16 for AES encryption
            try:
                mod = len(txt) % 16
                nPad = mod and 16 - mod or 0
                    
                # Add padding
                paddedURI = txt + ''.join(' '*nPad)
            except Exception, e:
                raise UserSessionError, "Padding text for encryption: %s" % e
        
            # Encrypt
            try:
                txt = AES.new(encrKey, AES.MODE_ECB).encrypt(paddedURI)
            
            except Exception, e:
                raise UserSessionError, "Encrypting Session Manager URI: %s"%e

        try:
            return base64.urlsafe_b64encode(txt)
        
        except Exception, e:
            raise UserSessionError, "Encoding Session Manager URI: %s"%e
        
    
    #_________________________________________________________________________
    @staticmethod                                   
    def decodeSessionMgrURI(txt, encrKey=None):
        """Decode the URI from cookie set by another Session Manager.  This
        is required when reading a session cookie to find out which 
        Session Manager holds the client's session
        
        @type txt: string
        @param txt: base 64 encoded encrypted text
        
        @type encrKey: string
        @param encrKey: 16 char encryption key used to encrypt the URI.  If
        omitted or set None, the URI is assumed to be unencrypted"""

        try:
            # Convert if unicode type - unicode causes TypeError with
            # base64.urlsafe_b64decode
            if isinstance(txt, unicode):
                txt = str(txt)
                
            # Decode from base 64
            b64DecodedEncrTxt = base64.urlsafe_b64decode(txt)
            
        except Exception, e:
            raise SessionMgrError, "Decoding Session Manager URI: %s" % e           


        if encrKey is not None:
            try:
                aes = AES.new(encrKey, AES.MODE_ECB)
                
                # Decrypt and strip trailing spaces
                return aes.decrypt(b64DecodedEncrTxt).strip()
            
            except Exception, e:
                raise SessionMgrError, "Decrypting Session Manager URI: %s"%e           
        else:
            return b64DecodedEncrTxt
        

    #_________________________________________________________________________
    def createCookie(self, 
                     sessMgrURI,
                     encrKey, 
                     sessID=None,
                     cookieDomain=None,
                     asString=True):
        """Create cookies for session ID Session Manager WSDL address

        @type sessMgrURI: string
        @param sessMgrURI: address for Session Mananger 
        
        @type encrKey: string
        @param encrKey: encryption key used to encrypted above URIs
        
        @type sessID: string
        @param sessID: if no session ID is provided, use the latest one to 
        be allocated.
        
        @type cookieDomain: string
        @param cookieDomain: domain set for cookie, if non set, web server
        domain name is used.  Nb. Generalised domains which don't set a 
        specific host can be a security risk.
        
        @type asString: bool
        @param asString: Set to True to return the cookie as string text.  
        If False, it is returned as a SessionCookie instance.
        
        @rtype: SessionCookie / string depending on asString keyword
        @return: session cookie"""
        
        log.debug("UserSession.createCookie ...")
          
        if sessID is None:
            # Use latest session ID allocated if none was input
            sessID = self.__sessIDlist[-1]
            
        elif not isinstance(sessID, basestring):
            raise UserSessionError, "Input session ID is not a valid string"
                                
            if sessID not in self.__sessIDlist:
                raise UserSessionError, "Input session ID not found in list"
 
 
        encrSessMgrURI = self.encodeSessionMgrURI(sessMgrURI, encrKey)
        dtExpiry = self.credWallet.userCert.notAfter
        
        # Call class method 
        cookieTags = SessionCookie.tags
        cookieTagsKw = {}.fromkeys(cookieTags)
        cookieTagsKw[cookieTags[0]] = sessID
        cookieTagsKw[cookieTags[1]] = encrSessMgrURI
        
        sessCookie = SessionCookie(dtExpiry=dtExpiry,
                                   cookieDomain=cookieDomain,
                                   **cookieTagsKw)
        if asString:
            return str(sessCookie)
        else:
            return sessCookie
    

#_____________________________________________________________________________
class SessionMgrError(_SessionMgrException):    
    """Exception handling for NDG Session Manager class."""

class SessionNotFound(SessionMgrError):
    """Raise from SessionMgr.__connect2UserSession when session ID is not 
    found in the Session dictionary"""
    
# Find the missing elements in targ referenced in ref
getMissingElem = lambda targ, ref: [e for e in targ if e not in ref]

# Expand environment variables for ElementTree Element type.  Use in 
# readProperties.
filtElemTxt = lambda elem: isinstance(elem.text, basestring) and \
                os.path.expandvars(elem.text).strip() or elem.text


#_____________________________________________________________________________
class SessionMgr(dict):
    """NDG authentication and session handling
    
    @type __validElem: dict
    @cvar __validElem: list of the valid properties file element names and
    sub-elements where appropriate
    
    @type __confDir: string
    @cvar __confDir: configuration directory under $NDGSEC_DIR - default location
    for properties file 
    
    @type __propFileName: string
    @cvar __propFileName: default file name for properties file under 
    __confDir
    """

    # valid configuration property keywords
    __validElem = \
    {
        'portNum':                None,
        'useSSL':                 None,
        'sslCertFile':            None,
        'sslKeyFile':             None,
        'sslCACertDir':           None,
        'useSignatureHandler':    None,
        'caCertFileList':         [],
        'certFile':               None,
        'keyFile':                None,
        'keyPwd':                 None,
        'clntCertFile':           None,
        'wssRefInclNS':           [],
        'wssSignedInfoInclNS':    [],
        'sessMgrEncrKey':         None, 
        'sessMgrURI':             None,
        'cookieDomain':           None, 
        'myProxyProp':            None, 
        'credReposProp':          ('modFilePath', 'modName', 'className', 
                                   'propFile'),
        'simpleCACltProp':        ('uri', 'xmlSigKeyFile', 'xmlSigCertFile', 
                                   'xmlSigCertPwd')
    }

    __confDir = "conf"
    __propFileName = "sessionMgrProperties.xml"
     
    
    #_________________________________________________________________________
    def __init__(self, propFilePath=None, credReposPPhrase=None, **prop):       
        """Create a new session manager to manager NDG User Sessions
        
        propFilePath:        path to properties file
        credReposPPhrase:    for credential repository if not set in
                             properties file
        **prop:              set any other properties corresponding to the
                             tags in the properties file"""        

        log.info("Initialising service ...")
        
        # Base class initialisation
        dict.__init__(self)

        # Key user sessions by session ID
        self.__sessDict = {}

        # Key user sessions by user DN
        self.__dnDict = {}

        # Credential Repository interface only set if properties file is set
        # otherwise explict calls are necessary to set credReposProp via
        # setProperties/readProperties and then loadCredReposInterface
        self.__credRepos = None
        
        # MyProxy interface
        try:
            self.__myPx = MyProxyClient()
            
        except Exception, e:
            raise SessionMgrError, "Creating MyProxy interface: %s" % e
    
        # Dictionary to hold properties      
        self.__prop = {}
        
        # Set from input or use defaults based or environment variables
        self.setPropFilePath(propFilePath)
        
        # Set properties from file
        self.readProperties()

        # Call here as we can safely expect that all Credential Repository
        # parameters have been set above
        self.loadCredReposInterface()

        # Set any properties that were provided by keyword input
        #
        # Nb. If any are duplicated with tags in the properties file they
        # will overwrite the latter
        #
        # loadCredReposInterface must be called explicitly if propFilePath
        # wasn't set.  This is because if properties are passed by keyword 
        # alone there is no guarantee that those needed to load the interface
        # will be present.  readProperties however, requires that all the
        # required parameters are present in the properties file.
        self.setProperties(**prop)
        
        
    #_________________________________________________________________________
    def loadCredReposInterface(self, credReposPPhrase=None, Force=False):
        """
        Pick up and instantiate Credential Repository interface class from 
        properties file settings/keywords set by setProperties/__init__
        
        @type credReposPPhrase: string
        @param credReposPPhrase: password for CredentialRepository database
        This is passed into the Credential Repository object but may not
        be needed.  e.g. the custom class could pick up a password from
        the properties file for it - ['credRepos']['propFilePath']
        
        @type Force: boolean
        @param Force: flag to force reload of Credential Repository instance
        """
        
        log.debug("Loading Credential Repository interface ...")
        
        # Don't bother if object has already been created.  Use Force=True
        # to override and force reload
        if Force is False and self.__credRepos is not None:
            return
        
        # Credentials repository - permanent store of user credentials
        try:
            try:
                # Module file path may be None if the new module to be loaded
                # can be found in the existing system path            
                if self.__prop['credReposProp']['modFilePath'] is not None:
                    # Temporarily extend system path ready for import
                    sysPathBak = sys.path[:]

                    if not os.path.exists(\
                              self.__prop['credReposProp']['modFilePath']):
                        raise Exception, "File path '%s' doesn't exist" % \
                              self.__prop['credReposProp']['modFilePath']
                              
                    sys.path.append(\
                                self.__prop['credReposProp']['modFilePath'])
                
                # Import module name specified in properties file
                credReposMod = \
                    __import__(self.__prop['credReposProp']['modName'],
                               globals(),
                               locals(),
                               [self.__prop['credReposProp']['className']])
    
                credReposClass = eval(\
                'credReposMod.' + self.__prop['credReposProp']['className'])
            finally:
                try:
                    sys.path[:] = sysPathBak
                except NameError:
                    # sysPathBak may not have been defined
                    pass
                
        except KeyError, e:
            raise SessionMgrError, \
        'Missing %s element for credential repository module import' % str(e)
                        
        except Exception, e:
            raise SessionMgrError, \
                        'Importing credential repository module: %s' % str(e)

        # Check class inherits from CredWallet.CredRepos abstract base class
        if not issubclass(credReposClass, CredRepos):
            raise SessionMgrError, \
                "Credential Repository class %s must be inherited from %s" % \
                (credReposClass, CredRepos)

        # Instantiate custom class
        try:
            self.__credRepos = credReposClass(\
                      propFilePath=self.__prop['credReposProp']['propFile'],
                      dbPPhrase=credReposPPhrase)
            
        except Exception, e:
            raise SessionMgrError, \
            "Error instantiating Credential Repository interface: " + str(e)
     
        log.info(\
'Instantiated "%s" class from Credential Repository module: "%s" file path %s' % \
         (self.__prop['credReposProp']['className'],
          self.__prop['credReposProp']['modName'],
          self.__prop['credReposProp']['modFilePath'] or "from PYTHONPATH"))

        
    #_________________________________________________________________________        
    def __repr__(self):
        """Return file properties dictionary as representation"""
        return repr(self.__prop)

    def __delitem__(self, key):
        "Session Manager keys cannot be removed"        
        raise KeyError, 'Keys cannot be deleted from '+self.__class__.__name__


    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of Session
        Manager properties
        """
        if key not in self.__prop:
            raise KeyError, "Invalid key '%s'" % key
        
        return self.__prop[key]
    
    
    def __setitem__(self, key, item):
        self.__class__.__name__ + """ behaves as data dictionary of Session
        Manager properties"""
        self.setProperties(**{key: item})
           
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


    #_________________________________________________________________________
    def setPropFilePath(self, val=None):
        """Set properties file from input or based on environment variable
        settings"""
        if not val:
            if 'NDGSEC_SM_PROPFILEPATH' in os.environ:
                val = os.environ['NDGSEC_SM_PROPFILEPATH']
                
                log.debug(\
                'Set properties file path "%s" from "NDGSEC_SM_PROPFILEPATH"'\
                % val)

            elif 'NDGSEC_DIR' in os.environ:
                val = os.path.join(os.environ['NDGSEC_DIR'], 
                                   self.__class__.__confDir,
                                   self.__class__.__propFileName)

                log.debug('Set properties file path %s from "NDGSEC_DIR"'%val)
            else:
                raise AttributeError, 'Unable to set default Session ' + \
                    'Manager properties file path: neither ' + \
                    '"NDGSEC_SM_PROPFILEPATH" or "NDGSEC_DIR" environment ' + \
                    'variables are set'
        else:
             log.debug('Set properties file path %s from user input' % val)       

        if not isinstance(val, basestring):
            raise AttributeError, "Input Properties file path " + \
                                  "must be a valid string."
      
        self.__propFilePath = val
        
    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            doc="Set the path to the properties file")   
            

    #_________________________________________________________________________
    def readProperties(self, propElem=None):
        """Read Session Manager properties from an XML file or cElementTree
        node
        
        @type propElem: Element
        @param propElem: pass in existing ElementTree treeroot
        """

        log.debug("Reading properties file ...")
        
        if not propElem:
            try:
                tree = ElementTree.parse(self.__propFilePath)
                propElem = tree.getroot()

            except IOError, e:
                raise SessionMgrError, \
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror)               
            except Exception, e:
                raise SessionMgrError, \
                    "Error parsing properties file: \"%s\": %s" % \
                    (self.__propFilePath, e)

        if propElem is None:
            raise SessionMgrError, \
                            "Parsing properties: root element is not defined"
 
        missingElem = []
        invalidElem = []
        try:
            for elem in propElem:
                if elem.tag == 'myProxyProp':
                    self.__myPx.readProperties(propElem=elem)
    
                elif elem.tag == 'credReposProp':
                    self.__prop['credReposProp'] = \
                                dict([(e.tag, filtElemTxt(e)) for e in elem])
                            
                    # Check for missing elements
                    missingElem.extend(getMissingElem(\
                                           self.__validElem['credReposProp'],
                                           self.__prop['credReposProp']))
                    
                elif elem.tag == 'simpleCACltProp':
                    self.__prop['simpleCACltProp'] = \
                                dict([(e.tag, filtElemTxt(e)) for e in elem])
                            
                    # Check for missing elements
                    missingElem.extend(getMissingElem(\
                                       self.__validElem['simpleCACltProp'],
                                       self.__prop['simpleCACltProp']))
                    
                elif elem.tag in self.__validElem:
                    # Strip white space but not in the case of password 
                    # field as password might contain leading or 
                    # trailing white space
                    if isinstance(self.__validElem[elem.tag], list):
                        if len(elem) == 0 and elem.text is not None:
                            # Treat as a list of space separated elements
                            self.__prop[elem.tag] = elem.text.split()
                        else:
                            # Parse from a list of sub-elements
                            self.__prop[elem.tag] = [filtElemTxt(subElem) \
                                                     for subElem in elem]
                        
                    elif elem.text is not None and elem.tag != 'keyPwd':                        
                        if elem.text.isdigit():
                            self.__prop[elem.tag] = int(elem.text)
                        else:                            
                            # Check for environment variables in file paths
                            self.__prop[elem.tag] = filtElemTxt(elem)        
                    else:
                        self.__prop[elem.tag] = elem.text
                else:
                    invalidElem.append(elem.tag)
                
        except Exception, e:
            raise SessionMgrError, \
                'Error parsing tag "%s" in properties file: %s' % (elem.tag,e)

        missingElem.extend(getMissingElem(self.__prop, self.__validElem))
        errMsg = ''
        
        if invalidElem != []:
            errMsg = 'Invalid elements: "%s"\n' % '", "'.join(invalidElem)

        if missingElem != []:
            errMsg += 'Missing elements: "%s"\n' % '", "'.join(missingElem)

        if errMsg:
            raise SessionMgrError, errMsg +  " for properties file"

        log.info('Loaded properties from "%s"' % self.__propFilePath)
       

    #_________________________________________________________________________
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        log.debug("Calling SessionMgr.setProperties with kw = %s" % prop)
        
        for key in prop.keys():
            if key not in self.__validElem:
                raise SessionMgrError, "Property name \"%s\" is invalid" % key


        for key, value in prop.items():
                       
            if key == 'myProxyProp':
                self.__myPx.setProperties(prop[key])
    
            elif key == 'credReposProp':
                self.__prop['credReposProp'] = prop[key].copy()

            elif key in self.__validElem:
                # Only update other keys if they are not None or ""
                if value:
                    if isinstance(value, basestring):
                        self.__prop[key] = os.path.expandvars(value).strip()
                    else:
                        self.__prop[key] = value              
            else:
                raise SessionMgrError, \
                    "Key \"%s\" is not a valid Session Manager property" % key
        
        
    #_________________________________________________________________________
    def addUser(self, username, passphrase=None):        
        """Register a new user with an NDG data centre
        
        addUser([caConfigFilePath, ]|[, caPassPhrase]
                |[, userName=u, pPhrase=p])

        returns XML formatted response message
        
        caConfigFilePath|caPassPhrase:  pass phrase for SimpleCA's
                                        certificate.  Set via file or direct
                                        string input respectively.  Set here
                                        to override setting [if any] made at
                                        object creation.
        
                                        Passphrase is only required if
                                        SimpleCA is instantiated on the local
                                        machine.  If SimpleCA WS is called no
                                        passphrase is required.
                                        
        **kw:                      use as alternative to 
                                        reqXMLtxt keyword - pass in 
                                        username and pass-phrase for new user 
                                        unencrypted as keywords username
                                        and pPhrase respectively."""

        log.debug("Calling SessionMgr.addUser ...")
        
        # Ask CA to sign certificate
        
        # Add new user certificate to MyProxy Repository
        self.__myPx.store(username, 
                          certFile,
                          keyFile,
                          ownerCertFile=None,
                          ownerKeyFile=None,
                          ownerPassphrase=None,
                          lifetime=None,
                          force=True)

        return userDN           
    
    
    #_________________________________________________________________________        
    def getSessionStatus(self, sessID=None, userDN=None):
        """Check the status of a given session identified by sessID or 
        user Distinguished Name
        
        @type sessID: string
        @param sessID: session identifier as returned from a call to connect()
        @type userDN: string
        @param userDN: user Distinguished Name of session to check
        @rtype: bool
        @return: True if session is active, False if no session found"""

        log.debug("Calling SessionMgr.getSessionStatus ...")
        
        # Look for a session corresponding to this ID
        if sessID and userDN:
            raise SessionMgrError, \
                            'Only "SessID" or "userDN" keywords may be set'
        elif sessID:
            if sessID in self.__sessDict:               
                log.info("Session found with ID = %s" % sessID)
                return True
            else:
                # User session not found with given ID
                log.info("No user session found matching input ID = %s" % \
                         sessID)
                return False
                          
        elif userDN:
            try:
                # Enables re-ordering of DN fields for following dict search
                userDN = str(X509DN(userDN))
                
            except Exception, e:
                raise SessionMgrError, \
                "Parsing input user certificate DN for getSessionStatus: %s"%e

            if userDN in self.__dnDict:
                log.info("Session found with DN = %s" % userDN)
                return True                        
            else:
                # User session not found with given proxy cert
                log.info("No user session found matching input userDN = %s" %\
                         userDN)
                return False

    
    #_________________________________________________________________________        
    def connect(self, 
                createServerSess=True,
                username=None,
                passphrase=None, 
                userCert=None, 
                sessID=None):        
        """Create a new user session or connect to an existing one:

        connect([createServerSess=True/False, ]|[, username=u, passphrase=p]|
                [, userCert=px]|[, sessID=id])

        @type createUserSess: bool
        @param createServerSess: If set to True, the SessionMgr will create
        and manage a session for the user.  For command line case, it's 
        possible to choose to have a client or server side session using this 
        keyword.
        
        @type username: string
        @param username: username of account to connect to

        @type passphrase: string
        @param passphrase: pass-phrase - user with username arg
        
        @type userCert: string
        @param userCert: connect to existing session with proxy certificate
        corresponding to user.  username/pass-phrase not required
        
        @type sessID: string
        @param sessID: connect to existing session corresponding to this ID.
        username/pass-phrase not required.
        
        @rtype: tuple
        @return user certificate, private key, issuing certificate and 
        session ID respectively.  Session ID will be none if createUserSess 
        keyword is set to False
        """
        
        log.debug("Calling SessionMgr.connect ...")
        
        # Initialise proxy cert to be returned
        userCert = None
        
        if sessID is not None:            
            # Connect to an existing session identified by a session ID and 
            # return equivalent proxy cert
            userSess = self.__connect2UserSession(sessID=sessID)
            userCert = userSess.credWallet.userCert
            
        elif userCert is not None:
            # Connect to an existing session identified by a proxy 
            # certificate 
            userSess = self.__connect2UserSession(userCert=userCert)
            sessID = userSess.latestSessID
            
        else:
            # Create a fresh session
            try:            
                # Get a proxy certificate to represent users ID for the new
                # session
                userCreds = self.__myPx.logon(username, passphrase)
                
                # unpack 
                userCert = userCreds[0]
                userPriKey = userCreds[1]
                
                # Issuing cert is needed only if userCert is a proxy
                issuingCert = len(userCreds) > 2 and userCreds[2] or None
                
            except Exception, e:
                raise SessionMgrError, "Delegating from MyProxy: %s" % e

            if createServerSess:
                # Session Manager creates and manages user's session
                userSess = self.__createUserSession(userCert, 
                                                    userPriKey, 
                                                    issuingCert)
                sessID = userSess.latestSessID
            else:
                sessID = None
                                
        # Return proxy details and cookie
        return userCert, userPriKey, issuingCert, sessID        
        
       
    #_________________________________________________________________________        
    def __createUserSession(self, *creds):
        """Create a new user session from input user credentials       
        and return
        
        @type creds: tuple
        @param creds: tuple containing user certificate, private key
        and optionally an issuing certificate.  An issuing certificate is
        present if user certificate is a proxy and therefore it's issuer is
        other than the CA."""
        
        log.debug("Calling SessionMgr.__createUserSession ...")
        
        # Check for an existing session for the same user
        try:
            userDN = str(X509CertParse(creds[0]).dn)
            
        except Exception, e:
            raise SessionMgrError, \
                "Parsing input certificate DN for session create: %s" % \
                                                                    str(e)

        if userDN in self.__dnDict:
            # Update existing session with user cert and add a new 
            # session ID to access it - a single session can be accessed
            # via multiple session IDs e.g. a user may wish to access the
            # same session from the their desktop PC and their laptop.
            # Different session IDs are allocated in each case.
            userSess = self.__dnDict[userDN]
            userSess.addNewSessID()            
        else:
            # Create a new user session using the new user certificate
            # and session ID
            #
            wssSignatureHandlerKw = {
            'refC14nKw': {'unsuppressedPrefixes': 
                          self.__prop.get('wssRefInclNS', [])},
            'signedInfoC14nKw':{'unsuppressedPrefixes':
                                self.__prop.get('wssSignedInfoInclNS', [])}}

            try:   
                userSess = UserSession(credRepos=self.__credRepos, 
                             caCertFilePathList=self.__prop['caCertFileList'],
                             wssSignatureHandlerKw=wssSignatureHandlerKw,
                             *creds)      
            except Exception, e:
                raise SessionMgrError, "Creating User Session: %s" % e

            # Also allow access by user DN
            self.__dnDict[userDN] = userSess

        
        newSessID = userSess.latestSessID
        
        # Check for unique session ID
        if newSessID in self.__sessDict:
            raise SessionMgrError, \
                "New Session ID is already in use:\n\n %s" % newSessID

        # Add new session to list                 
        self.__sessDict[newSessID] = userSess
                        
        # Return new session
        return userSess


    #_________________________________________________________________________        
    def __connect2UserSession(self, userCert=None, sessID=None):
        """Connect to an existing session by providing a valid session ID or
        proxy certificate

        __connect2UserSession([userCert]|[sessID])
        
        @type userCert: string
        @param userCert: proxy certificate string corresponding to an 
        existing session to connect to.
        
        @type sessID: string
        @param sessID: similiarly, a web browser session ID linking to an
        an existing session."""
        
        log.debug("Calling SessionMgr.__connect2UserSession ...")
            
        # Look for a session corresponding to this ID
        if sessID:
            try:
                # Check matched session has not expired
                userSess = self.__sessDict[sessID]
                
            except KeyError:
                # User session not found with given ID
                raise SessionNotFound, \
                        "No user session found matching input session ID"

            log.info("Connecting to session user DN = %s using ID = %s" % \
                     (userSess.credWallet.userCert.dn, sessID))
                               
        elif isinstance(userCert, basestring):
            try:
                userDN = str(X509CertParse(userCert).dn)
                
            except Exception, e:
                raise SessionMgrError, \
                "Parsing input user certificate DN for session connect: %s" %e

            try:
                userSess = self.__dnDict[userDN]
                        
            except KeyError:
                # User session not found with given proxy cert
                raise SessionNotFound, \
                    "No user session found matching input proxy certificate"
            
            log.info("Connecting to session ID = %s using cert, DN = %s" % \
                     (userSess.sessIDlist, userDN))
                    
        elif isinstance(userCert, X509Cert):
            try:
                userDN = str(userCert.dn)
                
            except Exception, e:
                raise SessionMgrError, \
                "Parsing input user certificate DN for session connect: %s" %e
            
            try:
                userSess = self.__dnDict[userDN]
                        
            except KeyError:
                # User session not found with given proxy cert
                raise SessionNotFound, \
                    "No user session found matching input proxy certificate"            

            log.info("Connecting to session ID = %s using cert, DN = %s" % \
                     (userSess.sessIDlist, userDN))
        else:
            raise SessionMgrError,\
                                '"sessID" or "userCert" keywords must be set'
                        
        try:
            userSess.credWallet.isValid(raiseExcep=True)
            return userSess
        
        except X509CertInvalidNotBeforeTime, e:
            # ! Delete user session since it's user certificate is invalid
            self.deleteUserSession(userSess=userSess)
            raise UserSessionX509CertNotBeforeTimeError, \
                                    "User session is invalid: %s" % e          
    
        except X509CertExpired, e:
            # ! Delete user session since it's user certificate is invalid
            self.deleteUserSession(userSess=userSess)
            raise UserSessionExpired, "User session is invalid: %s" % e          
        
        except Exception, e:
            raise InvalidUserSession, "User session is invalid: %s" % e
                


    #_________________________________________________________________________        
    def deleteUserSession(self, sessID=None, userCert=None, userSess=None):
        """Delete an existing session by providing a valid session ID or
        proxy certificate - use for user logout

        deleteUserSession([userCert]|[sessID]|[userSess])
        
        @type userCert: ndg.security.common.X509.X509Cert 
        @param userCert: proxy certificate corresponding to an existing 
        session to connect to.
        
        @type sessID: string
        @param sessID: similiarly, a web browser session ID linking to an
        an existing session.
        
        @type userSess: UserSession
        @param userSess: user session object to be deleted
        """
        
        log.debug("Calling SessionMgr.deleteUserSession ...")
        
        # Look for a session corresponding to the session ID/proxy cert.
        if sessID:
            try:
                userSess = self.__sessDict[sessID]
                
            except KeyError:
                raise SessionMgrError, \
                    "Deleting user session - no matching session ID exists"

            # Get associated user Distinguished Name
            userDN = str(userSess.credWallet.userCert.dn)
            
        elif userCert:
            try:
                userDN = str(userCert.dn)
                
            except Exception, e:
                raise SessionMgrError, \
                "Parsing input proxy certificate DN for session connect: %s"%\
                                                                        str(e)
            try:
                userSess = self.__dnDict[userDN]
                        
            except KeyError:
                # User session not found with given proxy cert
                raise SessionMgrError, \
                    "No user session found matching input proxy certificate"
        
        if userSess:
            userDN = str(userSess.credWallet.userCert.dn)
        else:
            # User session not found with given ID
            raise SessionMgrError, \
                    '"sessID", "userCert" or "userSess" keywords must be set'
 
        # Delete associated sessions
        try:
            # Each session may have a number of session IDs allocated to
            # it.  
            #
            # Use pop rather than del so that key errors are ignored
            for userSessID in userSess.sessIDlist:
                self.__sessDict.pop(userSessID, None)

            self.__dnDict.pop(userDN, None)
        
        except Exception, e:
            raise SessionMgrError, "Deleting user session: %s" % e        

        log.info("Deleted user session: user DN = %s, sessID = %s" % \
                 (userDN, userSess.sessIDlist))

    #_________________________________________________________________________
    def getAttCert(self,
                   userCert=None,
                   sessID=None,
                   encrSessMgrURI=None,
                   **credWalletKw):
        """For a given user, request Attribute Certificate from an Attribute 
        Authority given by service URI.  If sucessful, an attribute 
        certificate is added to the user session credential wallet and also 
        returned from this method

        @type userCert: string
        @param userCert: user's certificate to key into their session
        
        @type sessID: string
        @param sessID: user's ID to key into their session
        
        @type encrSessMgrURI: string
        @param encrSessMgrURI: URI for remote session manager to forward a
        request to.  This effectively use THIS session manager as a proxy to
        another.  This URI is encrypted with a shared key.  The key is stored
        in the property file 'sessMgrEncrKey' element.  *** This functionality
        is redundant for NDG BETA delivery ***
        
        @type credWalletKw: dict
        @param **credWalletKw: keywords to CredWallet.getAttCert
        """
        
        log.debug("Calling SessionMgr.getAttCert ...")
        
        # Web browser client input will include the encrypted address of the
        # Session Manager where the user's session is held.
        if encrSessMgrURI:
            
            # Decrypt the URI for where the user's session resides
            userSessMgrURI = UserSession.decodeSessionMgrURI(encrSessMgrURI,
                                               self.__prop['sessMgrEncrKey'])
                                               
            # Check the address against the address of THIS Session Manager  
            if userSessMgrURI != self.__prop['sessMgrURI']:
                
                # Session is held on a remote Session  Manager
                userSessMgrResp = self.__redirectAttCertReq(userSessMgrURI,
                                                            sessID=sessID,
                                                            userCert=userCert,
                                                            **credWalletKw)

                # Reset response by making a new AuthorisationResp object
                # The response from the remote Session Manager will still
                # contain the encrypted XML sent by it.  This should be
                # discarded
                return userSessMgrResp

            
        # User's session resides with THIS Session Manager / no encrypted
        # URI address passed in (as in command line use case for security) ...

           
        # Retrieve session corresponding to user's session ID using relevant
        # input credential
        userSess = self.__connect2UserSession(sessID=sessID,userCert=userCert)


        # User's Credential Wallet carries out attribute request to the
        # Attribute Authority
        try:
            attCert = userSess.credWallet.getAttCert(**credWalletKw)
            return attCert, None, []
            
        except CredWalletAttributeRequestDenied, e:
            # Exception object contains a list of attribute certificates
            # which could be used to re-try to get authorisation via a mapped
            # certificate
            return None, str(e), e.extAttCertList


    #_________________________________________________________________________
    def __redirectAttCertReq(self, userSessMgrURI, **kw):
        """Handle case where User session resides on another Session Manager -
        forward the request
        
        @type userSessMgrURI: string
        @param userSessMgrURI: address of remote session manager where user
        session is held
        
        @type **kw: dict
        @param **kw: same keywords which apply to getAttCert call"""

        
        log.info('SessionMgr.__redirectAttCertReq - redirecting to "%s"' % \
                 userSessMgrURI)
                
        
        # Instantiate WS proxy for remote session manager
        try:
            sessMgrClnt = SessionMgrClient(uri=userSessMgrURI,
                                 signingCertFilePath=self.__prop['certFile'],
                                 signingPriKeyFilePath=self.__prop['keyFile'],
                                 signingPriKeyPwd=self.__prop['keyPwd'])           
        except Exception, e:
            raise SessionMgrError, \
                "Re-directing attribute certificate request to \"%s\": %s" % \
                (userSessMgrURI, str(e))

            
        # Call remote session manager's authorisation request method
        # and return result to caller
        try:
            # Call remote SessionMgr where users session lies
            resp = sessMgrClnt.getAttCert(**kw)        
            return resp
        
        except Exception, e:
            raise SessionMgrError, \
        "Forwarding Authorisation request for Session Manager \"%s\": %s" %\
                (userSessMgrURI, e)


    #_________________________________________________________________________
    def auditCredRepos(self):
        """Remove expired Attribute Certificates from the Credential
        Repository"""
        log.debug("Calling SessionMgr.auditCredRepos ...")
        self.__credRepos.auditCredentials()
