"""NDG Session Management and security includes UserSession,
SessionMgr, Credentials Repository classes.

NERC Data Grid Project

P J Kershaw 02/06/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

# SQLObject Database interface
from sqlobject import *

# MYSQL exceptions have no error message associated with them so include here
# to allow an explicit trap around database calls
import _mysql_exceptions

# Placing of session ID on client
from Cookie import SimpleCookie

# Time module for use with cookie expiry
from time import strftime
from datetime import datetime

# For parsing of properties files
import cElementTree as ElementTree

# Base 64 encode session IDs if returned in strings - urandom's output may
# not be suitable for printing!
import base64

# Session Manager WSDL URI in cookie
from Crypto.Cipher import AES

# Check Session Mgr WSDL URI is encrypted
from urllib import urlopen

# Credential Wallet
from NDG.CredWallet import *

# MyProxy server interface
from NDG.MyProxy import *

# Tools for interfacing with SessionMgr WS
from NDG.SessionMgrIO import *

# SessionMgr.reqAuthorisation - getPubKey WS call.  Don't import 
# AttAuthorityIO's namespace as it would conflict with SessionMgrIO's
from NDG import AttAuthorityIO

# Use client package to allow reidrection of authorisation requests
from NDG.SessionClient import *

# Use to pipe output from ZSI ServiceProxy
from cStringIO import StringIO

# Use in SessionMgr __redirectAuthorisationReq to retrieve and store Public 
# key
import tempfile
import urllib

#_____________________________________________________________________________
class UserSessionError(Exception):    
    """Exception handling for NDG User Session class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
# Inheriting from 'object' allows Python 'new-style' class with Get/Set
# access methods
class UserSession(object):
    """Session details - created when a user logs into NDG"""

    # Session ID
    __sessIDlen = 128

    __cookieTags = ("NDG-ID1", "NDG-ID2")

    # Follow standard format for cookie path and expiry attributes
    __cookiePathTag = "path"
    __cookiePath = "/"
    __cookieDomainTag = 'domain'
    __cookieExpiryTag = "expires"
        
    __sessCookieExpiryFmt = "%a, %d-%b-%Y %H:%M:%S GMT"


    def __init__(self, *credWalletArgs, **credWalletKeys):
        """Initialise UserSession with args and keywords to CredWallet"""

        # Domain for cookie used by createCookie method - if not set, default
        # is web server domain name
        self.__cookieDomain = None
                
        
        # Each User Session has one or more browser sessions associated with
        # it.  These are stored in a list
        self.__sessIDlist = []
        self.__createSessID()
        self.__credWallet = CredWallet(*credWalletArgs, **credWalletKeys)

               
#    def __repr__(self):
#        "Represent User Session"        
#        return "<UserSession instance>"

    def __setCookieDomain(self, cookieDomain):
        """Set domain for cookie - set to None to assume domain of web server
        """

        if not isinstance(cookieDomain, basestring) and \
           cookieDomain is not None:
            raise UserSessionError(\
                "Expecting string or None type for \"cookieDomain\"")
                        
        self.__cookieDomain = cookieDomain

    cookieDomain = property(fset=__setCookieDomain,
                            doc="Set cookie domain")


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
    def __createSessID(self):
        """Add a new session ID to be associated with this UserSession
        instance"""

        # base 64 encode output from urandom - raw output from urandom is
        # causes problems when passed over SOAP.  A consequence of this is
        # that the string length of the session ID will almost certainly be
        # longer than SessionMgr.__sessIDlen
        sessID = base64.b64encode(os.urandom(self.__sessIDlen))
        self.__sessIDlist.append(sessID)


    #_________________________________________________________________________
    def __getExpiryStr(self):
        """Return session expiry date/time as would formatted for a cookie"""

        try:
            # Proxy certificate's not after time determines the expiry
            dtNotAfter = self.credWallet.proxyCert.notAfter

            return dtNotAfter.strftime(self.__sessCookieExpiryFmt)
        except Exception, e:
            UserSessionError("getExpiry: %s" % e)


    #_________________________________________________________________________
    @staticmethod
    def encrypt(txt, encrKey):
        """Encrypt the test of this Session Manager's WS URI / URI for its
        public key to allow inclusion in a web browser session cookie
        
        The address is encrypted and then base 64 encoded"""
        
        # Text length must be a multiple of 16 for AES encryption
        try:
            mod = len(txt) % 16
            if mod:
                nPad = 16 - mod
            else:
                nPad = 0
                
            # Add padding
            paddedURI = txt + ''.join([' ' for i in range(nPad)])
        except Exception, e:
            raise UserSessionError("Error padding text for encryption: " + \
                                   str(e))
        
        # encrypt
        try:
            aes = AES.new(encrKey, AES.MODE_ECB)
            return base64.b64encode(aes.encrypt(paddedURI))
        
        except Exception, e:
            raise UserSessionError("Error encrypting text: %s" % str(e))
                                       
    
    #_________________________________________________________________________
    @staticmethod                                   
    def decrypt(encrTxt, encrKey):
        """Decrypt text from cookie set by another Session Manager.  This
        is required when reading a session cookie to find out which 
        Session Manager holds the client's session
        
        encrTxt:    base 64 encoded encrypted text"""

        try:
            aes = AES.new(encrKey, AES.MODE_ECB)
            
            # Decode from base 64
            b64DecodedEncrTxt=base64.b64decode(encrTxt)
            
            # Decrypt and strip trailing spaces
            return aes.decrypt(b64DecodedEncrTxt).strip()
        
        except Exception, e:
            raise SessionMgrError("Decrypting: %s" % str(e))            


    #_________________________________________________________________________
    def createCookie(self, 
                     sessMgrWSDLuri,
                     encrKey, 
                     sessID=None,
                     cookieDomain=None,
                     asString=True):
        """Create cookies for session ID Session Manager WSDL address

        sessMgrWSDLuri:     WSDL address for Session Mananger 
        sessMgrPubKeyURI:   URI for public key of Session Manager
        encrKey:               encryption key used to encrypted above URIs
        sessID:                if no session ID is provided, use the latest 
                               one to be allocated.
        cookieDomain:          domain set for cookie, if non set, web server
                               domain name is used
        asString:              Set to True to return the cookie as string 
                               text.  If False, it is returned as a 
                               SimpleCookie instance."""


        # Nb. Implicit call to __setCookieDomain method
        if cookieDomain:
            self.cookieDomain = cookieDomain

          
        try:
            if sessID is None:
                # Use latest session ID allocated if none was input
                sessID = self.__sessIDlist[-1]
                
            elif not isinstance(sessID, basestring):
                raise UserSessionError(\
                                    "Input session ID is not a valid string")
                                    
                if sessID not in self.__sessIDlist:
                    raise UserSessionError(\
                                        "Input session ID not found in list")
 
            
            sessCookie = SimpleCookie()
            
            tagValues = (sessID, self.encrypt(sessMgrWSDLuri, encrKey))
                         
            expiryStr = self.__getExpiryStr()
            
            i=0
            for tag in self.__cookieTags:
                
                sessCookie[tag] = tagValues[i]
                i += 1
                
                # Use standard format for cookie path and expiry
                sessCookie[tag][self.__cookiePathTag] = self.__cookiePath                
                sessCookie[tag][self.__cookieExpiryTag]= expiryStr
                                            
                # Make cookie as generic as possible for domains - Nb. '.uk'
                # alone won't work
                if self.__cookieDomain:
                    sessCookie[tag][self.__cookieDomainTag] = \
                                                        self.__cookieDomain
            
            
            # Caller should set the cookie e.g. in a CGI script
            # print "Content-type: text/html"
            # print cookie.output() + os.linesep
            if asString:
                return sessCookie.output()
            else:
                return sessCookie
            
        except Exception, e:
            raise UserSessionError("Creating Session Cookie: %s" % e)


#_____________________________________________________________________________
class SessionMgrError(Exception):    
    """Exception handling for NDG Session Manager class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class SessionMgr(dict):
    """NDG authentication and session handling"""

    # valid configuration property keywords
    __validKeys = [    'caCertFile',
                       'certFile',
                       'keyFile',
                       'keyPPhrase', 
                       'sessMgrEncrKey', 
                       'sessMgrWSDLuri',
                       'cookieDomain', 
                       'myProxyProp', 
                       'credReposProp']

    
    #_________________________________________________________________________
    def __init__(self, 
                 propFilePath=None, 
                 credReposPPhrase=None, 
                 **prop):       
        """Create a new session manager to manager NDG User Sessions
        
        propFilePath:        path to properties file
        credReposPPhrase:    for credential repository if not set in
                             properties file
        **prop:              set any other properties corresponding to the
                             tags in the properties file"""        

        # Base class initialisation
        dict.__init__(self)
        

        # MyProxy interface
        try:
            self.__myPx = MyProxy()
            
        except Exception, e:
            raise SessionMgrError("Creating MyProxy interface: %s" % e)

        
        # Credentials repository - permanent stroe of user credentials
        try:
            self.__credRepos = SessionMgrCredRepos()
            
        except Exception, e:
            raise SessionMgrError(\
                    "Creating credential repository interface: %s" % e)

        self.__sessList = []

        # Dictionary to hold properties
        self.__prop = {}
        
        
        # Set properties from file
        if propFilePath is not None:
            self.readProperties(propFilePath,
                                credReposPPhrase=credReposPPhrase)


        # Set any properties that were provided by keyword input
        #
        # Nb. If any are duplicated with tags in the properties file they
        # will overwrite the latter
        self.setProperties(**prop)
     
        
    #_________________________________________________________________________        
    def __delitem__(self, key):
        "Session Manager keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from '+self.__class__.__name__)


    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of Session
        Manager properties
        """
        if key not in self.__prop:
            raise KeyError("Invalid key " + key)
        
        return self.__prop[key]
    
    
    def __setitem__(self, key, item):
        self.__class__.__name__ + """ behaves as data dictionary of Session
        Manager properties"""
        self.setProperties(**{key: item})
        

    def clear(self):
        raise KeyError("Data cannot be cleared from "+self.__class__.__name__)
   
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
                raise SessionMgrError(\
                    "Error parsing properties file: \"%s\": %s" % \
                    (propFilePath, e))

        if propElem is None:
            raise SessionMgrError("Root element for parsing is not defined")

        for elem in propElem:
            if elem.tag == 'myProxyProp':
                self.__myPx.readProperties(propElem=elem)

            elif elem.tag == 'credReposProp':
                self.__credRepos.readProperties(propElem=elem,
                                                dbPPhrase=credReposPPhrase)
            elif elem.tag in self.__validKeys:
                try:
                    # Check for environment variables in file paths
                    tagCaps = elem.tag.upper()
                    if 'FILE' in tagCaps or \
                       'PATH' in tagCaps or \
                       'DIR' in tagCaps:
                        elem.text = os.path.expandvars(elem.text)
                        
                    self.__prop[elem.tag] = elem.text
                    
                    # Strip white space but not in the case of pass-phrase 
                    # field as pass-phrase might contain leading or trailing 
                    # white space
                    if elem.tag != 'keyPPhrase' and \
                       isinstance(self.__prop[elem.tag], basestring):
                        self.__prop[elem.tag].strip()
                        
                except Exception, e:
                    raise SessionMgrError(\
                        "Error parsing properties file tag: \"%s\": %s" % \
                        (elem.tag, e))
                
            else:
                raise SessionMgrError(\
                    "\"%s\" is not a valid properties file tag" % elem.tag)


    #_________________________________________________________________________
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise SessionMgrError("Property name \"%s\" is invalid" % key)


        for key, value in prop.items():
                       
            if key == 'myProxyProp':
                self.__myPx.setProperties(prop[key])
    
            elif key == 'credReposProp':
                self.__credRepos.setProperties(prop[key])

            elif key in self.__validKeys:
                # Only update other keys if they are not None or ""
                if value:
                    self.__prop[key] = value                
            else:
                raise SessionMgrError(\
                    "Key \"%s\" is not a valid Session Manager property" %
                    key)


    #_________________________________________________________________________
    def addUser(self, caConfigFilePath=None, caPassPhrase=None, **reqKeys):        
        """Register a new user with NDG data centre
        
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
                                        
        **reqKeys:                      use as alternative to 
                                        reqXMLtxt keyword - pass in 
                                        username and pass-phrase for new user 
                                        unencrypted as keywords username
                                        and pPhrase respectively.  See
                                        SessionMgrIO.AddUserRequest class for
                                        reference."""
              
        try:
            # Add new user certificate to MyProxy Repository
            user = self.__myPx.addUser(reqKeys['userName'],
                                       reqKeys['pPhrase'],
                                       caConfigFilePath=caConfigFilePath,
                                       caPassPhrase=caPassPhrase,
                                       retDN=True)
            
            # Add to user database
            self.__credRepos.addUser(reqKeys['userName'], user['dn'])
            
        except Exception, e:
            return AddUserResp(errMsg=str(e))

        return AddUserResp(errMsg='')
    
    
    #_________________________________________________________________________        
    def connect(self, **reqKeys):        
        """Create a new user session or connect to an existing one:

        connect([getCookie=True/False][createServerSess=Tue/False, ]
                [, userName=u, pPhrase=p]|[, proxyCert=px]|[, sessID=id])

        getCookie:              If True, allocate a user session with a 
                                wallet in the session manager and return a 
                                cookie containing the new session ID 
                                allocated.  If set False, return a proxy 
                                certificate only.  The client is then 
                                responsible for Credential Wallet management.
        createServerSess:       If set to True, the SessionMgr will create
                                and manage a session for the user.  Nb.
                                this flag is ignored and set to True if
                                getCookie is set.  For command line case,
                                where getCookie is False, it's possible
                                to choose to have a client or server side
                                session using this keyword.
        reqXMLtxt:              encrypted XML containing user credentials -
                                user name, pass-phrase or proxy cert etc
        reqKeys:                username and pass-phrase or the proxy"""
        

        if 'sessID' in reqKeys:
            
            # Connect to an existing session identified by a session ID and 
            # return equivalent proxy cert
            userSess = self.__connect2UserSession(sessID=sessID)
            return ConnectResp(proxyCert=userSess.credWallet.proxyCertTxt)
        
        elif 'proxyCert' in reqKeys:
            # Connect to an existing session identified by a proxy 
            # certificate and return an equivalent session cookie
            userSess = self.__connect2UserSession(proxyCert=proxyCert)
            sessCookie = userSess.createCookie(self.__prop['sessMgrWSDLuri'],
                                               self.__prop['sessMgrEncrKey'])
            return ConnectResp(sessCookie=sessCookie)
        
        else:
            # Create a fresh session
            proxyCert = self.__delegateProxy(reqKeys['userName'], 
                                             reqKeys['pPhrase'])

            bGetCookie = 'getCookie' in reqKeys and reqKeys['getCookie']
                                                
            bCreateServerSess = 'createServerSess' in reqKeys and \
                                            reqKeys['createServerSess']
                                            
            if bGetCookie or bCreateServerSess:
                # Session Manager creates and manages user's session
                userSess = self.__createUserSession(proxyCert)
 
                               
            if bGetCookie:
                
                # Web browser client - Return session cookie
                userSess.cookieDomain = self.__prop['cookieDomain']

                sessCookie = userSess.createCookie(\
                                            self.__prop['sessMgrWSDLuri'],
                                            self.__prop['sessMgrEncrKey'])
                
                try:
                    # Encrypt response if a client public key is available
                    return ConnectResp(sessCookie=sessCookie)
                
                except Exception, e:
                    raise SessionMgrError(\
                        "Error formatting connect response: %s" % e)               
            else:
                # NDG Command line client - Return proxy certificate
                return ConnectResp(proxyCert=proxyCert)
            
                
    #_________________________________________________________________________        
    def __delegateProxy(self, userName, passPhrase):
        """Delegate a proxy certificate ID from input user credentials"""
        
        if not userName:
            raise SessionMgrError(\
                            "Getting proxy delegation: username is null")
        
        if not passPhrase:
            raise SessionMgrError(\
                            "Getting proxy delegation: pass-phrase is null")
        
        try:            
            # Get a proxy certificate to represent users ID for the new
            # session
            return self.__myPx.getDelegation(userName, passPhrase)

        except Exception, e:
            raise SessionMgrError("Delegating from MyProxy: %s" % e)
        
       
    #_________________________________________________________________________        
    def __createUserSession(self, proxyCert):
        """Create a new user session from input user credentials       
        and return
        
        """
        
        try:   
            # Search for an existing session for the same user
            userSess = None
            # PJK 16/12/05 - DON'T search for existing sessions make a new one
            # even if the user has one already.  
            # !! This allows users to have multiple sessions !!
#            for u in self.__sessList:
#                if u.credWallet['proxyCert'].dn['CN'] == userName:
#
#                    # Existing session found
#                    userSess = u
#
#                    # Replace it's Proxy Certificate with a more up to date
#                    # one
#                    userSess.credWallet.proxyCert = proxyCert
#                    break
                

            if userSess is None:
                # Create a new user session using the new proxy certificate
                # and session ID
                #
                # Nb. Client pub/pri key info to allow message level 
                # encryption for responses from Attribute Authority WS
                userSess = UserSession(proxyCert, 
                                caPubKeyFilePath=self.__prop['caCertFile'],
                                clntPubKeyFilePath=self.__prop['certFile'],
                                clntPriKeyFilePath=self.__prop['keyFile'],
                                clntPriKeyPwd=self.__prop['keyPPhrase'],
                                credRepos=self.__credRepos)                
                newSessID = userSess.latestSessID
                
                # Check for unique session ID
                for existingUserSess in self.__sessList:
                    if newSessID in existingUserSess.sessIDlist:
                        raise SessionMgrError(\
                            "Session ID is not unique:\n\n %s" % newSessID)

                # Add new session to list                 
                self.__sessList.append(userSess)

            # Return new session
            return userSess
        
        except Exception, e:
            raise SessionMgrError("Creating User Session: %s" % e)


    #_________________________________________________________________________        
    def __connect2UserSession(self, **idKeys):
        """Connect to an existing session by providing a valid session ID

        __connect2UserSession([proxyCert]|[sessID])
        
        proxyCert:    proxy certificate corresponding to an existing 
                      session to connect to.
        sessID:       similiarly, a web browser session ID linking to an
                      an existing session."""
        
            
        # Look for a session corresponding to this ID
        if 'sessID' in idKeys:
            try:
                for userSess in self.__sessList:
                    if idKeys['sessID'] in userSess.sessIDlist:
    
                        # Check matched session has not expired
                        userSess.credWallet.isValid(raiseExcep=True)
                        return userSess
                        
            except Exception, e:
                raise SessionMgrError(\
                "Matching session ID to existing user session: %s" % e)
                
            # User session not found with given ID
            raise SessionMgrError(\
                "No user session found matching input session ID")
        
        elif 'proxyCert' in idKeys:
            try:
                for userSess in self.__sessList:
                    if userSess.credWallet.proxyCertTxt==idKeys['proxyCert']:
                        
                        # Check matched session has not expired
                        userSess.credWallet.isValid(raiseExcep=True)
                        return userSess
                                        
            except Exception, e:
                raise SessionMgrError(\
                "Matching proxy certificate to existing user session: %s" % e)
                
            # User session not found with given proxy cert
            raise SessionMgrError(\
                    "No user session found matching input proxy certificate")
        else:
            raise SessionMgrError(\
                                '"sessID" or "proxyCert" keyword must be set')



    #_________________________________________________________________________
    def reqAuthorisation(self, **reqKeys):
        """For given sessID, request authorisation from an Attribute Authority
        given by aaWSDL.  If sucessful, an attribute certificate is
        returned.

        **reqKeys:            pass equivalent to XML as keywords instead.
                              See SessionMgrIO.AuthorisationReq class
        """
        
        # Web browser client input will include the encrypted address of the
        # Session Manager where the user's session is held.
        if 'encrSessMgrWSDLuri' in reqKeys:
            
            # Decrypt the URI for where the user's session resides
            userSessMgrWSDLuri = UserSession.decrypt(\
                                                reqKeys['encrSessMgrWSDLuri'],
                                                self.__prop['sessMgrEncrKey'])
                                               
            # Check the address against the address of THIS Session Manager  
            if userSessMgrWSDLuri != self.__prop['sessMgrWSDLuri']:
                
                # Session is held on a remote Session  Manager
                userSessMgrResp = self.__redirectAuthorisationReq(\
                                                        userSessMgrWSDLuri,
                                                        **reqKeys)

                # Reset response by making a new AuthorisationResp object
                # The response from the remote Session Manager will still
                # contain the encrypted XML sent by it.  This should be
                # discarded
                return userSessMgrResp

            
        # User's session resides with THIS Session Manager / no encrypted
        # WSDL address passed in (as in command line context for security) ...

           
        # Retrieve session corresponding to user's session ID using relevant
        # input credential
        idKeys = {}
        if 'sessID' in reqKeys:
            idKeys['sessID'] = reqKeys['sessID']
            
        elif 'proxyCert' in reqKeys:
            idKeys['proxyCert'] = reqKeys['proxyCert']           
        else:
            raise SessionMgrError(\
                                'Expecting "sessID" or "proxyCert" keywords')
                                
        userSess = self.__connect2UserSession(**idKeys)


        # Copy keywords to be passed onto the request to the attribute 
        # authority
        #
        # Nb. the following keys aren't required
        delKeys = ('proxyCert',
                   'sessID',
                   'encrCert',
                   'encrSessMgrWSDLuri', 
                   'aaPubKey')
                   
        aaKeys = dict([i for i in reqKeys.items() if i[0] not in delKeys])


        if 'aaPubKey' not in reqKeys:
            # Get public key using WS
            try:
                aaSrv = ServiceProxy(reqKeys['aaWSDL'], use_wsdl=True)
                
                pubKeyReq = AttAuthorityIO.PubKeyReq()
                resp = aaSrv.getPubKey(pubKeyReq=pubKeyReq())
                
                pubKeyResp = AttAuthorityIO.PubKeyResp(\
                                                   xmlTxt=resp['pubKeyResp'])
        
                if 'errMsg' in pubKeyResp and pubKeyResp['errMsg']:
                    raise Exception(pubKeyResp['errMsg'])
                
                reqKeys['aaPubKey'] = pubKeyResp['pubKey']
                
            except Exception, e:
                raise SessionMgrError(\
                    "Retrieving Attribute Authority public key: "+ str(e))
                                
                                                        
        # Make a temporary file to hold Attribute Authority Public Key.  
        # The Credential Wallet needs this to encrypt requests to the 
        # Attribute Authority
        try:
            aaPubKeyTmpFile = tempfile.NamedTemporaryFile()
            open(aaPubKeyTmpFile.name, "w").write(reqKeys['aaPubKey'])
            aaKeys['aaPubKeyFilePath'] = aaPubKeyTmpFile.name
            
        except IOError, (errNo, errMsg):
            raise SessionMgrError("Making temporary file for Attribute " + \
                                  "Authority public key: %s" % errMsg)
                
        except Exception, e:
            raise SessionMgrError("Making temporary file for Attribute " + \
                                  "Authority public key: %s" % str(e))

                                              
        # User's Credential Wallet carries out authorisation request to the
        # Attribute Authority
        try:
            attCert = userSess.credWallet.reqAuthorisation(**aaKeys)
            
            # AuthorisationResp class formats a response message in XML and
            # allow dictionary-like access to XML tags
            resp = AuthorisationResp(attCert=attCert, 
                                     statCode=AuthorisationResp.accessGranted)
            
        except CredWalletAuthorisationDenied, e:
            # Exception object containa a list of attribute certificates
            # which could be used to re-try to get authorisation via a mapped
            # certificate
            resp = AuthorisationResp(extAttCertList=e.extAttCertList,
                                     statCode=AuthorisationResp.accessDenied,
                                     errMsg=str(e))
        
        except Exception, e:
            # Some other error occured - create an error Authorisation
            # response
            resp = AuthorisationResp(statCode=AuthorisationResp.accessError,
                                     errMsg=str(e))
    
        return resp


    #_________________________________________________________________________
    def __redirectAuthorisationReq(self, userSessMgrWSDLuri, **reqKeys):
        """Handle case where User session resides on another Session Manager -
        forward the request"""
        
        # Instantiate WS proxy for remote session manager
        try:
            sessClnt = SessionClient(smWSDL=userSessMgrWSDLuri,
                                 clntPubKeyFilePath=self.__prop['certFile'],
                                 clntPriKeyFilePath=self.__prop['keyFile'])           
        except Exception, e:
            raise SessionMgrError(\
                        "Re-directing authorisation request to \"%s\": %s" % \
                        (userSessMgrWSDLuri, str(e)))

            
        # Call remote session manager's authorisation request method
        # and return result to caller
        try:
            # encrCert key not needed - it gets set above via 
            # 'clntPubKeyFilePath'
            if 'encrCert' in reqKeys:
                del reqKeys['encrCert']
                
            # Call remote SessionMgr where users session lies
            redirectAuthResp = sessClnt.reqAuthorisation(\
                                    clntPriKeyPwd=self.__prop['keyPPhrase'],
                                    **reqKeys)
          
            return redirectAuthResp
        
        except Exception, e:
            raise SessionMgrError(\
        "Forwarding Authorisation request for Session Manager \"%s\": %s" %\
                (userSessMgrWSDLuri, e))


    #_________________________________________________________________________
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
    



#_____________________________________________________________________________
class SessionMgrCredRepos(CredRepos):
    """Interface to Credential Repository Database
    
    Nb. inherits from CredWallet.CredRepos to ensure correct interface
    to the wallet"""

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
        SessionMgrCredRepos.User._connection = self.__con
        SessionMgrCredRepos.UserCredential._connection = self.__con
          



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
        prop = {}
        for elem in propElem:
                    
            # Check for environment variables in file paths
            tagCaps = elem.tag.upper()
            if 'FILE' in tagCaps or 'PATH' in tagCaps or 'DIR' in tagCaps:
                elem.text = os.path.expandvars(elem.text)

            prop[elem.tag] = elem.text
            
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


    def _initTables(self, prompt=True):
        """Use with EXTREME caution - this method will initialise the database
        tables removing any previous records entered"""
 
        if prompt:
            resp = raw_input(\
        "Are you sure you want to initialise the database tables? (yes/no)")
    
            if resp.upper() != "YES":
                print "Tables unchanged"
                return
        
        self.User.createTable()
        self.UserCredential.createTable()
        print "Tables created"

            
    #_________________________________________________________________________
    # Database tables defined using SQLObject derived classes
    # Nb. These are class variables of the SessionMgrCredRepos class
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
