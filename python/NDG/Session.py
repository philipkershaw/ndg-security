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

# Use to pipe output from ZSI ServiceProxy
from cStringIO import StringIO

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

    __cookieTagNames = ("NDG-ID1", "NDG-ID2")

    # Follow standard format for cookie path and expiry attributes
    __cookiePathTagName = "path"
    __cookiePath = "/"
    __cookieDomainTagName = 'domain'
    __cookieExpiryTagName = "expires"
        
    __sessCookieExpiryFmt = "%a, %d-%b-%Y %H:%M:%S GMT"


    def __init__(self, *credWalletArgs, **credWalletKeys):
        """Initialise UserSession with args and keywords to CredWallet"""
        
        # Each User Session has one or more browser sessions associated with
        # it.  These are stored in a list
        self.__sessIDlist = []
        self.__createSessID()
        self.__credWallet = CredWallet(*credWalletArgs, **credWalletKeys)

               
    def __repr__(self):
        "Represent User Session"        
        return "<UserSession instance>"


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

        
    def __latestSessID(self):
        """Get the session ID most recently allocated"""
        return self.__sessIDlist[-1]
    
    # Publish as an attribute
    latestSessID = property(fget=__latestSessID,
                            doc="Latest Session ID allocated")


    def __createSessID(self):
        """Add a new session ID to be associated with this UserSession
        instance"""

        # base 64 encode output from urandom - raw output from urandom is
        # causes problems when passed over SOAP.  A consequence of this is
        # that the string length of the session ID will almost certainly be
        # longer than SessionMgr.__sessIDlen
        sessID = base64.b64encode(os.urandom(self.__sessIDlen))
        self.__sessIDlist.append(sessID)


    def __getExpiryStr(self):
        """Return session expiry date/time as would formatted for a cookie"""

        try:
            # Proxy certificate's not after time determines the expiry
            dtNotAfter = self.credWallet.proxyCert.notAfter

            return dtNotAfter.strftime(self.__sessCookieExpiryFmt)
        except Exception, e:
            UserSessionError("getExpiry: %s" % e)
            
    
    def createCookie(self, encrSessMgrWSDLuri, sessID=None, asString=True):
        """Create cookies for session ID Session Manager WSDL address

        encrSessMgrWSDLuri:    encrypted WSDL address for Session Mananger 
                               WSDL
        sessID:                if no session ID is provided, use the latest 
                               one to be allocated.
        asString:              Set to True to return the cookie as string 
                               text.  If False, it is returned as a 
                               SimpleCookie instance."""

        if not encrSessMgrWSDLuri:
            raise UserSessionError("No encrypted WSDL address set")
                            
        elif not isinstance(encrSessMgrWSDLuri, basestring):
            raise UserSessionError(\
                            "Encrypted WSDL address must be a valid string")
            
            
        # Try to ensure WSDL address has been passed encrypted
        if encrSessMgrWSDLuri.find("http://") != -1 or \
           encrSessMgrWSDLuri.find("https://") != -1:
               raise UserSessionError(\
           "Session Manager WSDL address appears not to be encrypted: %s" % \
           encrSessMgrWSDLuri)
        else:
            # Sledge hammer approach
            try:
                urlopen(encrSessMgrWSDLuri)
                raise UserSessionError(\
           "Session Manager WSDL address appears not to be encrypted: %s" % \
           encrSessMgrWSDLuri)
                
            except:
                pass   

           
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
            
            tagValues = (sessID, encrSessMgrWSDLuri)
            
            i=0
            for tagName in self.__cookieTagNames:
    
                sessCookie[tagName] = tagValues[i]
                i += 1
                
                # Use standard format for cookie path and expiry
                sessCookie[tagName][self.__cookiePathTagName] = \
                                                        self.__cookiePath
                
                sessCookie[tagName][self.__cookieExpiryTagName]=\
                                                        self.__getExpiryStr()
                                            
                # Make cookie as generic as possible for domains - Nb. '.uk'
                # alone won't work
                sessCookie[tagName][self.__cookieDomainTagName] = '.rl.ac.uk'#'glue.badc.rl.ac.uk'
            
            
            # Caller should set the cookie e.g. in a CGI script
            # print "Content-type: text/html"
            # print cookie.output() + os.linesep
            if asString:
                return sessCookie.output()
            else:
                return sessCookie
            
        except Exception, e:
            UserSessionError("Creating Cookie: %s" % e)


#_____________________________________________________________________________
class SessionMgrError(Exception):    
    """Exception handling for NDG Session Manager class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class SessionMgr(object):
    """NDG authentication and session handling"""

    # valid configuration property keywords
    __validKeys = [    'caCertFile',
                       'certFile',
                       'keyFile',
                       'keyPPhrase', 
                       'sessMgrWSDLkey', 
                       'sessMgrWSDLuri', 
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

        for elem in propElem:
            if elem.tag == 'myProxyProp':
                self.__myPx.readProperties(propElem=elem)

            elif elem.tag == 'credReposProp':
                self.__credRepos.readProperties(propElem=elem,
                                                dbPPhrase=credReposPPhrase)
            elif elem.tag in self.__validKeys:
                # Check for environment variables in file paths
                tagCaps = elem.tag.upper()
                if 'FILE' in tagCaps or 'PATH' in tagCaps or 'DIR' in tagCaps:
                    elem.text = os.path.expandvars(elem.text)
                    
                self.__prop[elem.tag] = elem.text                
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
    def addUser(self, 
                caConfigFilePath=None,
                caPassPhrase=None,
                reqXMLtxt=None, 
                **addUserReqKeys):        
        """Register a new user with NDG data centre
        
        addUser([caConfigFilePath, ]|[, caPassPhrase][, reqXMLtxt]
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
                                        
        reqXMLtxt:                      XML containing credentials - may be 
                                        encrypted or plain text
                                        for new user: username, pass-phrase
        addUserReqKeys:                 use as alternative to 
                                        reqXMLtxt keyword - pass in 
                                        username and pass-phrase for new user 
                                        unencrypted as keywords username
                                        and pPhrase respectively."""
        

        if reqXMLtxt is not None:
            if not isinstance(reqXMLtxt, basestring):
                raise SessionMgrError(\
                    "New user credentials must be a string")
                                       
            try:
                # Assume text was input encrypted
                #
                # UserReq object returned behaves like a dictionary
                addUserReqKeys = AddUserReq(encrXMLtxt=reqXMLtxt,
                                    encrPriKeyFilePath=self.__prop['keyFile'],
                                    encrPriKeyPwd=self.__prop['keyPPhrase'])
            except:
                try:
                    # Check for plain text input
                    addUserReqKeys = AddUserReq(xmlTxt=reqXMLtxt)
                                    
                except Exception, e:
                    raise SessionMgrError(\
                        "Error parsing user credentials: %s" % e)
        
        try:
            # Add new user certificate to MyProxy Repository
            user = self.__myPx.addUser(addUserReqKeys['userName'],
                                       addUserReqKeys['pPhrase'],
                                       caConfigFilePath=caConfigFilePath,
                                       caPassPhrase=caPassPhrase,
                                       retDN=True)
            
            # Add to user database
            self.__credRepos.addUser(addUserReqKeys['userName'], user['dn'])
            
        except Exception, e:
            raise SessionMgrError("Error registering new user: %s" % e)


        return str(AddUserResp(errMsg=''))
    
    
    #_________________________________________________________________________        
    def connect(self, reqXMLtxt=None, **connectReqKeys):        
        """Create and return a new user session or connect to an existing
        one:

        connect([, reqXMLtxt=txt]|
                [getCookie=True/False][createServerSess=Tue/False, ]
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
        connectReqKeys:         username and pass-phrase or the proxy 
                                certificate or browser session ID 
                                corresponding to an existing session"""
        

        if reqXMLtxt is not None:
            if not isinstance(reqXMLtxt, basestring):
                raise SessionMgrError(\
                    "Encrypted user credentials must be a string")
                                       
            # Decrypt and parse
            try:
                # Connect request object returned behaves like a dictionary
                connectReqKeys = ConnectReq(encrXMLtxt=reqXMLtxt,
                                    encrPriKeyFilePath=self.__prop['keyFile'],
                                    encrPriKeyPwd=self.__prop['keyPPhrase'])
            except:
                try:
                    connectReqKeys = ConnectReq(xmlTxt=reqXMLtxt)
                    
                except Exception, e:
                    raise SessionMgrError(\
                        "Error parsing user credentials: %s" % e)

        
            if 'encrCert' in connectReqKeys:
                # ConnectResp class expects the public key to be in a file
                # - Copy public key string content into a temporary file
                try:
                    fdPubKeyTmp = NamedTemporaryFile()
                    open(fdPubKeyTmp.name).write(connectReqKeys['encrCert'])
                    
                    clntPubKeyFilePath = fdPubKeyTmp.name
                    
                except Exception, e:
                    raise SessionMgrError(\
                    "Error creating temporary file for client public key: %s"\
                        % e)
            else:
                clntPubKeyFilePath = None

                                          
        if 'sessID' in connectReqKeys:
            
            # Connect to an existing session identified by a session ID
            userSess = self.__connect2UserSession(sessID=sessID)
            return userSess.credWallet.proxyCertTxt
        
        elif 'proxyCert' in connectReqKeys:
            # Connect to an existing session identified by a session ID or 
            # proxy certificate
            
            # What should this return??
            # PJK 20/12/05 
            return self.__connect2UserSession(sessID=sessID, 
                                              proxyCert=proxyCert)
        else:
            # Create a fresh session
            proxyCert = self.__delegateProxy(connectReqKeys['userName'], 
                                             connectReqKeys['pPhrase'])

            bGetCookie = 'getCookie' in connectReqKeys and \
                                                connectReqKeys['getCookie']
                                                
            bCreateServerSess = 'createServerSess' in connectReqKeys and \
                                            connectReqKeys['createServerSess']
                                            
            if bGetCookie or bCreateServerSess:
                # Session Manager creates and manages user's session
                userSess = self.__createUserSession(proxyCert)
 
                               
            if bGetCookie:
                
                # Web browser client - Return session cookie
                sessCookie = userSess.createCookie(self.encrSessMgrWSDLuri)
                
                try:
                    # Encrypt response if a client public key is available
                    connectResp = ConnectResp(sessCookie=sessCookie,
                                      encrPubKeyFilePath=clntPubKeyFilePath)
                except Exception, e:
                    raise SessionMgrError(\
                        "Error formatting connect response: %s" % e)               
            else:
                # NDG Command line client - Return proxy certificate
                try:
                    connectResp = ConnectResp(proxyCert=proxyCert,
                                      encrPubKeyFilePath=clntPubKeyFilePath)
                except Exception, e:
                    raise SessionMgrError(\
                        "Error formatting connect response: %s" % e)
                
            # Return connection response as XML formatted string
            return str(connectResp)
            
                
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
                userSess=UserSession(proxyCert, 
                                     caCertFilePath=self.__prop['caCertFile'],
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


    def __encryptSessMgrWSDLuri(self):
        """Encrypt the WSDL address of this Session Manager's WS to allow
        inclusion in a web browser session cookie
        
        The address is encrypted and then base 64 encoded"""
        
        # Text length must be a multiple of 16 for AES encryption
        try:
            mod = len(self.__prop['sessMgrWSDLuri']) % 16
            if mod:
                nPad = 16 - mod
            else:
                nPad = 0
                
            # Add padding
            paddedURI = self.__prop['sessMgrWSDLuri'] + \
                        ''.join([' ' for i in range(nPad)])
        except Exception, e:
            raise SessionMgrError("Error padding WSDL URI: %s" % e)
        
        # encrypt
        try:
            aes = AES.new(self.__prop['sessMgrWSDLkey'], AES.MODE_ECB)
            return base64.b64encode(aes.encrypt(paddedURI))
        
        except Exception, e:
            raise SessionMgrError("Error encrypting WSDL URI: %s" % e)


    # Make available as read-only attribute
    encrSessMgrWSDLuri = property(fget=__encryptSessMgrWSDLuri,
                                  doc="Encrypted SessionMgr WSDL Address")
                                       
                                       
    def decryptSessMgrWSDLuri(self, encrSessMgrWSDLuri):
        """Decrypt the WSDL address of another Session Manager.  This
        is required when reading a session cookie to find out which 
        Session Manager holds the client's session
        
        encrSessMgrWSDLuri:    base 64 encoded encrypted WSDL address"""

        try:
            aes = AES.new(self.__prop['sessMgrWSDLkey'], AES.MODE_ECB)
            
            # Decode from base 64
            b64DecodedEncrSessMgrWSDLuri=base64.b64decode(encrSessMgrWSDLuri)
            
            # Decrypt and strip trailing spaces
            return aes.decrypt(b64DecodedEncrSessMgrWSDLuri).strip()
        
        except Exception, e:
            raise SessionMgrError("Error encrypting WSDL URI: %s" % e)


    #_________________________________________________________________________
    def reqAuthorisation(self, reqXMLtxt=None, **reqKeys):
        """For given sessID, request authorisation from an Attribute Authority
        given by aaWSDL.  If sucessful, an attribute certificate is
        returned.

        **reqKeys:              keywords used by 
        """

        if reqXMLtxt is not None:
            # Parse XML text into keywords corresponding to the input
            # parameters
            if not isinstance(reqXMLtxt, basestring):
                raise SessionMgrError(\
                            "XML Authorisation request must be a string")
                                       
            # Parse and decrypt as necessary
            try:
                # 1st assume that the request was encrypted
                reqKeys = AuthorisationReq(encrXMLtxt=reqXMLtxt,
                                    encrPriKeyFilePath=self.__prop['keyFile'],
                                    encrPriKeyPwd=self.__prop['keyPPhrase'])
            except Exception, e:
                
                # Error occured decrypting - Trying parsing again, but this 
                # time assuming non-encrypted
                try:
                    reqKeys = AuthorisationReq(xmlTxt=reqXMLtxt)
                    
                except Exception, e:
                    raise SessionMgrError(\
                        "Error parsing authorisation request: %s" % e)

        
        if 'encrSessMgrWSDLuri' in reqKeys:
            # Decrypt the URI for where the user's session resides
            userSessMgrWSDLuri = self.decryptSessMgrWSDLuri(\
                                                reqKeys['encrSessMgrWSDLuri'])
    
                                           
            # Check the address against the address of THIS Session Manager  
            if userSessMgrWSDLuri != self.__prop['sessMgrWSDLuri']:
                # User session resides on another Session Manager - forward the
                # request
                
                # Instantiate WS proxy for remote session manager
                try:
                    smSrv = ServiceProxy(userSessMgrWSDLuri, use_wsdl=True)
                except Exception, e:
                    raise SessionMgrError(\
                        "Error initialising WS for \"%s\": %s" % \
                        (userSessMgrWSDLuri, e))
                
                
                # Call remote session manager's authorisation request method
                # and return result to caller
                #
                # TODO: Message level encryption public key of target SessionMgr
                # is needed here in order to be able to apply message level 
                # encryption.  Get from cookie??
                #
                # P J Kershaw 02/03/06
                try:    
                    # Format parsed request into a new request encrypted by the
                    # target SessionMgr's public key
                    redirectAuthReq = AuthorisationReq(\
                                        #encrPubKeyFilePath=userSessMgrPubKeyURI,
                                        **dict(reqKeys.items()))
                                        
                    # Call remote SessionMgr where users session lies
                    redirectAuthResp = smSrv.reqAuthorisation(\
                                            authorisationReq=redirectAuthReq())
                  
                    # Parse XML contained in response                  
                    resp = AuthorisationResp(\
                            xmlTxt=str(redirectAuthResp['authorisationResp']))
                    return resp
                
                except Exception, e:
                    raise SessionMgrError(\
                    "Error requesting authorisation for Session Manager %s: %s" %\
                    (userSessMgrWSDLuri, e))
            
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
        aaKeys = dict(reqKeys.items())
        
        # ID keys aren't required
        try: del aaKeys['sessID']
        except KeyError: pass
        
        try: del aaKeys['encrSessMgrWSDLuri']
        except KeyError: pass
        
        try: del aaKeys['proxyCert']
        except KeyError: pass
        
        # Ensure CA certificate file is set
        if not "caCertFilePath" in aaKeys:
            aaKeys['caCertFilePath'] = self.__prop['caCertFile']


        # Check to see if the client passed a public key to encrypt the 
        # response message
        if 'encrCert' in reqKeys:
            # AuthorisationResp class expects the public key to be in a file
            # - Copy public key string content into a temporary file
            try:
                fdPubKeyTmp = NamedTemporaryFile()
                open(fdPubKeyTmp.name).write(reqKeys['encrCert'])
                
                clntPubKeyFilePath = fdPubKeyTmp.name
                
            except Exception, e:
                raise SessionMgrError(\
                "Error creating temporary file for client public key: %s"\
                    % e)
        else:
            # No client public key passed
            clntPubKeyFilePath = None

            
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
