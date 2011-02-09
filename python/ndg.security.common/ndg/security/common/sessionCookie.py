"""NDG Session Cookie used by Session Manager UserSession and Login
Service CGI code.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/10/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import base64
from datetime import datetime, timedelta
from Cookie import SimpleCookie
from M2Crypto import X509, BIO, RSA

from ndg.security.common.X509 import X509Cert, X509CertRead

#_____________________________________________________________________________
class SessionCookieError(Exception):
    "Handle exception from SessionCookie class"
    
        
#_____________________________________________________________________________
class _MetaSessionCookie(type):
    """Enable SessionCookie to have read only class variables e.g.
    
    print sessionCookie.cookieTags is allowed but,
    
    sessionCookie.cookieTags = None
    
    ... raises - AttributeError: can't set attribute"""
    def __getTag(cls):
        '''tag refs the morsel containing the encrypted user DN, session ID 
        and the encrypted session manager address.'''
        return "ndgSID1"

    tag = property(fget=__getTag)

    def __getSessIDlen(cls):
        '''This sets the session ID length (!)'''
        return 32
    
    sessIDlen = property(fget=__getSessIDlen)
    
    
#_____________________________________________________________________________
class SessionCookie(object):
    """Handler for creation and parsing of NDG Security Session Cookies"""
    
    __metaclass__ = _MetaSessionCookie

    # Follow standard format for cookie path and expiry attributes
    __cookiePathTag = "path"
    __cookiePath = "/"
    __cookieDomainTag = 'domain'
    __cookieExpiryTag = "expires"
 
    morselArgSep = ','
    nMorselArgs = 3
    
    # Quotes are vital (and part of the official cookei format) - otherwise it
    # will not be parsed correctly
    __sessCookieExpiryFmt = "\"%a, %d-%b-%Y %H:%M:%S GMT\""

        
    #_________________________________________________________________________    
    def __init__(self):
        """NDG Security Session Cookie"""

        self.__x509Cert = None
        self.__priKey = None
        
        self.__simpleCookie = None
        self.__userDN = None
        self.__sessID = None
        self.__sessMgrURI = None

    
    #_________________________________________________________________________
    def __setCert(self, cert):
        """filter and convert input cert for encryption of cookie morsel
        
        @type: ndg.security.common.X509.X509Cert / M2Crypto.X509.X509 /
        string 
        @param cert: X.509 certificate.  
        
        @rtype ndg.security.common.X509.X509Cert
        @return X.509 certificate object"""
        
        if isinstance(cert, X509Cert):
            # ndg.security.common.X509.X509Cert type / None
            return cert
            
        elif isinstance(cert, X509.X509):
            # M2Crypto.X509.X509 type
            return X509Cert(m2CryptoX509=cert)
            
        elif isinstance(cert, basestring):
            return X509CertParse(cert)
        
        else:
            raise AttributeError, "X.509 Cert. must be type: " + \
                "ndg.security.common.X509.X509Cert, M2Crypto.X509.X509 or " +\
                "a base64 encoded string"


    #_________________________________________________________________________
    def __setX509Cert(self, x509Cert):
        "Set property method for X.509 cert. to encrypt cookie morsel"
        self.__x509Cert = self.__setCert(x509Cert)
        
    x509Cert = property(fset=__setX509Cert,
                        doc="Set X.509 Cert. to encrypt cookie morsel")

 
    #_________________________________________________________________________
    def __setX509CertFromFile(self, x509CertFilePath):
        "Set X.509 cert property method"
        
        if isinstance(x509CertFilePath, basestring):
            self.__x509Cert = X509CertRead(x509CertFilePath)
            
        elif x509CertFilePath is not None:
            raise AttributeError, \
                "Signature X.509 cert. file path must be a valid string"
        
        
    x509CertFilePath = property(fset=__setX509CertFromFile,
                   doc="File path X.509 cert. for encryption of morsel")

 
    #_________________________________________________________________________
    def __setPriKeyPwd(self, priKeyPwd):
        """Set method for private key file password used to decrypt cookie
        morsel"""
        if priKeyPwd is not None and not isinstance(priKeyPwd, basestring):
            raise AttributeError, \
                "Signing private key password must be None or a valid string"
        
        self.__priKeyPwd = priKeyPwd
        
    priKeyPwd = property(fset=__setPriKeyPwd,
             doc="Password protecting private key file used to sign message")

 
    #_________________________________________________________________________
    def __setSigningPriKey(self, signingPriKey):
        """Set method for client private key
        
        Nb. if input is a string, priKeyPwd will need to be set if
        the key is password protected.
        
        @type signingPriKey: M2Crypto.RSA.RSA / string
        @param signingPriKey: private key used to sign message"""
        
        if isinstance(signingPriKey, basestring):
            pwdCallback = lambda *ar, **kw: self.__priKeyPwd
            self.__priKey = RSA.load_key_string(signingPriKey,
                                                       callback=pwdCallback)

        elif isinstance(signingPriKey, RSA.RSA):
            self.__priKey = signingPriKey 
                   
        else:
            raise AttributeError, "Signing private key must be a valid " + \
                                  "M2Crypto.RSA.RSA type or a string"
                
    signingPriKey = property(fset=__setSigningPriKey,
                             doc="Private key used to sign outbound message")

 
    #_________________________________________________________________________
    def __setPriKeyFromFile(self, priKeyFilePath):
        """Set method for client private key file path
        
        priKeyPwd MUST be set prior to a call to this method"""
        if isinstance(priKeyFilePath, basestring):                           
            try:
                # Read Private key to sign with    
                priKeyFile = BIO.File(open(priKeyFilePath)) 
                pwdCallback = lambda *ar, **kw: self.__priKeyPwd                                           
                self.__priKey = RSA.load_key_bio(priKeyFile, 
                                                        callback=pwdCallback)           
            except Exception, e:
                raise AttributeError, \
                                "Setting private key for signature: %s" % e
        
        else:
            raise AttributeError, \
                        "Private key file path must be a valid string"
        
    priKeyFilePath = property(fset=__setPriKeyFromFile,
                      doc="File path for private key used to sign message")


    def __str__(self):
        return str(self.__simpleCookie)
    
    
    def __getUserDN(self):
        return self.__userDN
       
    userDN = property(fget=__getUserDN, doc="user Distinguished Name")
    
    
    def __getSessID(self):
        return self.__sessID
       
    sessID = property(fget=__getSessID, doc="user Session ID")
    
    
    def __getSessMgrURI(self):
        return self.__sessMgrURI
       
    sessMgrURI = property(fget=__getSessMgrURI, doc="Session Manager URI")


    def parse(self, cookieStr):
        '''Parse from string text
        
        @rtype tuple
        @return (userDN, sessID, sessMgrURI)'''
        
        # Nb. SimpleCookie doesn't like unicode
        self.__simpleCookie = SimpleCookie(str(cookieStr))
            
        try:
            # Check for expected cookie morsel
            b64EncMorsel = self.__simpleCookie[self.__class__.tag].value
            encrMorsel = base64.urlsafe_b64decode(b64EncMorsel)
            morsel = self.__priKey.private_decrypt(encrMorsel, 
                                                       RSA.pkcs1_padding)
            morselArgs = morsel.split(self.morselArgSep)
            
        except KeyError:
            raise SessionCookieError, 'Missing cookie morsel "%s"' % \
                                      SessionCookie.tag

        if len(morselArgs) != self.__class__.nMorselArgs:
            raise SessionCookieError, \
                        "Expecting three input parameters for cookie morsel"

        self.__userDN, self.__sessID, self.__sessMgrURI = morselArgs

        if len(self.__sessID) < SessionCookie.sessIDlen:
            raise SessionCookieError, "Session ID has an invalid length"
      
      
    def create(self,
               userDN,
               sessID,
               sessMgrURI,
               dtExpiry=None,
               strExpiry=None,
               lifetime=28800):
        '''Create an NDG Session cookie.  Requires x509Cert to be set'''
        morselArgs = userDN, sessID, sessMgrURI
        self.__userDN, self.__sessID, self.__sessMgrURI = morselArgs
                        
        morsel = self.__class__.morselArgSep.join(morselArgs)
 
        rsaPubKey = self.__x509Cert.pubKey.get_rsa()
        encrMorsel = rsaPubKey.public_encrypt(morsel, RSA.pkcs1_padding)
        b64EncMorsel = base64.urlsafe_b64encode(encrMorsel)


        # Set the cookie expiry
        if dtExpiry is not None:
            if not isinstance(dtExpiry, datetime):
                SessionCookieError, \
                    "Expecting valid datetime object with dtExpiry keyword"
                
            strExpiry=dtExpiry.strftime(self.__class__.__sessCookieExpiryFmt)
            
        elif strExpiry is not None:
            if not isinstance(strExpiry, basestring):
                raise SessionCookieError, "strExpiry is not a valid string"
            
            # SimpleCookie doesn't like unicode
            strExpiry = str(strExpiry)
            
        elif lifetime is not None:
            dtExpiry = datetime.utcnow() + timedelta(seconds=lifetime)
            strExpiry=dtExpiry.strftime(self.__class__.__sessCookieExpiryFmt)
         
        self.__simpleCookie = SimpleCookie()              
        tag = self.__class__.tag
        
        self.__simpleCookie[tag] = b64EncMorsel
        
        # Use standard format for cookie path and expiry
        self.__simpleCookie[tag][self.__cookiePathTag] = self.__cookiePath
        self.__simpleCookie[tag][self.__cookieExpiryTag] = strExpiry

        return self.__simpleCookie
    
    
    #_________________________________________________________________________
    @classmethod   
    def isValid(cls, cookie, raiseExcep=False):
        """Check cookie has the expected session keys.  Cookie may be a 
        string or SimpleCookie type"""
        
        if isinstance(cookie, basestring):
            cookie = SimpleCookie(cookie)
            
        elif not isinstance(cookie, SimpleCookie):
            if raiseExcep:
                raise SessionCookieError,"Input cookie must be a string or "+\
                                        "SimpleCookie type"
            else:
                return False
        
        if self.tag not in cookie:
            if raiseExcep:
                raise SessionCookieError, \
                    'Input cookie missing security tag: "%s"' % self.tag
            else:
                return False
        
        return True
