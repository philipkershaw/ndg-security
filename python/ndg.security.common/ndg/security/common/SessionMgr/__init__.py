"""NDG Security client - client interface classes to Session Manager 

Make requests for authentication and authorisation

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2007 STFC & NERC"
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"
__all__ = ['SessionMgr_services', 'SessionMgr_services_types']

import sys
import os

# Determine https http transport
import urlparse

from ZSI.wstools.Utility import HTTPResponse

from ndg.security.common.wsSecurity import SignatureHandler
from ndg.security.common.X509 import *
from ndg.security.common.AttCert import AttCert, AttCertParse
from ndg.security.common.m2CryptoSSLUtility import HTTPSConnection, \
    HostCheck
from ndg.security.common.zsi_utils.httpproxy import ProxyHTTPConnection
from SessionMgr_services import SessionMgrServiceLocator

import logging
log = logging.getLogger(__name__)


#_____________________________________________________________________________
class SessionMgrClientError(Exception):
    """Exception handling for SessionMgrClient class"""

#_____________________________________________________________________________
class SessionNotFound(SessionMgrClientError):
    """Raise when a session ID input doesn't match with an active session on
    the Session Manager"""

#_____________________________________________________________________________
class SessionCertTimeError(SessionMgrClientError):
    """Session's X.509 Cert. not before time is BEFORE the system time - 
    usually caused by server's clocks being out of sync.  Fix by all servers
    running NTP"""

#_____________________________________________________________________________
class SessionExpired(SessionMgrClientError):
    """Session's X.509 Cert. has expired"""

#_____________________________________________________________________________
class InvalidSession(SessionMgrClientError):
    """Session is invalid"""

#_____________________________________________________________________________
class InvalidAttAuthorityClientCtx(SessionMgrClientError):
    """Attribute Authority ZSI Client is not initialised"""
 
#_____________________________________________________________________________
class AttributeRequestDenied(SessionMgrClientError):
    """Raise when a getAttCert call to the Attribute Authority is denied"""
    
    def __init__(self, *args, **kw):
        """Raise exception for attribute request denied with option to give
        caller hint to certificates that could used to try to obtain a
        mapped certificate
        
        @type extAttCertList: list
        @param extAttCertList: list of candidate Attribute Certificates that
        could be used to try to get a mapped certificate from the target 
        Attribute Authority"""
        
        # Prevent None type setting
        self.__extAttCertList = []
        if 'extAttCertList' in kw and kw['extAttCertList'] is not None:
            for ac in kw['extAttCertList']:
                if isinstance(ac, basestring):
                    ac = AttCertParse(ac)
                elif not isinstance(ac, AttCert):
                    raise SessionMgrClientError, \
                        "Input external Attribute Cert. must be AttCert type"
                         
                self.__extAttCertList += [ac]
                
            del kw['extAttCertList']
            
        Exception.__init__(self, *args, **kw)

        
    def __getExtAttCertList(self):
        """Return list of candidate Attribute Certificates that could be used
        to try to get a mapped certificate from the target Attribute Authority
        """
        return self.__extAttCertList

    extAttCertList = property(fget=__getExtAttCertList,
                              doc="list of candidate Attribute " + \
                              "Certificates that could be used " + \
                              "to try to get a mapped certificate " + \
                              "from the target Attribute Authority")

#_____________________________________________________________________________       
class SessionMgrClient(object):
    """Client interface to Session Manager Web Service
    
    @type excepMap: dict
    @cvar excepMap: map exception strings returned from SOAP fault to client
    Exception class to call"""

    excepMap = {
        'SessionNotFound':                         SessionNotFound,
        'UserSessionX509CertNotBeforeTimeError':   SessionCertTimeError,
        'UserSessionExpired':                      SessionExpired,
        'InvalidUserSession':                      InvalidSession
    }
    
    #_________________________________________________________________________
    def __init__(self, 
                 uri=None, 
                 tracefile=None,
                 httpProxyHost=None,
                 noHttpProxyList=False,
                 sslCACertList=[],
                 sslCACertFilePathList=[],
                 sslPeerCertCN=None, 
                 setSignatureHandler=True,
                 **signatureHandlerKw):
        """
        @type uri: string
        @param uri: URI for Session Manager WS.  Setting it will set the 
        Service user
                
        @type tracefile: file stream type
        @param tracefile: set to file object such as sys.stderr to give extra 
        WS debug information
        
        @type sslCACertList: list
        @param sslCACertList: This keyword is for use with SSL connections 
        only.  Set a list of one or more CA certificates.  The peer cert.
        must verify against at least one of these otherwise the connection
        is dropped.
        
        @type sslCACertFilePathList: list
        @param sslCACertFilePathList: the same as the above except CA certs
        can be passed as a list of file paths to read from
        
        @type sslPeerCertCN: string
        @param sslPeerCertCN: set an alternate CommonName to match with peer
        cert.  This keyword is for use with SSL connections only.
        
        @type setSignatureHandler: bool
        @param setSignatureHandler: flag to determine whether to apply
        WS-Security Signature Handler or not

        @type signatureHandlerKw: dict
        @param signatureHandlerKw: keywords to configure signature handler"""

        log.debug("SessionMgrClient.__init__ ...")
        
        self.__srv = None
        self.__uri = None
        self._transdict = {}
        self._transport = ProxyHTTPConnection       
        
        if uri:
            self.__setURI(uri)

        self.__setHTTPProxyHost(httpProxyHost)
        self.__setNoHttpProxyList(noHttpProxyList)

        if sslPeerCertCN:
            self.__setSSLPeerCertCN(sslPeerCertCN)
        
        if sslCACertList:
            self.__setSSLCACertList(sslCACertList)
        elif sslCACertFilePathList:
            self.__setSSLCACertFilePathList(sslCACertFilePathList)

        # WS-Security Signature handler - set only if any of the keywords were
        # set
        log.debug("signatureHandlerKw = %s" % signatureHandlerKw)
        if setSignatureHandler:
            self.__signatureHandler = SignatureHandler(**signatureHandlerKw)
        else:
            self.__signatureHandler = None
        
        self.__tracefile = tracefile

         
        # Instantiate Session Manager WS ZSI client
        if self.__uri:
            self.initService()
        

    #_________________________________________________________________________
    def __setURI(self, uri):
        """Set URI for service
        @type uri: string
        @param uri: URI for service to connect to"""
        
        if not isinstance(uri, basestring):
            raise SessionMgrClientError(
                             "Session Manager URI must be a valid string")
        
        self.__uri = uri
        try:
            scheme = urlparse.urlparse(self.__uri)[0]
        except TypeError:
            raise AttributeAuthorityClientError(
                    "Error parsing transport type from URI: %s" % self.__uri)
                
        if scheme == "https":
            self._transport = HTTPSConnection
        else:
            self._transport = ProxyHTTPConnection
            
            # Ensure SSL settings are cancelled
            self.__setSSLPeerCertCN(None)

    #_________________________________________________________________________
    def __getURI(self):
        """Get URI for service
        @rtype: string
        @return: uri for service to be invoked"""
        return self.__uri
        
    uri = property(fset=__setURI, fget=__getURI, doc="Session Manager URI")


    #_________________________________________________________________________
    def __setHTTPProxyHost(self, val):
        """Set a HTTP Proxy host overriding any http_proxy environment variable
        setting"""
        if self._transport != ProxyHTTPConnection:
            log.info("Ignoring httpProxyHost setting: transport class is " +\
                     "not ProxyHTTPConnection type")
            return
        
        self._transdict['httpProxyHost'] = val

    httpProxyHost = property(fset=__setHTTPProxyHost, 
        doc="HTTP Proxy hostname - overrides any http_proxy env var setting")


    #_________________________________________________________________________
    def __setNoHttpProxyList(self, val):
        """Set to list of hosts for which to ignore the HTTP Proxy setting"""
        if self._transport != ProxyHTTPConnection:
            log.info("Ignore noHttpProxyList setting: transport " + \
                     "class is not ProxyHTTPConnection type")
            return
        
        self._transdict['noHttpProxyList']= val

    noHttpProxyList = property(fset=__setNoHttpProxyList, 
    doc="Set to list of hosts for which to ignore the HTTP Proxy setting")
    

    #_________________________________________________________________________
    def __setSSLPeerCertCN(self, cn):
        """For use with HTTPS connections only.  Specify the Common
        Name to match with Common Name of the peer certificate.  This is not
        needed if the peer cert CN = peer hostname"""
        if self._transport != HTTPSConnection:
            return
        
        if self._transdict.get('postConnectionCheck'):
            self._transdict['postConnectionCheck'].peerCertCN = cn
        else:
            self._transdict['postConnectionCheck'] = HostCheck(peerCertCN=cn)

    sslPeerCertCN = property(fset=__setSSLPeerCertCN, 
doc="for https connections, set CN of peer cert if other than peer hostname")


    #_________________________________________________________________________
    def __setSSLCACertList(self, caCertList):
        """For use with HTTPS connections only.  Specify CA certs to one of 
        which the peer cert must verify its signature against"""
        if self._transport != HTTPSConnection:
            return
        
        if self._transdict.get('postConnectionCheck'):
            self._transdict['postConnectionCheck'].caCertList = caCertList
        else:
            self._transdict['postConnectionCheck'] = \
                                            HostCheck(caCertList=caCertList)

    sslCACertList = property(fset=__setSSLCACertList, 
doc="for https connections, set list of CA certs from which to verify peer cert")


    #_________________________________________________________________________
    def __setSSLCACertFilePathList(self, caCertFilePathList):
        """For use with HTTPS connections only.  Specify CA certs to one of 
        which the peer cert must verify its signature against"""
        if self._transport != HTTPSConnection:
            return
        
        if self._transdict.get('postConnectionCheck'):
            self._transdict['postConnectionCheck'].caCertFilePathList = \
                                            caCertFilePathList
        else:
            self._transdict['postConnectionCheck'] = \
                            HostCheck(caCertFilePathList=caCertFilePathList)

    sslCACertFilePathList = property(fset=__setSSLCACertFilePathList, 
                                     doc=\
"for https connections, set list of CA cert files from which to verify peer cert")


    #_________________________________________________________________________
    def __setSignatureHandler(self, signatureHandler):
        """Set SignatureHandler object property method - set to None to for no
        digital signature and verification"""
        if signatureHandler is not None and \
           not isinstance(signatureHandler, SignatureHandler):
            raise AttributeError, \
    "Signature Handler must be %s type or None for no message security" % \
        "ndg.security.common.wsSecurity.SignatureHandler"
                            
        self.__signatureHandler = signatureHandler


    #_________________________________________________________________________
    def __getSignatureHandler(self):
        "Get SignatureHandler object property method"
        return self.__signatureHandler
    
    signatureHandler = property(fget=__getSignatureHandler,
                                fset=__setSignatureHandler,
                                doc="SignatureHandler object")
    
        
    #_________________________________________________________________________
    def initService(self, uri=None):
        """Set the WS client for the Session Manager"""
        if uri:
            self.__setURI(uri)
    
        # WS-Security Signature handler object is passed to binding
        try:
            locator = SessionMgrServiceLocator()
            self.__srv = locator.getSessionMgr(self.__uri,
                                         sig_handler=self.__signatureHandler,
                                         tracefile=self.__tracefile,
                                         transport=self._transport,
                                         transdict=self._transdict)
        except HTTPResponse, e:
            raise SessionMgrClientError, \
                "Initialising Service for \"%s\": %s %s" % \
                (self.__uri, e.status, e.reason)
    
        
    #_________________________________________________________________________   
    def connect(self,
                username,
                passphrase=None,
                passphraseFilePath=None,
                createServerSess=True):
        """Request a new user session from the Session Manager
        
        @type username: string
        @param username: the username of the user to connect
        
        @type passphrase: string
        @param passphrase: user's pass-phrase
        
        @type passphraseFilePath: string
        @param passphraseFilePath: a file containing the user's pass-phrase.  
        Use this as an alternative to passphrase keyword.
                                 
        @type createServerSess: bool
        @param createServerSess: If set to True, the SessionMgr will create
        and manage a session for the user.  For non-browser client case, it's 
        possible to choose to have a client or server side session using this 
        keyword.  If set to False sessID returned will be None
        
        @rtype: tuple
        @return user cert, user private key, issuing cert and sessID all as
        strings but sessID will be None if the createServerSess keyword is 
        False"""
    
        if not self.__srv:
            raise InvalidAttAuthorityClientCtx(\
                                        "Client binding is not initialised")
        
        if passphrase is None:
            try:
                passphrase = open(passphraseFilePath).read().strip()
            
            except Exception, e:
                raise SessionMgrClientError, "Pass-phrase not defined: " + \
                                             str(e)

        # Make connection
        res = self.__srv.connect(username, passphrase, createServerSess)

        # Convert from unicode because unicode causes problems with
        # M2Crypto private key load
        return tuple([isinstance(i,unicode) and str(i) or i for i in res])
    
        
    #_________________________________________________________________________   
    def disconnect(self, userCert=None, sessID=None):
        """Delete an existing user session from the Session Manager
        
        disconnect([userCert=c]|[sessID=i])
        
        @type userCert: string                 
        @param userCert: user's certificate used to identifier which session
        to disconnect.  This arg is not needed if the message is signed with
        the user cert or if sessID is set.  
                               
        @type sessID: string
        @param sessID: session ID.  Input this as an alternative to userCert
        This arg is not needed if the message is signed with the user cert or 
        if userCert keyword is."""
    
        if not self.__srv:
            raise InvalidAttAuthorityClientCtx(\
                                        "Client binding is not initialised")

        # Make connection
        self.__srv.disconnect(userCert, sessID)
    
        
    #_________________________________________________________________________   
    def getSessionStatus(self, userDN=None, sessID=None):
        """Check for the existence of a session with a given
        session ID / user certificate Distinguished Name
        
        disconnect([sessID=id]|[userDN=dn])
        
        @type userCert: string                 
        @param userCert: user's certificate used to identifier which session
        to disconnect.  This arg is not needed if the message is signed with
        the user cert or if sessID is set.  
                               
        @type sessID: string
        @param sessID: session ID.  Input this as an alternative to userCert
        This arg is not needed if the message is signed with the user cert or 
        if userCert keyword is."""
    
        if not self.__srv:
            raise InvalidAttAuthorityClientCtx(\
                                        "Client binding is not initialised")
        
        if sessID and userDN:
            raise SessionMgrClientError(
                            'Only "SessID" or "userDN" keywords may be set')
            
        if not sessID and not userDN:
            raise SessionMgrClientError(
                            'A "SessID" or "userDN" keyword must be set')          
            
        # Make connection
        return self.__srv.getSessionStatus(userDN, sessID)

    
    #_________________________________________________________________________ 
    def getAttCert(self,
                   userCert=None,
                   sessID=None,
                   attAuthorityURI=None,
                   attAuthorityCert=None,
                   reqRole=None,
                   mapFromTrustedHosts=True,
                   rtnExtAttCertList=False,
                   extAttCertList=[],
                   extTrustedHostList=[]):    
        """Request NDG Session Manager Web Service to retrieve an Attribute
        Certificate from the given Attribute Authority and cache it in the
        user's credential wallet held by the session manager.
        
        ac = getAttCert([sessID=i]|[userCert=p][key=arg, ...])
         
        @raise AttributeRequestDenied: this is raised if the request is 
        denied because the user is not registered with the Attribute 
        Authority.  In this case, a list of candidate attribute certificates
        may be returned which could be used to retry with a request for a
        mapped AC.  These are assigned to the raised exception's 
        extAttCertList attribute
             
        @type userCert: string
        @param userCert: user certificate - use as ID instead of session 
        ID.  This can be omitted if the message is signed with a user 
        certificate.  In this case the user certificate is passed in the 
        BinarySecurityToken of the WS-Security header
        
        @type sessID: string
        @param sessID: session ID.  Input this as an alternative to 
        userCert in the case of a browser client.
        
        @type attAuthorityURI: string
        @param attAuthorityURI: URI for Attribute Authority WS.
        
        @type attAuthorityCert: string
        @param attAuthorityCert: The Session Manager uses the Public key of 
        the Attribute Authority to encrypt requests to it.
        
        @type reqRole: string
        @param reqRole: The required role for access to a data set.  This 
        can be left out in which case the Attribute Authority just returns 
        whatever Attribute Certificate it has for the user
        
        @type mapFromTrustedHosts: bool
        @param mapFromTrustedHosts: Allow a mapped Attribute Certificate to 
        be created from a user certificate from another trusted host.
        
        @type rtnExtAttCertList: bool
        @param rtnExtAttCertList: Set this flag True so that if the 
        attribute request is denied, a list of potential attribute 
        certificates for mapping may be returned. 
        
        @type extAttCertList: list
        @param extAttCertList: A list of Attribute Certificates from other
        trusted hosts from which the target Attribute Authority can make a 
        mapped certificate
        
        @type extTrustedHostList: list
        @param extTrustedHostList: A list of trusted hosts that can be used 
        to get Attribute Certificates for making a mapped AC.
        
        @rtype: ndg.security.common.AttCert.AttCert
        @return: if successful, an attribute certificate."""
    
        if not self.__srv:
            raise InvalidAttAuthorityClientCtx(\
                                        "Client binding is not initialised")
        
        # Make request
        try:
            attCert, msg, extAttCertList = self.__srv.getAttCert(userCert,
                                                           sessID, 
                                                           attAuthorityURI,
                                                           attAuthorityCert,
                                                           reqRole,
                                                           mapFromTrustedHosts,
                                                           rtnExtAttCertList,
                                                           extAttCertList,
                                                           extTrustedHostList)
        except Exception, e:
            # Try to detect exception type from SOAP fault message
            errMsg = str(e)
            for excep in self.excepMap:
                if excep in errMsg:
                    raise self.excepMap[excep]
        
            # Catch all in case none of the known types matched
            raise e
        
        if not attCert:
            raise AttributeRequestDenied(msg, extAttCertList=extAttCertList)
        
        return AttCertParse(attCert)
    
                                    
    #_________________________________________________________________________
    def getX509Cert(self):
        """Retrieve the public key of the Session Manager"""
    
        if not self.__srv:
            raise InvalidAttAuthorityClientCtx(\
                                        "Client binding is not initialised")
        return self.__srv.getX509Cert()
                            