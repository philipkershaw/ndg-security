"""NDG Security client - client interface classes to Session Manager 

Make requests for authentication and authorisation

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id:sessionmanager.py 4373 2008-10-29 09:54:39Z pjkersha $"

import logging
log = logging.getLogger(__name__)

# Determine https/http transport
import urlparse

from ZSI.wstools.Utility import HTTPResponse

from ndg.security.common.wssecurity.signaturehandler.foursuite import \
    SignatureHandler
    
from ndg.security.common.wssecurity.utils import DomletteReader, \
    DomletteElementProxy
    
from ndg.security.common.AttCert import AttCert, AttCertParse
from ndg.security.common.m2CryptoSSLUtility import HTTPSConnection, \
    HostCheck
from ndg.security.common.zsi.httpproxy import ProxyHTTPConnection
from ndg.security.common.zsi.sessionmanager.SessionManager_services import \
                                                SessionManagerServiceLocator

class SessionManagerClientError(Exception):
    """Exception handling for SessionManagerClient class"""

class SessionNotFound(SessionManagerClientError):
    """Raise when a session ID input doesn't match with an active session on
    the Session Manager"""

class SessionCertTimeError(SessionManagerClientError):
    """Session's X.509 Cert. not before time is BEFORE the system time - 
    usually caused by server's clocks being out of sync.  Fix by all servers
    running NTP"""

class SessionExpired(SessionManagerClientError):
    """Session's X.509 Cert. has expired"""

class InvalidSession(SessionManagerClientError):
    """Session is invalid"""

class InvalidSessionManagerClientCtx(SessionManagerClientError):
    """Session Manager ZSI Client is not initialised"""
 
class AttributeRequestDenied(SessionManagerClientError):
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
                    raise SessionManagerClientError("Input external Attribute "
                                                    "Certificate must be "
                                                    "AttCert type")
                         
                self.__extAttCertList += [ac]
                
            del kw['extAttCertList']
            
        Exception.__init__(self, *args, **kw)

        
    def __getExtAttCertList(self):
        """Return list of candidate Attribute Certificates that could be used
        to try to get a mapped certificate from the target Attribute Authority
        """
        return self.__extAttCertList

    extAttCertList = property(fget=__getExtAttCertList,
                              doc="list of candidate Attribute Certificates "
                                  "that could be used to try to get a mapped "
                                  "certificate from the target Attribute "
                                  "Authority")


class SessionManagerClient(object):
    """Client interface to Session Manager Web Service
    
    @type excepMap: dict
    @cvar excepMap: map exception strings returned from SOAP fault to client
    Exception class to call"""

    excepMap = {
        'SessionNotFound':                 SessionNotFound,
        'UserSessionNotBeforeTimeError':   SessionCertTimeError,
        'UserSessionExpired':              SessionExpired,
        'InvalidUserSession':              InvalidSession
    }
    
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

        log.debug("SessionManagerClient.__init__ ...")
        
        self.__srv = None
        self.__uri = None
        self._transdict = {}
        self._transport = ProxyHTTPConnection       
        
        if uri:
            self.uri = uri

        self.httpProxyHost = httpProxyHost
        self.noHttpProxyList = noHttpProxyList

        if sslPeerCertCN:
            self.sslPeerCertCN = sslPeerCertCN
        
        if sslCACertList:
            self.sslCACertList = sslCACertList
        elif sslCACertFilePathList:
            self.sslCACertFilePathList = sslCACertFilePathList

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
        

    def __setURI(self, uri):
        """Set URI for service
        @type uri: string
        @param uri: URI for service to connect to"""
        
        if not isinstance(uri, basestring):
            raise SessionManagerClientError(
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

    def __getURI(self):
        """Get URI for service
        @rtype: string
        @return: uri for service to be invoked"""
        return self.__uri
        
    uri = property(fset=__setURI, fget=__getURI, doc="Session Manager URI")


    def __setHTTPProxyHost(self, val):
        """Set a HTTP Proxy host overriding any http_proxy environment variable
        setting"""
        if self._transport != ProxyHTTPConnection:
            log.debug("Ignoring httpProxyHost setting: transport class is "
                      "not ProxyHTTPConnection type")
            return
        
        self._transdict['httpProxyHost'] = val

    httpProxyHost = property(fset=__setHTTPProxyHost, 
                             doc="HTTP Proxy hostname - overrides any "
                                 "http_proxy env var setting")


    def __setNoHttpProxyList(self, val):
        """Set to list of hosts for which to ignore the HTTP Proxy setting"""
        if self._transport != ProxyHTTPConnection:
            log.debug("Ignore noHttpProxyList setting: transport " + \
                      "class is not ProxyHTTPConnection type")
            return
        
        self._transdict['noHttpProxyList']= val

    noHttpProxyList = property(fset=__setNoHttpProxyList, 
                               doc="Set to list of hosts for which to ignore "
                                   "the HTTP Proxy setting")
    

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
                             doc="for https connections, set CN of peer cert "
                                 "if other than peer hostname")


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
                             doc="for https connections, set list of CA certs "
                                 "from which to verify peer cert")


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
                                     doc="for https connections, set list of "
                                     "CA cert files from which to verify peer "
                                     "cert")

    def __setSignatureHandler(self, signatureHandler):
        """Set SignatureHandler object property method - set to None to for no
        digital signature and verification"""
        if not isinstance(signatureHandler, (SignatureHandler,None.__class__)):
            raise AttributeError("Signature Handler must be %s type or None "
                                 "for no message security" % SignatureHandler)
                            
        self.__signatureHandler = signatureHandler

    def __getSignatureHandler(self):
        "Get SignatureHandler object property method"
        return self.__signatureHandler
    
    signatureHandler = property(fget=__getSignatureHandler,
                                fset=__setSignatureHandler,
                                doc="SignatureHandler object")
    
    def initService(self, uri=None):
        """Set the WS client for the Session Manager"""
        if uri:
            self.__setURI(uri)
    
        # WS-Security Signature handler object is passed to binding
        try:
            locator = SessionManagerServiceLocator()
            self.__srv = locator.getSessionManager(self.__uri,
                                         sig_handler=self.__signatureHandler,
                                         readerclass=DomletteReader, 
                                         writerclass=DomletteElementProxy,
                                         tracefile=self.__tracefile,
                                         transport=self._transport,
                                         transdict=self._transdict)
        except HTTPResponse, e:
            raise SessionManagerClientError(
                "Initialising Service for \"%s\": %s %s" %
                (self.__uri, e.status, e.reason))
    
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
        @param createServerSess: If set to True, the SessionManager will create
        and manage a session for the user.  For non-browser client case, it's 
        possible to choose to have a client or server side session using this 
        keyword.  If set to False sessID returned will be None
        
        @rtype: tuple
        @return user cert, user private key, issuing cert and sessID all as
        strings but sessID will be None if the createServerSess keyword is 
        False
        
        @raise InvalidSessionManagerClientCtx: no client binding to service has
        been set up
        @raise SessionManagerClientError: error reading passphrase file"""
    
        if not self.__srv:
            raise InvalidSessionManagerClientCtx("Client binding is not "
                                                 "initialised")
        
        if passphrase is None:
            try:
                passphrase = open(passphraseFilePath).read().strip()
            
            except Exception, e:
                raise SessionManagerClientError("Pass-phrase not defined: %s" %
                                                e)

        # Make connection
        res = self.__srv.connect(username, passphrase, createServerSess)

        # Convert from unicode because unicode causes problems with
        # M2Crypto private key load
        return tuple([isinstance(i,unicode) and str(i) or i for i in res])
    
    
    def disconnect(self, userX509Cert=None, sessID=None):
        """Delete an existing user session from the Session Manager
        
        disconnect([userX509Cert=c]|[sessID=i])
        
        @type userX509Cert: string                 
        @param userX509Cert: user's certificate used to identifier which session
        to disconnect.  This arg is not needed if the message is signed with
        the user cert or if sessID is set.  
                               
        @type sessID: string
        @param sessID: session ID.  Input this as an alternative to userX509Cert
        This arg is not needed if the message is signed with the user cert or 
        if userX509Cert keyword is."""
    
        if not self.__srv:
            raise InvalidSessionManagerClientCtx("Client binding is not "
                                                 "initialised")

        # Make connection
        self.__srv.disconnect(userX509Cert, sessID)


    def getSessionStatus(self, userDN=None, sessID=None):
        """Check for the existence of a session with a given
        session ID / user certificate Distinguished Name
        
        disconnect([sessID=id]|[userDN=dn])
        
        @type userDN: string                 
        @param userDN: user's certificate Distinguished Name used to identify
        which session to disconnect from.  This arg is not needed if the 
        message is signed with the user X.509 cert or if sessID is set.  
                               
        @type sessID: string
        @param sessID: session ID.  Input this as an alternative to userDN
        This arg is not needed if the message is signed with the user X.509 cert or 
        if userDN keyword is."""
    
        if not self.__srv:
            raise InvalidSessionManagerClientCtx("Client binding is not "
                                                 "initialised")
        
        if sessID and userDN:
            raise SessionManagerClientError(
                            'Only "SessID" or "userDN" keywords may be set')
            
        if not sessID and not userDN:
            raise SessionManagerClientError(
                            'A "SessID" or "userDN" keyword must be set')          
            
        # Make connection
        return self.__srv.getSessionStatus(userDN, sessID)


    def getAttCert(self,
                   userX509Cert=None,
                   sessID=None,
                   attributeAuthorityURI=None,
                   reqRole=None,
                   mapFromTrustedHosts=True,
                   rtnExtAttCertList=False,
                   extAttCertList=[],
                   extTrustedHostList=[]):    
        """Request NDG Session Manager Web Service to retrieve an Attribute
        Certificate from the given Attribute Authority and cache it in the
        user's credential wallet held by the session manager.
        
        ac = getAttCert([sessID=i]|[userX509Cert=p][key=arg, ...])
         
        @raise AttributeRequestDenied: this is raised if the request is 
        denied because the user is not registered with the Attribute 
        Authority.  In this case, a list of candidate attribute certificates
        may be returned which could be used to retry with a request for a
        mapped AC.  These are assigned to the raised exception's 
        extAttCertList attribute
             
        @type userX509Cert: string
        @param userX509Cert: user certificate - use as ID instead of session 
        ID.  This can be omitted if the message is signed with a user 
        certificate.  In this case the user certificate is passed in the 
        BinarySecurityToken of the WS-Security header
        
        @type sessID: string
        @param sessID: session ID.  Input this as an alternative to 
        userX509Cert in the case of a browser client.
        
        @type attributeAuthorityURI: string
        @param attributeAuthorityURI: URI for Attribute Authority WS.
        
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
            raise InvalidSessionManagerClientCtx("Client binding is not "
                                                 "initialised")
        
        # Make request
        try:
            attCert, msg, extAttCertList = self.__srv.getAttCert(userX509Cert,
                                                       sessID, 
                                                       attributeAuthorityURI,
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
                            