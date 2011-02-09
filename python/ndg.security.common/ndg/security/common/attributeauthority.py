"""NDG Security Attribute Authority client - client interface classes to the
Attribute Authority.  These have been separated from their
original location in the SecurityClient since they have the 
unusual place of being required by both client and server
NDG security packages.  For the server side they are required
as the CredentialWallet invoked by the Session Manager acts as a
client to Attribute Authorities when negotiating the required
Attribute Certificate.

Make requests for Attribute Certificates used for authorisation

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/11/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id:attributeauthority.py 4373 2008-10-29 09:54:39Z pjkersha $"

import logging
log = logging.getLogger(__name__)

# Determine https http transport
import urlparse, httplib
from ZSI.wstools.Utility import HTTPResponse

from ndg.security.common.zsi.attributeauthority.AttributeAuthority_services \
    import AttributeAuthorityServiceLocator
from ndg.security.common.wssecurity.dom import SignatureHandler
from ndg.security.common.AttCert import AttCert, AttCertParse
from ndg.security.common.m2CryptoSSLUtility import HTTPSConnection, HostCheck
from ndg.security.common.zsi.httpproxy import ProxyHTTPConnection

class AttributeAuthorityClientError(Exception):
    """Exception handling for AttributeAuthorityClient class"""

class AttributeRequestDenied(Exception):
    """Raise when a getAttCert call to the AA is denied"""

class NoTrustedHosts(AttributeAuthorityClientError):
    """Raise from getTrustedHosts if there are no trusted hosts defined in
    the map configuration"""

class NoMatchingRoleInTrustedHosts(AttributeAuthorityClientError):
    """Raise from getTrustedHosts if there is no mapping to any of the 
    trusted hosts for the given input role name"""

class InvalidAttributeAuthorityClientCtx(AttributeAuthorityClientError):
    """Attribute Authority ZSI Client is not initialised"""

class AttributeAuthorityClient(object):
    """Client interface to Attribute Authority web service
    
    @type excepMap: dict
    @cvar excepMap: map exception strings returned from SOAP fault to client
    Exception class to call"""
    
    excepMap = {
        'AttributeAuthorityNoTrustedHosts': NoTrustedHosts,
        'AttributeAuthorityNoMatchingRoleInTrustedHosts':NoMatchingRoleInTrustedHosts
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
        @param uri: URI for Attribute Authority WS.  Setting it will also
        initialise the Service Proxy
                                         
        @param tracefile: set to file object such as sys.stderr to give 
        extra WS debug information
        
        @type sslCACertList: list
        @param sslCACertList: This keyword is for use with SSL connections 
        only.  Set a list of one ore more CA certificates.  The peer cert.
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

        log.debug("AttributeAuthorityClient.__init__ ...")
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
        if setSignatureHandler:
            log.debug('signatureHandlerKw = %s' % signatureHandlerKw)
            self.__signatureHandler = SignatureHandler(**signatureHandlerKw)
        else:
            self.__signatureHandler = None
           
        self.__tracefile = tracefile
        
        # Instantiate Attribute Authority WS proxy
        if self.uri:
            self.initService()
        
    def __setURI(self, uri):
        """Set URI for service
        @type uri: string
        @param uri: URI for service to connect to"""
        if not isinstance(uri, basestring):
            raise AttributeAuthorityClientError(
                        "Attribute Authority URI must be a valid string")
        
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

    def __getURI(self):
        """Get URI for service
        @rtype: string
        @return: uri for service to be invoked"""
        return self.__uri
            
    uri = property(fset=__setURI, fget=__getURI,doc="Attribute Authority URI")

    def __setHTTPProxyHost(self, val):
        """Set a HTTP Proxy host overriding any http_proxy environment variable
        setting"""
        if self._transport != ProxyHTTPConnection:
            log.info("Ignoring httpProxyHost setting: transport class is "
                     "not ProxyHTTPConnection type")
            return
        
        self._transdict['httpProxyHost'] = val

    httpProxyHost = property(fset=__setHTTPProxyHost, 
        doc="HTTP Proxy hostname - overrides any http_proxy env var setting")

    def __setNoHttpProxyList(self, val):
        """Set to list of hosts for which to ignore the HTTP Proxy setting"""
        if self._transport != ProxyHTTPConnection:
            log.info("Ignore noHttpProxyList setting: transport class is not "
                     "ProxyHTTPConnection type")
            return
        
        self._transdict['noHttpProxyList'] = val

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
                             doc="for https connections, set list of CA "
                                 "certs from which to verify peer cert")

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
doc="for https connections, set list of CA cert files from which to verify peer cert")

    def __setSignatureHandler(self, signatureHandler):
        """Set SignatureHandler object property method - set to None to for no
        digital signature and verification"""
        if signatureHandler is not None and \
           not isinstance(signatureHandler, signatureHandler):
            raise AttributeError("Signature Handler must be %s type or None "
                                 "for no message security" % 
                        "ndg.security.common.wssecurity.dom.SignatureHandler")
                            
        self.__signatureHandler = signatureHandler
    
    def __getSignatureHandler(self):
        "Get SignatureHandler object property method"
        return self.__signatureHandler
    
    signatureHandler = property(fget=__getSignatureHandler,
                                fset=__setSignatureHandler,
                                doc="SignatureHandler object")
    
    def initService(self, uri=None):
        """Set the WS proxy for the Attribute Authority
        
        @type uri: string
        @param uri: URI for service to invoke"""
        
        if uri:
            self.__setURI(uri)

        # WS-Security Signature handler object is passed to binding
        try:
            locator = AttributeAuthorityServiceLocator()
            self.__srv = locator.getAttributeAuthority(self.__uri, 
                                         sig_handler=self.__signatureHandler,
                                         tracefile=self.__tracefile,
                                         transport=self._transport,
                                         transdict=self._transdict)
        except HTTPResponse, e:
            raise AttributeAuthorityClientError(
                "Error initialising service for \"%s\": %s %s" % 
                (self.__uri, e.status, e.reason))

    def getHostInfo(self):
        """Get host information for the data provider which the 
        Attribute Authority represents
        
        @rtype: dict
        @return: dictionary of host information derived from the Attribute
        Authority's map configuration
        """
    
        if not self.__srv:
            raise InvalidAttributeAuthorityClientCtx("Client binding is not "
                                                     "initialised")

        try:
            # Convert return tuple into list to enable use of pop() later
            response = list(self.__srv.getHostInfo())
        except httplib.BadStatusLine, e:
            raise AttributeAuthorityClientError("HTTP bad status line: %s" % e)

        except Exception, e:
            # Try to detect exception type from SOAP fault message
            errMsg = str(e)
            for excep in self.excepMap:
                if excep in errMsg:
                    raise self.excepMap[excep]
                
            # Catch all    
            raise e

        # Unpack response into dict
        hostInfoKw = ['siteName',
                      'aaURI',
                      'aaDN',
                      'loginURI',
                      'loginServerDN',
                      'loginRequestServerDN']
        hostInfoKw.reverse()
        hostInfo = {response.pop(): \
                    dict([(k, response.pop()) for k in hostInfoKw])}

        return hostInfo

    def getTrustedHostInfo(self, role=None):
        """Get list of trusted hosts for an Attribute Authority
        
        @type role: string
        @param role: get information for trusted hosts that have a mapping to
        this role
        
        @rtype: dict
        @return: dictionary of host information indexed by hostname derived 
        from the map configuration"""
    
        if not self.__srv:
            raise InvalidAttributeAuthorityClientCtx("Client binding is not "
                                                     "initialised")
            
        try:
            trustedHosts = self.__srv.getTrustedHostInfo(role)

        except httplib.BadStatusLine, e:
            raise AttributeAuthorityClientError("HTTP bad status line: %s" % e)

        except Exception, e:
            # Try to detect exception type from SOAP fault message
            errMsg = str(e)
            for excep in self.excepMap:
                if excep in errMsg:
                    raise self.excepMap[excep]
                
            # Catch all    
            raise e

        # Convert into dictionary form as used by AttributeAuthority class
        trustedHostInfo = {}
        for host in trustedHosts:
            hostname = host.get_element_hostname()
            
            trustedHostInfo[hostname] = {
                'siteName': host.SiteName,
                'aaURI': host.AaURI,
                'aaDN': host.AaDN,
                'loginURI': host.LoginURI,
                'loginServerDN': host.LoginServerDN,
                'loginRequestServerDN': host.LoginRequestServerDN,
                'role': host.RoleList
            }
            
        return trustedHostInfo

    def getAllHostsInfo(self):
        """Get list of all hosts for an Attribute Authority i.e. itself and
        all the hosts it trusts
        
        @rtype: dict
        @return: dictionary of host information indexed by hostname derived 
        from the map configuration"""
    
        if not self.__srv:
            raise InvalidAttributeAuthorityClientCtx("Client binding is not "
                                                     "initialised")

        hosts = self.__srv.getAllHostsInfo()
        try:
            hosts = self.__srv.getAllHostsInfo()

        except httplib.BadStatusLine, e:
            raise AttributeAuthorityClientError("HTTP bad status line: %s" % e)

        except Exception, e:
            # Try to detect exception type from SOAP fault message
            errMsg = str(e)
            for excep in self.excepMap:
                if excep in errMsg:
                    raise self.excepMap[excep]
                
            # Catch all    
            raise e

        # Convert into dictionary form as used by AttributeAuthority class
        allHostInfo = {}
        for host in hosts:
            hostname = host.Hostname
            allHostInfo[hostname] = {
                'siteName': host.SiteName,
                'aaURI': host.AaURI,
                'aaDN': host.AaDN,
                'loginURI': host.LoginURI,
                'loginServerDN': host.LoginServerDN,
                'loginRequestServerDN': host.LoginRequestServerDN,
                'role': host.RoleList
            }

        return allHostInfo   

    def getAttCert(self, userId=None, userX509Cert=None, userAttCert=None):
        """Request attribute certificate from NDG Attribute Authority Web 
        Service.
        
        @type userId: string
        @param userId: DN of the X.509 certificate used in SOAP digital 
        signature corresponds to the *holder* of the Attribute Certificate
        that is issued.  Set this additional field to specify an alternate
        user ID to associate with the AC.  This is useful in the case where,
        as in the DEWS project, the holder will be a server cert. rather than
        a user cert.
        
        If this keword is omitted, userId in the AC will default to the same
        value as the holder DN.
        
        @type userX509Cert: string
        @param userX509Cert: certificate corresponding to proxy private key and
        proxy cert used to sign the request.  Enables server to establish
        chain of trust proxy -> user cert -> CA cert.  If a standard 
        private key is used to sign the request, this argument is not 
        needed.
        
        @type userAttCert: string / AttCert
        @param userAttCert: user attribute certificate from which to make a 
        mapped certificate at the target attribute authority.  userAttCert
        must have been issued from a trusted host to the target.  This is not 
        necessary if the user is registered at the target Attribute Authority.
        
        @rtype ndg.security.common.AttCert.AttCert
        @return attribute certificate for user.  If access is refused, 
        AttributeRequestDenied is raised"""
    
        if not self.__srv:
            raise InvalidAttributeAuthorityClientCtx("Client binding is not "
                                                     "initialised")

        # Ensure cert is serialized before passing over web service interface
        if isinstance(userAttCert, AttCert):
            userAttCert = userAttCert.toString()

        try:
            sAttCert, msg = self.__srv.getAttCert(userId,
                                                  userX509Cert,
                                                  userAttCert)  
        except httplib.BadStatusLine, e:
            raise AttributeAuthorityClientError(
                'Calling "%s" HTTP bad status line: %s' % (self.__uri, e))

        except Exception, e:
            # Try to detect exception type from SOAP fault message
            errMsg = str(e)
            for excep in self.excepMap:
                if excep in errMsg:
                    raise self.excepMap[excep]
                
            # Catch all    
            raise e
        
        if sAttCert:
            return AttCertParse(sAttCert)
        else:
            raise AttributeRequestDenied(msg)
