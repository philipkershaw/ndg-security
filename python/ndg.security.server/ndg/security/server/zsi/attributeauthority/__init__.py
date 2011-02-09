"""ZSI Server side SOAP Binding for Attribute Authority Web Service

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "11/06/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os
import sys
import base64
import logging
log = logging.getLogger(__name__)

from ndg.security.common.zsi.attributeauthority.AttributeAuthority_services \
    import getAttCertInputMsg, getAttCertOutputMsg, \
        getHostInfoInputMsg, getHostInfoOutputMsg, \
        getTrustedHostInfoInputMsg, getTrustedHostInfoOutputMsg, \
        getAllHostsInfoInputMsg, getAllHostsInfoOutputMsg
    
from \
ndg.security.server.zsi.attributeauthority.AttributeAuthority_services_server \
    import AttributeAuthorityService as _AttributeAuthorityService

from ndg.security.server.attributeauthority import AttributeAuthority, \
    AttributeAuthorityAccessDenied
    
from ndg.security.common.wssecurity.dom import SignatureHandler
from ndg.security.common.X509 import X509Cert, X509CertRead


class AttributeAuthorityWS(_AttributeAuthorityService):
    '''Attribute Authority ZSI SOAP Service Binding class'''

    def __init__(self, **kw):
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        # Extract local WS-Security signature verification filter
        self.wsseSignatureVerificationFilterID = kw.pop(
                                        'wsseSignatureVerificationFilterID', 
                                        None)
        if self.wsseSignatureVerificationFilterID is None:
            log.warning('No "wsseSignatureVerificationFilterID" option was '
                        'set in the input config')
     
        # Initialise Attribute Authority class - property file will be
        # picked up from default location under $NDG_DIR directory
        self.aa = AttributeAuthority(**kw)


    def soap_getAttCert(self, ps):
        '''Retrieve an Attribute Certificate
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: ndg.security.common.zsi.attributeauthority.AttributeAuthority_services_types.getAttCertResponse_Holder
        @return: response'''
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        request = ps.Parse(getAttCertInputMsg.typecode)    
        response = _AttributeAuthorityService.soap_getAttCert(self, ps)

        # Derive designated holder cert differently according to whether
        # a signed message is expected from the client - NB, this is dependent
        # on whether a reference to the signature filter was set in the 
        # environment
        signatureFilter = self.referencedWSGIFilters.get(
                                        self.wsseSignatureVerificationFilterID)
        if signatureFilter is not None:
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's proxy
            log.debug("Reading holder certificate from WS-Security signature "
                      "header")
            holderX509Cert = signatureFilter.signatureHandler.verifyingCert
        else:
            # No signature from client - they must instead provide the
            # designated holder cert via the UserX509Cert input
            log.debug('Reading holder certificate from SOAP request '
                      '"userX509Cert" parameter')
            holderX509Cert = request.UserX509Cert

        try:
            attCert = self.aa.getAttCert(userId=request.UserId,
                                         holderX509Cert=holderX509Cert,
                                         userAttCert=request.UserAttCert)  
            response.AttCert = attCert.toString()
            
        except AttributeAuthorityAccessDenied, e:
            response.Msg = str(e)
            
        return response
       

    def soap_getHostInfo(self, ps):
        '''Get information about this host
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: response
        @return: response'''
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        response = _AttributeAuthorityService.soap_getHostInfo(self, ps)
        
        response.Hostname = self.aa.hostInfo.keys()[0]
        response.SiteName = self.aa.hostInfo[response.Hostname]['siteName']
        response.AaURI = self.aa.hostInfo[response.Hostname]['aaURI']
        response.AaDN = self.aa.hostInfo[response.Hostname]['aaDN']
        response.LoginURI = self.aa.hostInfo[response.Hostname]['loginURI']
        response.LoginServerDN = \
            self.aa.hostInfo[response.Hostname]['loginServerDN']
        response.LoginRequestServerDN = \
            self.aa.hostInfo[response.Hostname]['loginRequestServerDN']

        return response
       

    def soap_getAllHostsInfo(self, ps):
        '''Get information about all hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: response object'''
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        response = _AttributeAuthorityService.soap_getAllHostsInfo(self, ps)
        

        trustedHostInfo = self.aa.getTrustedHostInfo()

        # Convert ready for serialization
        
        # First get info for THIS Attribute Authority ...
        # Nb. No role lsit applies here
        hosts = [response.new_hosts()]
        
        hosts[0].Hostname = self.aa.hostInfo.keys()[0]
        
        hosts[0].AaURI = self.aa.hostInfo[hosts[0].Hostname]['aaURI']
        hosts[0].SiteName = self.aa.hostInfo[hosts[0].Hostname]['siteName']
        hosts[0].AaDN = self.aa.hostInfo[hosts[0].Hostname]['aaDN']
        hosts[0].LoginURI = self.aa.hostInfo[hosts[0].Hostname]['loginURI']
        hosts[0].LoginServerDN = \
            self.aa.hostInfo[hosts[0].Hostname]['loginServerDN']
        hosts[0].LoginRequestServerDN = \
            self.aa.hostInfo[hosts[0].Hostname]['loginRequestServerDN']
        
        # ... then append info for other trusted attribute authorities...
        for hostname, hostInfo in trustedHostInfo.items():
            host = response.new_hosts()
            
            host.Hostname = hostname
            host.SiteName = hostInfo['siteName']
            host.AaURI = hostInfo['aaURI']
            host.AaDN = hostInfo['aaDN']
            host.LoginURI = hostInfo['loginURI']
            host.LoginServerDN = hostInfo['loginServerDN']
            host.LoginRequestServerDN=hostInfo['loginRequestServerDN']
            host.RoleList = hostInfo['role']
            
            hosts.append(host)
            
        response.Hosts = hosts

        return response


    def soap_getTrustedHostInfo(self, ps):
        '''Get information about other trusted hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: response object'''
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        request = ps.Parse(getTrustedHostInfoInputMsg.typecode)    
        response = _AttributeAuthorityService.soap_getTrustedHostInfo(self, ps)
        
        trustedHostInfo = self.aa.getTrustedHostInfo(role=request.Role)

        # Convert ready for serialization
        trustedHosts = []
        for hostname, hostInfo in trustedHostInfo.items():
            trustedHost = response.new_trustedHosts()
            
            trustedHost.Hostname = hostname
            trustedHost.SiteName = hostInfo['siteName']
            trustedHost.AaURI = hostInfo['aaURI']
            trustedHost.AaDN = hostInfo['aaDN']
            trustedHost.LoginURI = hostInfo['loginURI']
            trustedHost.LoginServerDN = hostInfo['loginServerDN']
            trustedHost.LoginRequestServerDN=hostInfo['loginRequestServerDN']
            trustedHost.RoleList = hostInfo['role']
            
            trustedHosts.append(trustedHost)
            
        response.TrustedHosts = trustedHosts
        
        return response
