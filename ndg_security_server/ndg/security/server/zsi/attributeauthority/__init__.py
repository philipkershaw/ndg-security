"""ZSI Server side SOAP Binding for Attribute Authority Web Service

NERC DataGrid Project"""
__author__ = "P J Kershaw"
__date__ = "11/06/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
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
    
from ndg.security.common.wssecurity.signaturehandler.dom import SignatureHandler
from ndg.security.common.X509 import X509Cert, X509CertRead


class AttributeAuthorityWS(_AttributeAuthorityService):
    '''Attribute Authority ZSI SOAP Service Binding class'''
    
    DEBUG_ENVIRON_VARNAME = 'NDGSEC_INT_DEBUG'
    WSSE_SIGNATURE_VERIFICATION_FILTER_ID_OPTNAME = \
                                            'wsseSignatureVerificationFilterID'
    
    def __init__(self, **kw):
        self.__wsseSignatureVerificationFilterID = None
        self.__debug = None
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.debug = bool(os.environ.get(
                                AttributeAuthorityWS.DEBUG_ENVIRON_VARNAME))
        if self.debug:
            import pdb
            pdb.set_trace()
            
        # Extract local WS-Security signature verification filter
        self.wsseSignatureVerificationFilterID = kw.pop(
            AttributeAuthorityWS.WSSE_SIGNATURE_VERIFICATION_FILTER_ID_OPTNAME, 
            None)
        if self.wsseSignatureVerificationFilterID is None:
            log.warning('No "wsseSignatureVerificationFilterID" option was '
                        'set in the input config')
     
        # Initialise Attribute Authority class - property file will be
        # picked up from default location under $NDG_DIR directory
        if kw:
            self.aa = AttributeAuthority.fromProperties(**kw)

    def _get_debug(self):
        return self.__debug

    def _set_debug(self, value):
        if not isinstance(value, bool):
            raise TypeError('Expecting %r for "debug"; got %r' %
                            (bool, type(value)))
        self.__debug = value

    debug = property(_get_debug, _set_debug, 
                     doc="Set to True to drop into the debugger for each SOAP "
                         "callback")
    
    def _get_aa(self):
        return self.__aa
    
    def _set_aa(self, val):
        if not isinstance(val, AttributeAuthority):
            raise TypeError('Expecting %r for "aa" attribute; got %r' %
                            (AttributeAuthority, type(val)))
        self.__aa = val
            
    aa = property(fget=_get_aa,
                  fset=_set_aa,
                  doc="Attribute Authority instance")

    def _get_wsseSignatureVerificationFilterID(self):
        return self.__wsseSignatureVerificationFilterID

    def _set_wsseSignatureVerificationFilterID(self, value):
        if not isinstance(value, (basestring, type(None))):
            raise TypeError('Expecting string or None type for '
                            '"wsseSignatureVerificationFilterID"; got %r' %
                            type(value))
        self.__wsseSignatureVerificationFilterID = value

    wsseSignatureVerificationFilterID = property(
                                    _get_wsseSignatureVerificationFilterID, 
                                    _set_wsseSignatureVerificationFilterID, 
                                    doc="Reference the Signature Verification "
                                        "filter upstream in the stack by "
                                        "the WSGI environ with this keyword.  "
                                        "The verification middleware must "
                                        "likewise set a reference to itself "
                                        "in the environ")
    
    def soap_getAttCert(self, ps):
        '''Retrieve an Attribute Certificate
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: ndg.security.common.zsi.attributeauthority.AttributeAuthority_services_types.getAttCertResponse_Holder
        @return: response'''
        if self.debug:
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
        if self.debug:
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
        if self.debug:
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
            host.LoginRequestServerDN = hostInfo['loginRequestServerDN']
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
        if self.debug:
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
            trustedHost.LoginRequestServerDN = hostInfo['loginRequestServerDN']
            trustedHost.RoleList = hostInfo['role']
            
            trustedHosts.append(trustedHost)
            
        response.TrustedHosts = trustedHosts
        
        return response
