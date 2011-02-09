"""ZSI Server side SOAP Binding for Session Manager Web Service

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "01/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os, sys
import base64
import logging
log = logging.getLogger(__name__)


from ndg.security.server.zsi.sessionmanager.SessionManager_services_server \
    import SessionManagerService as _SessionManagerService
from ndg.security.common.zsi.sessionmanager.SessionManager_services import \
    connectInputMsg, disconnectInputMsg, getSessionStatusInputMsg, \
    getAttCertInputMsg
    
    
from ndg.security.server.sessionmanager import SessionManager
from ndg.security.common.credentialwallet import \
                                        CredentialWalletAttributeRequestDenied  
from ndg.security.common.wssecurity.signaturehandler.dom import SignatureHandler
from ndg.security.common.X509 import X509Cert, X509CertRead

class SessionManagerWSConfigError(Exception):
    '''Raise for errors related to the Session Manager Web Service 
    configuration'''
    
class SessionManagerWS(_SessionManagerService):
    '''Session Manager ZSI SOAP Service Binding class'''
    
    def __init__(self, **kw):
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        # Extract local Attribute Authority environ identifier
        self.attributeAuthorityFilterID = kw.pop('attributeAuthorityFilterID', 
                                                 None)
        if self.attributeAuthorityFilterID is None:
            log.warning('No "attributeAuthorityFilterID" option was '
                        'set in the input config: link to a local Attibute '
                        'Authority instance is disabled')
        
        # ... and WS-Security signature verification filter
        self.wsseSignatureVerificationFilterID = kw.pop(
                                        'wsseSignatureVerificationFilterID', 
                                        None)
        if self.wsseSignatureVerificationFilterID is None:
            log.warning('No "wsseSignatureVerificationFilterID" option was '
                        'set in the input config')
        
        # Initialise Attribute Authority class - property file will be
        # picked up from default location under $NDG_DIR directory
        self.sm = SessionManager(**kw)


    def soap_connect(self, ps):
        '''Connect to Session Manager and create a user session
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''

        if self.__debug:
            import pdb
            pdb.set_trace()
            
        request = ps.Parse(connectInputMsg.typecode)    
        response = _SessionManagerService.soap_connect(self, ps)
        
        result = self.sm.connect(username=request.Username,
                                 passphrase=request.Passphrase,
                                 createServerSess=request.CreateServerSess)
                    
        response.UserX509Cert, response.UserPriKey, response.issuingCert, \
            response.SessID = result
                 
        return response


    def soap_disconnect(self, ps):
        '''Disconnect and remove user's session
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
            import pdb
            pdb.set_trace()
           
        request = ps.Parse(disconnectInputMsg.typecode)             
        response = _SessionManagerService.soap_disconnect(self, ps)
        
        # Derive designated user ID differently according to whether
        # a session ID was passed and the message was signed
        sessID = request.SessID or None
            
        # Derive designated holder X.509 cert differently according to whether
        # a signed message is expected from the client - NB, this is dependent
        # on whether a reference to the signature filter was set in the 
        # environment
        signatureFilter = self.referencedWSGIFilters.get(
                                        self.wsseSignatureVerificationFilterID)
        if signatureFilter is not None:
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's certificate
            log.debug("Reading holder certificate from WS-Security "
                      "signature header")
            userX509Cert = signatureFilter.signatureHandler.verifyingCert
        else:
            # No signature from client - they must instead provide the
            # designated holder cert via the UserX509Cert input
            log.debug('Reading holder certificate from SOAP "userX509Cert" '
                      'parameter')
            userX509Cert = request.UserX509Cert
            
        self.sm.deleteUserSession(sessID=sessID, userX509Cert=userX509Cert)
        return response


    def soap_getSessionStatus(self, ps):
        '''Check for existence of a session with given session ID or user
        Distinguished Name
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''

        if self.__debug:
            import pdb
            pdb.set_trace()
            
        request = ps.Parse(getSessionStatusInputMsg.typecode)             
        response = _SessionManagerService.soap_getSessionStatus(self, ps)
        
        response.IsAlive = self.sm.getSessionStatus(userDN=request.UserDN,
                                                    sessID=request.SessID)
                 
        return response


    def soap_getAttCert(self, ps):
        '''Get Attribute Certificate from a given Attribute Authority
        and cache it in user's Credential Wallet
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        request = ps.Parse(getAttCertInputMsg.typecode)             
        response = _SessionManagerService.soap_getAttCert(self, ps)

        # Derive designated holder X.509 cert. differently according to whether
        # a signed message is expected from the client - NB, this is dependent
        # on whether a reference to the signature filter was set in the 
        # environment
        signatureFilter = self.referencedWSGIFilters.get(
                                        self.wsseSignatureVerificationFilterID)
        if signatureFilter is not None:
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's proxy
            log.debug("Reading holder certificate from WS-Security "
                      "signature header")
            userX509Cert = signatureFilter.signatureHandler.verifyingCert
        else:
            # No signature from client - they must instead provide the
            # designated holder cert via the UserX509Cert input
            log.debug('Reading holder certificate from SOAP "userX509Cert" '
                      'parameter')
            userX509Cert = request.UserX509Cert

        # If no Attribute Authority URI is set pick up local Attribute 
        # instance Authority
        if request.AttributeAuthorityURI is None:
            attributeAuthorityFilter = \
                self.referencedWSGIFilters.get(self.attributeAuthorityFilterID)
                
            try:
                attributeAuthority= \
                                attributeAuthorityFilter.serviceSOAPBinding.aa
            except AttributeError, e:
                raise SessionManagerWSConfigError("No Attribute Authority URI "
                        "was input and no Attribute Authority instance "
                        "reference set in environ: %s" % e)
        else:
            attributeAuthority = None
                
        # X.509 Cert used in signature is preferred over userX509Cert input 
        # element - userX509Cert may have been omitted.
        try:
            attCert = self.sm.getAttCert(
                            userX509Cert=userX509Cert or request.UserX509Cert,
                            sessID=request.SessID,
                            attributeAuthorityURI=request.AttributeAuthorityURI,
                            attributeAuthority=attributeAuthority,
                            reqRole=request.ReqRole,
                            mapFromTrustedHosts=request.MapFromTrustedHosts,
                            rtnExtAttCertList=request.RtnExtAttCertList,
                            extAttCertList=request.ExtAttCert,
                            extTrustedHostList=request.ExtTrustedHost)
            response.AttCert = attCert.toString() 
            
        except CredentialWalletAttributeRequestDenied, e:
            # Exception object contains a list of attribute certificates
            # which could be used to re-try to get authorisation via a mapped
            # certificate
            response.Msg = str(e)
            response.ExtAttCertOut = e.extAttCertList
        
        return response
