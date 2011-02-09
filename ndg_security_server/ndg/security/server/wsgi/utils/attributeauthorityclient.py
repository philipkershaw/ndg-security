"""NDG Security - client interface classes to Session Manager 

Make requests for authentication and authorisation

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "27/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

from ndg.security.server.wsgi.utils.clientbase import WSGIClientBase
from ndg.security.common.attributeauthority import AttributeAuthorityClient

class WSGIAttributeAuthorityClientError(Exception):
    """Base class for WSGIAttributeAuthorityClient exceptions"""
    
class WSGIAttributeAuthorityClientConfigError(
                                        WSGIAttributeAuthorityClientError):
    """Configuration error"""
    
class WSGIAttributeAuthorityClient(WSGIClientBase):
    """Client interface to Attribute Authority for WSGI based applications
    
    This class wraps the SOAP based web service client and alternate direct 
    access to a Attribute Authority instance in the same code stack available
    via an environ keyword
    """
    
    defaultEnvironKeyName = "ndg.security.server.wsgi.attributeAuthorityFilter"
            
    _getLocalClient = lambda self:self._environ[
                                    self.environKeyName].serviceSOAPBinding.aa
    localClient = property(fget=_getLocalClient, 
                           doc="Attribute Authority local instance")

    def __init__(self, environKeyName=None, environ={}, **clientKw):
        """Initialise an interface to an Attribute Authority accessible either 
        via a keyword to a WSGI environ dictionary or via a web service call
        
        @type environKeyName: basestring or None
        @param environKeyName: dict key reference to service object to be 
        invoked.  This may be set later using the environKeyName property
        or may be omitted altogether if the service is to be invoked via a
        web service call
        @type environ: dict
        @param environ: WSGI environment dictionary containing a reference to
        the service object.  This may not be known at instantiation of this
        class.  environ is not required if the service is to be invoked over
        a web service interface
        @type clientKw: dict
        @param clientKw: custom keywords to instantiate a web service client
        interface.  Derived classes are responsible for instantiating this
        from an extended version of this __init__ method.
        """

        log.debug("WSGIAttributeAuthorityClient.__init__ ...")
        
        self.environKeyName = environKeyName or \
                            WSGIAttributeAuthorityClient.defaultEnvironKeyName
        
        # Standard WSGI environment dict
        self._environ = environ
        
        if clientKw.get('uri'):
            self.wsClient = AttributeAuthorityClient(**clientKw)
        else:
            self.wsClient = None
            
    def getHostInfo(self):
        """Return details about the Attribute Authority host: its ID,
        the user login URI and AA URI address.  
        
        @rtype: dict
        @return: dictionary of host information derived from the map 
        configuration held by the AA"""
        
        if self.localClientInEnviron:
            # Connect to local instance
            return self.localClient.hostInfo
        
        elif self.wsClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialised")
        else:            
            # Make connection to remote service
            return self.wsClient.getHostInfo()
        
        
    def getTrustedHostInfo(self, **kw):
        """Get list of trusted hosts for an Attribute Authority
        
        @type **kw: dict
        @param **kw: getTrustedHostInfo keywords applicable to 
        ndg.security.server.attributeauthority.AttributeAuthority.getTrustedHostInfo and
        ndg.security.common.attributeauthority.AttributeAuthorityClient.getTrustedHostInfo
        the SOAP client
                
        @rtype: dict
        @return: dictionary of host information indexed by hostname derived 
        from the map configuration"""
        
        if self.localClientInEnviron:
            # Connect to local instance
            return self.localClient.getTrustedHostInfo(**kw)
        
        elif self.wsClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialised")
        else:
            # Make connection to remote service
            return self.wsClient.getTrustedHostHostInfo(**kw)


    def getAllHostsInfo(self):
        """Get list of all hosts for an Attribute Authority i.e. itself and
        all the hosts it trusts
        
        @rtype: dict
        @return: dictionary of host information indexed by hostname derived 
        from the map configuration"""
        
        if self.localClientInEnviron:
            # Connect to local instance - combine this host's info with info
            # from other trusted hosts
            allHostsInfo = self.localClient.hostInfo
            allHostsInfo.update(self.localClient.getTrustedHostInfo())
            return allHostsInfo
        elif self.wsClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialised")
        else:
            # Make connection to remote service
            return self.wsClient.getAllHostsInfo()


    def getAttCert(self, **kw):
        """Request attribute certificate from NDG Attribute Authority 
        
        @type **kw: dict
        @param **kw: getTrustedHostInfo keywords applicable to 
        ndg.security.server.attributeauthority.AttributeAuthority.getAttCert and
        ndg.security.common.attributeauthority.AttributeAuthorityClient.getAttCert
        the SOAP client
                
        @rtype ndg.security.common.AttCert.AttCert
        @return attribute certificate for user.  If access is refused, 
        AttributeRequestDenied or AttributeAuthorityAccessDenied are raised
        depending on whether the call is to a local instance or a remote
        service"""
        
        if self.localClientInEnviron:
            # Connect to local instance
            if 'userX509Cert' in kw:
                kw['holderX509Cert'] = kw.pop('userX509Cert')

            return self.localClient.getAttCert(**kw)
        elif self.wsClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialised")
        else:
            # Make connection to remote service
            if 'holderX509Cert' in kw:
                kw['userX509Cert'] = kw.pop('holderX509Cert')
                
            return self.wsClient.getAttCert(**kw)
