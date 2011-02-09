"""NDG Security - client interface classes to Session Manager 

Make requests for authentication and authorisation

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "27/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ndg.security.common.attributeauthority import AttributeAuthorityClient

class WSGIAttributeAuthorityClientError(Exception):
    """Base class for WSGIAttributeAuthorityClient exceptions"""
    
class WSGIAttributeAuthorityClientConfigError(
                                        WSGIAttributeAuthorityClientError):
    """Configuration error"""
    
class WSGIAttributeAuthorityClient(object):
    """Client interface to Attribute Authority for WSGI based applications
    
    This class wraps the SOAP based web service client and alternate direct 
    access to a Attribute Authority instance in the same code stack available
    via an environ keyword
    """
    
    environKey = "ndg.security.server.wsgi.attributeAuthorityFilter"
            
    _refInEnviron=lambda self: self._environKey in self._environ
    
    # Define as property for convenient call syntax
    refInEnviron = property(fget=_refInEnviron,
                            doc="return True if a Attribute Authority "
                                "instance is available in WSGI environ")
    
    _getRef = lambda self:self._environ[self._environKey].serviceSOAPBinding.aa
    ref = property(fget=_getRef, doc="Attribute Authority local instance")

    
    def __init__(self, environKey=None, environ={}, **soapClientKw):

        log.debug("WSGIAttributeAuthorityClient.__init__ ...")
        
        self._environKey=environKey or WSGIAttributeAuthorityClient.environKey
        
        # Standard WSGI environment dict
        self._environ = environ
        
        if soapClientKw.get('uri'):
            self._soapClient = AttributeAuthorityClient(**soapClientKw)
        else:
            self._soapClient = None
             
    def _setEnviron(self, environ):
        if not isinstance(environ, dict):
            raise TypeError("Expecting dict type for 'environ' property")
        self._environ = environ
        
    def _getEnviron(self, environ):
        return self._environ
    
    environ = property(fget=_getEnviron, 
                       fset=_setEnviron, 
                       doc="WSGI environ dictionary")
            
    def getHostInfo(self):
        """Return details about the Attribute Authority host: its ID,
        the user login URI and AA URI address.  
        
        @rtype: dict
        @return: dictionary of host information derived from the map 
        configuration held by the AA"""
        
        if self.refInEnviron:
            # Connect to local instance
            return self.ref.hostInfo
        
        elif self._soapClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialized")
        else:            
            # Make connection to remote service
            return self._soapClient.getHostInfo()
        
        
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
        
        if self.refInEnviron:
            # Connect to local instance
            return self.ref.getTrustedHostInfo(**kw)
        elif self._soapClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            # Make connection to remote service
            return self._soapClient.getTrustedHostHostInfo(**kw)


    def getAllHostsInfo(self):
        """Get list of all hosts for an Attribute Authority i.e. itself and
        all the hosts it trusts
        
        @rtype: dict
        @return: dictionary of host information indexed by hostname derived 
        from the map configuration"""
        
        if self.refInEnviron:
            # Connect to local instance - combine this host's info with info
            # from other trusted hosts
            allHostsInfo = self.ref.hostInfo
            allHostsInfo.update(self.ref.getTrustedHostInfo())
            return allHostsInfo
        elif self._soapClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            # Make connection to remote service
            return self._soapClient.getAllHostsInfo()


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
        
        if self.refInEnviron:
            # Connect to local instance
            if 'userX509Cert' in kw:
                kw['holderX509Cert'] = kw.pop('userX509Cert')

            return self.ref.getAttCert(**kw)
        elif self._soapClient is None:            
            raise WSGIAttributeAuthorityClientConfigError("No reference to a "
                        "local Attribute Authority is set and no SOAP client "
                        "to a remote service has been initialized")
        else:
            # Make connection to remote service
            if 'holderX509Cert' in kw:
                kw['userX509Cert'] = kw.pop('holderX509Cert')
                
            return self._soapClient.getAttCert(**kw)
