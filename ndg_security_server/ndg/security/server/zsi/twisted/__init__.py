"""Package for ZSI Web service bindings compliants to Twisted application 
server interface

These may be deprecated in the future in favour of a WSGI interface

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "27/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

"""WS-Security digital signature handler for Twisted framework

(moved from ndg.security.common.wsSecurity)

This is used by NDG-Security server side code ONLY

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "28/08/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

from zope.interface import classProvides, implements, Interface
from ZSI.twisted.WSresource import DefaultHandlerChain, \
    DefaultCallbackHandler, HandlerChainInterface, DataHandler

    
class WSSecurityHandlerChainFactory:
    protocol = DefaultHandlerChain
    
    @classmethod
    def newInstance(cls):
        return cls.protocol(DefaultCallbackHandler, 
                            DataHandler,
                            WSSecurityHandler)

class WSSecurityHandler:
    classProvides(HandlerChainInterface)

    signatureHandler = None
    
    @classmethod
    def processRequest(cls, ps, **kw):
        """Callback for verifying a signature.
        
        @param ps: instance representing SOAP request Body.
        @type ps: ZSI.parse.ParsedSoap
        @return ps: instance representing SOAP request Body
        @rtype ps: ZSI.parse.ParsedSoap
        """
        if cls.signatureHandler:
            cls.signatureHandler.verify(ps)
            
        return ps
    
    @classmethod
    def processResponse(cls, sw, **kw):
        """Callback for signing an outbound message.
        
        @param ps: instance representing SOAP response Body.
        @type ps: ZSI.writer.SoapWriter
        @return ps: instance representing SOAP response Body
        @rtype ps: ZSI.writer.SoapWriter
        """
        if cls.signatureHandler:
            cls.signatureHandler.sign(sw)
            
        return sw
