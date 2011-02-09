"""SOAP common package for NDG SAML.  

Initially for use with SAML SOAP Bindings.  This itself
uses ElementTree.  This SOAP interface provides an ElementTree interface to
support it

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: __init__.py 7130 2010-06-30 13:33:07Z pjkersha $'
import logging
log = logging.getLogger(__name__)

class SOAPException(Exception):
    """Base SAOP Exception class"""
    
class SOAPFault(SOAPException):
    """SOAP Fault"""
    
class SOAPObject(object):
    """Base class for SOAP envelope, header and body elements"""
    
    ELEMENT_PREFIX = "soap11"
    SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"
    SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope"
    DEFAULT_NS = SOAP11_NS
    
    def create(self):
        raise NotImplementedError()
    
    def parse(self):
        raise NotImplementedError()
    
    def serialize(self):
        raise NotImplementedError()
    
    def prettyPrint(self):
        raise NotImplementedError()
  
    
class SOAPEnvelopeBase(SOAPObject):
    """SOAP Envelope"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Envelope"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
    
    soapHeader = property()
    soapBody = property()
    
    
class SOAPHeaderBase(SOAPObject):
    """SOAP Header base class"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Header"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX    
        
class SOAPBodyBase(SOAPObject):
    """SOAP Body base class"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Body"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
