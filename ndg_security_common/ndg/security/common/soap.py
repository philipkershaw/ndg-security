"""SOAP implementation

Initially for use with SAML SOAP Binding to Attribute Authority.  This itself
uses ElementTree.  This SOAP interface provides an ElementTree interface to
support it

NERC DataGrid Project"""
__author__ = "P J Kershaw"
__date__ = "24/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
log = logging.getLogger(__name__)

from ndg.security.common.utils.etree import QName

class SOAPException(Exception):
    """Base SAOP Exception class"""
    
class SOAPFault(SOAPException):
    """SOAP Fault"""
    
class SOAPObject(object):
    """Base class for SOAP envelope, header and body elements"""
    
    ELEMENT_PREFIX = "SOAP-ENV"
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
    DEFAULT_ELEMENT_NAME = QName(DEFAULT_ELEMENT_NS,
                                 tag=DEFAULT_ELEMENT_LOCAL_NAME,
                                 prefix=DEFAULT_ELEMENT_NS_PREFIX)
    
    soapHeader = property()
    soapBody = property()
    
    
class SOAPHeaderBase(SOAPObject):
    """SOAP Header base class"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Header"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
    DEFAULT_ELEMENT_NAME = QName(DEFAULT_ELEMENT_NS,
                                 tag=DEFAULT_ELEMENT_LOCAL_NAME,
                                 prefix=DEFAULT_ELEMENT_NS_PREFIX)
    
        
class SOAPBodyBase(SOAPObject):
    """SOAP Body base class"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Body"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
    DEFAULT_ELEMENT_NAME = QName(DEFAULT_ELEMENT_NS,
                                 tag=DEFAULT_ELEMENT_LOCAL_NAME,
                                 prefix=DEFAULT_ELEMENT_NS_PREFIX)
    
    
# ElementTree Specific implementations start here
# TODO: refactor into a separate module
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

from ndg.security.common.utils import canonicalize, getLocalName


class ETreeSOAPExtensions(object):  
    """Utility to enable addition of core ElementTree specific attributes and
    methods for ElementTree SOAP implementation
    """
    def __init__(self):
        self.__qname = None
        self.__elem = None

    def _getQname(self):
        return self.__qname

    def _setQname(self, value):
        if not isinstance(value, QName):
            raise TypeError('Expecting %r for "qname" attribute; got %r' %
                            (QName, type(value)))
        self.__qname = value

    def _getElem(self):
        return self.__elem

    def _setElem(self, value):
        if not ElementTree.iselement(value):
            raise TypeError('Expecting %r for "elem" attribute; got %r' %
                            (ElementTree.Element, type(value)))
        self.__elem = value
        
    qname = property(_getQname, _setQname, None, "Qualified name object")
    elem = property(_getElem, _setElem, None, "Root element")
    
    @staticmethod
    def _serialize(elem):
        """Serialise element tree into string"""
        
        # Make a basic check for the SOAP name space declaration, if the
        # element is constructed from a call to ElementTree.parse it may not
        # be present 
        namespaceDeclarationFound = False
        soapElemNsDeclaration = (
            'xmlns:%s' % SOAPObject.ELEMENT_PREFIX, 
            SOAPObject.DEFAULT_NS
        )
        if soapElemNsDeclaration[0] not in elem.attrib:
            log.warning("No SOAP namespace declaration found - adding one in")
            elem.set(*soapElemNsDeclaration)
        
        return canonicalize(elem)
    
    @classmethod
    def _prettyPrint(cls, elem):
        """Basic pretty printing separating each element on to a new line"""
        xml = cls._serialize(elem)
        xml = ">\n".join(xml.split(">"))
        xml = "\n<".join(xml.split("<"))
        xml = '\n'.join(xml.split('\n\n'))
        return xml

    def _parse(self, source):
        """Read in the XML from source
        @type source: basestring/file
        @param source: file path to XML file or file object
        """
        tree = ElementTree.parse(source)
        elem = tree.getroot()
        
        return elem        


class SOAPHeader(SOAPHeaderBase, ETreeSOAPExtensions):
    """ElementTree implementation of SOAP Header object"""
    
    def __init__(self):
        SOAPHeaderBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPHeaderBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPHeaderBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX)

    def create(self, makeNsDeclaration=True):
        """Create header ElementTree element"""
        
        self.elem = ElementTree.Element(str(self.qname))
        if makeNsDeclaration:
            self.elem.set(
                    "xmlns:%s" % SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX,
                    SOAPHeaderBase.DEFAULT_ELEMENT_NS)
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)


class SOAPBody(SOAPBodyBase, ETreeSOAPExtensions):
    """ElementTree based implementation for SOAP Body object"""
    
    def __init__(self):
        SOAPBodyBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPBodyBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPBodyBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX)
        
    def create(self, makeNsDeclaration=True):
        """Create header ElementTree element"""
        
        self.elem = ElementTree.Element(str(self.qname))
        if makeNsDeclaration:
            self.elem.set("xmlns:%s" % SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX,
                          SOAPBodyBase.DEFAULT_ELEMENT_NS)
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)
    

class SOAPEnvelope(SOAPEnvelopeBase, ETreeSOAPExtensions):
    """ElementTree based SOAP implementation"""

    def __init__(self):
        SOAPEnvelopeBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPEnvelopeBase.DEFAULT_ELEMENT_NS, 
                             tag=SOAPEnvelopeBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                             prefix=SOAPEnvelopeBase.DEFAULT_ELEMENT_NS_PREFIX)
        self.__header = SOAPHeader()
        self.__body = SOAPBody()

    def _getHeader(self):
        return self.__header

    def _setHeader(self, value):
        if not isinstance(value, SOAPHeader):
            raise TypeError('Expecting %r for "header" attribute; got %r' %
                            (SOAPHeader, type(value)))
        self.__header = value

    def _getBody(self):
        return self.__body

    def _setBody(self, value):
        if not isinstance(value, SOAPBody):
            raise TypeError('Expecting %r for "header" attribute; got %r' %
                            (SOAPBody, type(value)))
        self.__body = value

    header = property(_getHeader, _setHeader, None, "SOAP header object")
    body = property(_getBody, _setBody, None, "SOAP body object")

    def create(self, makeNsDeclaration=True):
        """Create SOAP Envelope with header and body"""
        
        self.elem = ElementTree.Element(str(self.qname))
        if makeNsDeclaration:
            self.elem.set("xmlns:%s" % SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX,
                          SOAPBodyBase.DEFAULT_ELEMENT_NS)
            
        self.header.create(makeNsDeclaration=False)
        self.elem.append(self.header.elem)
        
        self.body.create(makeNsDeclaration=False)
        self.elem.append(self.body.elem)
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element onto a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)
    
    def parse(self, source):
        self.elem = ETreeSOAPExtensions._parse(self, source) 
        
        for elem in self.elem:
            localName = getLocalName(elem)
            if localName == SOAPHeader.DEFAULT_ELEMENT_LOCAL_NAME:
                self.header.elem = elem
                
            elif localName == SOAPBody.DEFAULT_ELEMENT_LOCAL_NAME:
                self.body.elem = elem
                
            else:
                raise SOAPFault('Invalid child element in SOAP Envelope "%s" '
                                'for source %r' % (localName, source))