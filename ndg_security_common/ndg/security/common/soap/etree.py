"""SOAP client package - XML representation using ElementTree

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/07/09"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'
import logging
log = logging.getLogger(__name__)
    
try: # python 2.5
    from xml.etree import cElementTree, ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree, ElementTree

# ElementTree helper functions
from ndg.security.common.utils.etree import QName

from ndg.security.common.soap import SOAPObject, SOAPEnvelopeBase, \
    SOAPHeaderBase, SOAPBodyBase, SOAPFault

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
         return cElementTree.tostring(elem)
       
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
    
    DEFAULT_ELEMENT_NAME = QName(SOAPHeaderBase.DEFAULT_ELEMENT_NS,
                               tag=SOAPHeaderBase.DEFAULT_ELEMENT_LOCAL_NAME,
                               prefix=SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    def __init__(self):
        SOAPHeaderBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPHeaderBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPHeaderBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX)

    def create(self):
        """Create header ElementTree element"""
        
        self.elem = ElementTree.Element(str(self.qname))
        ElementTree._namespace_map[SOAPHeaderBase.DEFAULT_ELEMENT_NS
                                   ] = SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)


class SOAPBody(SOAPBodyBase, ETreeSOAPExtensions):
    """ElementTree based implementation for SOAP Body object"""
    
    DEFAULT_ELEMENT_NAME = QName(SOAPBodyBase.DEFAULT_ELEMENT_NS,
                                 tag=SOAPBodyBase.DEFAULT_ELEMENT_LOCAL_NAME,
                                 prefix=SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    def __init__(self):
        SOAPBodyBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPBodyBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPBodyBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX)
        
    def create(self):
        """Create header ElementTree element"""
        self.elem = ElementTree.Element(str(self.qname))
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)
    

class SOAPEnvelope(SOAPEnvelopeBase, ETreeSOAPExtensions):
    """ElementTree based SOAP implementation"""
    DEFAULT_ELEMENT_NAME = QName(SOAPEnvelopeBase.DEFAULT_ELEMENT_NS,
                             tag=SOAPEnvelopeBase.DEFAULT_ELEMENT_LOCAL_NAME,
                             prefix=SOAPEnvelopeBase.DEFAULT_ELEMENT_NS_PREFIX)

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

    def create(self):
        """Create SOAP Envelope with header and body"""
        
        self.elem = ElementTree.Element(str(self.qname))
            
        self.header.create()
        self.elem.append(self.header.elem)
        
        self.body.create()
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
            localName = QName.getLocalPart(elem.tag)
            if localName == SOAPHeader.DEFAULT_ELEMENT_LOCAL_NAME:
                self.header.elem = elem
                
            elif localName == SOAPBody.DEFAULT_ELEMENT_LOCAL_NAME:
                self.body.elem = elem
                
            else:
                raise SOAPFault('Invalid child element in SOAP Envelope "%s" '
                                'for stream %r' % (localName, source))
