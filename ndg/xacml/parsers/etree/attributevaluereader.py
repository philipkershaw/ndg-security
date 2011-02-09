"""NDG XACML ElementTree based reader for AttributeValue type

NERC DataGrid
"""
__author__ = "P J Kershaw"
__date__ = "16/03/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.xacml.core.attributevalue import (AttributeValue, 
                                           AttributeValueClassFactory)
from ndg.xacml.parsers import XMLParseError
from ndg.xacml.parsers.etree import QName
from ndg.xacml.parsers.etree.expressionreader import ExpressionReader


class AttributeValueReader(ExpressionReader):
    '''ElementTree based XACML Expression type parser
    
    @cvar TYPE: XACML class type that this reader will read values into
    @type TYPE: abc.ABCMeta
    
    @cvar FACTORY: factory function for returning an Attribute value type for a 
    given XACML Attribute value URI
    @type FACTORY: ndg.xacml.core.attributevalue.AttributeValueClassFactory
    '''
    TYPE = AttributeValue
    FACTORY = AttributeValueClassFactory()
    
    def __call__(self, obj):
        """Parse *AttributeValue type element - override this method instead of
        _parseExtension since AttributeValue class is virtual.  A sub-type can
        be instantiated only once the data type attribute is parsed
        
        @param obj: input object to parse
        @type obj: ElementTree Element, or stream object
        @return: new XACML attribute value instance
        @rtype: ndg.xacml.core.attributevalue.AttributeValue derived type 
        @raise XMLParseError: error reading element       
        """
        elem = super(AttributeValueReader, self)._parse(obj)
        
        xacmlType = self.__class__.TYPE
        localName = QName.getLocalPart(elem.tag)
        if localName != xacmlType.ELEMENT_LOCAL_NAME:
            raise XMLParseError("No \"%s\" element found" % 
                                xacmlType.ELEMENT_LOCAL_NAME)
            
        # Unpack *required* attributes from top-level element
        elemAttributeValues = []
        for attributeName in (xacmlType.DATA_TYPE_ATTRIB_NAME,):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLParseError('No "%s" attribute found in "%s" element' %
                                    (attributeName, 
                                     xacmlType.ELEMENT_LOCAL_NAME))
                
            elemAttributeValues.append(attributeValue)
             
        attributeValueClass = self.__class__.FACTORY(elemAttributeValues[0])
        attributeValue = attributeValueClass()
        attributeValue.dataType = elemAttributeValues[0]
        self._parseExtension(elem, attributeValue)
        
        return attributeValue
    
    def _parseExtension(self, elem, attributeValue):
        """Parse XML Attribute value element
        
        @param elem: ElementTree XML element
        @type elem: xml.etree.Element
        
        @param attributeValue: attribute selector to be updated with parsed
        values
        @type attributeValue: ndg.xacml.core.attributevalue.AttributeValue
        
        @raise XMLParseError: error parsing attribute ID XML attribute
        """
        if elem.text is None:
            raise XMLParseError('No attribute value element found parsing %r' % 
                                AttributeValueReader.TYPE.ELEMENT_LOCAL_NAME) 
            
        attributeValue.value = elem.text
    