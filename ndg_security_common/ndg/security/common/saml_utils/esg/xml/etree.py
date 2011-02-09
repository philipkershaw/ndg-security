"""SAML 2.0 Earth System Grid Group/Role ElementTree representation

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "09/11/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
import re

from xml.etree import ElementTree

from saml.xml import XMLTypeParseError, UnknownAttrProfile
from saml.xml.etree import AttributeValueElementTreeBase, QName

from ndg.security.common.saml_utils.esg import XSGroupRoleAttributeValue


class XSGroupRoleAttributeValueElementTree(AttributeValueElementTreeBase,
                                           XSGroupRoleAttributeValue):
    """ElementTree XML representation of Earth System Grid custom Group/Role 
    Attribute Value""" 

    @classmethod
    def toXML(cls, attributeValue):
        """Create an XML representation of the input SAML ESG Group/Role type
        Attribute Value
        
        @type assertion: saml.saml2.core.XSGroupRoleAttributeValue
        @param assertion: XSGroupRoleAttributeValue to be represented as an 
        ElementTree Element
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        elem = AttributeValueElementTreeBase.toXML(attributeValue)
        
        if not isinstance(attributeValue, XSGroupRoleAttributeValue):
            raise TypeError("Expecting %r type; got: %r" % 
                            (XSGroupRoleAttributeValue, type(attributeValue)))
            
        ElementTree._namespace_map[attributeValue.namespaceURI
                                   ] = attributeValue.namespacePrefix
                                   
        tag = str(QName.fromGeneric(cls.TYPE_NAME))    
        groupRoleElem = ElementTree.Element(tag)
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix 
        
        groupRoleElem.set(cls.GROUP_ATTRIB_NAME, attributeValue.group)
        groupRoleElem.set(cls.ROLE_ATTRIB_NAME, attributeValue.role)

        elem.append(groupRoleElem)
        
        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree ESG Group/Role attribute element into a SAML 
        XSGroupRoleAttributeValue object
        
        @type elem: ElementTree.Element
        @param elem: Attribute value as ElementTree XML element
        @rtype: saml.saml2.core.XSGroupRoleAttributeValue
        @return: SAML ESG Group/Role Attribute value
        """
        
        # Update namespace map for the Group/Role type referenced.  
        ElementTree._namespace_map[cls.DEFAULT_NS] = cls.DEFAULT_PREFIX
        
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
                                   
        # Check for group/role child element
        if len(elem) == 0:
            raise XMLTypeParseError('Expecting "%s" child element to "%s" '
                                    'element' % (cls.TYPE_LOCAL_NAME,
                                               cls.DEFAULT_ELEMENT_LOCAL_NAME))
        
        childElem = elem[0]
        childLocalName = QName.getLocalPart(childElem.tag)
        if childLocalName != cls.TYPE_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.TYPE_LOCAL_NAME)

                                      
        attributeValue = XSGroupRoleAttributeValue()
        groupName = childElem.attrib.get(cls.GROUP_ATTRIB_NAME)
        if groupName is None:
            raise XMLTypeParseError('No "%s" attribute found in Group/Role '
                                    'attribute element' % 
                                    cls.GROUP_ATTRIB_NAME)
        attributeValue.group = groupName
        
        roleName = childElem.attrib.get(cls.ROLE_ATTRIB_NAME)
        if roleName is None:
            raise XMLTypeParseError('No "%s" attribute found in Group/Role '
                                    'attribute element' % 
                                    cls.GROUP_ATTRIB_NAME)
        attributeValue.role = roleName

        return attributeValue
    
    @classmethod
    def factoryMatchFunc(cls, elem):
        """Match function used by AttributeValueElementTreeFactory to
        determine whether the given attribute is XSGroupRole type
        
        @type elem: ElementTree.Element
        @param elem: Attribute value as ElementTree XML element
        @rtype: saml.saml2.core.XSGroupRoleAttributeValue or None
        @return: SAML ESG Group/Role Attribute Value class if elem is an
        Group/role type element or None if if doesn't match this type 
        """
        
        # Group/role element is a child of the AttributeValue element
        if len(elem) == 0:
            return None
        
        childLocalName = QName.getLocalPart(elem[0].tag)
        if childLocalName != cls.TYPE_LOCAL_NAME:
            raise XMLTypeParseError('No "%s" child element found in '
                                    'AttributeValue' % cls.TYPE_LOCAL_NAME)
               
        if cls.GROUP_ATTRIB_NAME in elem[0].attrib and \
           cls.ROLE_ATTRIB_NAME in elem[0].attrib:
            return cls

        return None

