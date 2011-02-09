"""NDG XACML match function module - contains implementations for XACML 1.0
*-match functions

NERC DataGrid
"""
__author__ = "P J Kershaw"
__date__ = "26/03/10"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
from ndg.xacml.core.context.exceptions import XacmlContextTypeError
from ndg.xacml.core.functions import AbstractFunction, FunctionClassFactoryBase
from ndg.xacml.core.attributevalue import AttributeValueClassFactory


class MatchBase(AbstractFunction):
    """Generic match function for all types
    
    @cvar TYPE: attribute type for the given implementation.  Derived classes
    should set appropriately
    @type TYPE: NoneType    
    """
    TYPE = None
    
    def evaluate(self, string1, string2):
        """Match input strings
        
        @param string1: first of two strings to match
        @type string1: basestring
        @param string2: second string
        @type string2: basestring
        @return: True if strings match, False otherwise
        @rtype: bool
        """
        if not isinstance(string1, basestring):
            raise XacmlContextTypeError('Expecting %r derived type for '
                                        '"string1"; got %r' %
                                        (self.__class__.TYPE, 
                                         type(string1)))
            
        if not isinstance(string2, self.__class__.TYPE):
            raise XacmlContextTypeError('Expecting %r derived type for '
                                        '"string2"; got %r' %
                                        (self.__class__.TYPE, 
                                         type(string2)))
            
        return string1 == string2
 
    
attributeValueClassFactory = AttributeValueClassFactory()


class Rfc822NameMatch(AbstractFunction):
    """Match RFC 822 type name - e.g. e-mail addresses"""
    FUNCTION_NS = 'urn:oasis:names:tc:xacml:1.0:function:rfc822Name-match'
    TYPE = attributeValueClassFactory(
                                'http://www.w3.org/2001/XMLSchema#Rfc822Name')
    STRING_TYPE = attributeValueClassFactory(
                                'http://www.w3.org/2001/XMLSchema#string')
    
    def evaluate(self, string1, rfc822Name):
        """Match Rfc822 name
        
        @param string1: string to match to rfc822Name
        @type string1: basestring
        @param rfc822Name: RFC822 Name to match
        @type rfc822Name: basestring
        @return: True if strings match, False otherwise
        @rtype: bool
        """
        if not isinstance(string1, self.__class__.STRING_TYPE):
            raise TypeError('Expecting %r derived type for "string1"; got %r' %
                            (self.__class__.STRING_TYPE, type(string1)))
            
        if not isinstance(rfc822Name, self.__class__.TYPE):
            raise TypeError('Expecting %r derived type for "rfc822Name"; got '
                            '%r' % (self.__class__.TYPE, type(rfc822Name)))
            
        return string1.lower() == rfc822Name.lower()
        
    
class FunctionClassFactory(FunctionClassFactoryBase):
    """Class Factory for *-match XACML 1.0 function classes
    
    @cvar FUNCTION_NAMES: equal function URNs
    @type FUNCTION_NAMES: tuple
    
    @cvar FUNCTION_NS_SUFFIX: generic suffix for match function URNs
    @type FUNCTION_NS_SUFFIX: string
    
    @cvar FUNCTION_BASE_CLASS: base class for all match function classes (apart
    from Rfc822NameMatch)
    @type FUNCTION_BASE_CLASS: ndg.xacml.core.functions.v1.MatchBase
    """
    FUNCTION_NAMES = (
        'urn:oasis:names:tc:xacml:1.0:function:x500Name-match',
        'urn:oasis:names:tc:xacml:1.0:function:rfc822Name-match',
        'urn:oasis:names:tc:xacml:1.0:function:xpath-node-match'
    )
    FUNCTION_NS_SUFFIX = '-match'
    FUNCTION_BASE_CLASS = MatchBase
