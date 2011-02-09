"""XACML Attribute module

NERC DataGrid Project

This code is adapted from the Sun Java XACML implementation ...

Copyright 2004 Sun Microsystems, Inc. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistribution of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistribution in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

Neither the name of Sun Microsystems, Inc. or the names of contributors may
be used to endorse or promote products derived from this software without
specific prior written permission.

This software is provided "AS IS," without a warranty of any kind. ALL
EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

You acknowledge that this software is not designed or intended for use in
the design, construction, operation or maintenance of any nuclear facility.
"""
__author__ = "P J Kershaw"
__date__ = "03/04/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"

import logging
log = logging.getLogger(__name__)

from ndg.security.common.utils.etree import QName
from ndg.security.common.authz.xacml.cond.eval import Evaluatable, \
    EvaluationResult

class AttributeDesignator(object):
    elemNames = [n+'AttributeDesignator' for n in ('Action', 'Environment',
                                                   'Resource', 'Subject')]
    targetCodes = range(4)
    targetLUT = dict(zip(elemNames, targetCodes))
    
    (ACTION_TARGET, 
    ENVIRONMENT_TARGET, 
    RESOURCE_TARGET, 
    SUBJECT_TARGET) = targetCodes
    
    def __init__(self, 
                 target, 
                 type, 
                 attributeId, 
                 mustBePresent=False, 
                 issuer=None):
        if target not in AttributeDesignator.targetCodes:
            raise AttributeError("Target code must be one of %r; input code "
                                 "is %r" % (AttributeDesignator.targetCodes,
                                            target))
        self.target = target
        self.type = type
        self.id = attributeId
        self.mustBePresent = mustBePresent
        self.issuer = issuer

    @classmethod
    def getInstance(cls, elem, target):
        """Create a new instance from an ElementTree element
        @type elem: ElementTree.Element
        @param elem: AttributeDesignator XML element
        @type target: int
        @param target: target code
        @rtype: AttributeDesignator
        @return: new AttributeDesignator instance
        """
        localName = QName.getLocalPart(elem.tag)
        if localName not in cls.elemNames:
            raise AttributeError("Element name [%s] is not a recognised "
                                 "AttributeDesignator name %r" % 
                                 (localName, cls.elemNames))
            
        
        if target not in cls.targetCodes:
            raise AttributeError("Target code [%d] is not a recognised "
                                 "AttributeDesignator target code %r" % 
                                 (localName, cls.targetCodes))
            
        id = elem.attrib['AttributeId']
        type = elem.attrib['DataType']
        mustBePresent=elem.attrib.get('mustBePresent','false').lower()=='true'
        issuer = elem.attrib.get('issuer')
        return cls(target, type, id, mustBePresent=mustBePresent,issuer=issuer)


class AttributeValue(Evaluatable):
    '''The base type for all datatypes used in a policy or request/response,
    this abstract class represents a value for a given attribute type.
    All the required types defined in the XACML specification are
    provided as instances of AttributeValues. If you want to
    provide a new type, extend this class and implement the
    equals(Object) and hashCode methods from
    Object, which are used for equality checking.'''
    
    def __init__(self, type):
        '''@param type the attribute's type
        '''
        self.type = type
        
    def _getIsBag(self, val):
        '''BagAttribute should override this to True'''
        return False
    
    isBag = property(fget=_getIsBag)
    
    def evaluatesToBag(self): 
        '''Returns whether or not this value is actually a bag of values. This
        is a required interface from Evaluatable, but the
        more meaningful isBag method is used by
        AttributeValues, so this method is declared as final
        and calls the isBag method for this value.
        
        @return true if this is a bag of values, false otherwise
        '''
        return self.isBag

    def getChildren(self):
        '''Always returns an empty list since values never have children.
        
        @return an empty List'''
        return []
   
    def evaluate(self, context):
        '''Implements the required interface from Evaluatable.
        Since there is nothing to evaluate in an attribute value, the default
        result is just this instance. Override this method if you want
        special behavior, like a dynamic value.
        
        @param context the representation of the request
        
        @return a successful evaluation containing this value'''    
        return EvaluationResult(self)

    def _encode(self):
        '''Encodes the value in a form suitable for including in XML data like
        a request or an obligation. This must return a value that could in
        turn be used by the factory to create a new instance with the same
        value.
        
        @return a string form of the value'''
        raise NotImplementedError()
    
    def encode(self, output=None):
        '''Encodes this AttributeValue into its XML representation
        and writes this encoding to the given OutputStream with
        no indentation. This will always produce the version used in a
        policy rather than that used in a request, so this is equivalent
        to calling encodeWithTags(true) and then stuffing that
        into a stream.
        
        @param output a stream into which the XML-encoded data is written'''
        if output is not None:
            output.write(self.encodeWithTags())
        else:
            return self._encode()
    
    def encodeWithTags(includeType=True):
        '''Encodes the value and includes the AttributeValue XML tags so that
        the resulting string can be included in a valid XACML policy or
        Request/Response. The boolean parameter lets you include
        the DataType attribute, which is required in a policy but not allowed
        in a Request or Response.
        
        @param includeType include the DataType XML attribute if
                           true, exclude if false
        
        @return a String encoding including the XML tags
        '''
        if includeType:
            return '<AttributeValue DataType="%s">%s</AttributeValue>' % \
                    (self.type, self.encode())
        else:
            return "<AttributeValue>%s</AttributeValue>" % self.encode()
                           
class StringAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#string"
    
    def __init__(self, value=''):
        self.value = value
        super(StringAttribute, self).__init__(self.__class__.identifier)
        
    def __str__(self):
        return self.value
    
    def _encode(self):
        return self.value
    
    @classmethod
    def getInstance(cls, root=None, value=None):
        """Make a new StrinAttribute instance from an element or string value
        @type root: ElementTree.Element
        @param root: XML element
        @type value: basestring
        @param value: value to set string to
        """
        if root is not None:
            value = root.text
        elif value is None:
            raise TypeError('"elem" or "value" keyword must be set')
            
        return StringAttribute(value=value)
    

class AnyURIAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#anyURI"
    
    def __init__(self, value=''):
        self.value = value
        super(AnyURIAttribute, self).__init__(self.__class__.identifier)
        
    def __str__(self):
        return self.value
    
    def _encode(self):
        return self.value

class Base64BinaryAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#base64Binary"
    
    def __init__(self, value=0):
        self.value = value
        super(Base64BinaryAttribute, self).__init__(self.__class__.identifier)
        
    def __str__(self):
        return self.value
    
    def _encode(self):
        return self.value
     
class BooleanAttribute(AttributeValue):   
    identifier = "http://www.w3.org/2001/XMLSchema#boolean"
    
    def __init__(self, value=False):
        self.value = value
        super(BooleanAttribute, self).__init__(self.__class__.identifier)
        
    def __str__(self):
        return self.value
    
    def _encode(self):
        return str(self.value)
    
class DateAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#date"
    
    def __init__(self, value=''):
        self.value = value
        super(DateAttribute, self).__init__(self.__class__.identifier)
    
class DateTimeAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#dateTime"
    
    def __init__(self, value=''):
        self.value = value
        super(DateTimeAttribute, self).__init__(self.__class__.identifier)
    
class DayTimeDurationAttribute(AttributeValue):
    identifier = ("http://www.w3.org/TR/2002/WD-xquery-operators-20020816#"
                  "dayTimeDuration")
    
    def __init__(self, value=''):
        self.value = value
        super(DayTimeDurationAttribute, self).__init__(
                                                    self.__class__.identifier)
   
class DoubleAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#double"
    
    def __init__(self, value=0.):
        self.value = value
        super(DoubleAttribute, self).__init__(self.__class__.identifier)
    
class HexBinaryAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#hexBinary"
    
    def __init__(self, value=0x0):
        self.value = value
        super(HexBinaryAttribute, self).__init__(self.__class__.identifier)
   
class IntegerAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#integer"
    
    def __init__(self, value=0):
        self.value = value
        super(IntegerAttribute, self).__init__(self.__class__.identifier)
    
class RFC822NameAttribute(AttributeValue):
    identifier = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name"
    
    def __init__(self, value=''):
        self.value = value
        super(RFC822NameAttribute, self).__init__(self.__class__.identifier)
        
class TimeAttribute(AttributeValue):
    identifier = "http://www.w3.org/2001/XMLSchema#time"
    
    def __init__(self, value=''):
        self.value = value
        super(TimeAttribute, self).__init__(self.__class__.identifier)

class X500NameAttribute(AttributeValue):
    identifier = "urn:oasis:names:tc:xacml:1.0:data-type:x500Name"

    def __init__(self, value=''):
        self.value = value
        super(X500NameAttribute, self).__init__(self.__class__.identifier)

class YearMonthDurationAttribute(AttributeValue):
    identifier = ("http://www.w3.org/TR/2002/WD-xquery-operators-20020816#"
                  "yearMonthDuration")
    
    def __init__(self, value=''):
        self.value = value
        super(YearMonthDurationAttribute, self).__init__(
                                                    self.__class__.identifier)

    
class AttributeFactoryProxy(object):
    '''A simple proxy interface used to install new AttributeFactory'''
    @staticmethod
    def getFactory():
        raise NotImplementedError()

              
class AttributeFactory(object):
    '''This is an abstract factory class for creating XACML attribute values.
    There may be any number of factories available in the system, though
    there is always one default factory used by the core code.
    '''

    # the proxy used to get the default factory
    defaultFactoryProxy = AttributeFactoryProxy() 
    defaultFactoryProxy.getFactory = lambda: \
                                        StandardAttributeFactory.getFactory()
             
    @classmethod
    def getInstance(cls):
        '''Returns the default factory. Depending on the default factory's
        implementation, this may return a singleton instance or new instances
        with each invocation.
    
        @return: the default AttributeFactory
        '''
        return cls.defaultFactoryProxy.getFactory()    

    
    def addDatatype(self, id, proxy):
        '''Adds a proxy to the factory, which in turn will allow new attribute
        types to be created using the factory. Typically the proxy is
        provided as an anonymous class that simply calls the getInstance
        methods (or something similar) of some AttributeValue
        class.
        
        @param id the name of the attribute type
        @param proxy the proxy used to create new attributes of the given type
        
        @raise AttributeError if the given id is already in use
        '''
        raise NotImplementedError()
    
    def getSupportedDatatypes(self):
        '''Returns the datatype identifiers supported by this factory.
        
        @return: a list of strings
        '''
        raise NotImplementedError()

    def createValue(self, root, dataType=None, value=None):
        '''Creates a value based on the given root element. The type of the
        attribute is assumed to be present in the node as an XAML attribute
        named DataType, as is the case with the AttributeValueType in the 
        policy schema. The value is assumed to be the first child of this node.
        
        @param: ElementTree.Element root of an attribute value     
        @param dataType: the type of the attribute
        @param value the text-encoded representation of an attribute's value
        @return: a new AttributeValue    
        @raise UnknownIdentifierException if the type in the node isn't
                                           known to the factory
        @raise ParsingException if the node is invalid or can't be parsed
                                 by the appropriate proxy
        '''
        raise NotImplementedError()  
    
      
class BaseAttributeFactory(AttributeFactory):
    '''This is a basic implementation of AttributeFactory abstract class. It
    implements the insertion and retrieval methods, but doesn't actually
    setup the factory with any datatypes.
 
    Note that while this class is thread-safe on all creation methods, it
    is not safe to add support for a new datatype while creating an instance
    of a value. This follows from the assumption that most people will
    initialize these factories up-front, and then start processing without
    ever modifying the factories. If you need these mutual operations to
    be thread-safe, then you should write a wrapper class that implements
    the right synchronization.
    '''

    def __init__(self, attributeMap={}): 
        # the map of proxies
        self._attributeMap = attributeMap.copy()
    
    
    def addDatatype(self, id, proxy):
        '''Adds a proxy to the factory, which in turn will allow new attribute
        types to be created using the factory. Typically the proxy is
        provided as an anonymous class that simply calls the getInstance
        methods (or something similar) of some AttributeValue
        class.
    
        @param id: the name of the attribute type
        @param proxy: the proxy used to create new attributes of the given type
        '''
        # make sure this doesn't already exist
        if id in self._attributeMap:
            raise AttributeError("Data type %s already exists" % id)

        self._attributeMap[id] = proxy
    
    def getSupportedDatatypes(self): 
        '''Returns the datatype identifiers supported by this factory.
        
        @return: a list of types'''
        return self._attributeMap.keys()
    
    def createValue(self, root=None, dataType=None, value=None):
        '''Creates a value based on the given elem root node. The type of the
        attribute is assumed to be present in the node as an XACML attribute
        named DataType, as is the case with the
        AttributeValueType in the policy schema. The value is assumed to be
        the first child of this node.
        
        @param root: the root elem of an attribute value
        @param dataType: the type of the attribute
        @param value: the text-encoded representation of an attribute's value
        @return: a new AttributeValue instance
        @raise UnknownIdentifierException: if the type in the node isn't
                                            known to the factory
        @raise ParsingException: if the node is invalid or can't be parsed
        by the appropriate proxy
        '''
        if dataType is None:
            dataType = root.attrib["DataType"]

        proxy = self._attributeMap.get(dataType)
        if proxy is None:
            raise UnknownIdentifierException("Attributes of type %s aren't "
                                             "supported." % dataType)
            
        if root is not None:
            param = root
        elif value is not None:
            param = value
        else:
            raise TypeError('A "root" or "value" keyword must be set')
            
        try:
            return proxy.getInstance(param)
        except Exception, e: 
            raise ParsingException("Couldn't create %s attribute based on "
                                   "element: %s" % (dataType, e))
            

class StandardAttributeFactory(BaseAttributeFactory):
    '''This factory supports the standard set of datatypes specified in XACML
    1.0 and 1.1. It is the default factory used by the system, and imposes
    a singleton pattern insuring that there is only ever one instance of
    this class.
    
    Note that because this supports only the standard datatypes, this
    factory does not allow the addition of any other datatypes. If you call
    addDatatype on an instance of this class, an exception
    will be thrown. If you need a standard factory that is modifiable, you
    should create a new BaseAttributeFactory (or some other
    AttributeFactory) and configure it with the standard
    datatypes using addStandardDatatypes (or, in the case of
    BaseAttributeFactory, by providing the datatypes in the
    constructor).'''
    
    factoryInstance = None
    
    # the datatypes supported by this factory
    supportedDatatypes = None
    
    def __init__(self):
        """Initialise attribute map from supportedDatatypes class var by 
        calling BaseAttributeFactory constructor
        """
        super(StandardAttributeFactory, self).__init__(
                    attributeMap=StandardAttributeFactory.supportedDatatypes)
        
    @classmethod
    def _initDatatypes(cls): 
        '''Private initializer for the supported datatypes. This isn't called
        until something needs these values, and is only called once.'''
        log.info("Initializing standard datatypes")

        # TODO: implement Attribute proxy classes - maybe not needed?
        cls.supportedDatatypes = {
#            BooleanAttribute.identifier: BooleanAttributeProxy(),
#            StringAttribute.identifier: StringAttributeProxy(),
#            DateAttribute.identifier: DateAttributeProxy(),
#            TimeAttribute.identifier: TimeAttributeProxy(),
#            DateTimeAttribute.identifier: DateTimeAttributeProxy(),
#            DayTimeDurationAttribute.identifier: DayTimeDurationAttributeProxy(),
#            YearMonthDurationAttribute.identifier: YearMonthDurationAttributeProxy(),
#            DoubleAttribute.identifier: DoubleAttributeProxy(),
#            IntegerAttribute.identifier: IntegerAttributeProxy(),
#            AnyURIAttribute.identifier: AnyURIAttributeProxy(),
#            HexBinaryAttribute.identifier: HexBinaryAttributeProxy(),
#            Base64BinaryAttribute.identifier: Base64BinaryAttributeProxy(),
#            X500NameAttribute.identifier: X500NameAttributeProxy(),
#            RFC822NameAttribute.identifier: RFC822NameAttributeProxy()
            BooleanAttribute.identifier: BooleanAttribute(),
            StringAttribute.identifier: StringAttribute(),
            DateAttribute.identifier: DateAttribute(),
            TimeAttribute.identifier: TimeAttribute(),
            DateTimeAttribute.identifier: DateTimeAttribute(),
            DayTimeDurationAttribute.identifier: DayTimeDurationAttribute(),
            YearMonthDurationAttribute.identifier: YearMonthDurationAttribute(),
            DoubleAttribute.identifier: DoubleAttribute(),
            IntegerAttribute.identifier: IntegerAttribute(),
            AnyURIAttribute.identifier: AnyURIAttribute(),
            HexBinaryAttribute.identifier: HexBinaryAttribute(),
            Base64BinaryAttribute.identifier: Base64BinaryAttribute(),
            X500NameAttribute.identifier: X500NameAttribute(),
            RFC822NameAttribute.identifier: RFC822NameAttribute()
        }

    @classmethod
    def getFactory(cls):
        '''Returns an instance of this factory. This method enforces a 
        singleton model, meaning that this always returns the same instance, 
        creating the factory if it hasn't been requested before. This is the 
        default model used by the AttributeFactory, ensuring quick access to 
        this factory.
        
        @return the factory instance
        @classmethod'''
        if cls.factoryInstance is None:
            cls._initDatatypes()
            cls.factoryInstance = cls()
            
        return cls.factoryInstance
    
    def addDatatype(self, id, proxy):
        '''
        @param id the name of the attribute type
        @param proxy the proxy used to create new attributes of the given type
        
        @raise: NotImplementedError: standard factory can't be 
        modified
        '''
        raise NotImplementedError("a standard factory cannot support new data "
                                  "types")


    


    