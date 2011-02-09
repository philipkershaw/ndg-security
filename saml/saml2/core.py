"""SAML 2.0 core module

Implementation of SAML 2.0 for NDG Security

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "11/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from datetime import datetime

from saml.common import SAMLObject, SAMLVersion
from saml.common.xml import SAMLConstants, QName
from saml.utils import TypedList


class Attribute(SAMLObject):
    '''SAML 2.0 Core Attribute.'''
    
    # Local name of the Attribute element. 
    DEFAULT_ELEMENT_LOCAL_NAME = "Attribute"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "AttributeType"

    # QName of the XSI type. 
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Name of the Name attribute. 
    NAME_ATTRIB_NAME = "Name"

    # Name for the NameFormat attribute. 
    NAME_FORMAT_ATTRIB_NAME = "NameFormat"

    # Name of the FriendlyName attribute. 
    FRIENDLY_NAME_ATTRIB_NAME = "FriendlyName"

    # Unspecified attribute format ID. 
    UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

    # URI reference attribute format ID. 
    URI_REFERENCE = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

    # Basic attribute format ID. 
    BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

    def __init__(self):
        """Initialise Attribute Class attributes"""
        self.__name = None
        self.__nameFormat = None
        self.__friendlyName = None
        self.__attributeValues = []

    def _get_name(self):
        return self.__name
    
    def _set_name(self, name):
        if not isinstance(name, basestring):
            raise TypeError("Expecting basestring type for name, got %r"% name)
        
        self.__name = name
        
    name = property(fget=_get_name,
                    fset=_set_name,
                    doc="name of this attribute")
    
    def _get_nameFormat(self):
        return self.__nameFormat
    
    def _set_nameFormat(self, nameFormat):
        if not isinstance(nameFormat, basestring):
            raise TypeError("Expecting basestring type for nameFormat, got %r"
                            % nameFormat)
            
        self.__nameFormat = nameFormat
        
    nameFormat = property(fget=_get_nameFormat,
                          fset=_set_nameFormat,
                          doc="Get the name format of this attribute.")
    
    def _get_friendlyName(self):
        return self.__friendlyName
    
    def _set_friendlyName(self, friendlyName):
        if not isinstance(friendlyName, basestring):
            raise TypeError("Expecting basestring type for friendlyName, got "
                            "%r" % friendlyName)
            
        self.__friendlyName = friendlyName
        
    friendlyName = property(fget=_get_friendlyName,
                            fset=_set_friendlyName,
                            doc="the friendly name of this attribute.")
    
    def _get_attributeValues(self):
        return self.__attributeValues
    
    def _set_attributeValues(self, attributeValues):
        if not isinstance(attributeValues, (list, tuple)):
            raise TypeError("Expecting basestring type for attributeValues, "
                            "got %r" % attributeValues)
            
        self.__attributeValues = attributeValues
        
    attributeValues = property(fget=_get_attributeValues,
                               fset=_set_attributeValues,
                               doc="the list of attribute values for this "
                               "attribute.")


class Statement(SAMLObject):
    '''SAML 2.0 Core Statement.  Abstract base class which all statement 
    types must implement.'''
    
    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "Statement"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "StatementAbstractType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)
    
            
class AttributeStatement(Statement):
    '''SAML 2.0 Core AttributeStatement'''

    def __init__(self):
        self.__attributes = TypedList(Attribute)
        self.__encryptedAttributes = TypedList(Attribute)

    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AttributeStatement"
    
    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME, 
                                 SAMLConstants.SAML20_PREFIX)
    
    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "AttributeStatementType" 
        
    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.SAML20_PREFIX)

    def _get_attributes(self):
        '''@return the attributes expressed in this statement
        '''
        return self.__attributes

    attributes = property(fget=_get_attributes)
    
    def _get_encryptedAttributes(self):
       '''@return the encrypted attribtues expressed in this statement
       '''
       return self.__encryptedAttributes
   
    encryptedAttributes = property(fget=_get_encryptedAttributes)


class AuthnStatement(Statement):
    '''SAML 2.0 Core AuthnStatement.  Currently implemented in abstract form
    only
    '''

    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AuthnStatement"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "AuthnStatementType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # AuthnInstant attribute name
    AUTHN_INSTANT_ATTRIB_NAME = "AuthnInstant"

    # SessionIndex attribute name
    SESSION_INDEX_ATTRIB_NAME = "SessionIndex"

    # SessionNoOnOrAfter attribute name
    SESSION_NOT_ON_OR_AFTER_ATTRIB_NAME = "SessionNotOnOrAfter"

    def _getAuthnInstant(self):
        '''Gets the time when the authentication took place.
        
        @return the time when the authentication took place
        '''
        raise NotImplementedError()

    def _setAuthnInstant(self, value):
        '''Sets the time when the authentication took place.
        
        @param newAuthnInstant the time when the authentication took place
        '''
        raise NotImplementedError()

    def _getSessionIndex(self):
        '''Get the session index between the principal and the authenticating 
        authority.
        
        @return the session index between the principal and the authenticating 
        authority
        '''
        raise NotImplementedError()

    def _setSessionIndex(self, value):
        '''Sets the session index between the principal and the authenticating 
        authority.
        
        @param newIndex the session index between the principal and the 
        authenticating authority
        '''
        raise NotImplementedError()

    def _getSessionNotOnOrAfter(self):
        '''Get the time when the session between the principal and the SAML 
        authority ends.
        
        @return the time when the session between the principal and the SAML 
        authority ends
        '''
        raise NotImplementedError()

    def _setSessionNotOnOrAfter(self, value):
        '''Set the time when the session between the principal and the SAML 
        authority ends.
        
        @param newSessionNotOnOrAfter the time when the session between the 
        principal and the SAML authority ends
        '''
        raise NotImplementedError()

    def _getSubjectLocality(self):
        '''Get the DNS domain and IP address of the system where the principal 
        was authenticated.
        
        @return the DNS domain and IP address of the system where the principal
        was authenticated
        '''
        raise NotImplementedError()

    def _setSubjectLocality(self, value):
        '''Set the DNS domain and IP address of the system where the principal 
        was authenticated.
        
        @param newLocality the DNS domain and IP address of the system where 
        the principal was authenticated
        '''
        raise NotImplementedError()

    def _getAuthnContext(self):
        '''Gets the context used to authenticate the subject.
        
        @return the context used to authenticate the subject
        '''
        raise NotImplementedError()

    def _setAuthnContext(self, value):
        '''Sets the context used to authenticate the subject.
        
        @param newAuthnContext the context used to authenticate the subject
        '''
        raise NotImplementedError()
            

class AuthzDecisionStatement(Statement):
    '''SAML 2.0 Core AuthzDecisionStatement.  Currently implemented in abstract
    form only'''
    
    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AuthzDecisionStatement"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "AuthzDecisionStatementType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Resource attribute name
    RESOURCE_ATTRIB_NAME = "Resource"

    # Decision attribute name
    DECISION_ATTRIB_NAME = "Decision"

    def _getResource(self):
        '''
        Get URI of the resource to which authorization is saught.
        
        @return URI of the resource to which authorization is saught
        '''
        raise NotImplementedError()

    def _setResource(self, value):
        '''
        Sets URI of the resource to which authorization is saught.
        
        @param newResourceURI URI of the resource to which authorization is 
        saught
        '''
        raise NotImplementedError()

    def _getDecision(self):
        '''
        Gets the decision of the authorization request.
        
        @return the decision of the authorization request
        '''
        raise NotImplementedError()

    def _setDecision(self, value):
        '''
        Sets the decision of the authorization request.
        
        @param newDecision the decision of the authorization request
        '''
        raise NotImplementedError()

    def _getActions(self):
        '''
        Gets the actions authorized to be performed.
        
        @return the actions authorized to be performed
        '''
        raise NotImplementedError()


    def _getEvidence(self):
        '''
        Get the SAML assertion the authority relied on when making the 
        authorization decision.
        
        @return the SAML assertion the authority relied on when making the 
        authorization decision
        '''
        raise NotImplementedError()

    def _setEvidence(self, value):
        '''
        Sets the SAML assertion the authority relied on when making the 
        authorization decision.
        
        @param newEvidence the SAML assertion the authority relied on when 
        making the authorization decision
        '''
        raise NotImplementedError()
        

class Subject(SAMLObject):
    '''Concrete implementation of @link org.opensaml.saml2.core.Subject.'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Subject"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "SubjectType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    def __init__(self, 
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 elementLocalName=DEFAULT_ELEMENT_LOCAL_NAME, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        '''@param namespaceURI the namespace the element is in
        @param elementLocalName the local name of the XML element this Object 
        represents
        @param namespacePrefix the prefix for the given namespace
        '''
        self.__qname = QName(namespaceURI, 
                             elementLocalName, 
                             namespacePrefix)
        
        # BaseID child element.
        self.__baseID = None
    
        # NameID child element.
        self.__nameID = None
    
        # EncryptedID child element.
        self.__encryptedID = None
    
        # Subject Confirmations of the Subject.
        self.__subjectConfirmations = []
    
    def _get_qname(self):
        return self.__qname
    
    qname = property(fget=_get_qname, doc="Qualified Name for Subject")
    
    def _getBaseID(self): 
        return self.__baseID

    def _setBaseID(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for \"baseID\" got %r" %
                            (basestring, value.__class__))
        self.__baseID = value

    baseID = property(fget=_getBaseID, 
                      fset=_setBaseID, 
                      doc="Base identifier")
      
    def _getNameID(self):
        return self.__nameID
    
    def _setNameID(self, value):
        if not isinstance(value, NameID):
            raise TypeError("Expecting %r type for \"nameID\" got %r" %
                            (NameID, type(value)))
        self.__nameID = value

    nameID = property(fget=_getNameID, 
                      fset=_setNameID, 
                      doc="Name identifier")
    
    def _getEncryptedID(self):
        return self.__encryptedID
    
    def _setEncryptedID(self, value): 
        self.__encryptedID = value

    encryptedID = property(fget=_getEncryptedID, 
                           fset=_setEncryptedID, 
                           doc="EncryptedID's Docstring")    
    def _getSubjectConfirmations(self): 
        return self.__subjectConfirmations

    subjectConfirmations = property(fget=_getSubjectConfirmations, 
                                    doc="Subject Confirmations")    
    def getOrderedChildren(self): 
        children = []

        if self.baseID is not None:
            children.append(self.baseID)
        
        if self.nameID is not None: 
            children.append(self.nameID)
        
        if self.encryptedID is not None: 
            children.append(self.encryptedID)
        
        children += self.subjectConfirmations

        return tuple(children)


class AbstractNameIDType(SAMLObject):
    '''Abstract implementation of NameIDType'''

    # SPNameQualifier attribute name.
    SP_NAME_QUALIFIER_ATTRIB_NAME = "SPNameQualifier"

    # Format attribute name.
    FORMAT_ATTRIB_NAME = "Format"

    # SPProviderID attribute name.
    SPPROVIDED_ID_ATTRIB_NAME = "SPProvidedID"

    # URI for unspecified name format.
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

    # URI for email name format.
    EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # URI for X509 subject name format.
    X509_SUBJECT = "urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName"

    # URI for windows domain qualified name name format.
    WIN_DOMAIN_QUALIFIED = \
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"

    # URI for kerberos name format.
    KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"

    # URI for SAML entity name format.
    ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

    # URI for persistent name format.
    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

    # URI for transient name format.
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

    # Special URI used by NameIDPolicy to indicate a NameID should be encrypted
    ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
    
    def __init__(self, namespaceURI, elementLocalName, namespacePrefix): 
        '''@param namespaceURI the namespace the element is in
        @param elementLocalName the local name of the XML element this Object 
        represents
        @param namespacePrefix the prefix for the given namespace
        '''
        self.__qname = QName(namespaceURI, elementLocalName, namespacePrefix)
    
        # Name of the Name ID.
        self.__name = None
        
        # Name Qualifier of the Name ID.
        self.__nameQualifier = None
    
        # SP Name Qualifier of the Name ID.
        self.__spNameQualifier = None
    
        # Format of the Name ID.
        self.__format = None
    
        # SP ProvidedID of the NameID.
        self.__spProvidedID = None

        self.__value = None
        
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
             
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("\"value\" must be a basestring derived type, "
                            "got %r" % value.__class__)
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, doc="string value")  
    
    def _getNameQualifier(self): 
        return self.__nameQualifier
    
    def _setNameQualifier(self, value): 
        self.__nameQualifier = value

    nameQualifier = property(fget=_getNameQualifier, 
                             fset=_setNameQualifier, 
                             doc="Name qualifier")    

    def _getSPNameQualifier(self): 
        return self.__spNameQualifier
    
    def _setSPNameQualifier(self, value): 
        self.__spNameQualifier = value

    spNameQualifier = property(fget=_getSPNameQualifier, 
                               fset=_setSPNameQualifier, 
                               doc="SP Name qualifier")    
    
    def _getFormat(self):
        return self.__format
        
    def _setFormat(self, format):
        if not isinstance(format, basestring):
            raise TypeError("\"format\" must be a basestring derived type, "
                            "got %r" % format.__class__)
            
        self.__format = format

    format = property(fget=_getFormat, fset=_setFormat, doc="Name format")  
    
    def _getSPProvidedID(self): 
        return self.__spProvidedID
    
    def _setSPProvidedID(self, value): 
        self.__spProvidedID = value

    spProvidedID = property(fget=_getSPProvidedID, fset=_setSPProvidedID, 
                            doc="SP Provided Identifier")  
    
    def getOrderedChildren(self): 
        raise NotImplementedError()

   
class Issuer(AbstractNameIDType):
    """SAML 2.0 Core Issuer type"""
    
    # Element local name. 
    DEFAULT_ELEMENT_LOCAL_NAME = "Issuer"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "IssuerType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX) 
    
    def __init__(self, 
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 localPart=DEFAULT_ELEMENT_LOCAL_NAME, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        super(Issuer, self).__init__(namespaceURI,
                                     localPart,
                                     namespacePrefix)

     
class NameID(AbstractNameIDType):
    '''SAML 2.0 Core NameID'''
    # Element local name. 
    DEFAULT_ELEMENT_LOCAL_NAME = "NameID"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "NameIDType"

    # QName of the XSI type. 
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)
    
    def __init__(self, 
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 localPart=DEFAULT_ELEMENT_LOCAL_NAME, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        super(NameID, self).__init__(namespaceURI,
                                     localPart,
                                     namespacePrefix)


class Conditions(SAMLObject): 
    '''SAML 2.0 Core Conditions.'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Conditions"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "ConditionsType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # NotBefore attribute name.
    NOT_BEFORE_ATTRIB_NAME = "NotBefore"

    # NotOnOrAfter attribute name.
    NOT_ON_OR_AFTER_ATTRIB_NAME = "NotOnOrAfter"

    def __init__(self):
        
        # A Condition.
        self.__conditions = []
    
        # Not Before conditions.
        self.__notBefore = None
    
        # Not On Or After conditions.
        self.__notOnOrAfter = None

    def _getNotBefore(self):
        '''Get the date/time before which the assertion is invalid.
        
        @return the date/time before which the assertion is invalid'''
        return self.__notBefore
    
    def _setNotBefore(self, value):
        '''Sets the date/time before which the assertion is invalid.
        
        @param newNotBefore the date/time before which the assertion is invalid
        '''
        if not isinstance(value, datetime):
            raise TypeError('Expecting "datetime" type for "notBefore", '
                            'got %r' % type(value))
        self.__notBefore = value

    def _getNotOnOrAfter(self):
        '''Gets the date/time on, or after, which the assertion is invalid.
        
        @return the date/time on, or after, which the assertion is invalid'
        '''
        return self.__notBefore
    
    def _setNotOnOrAfter(self, value):
        '''Sets the date/time on, or after, which the assertion is invalid.
        
        @param newNotOnOrAfter the date/time on, or after, which the assertion 
        is invalid
        '''
        if not isinstance(value, datetime):
            raise TypeError('Expecting "datetime" type for "notOnOrAfter", '
                            'got %r' % type(value))
        self.__notOnOrAfter = value  

    def _getConditions(self):
        '''Gets all the conditions on the assertion.
        
        @return all the conditions on the assertion
        '''
        return self.__conditions
    
    conditions = property(fget=_getConditions,
                          doc="List of conditions")
    
    def _getAudienceRestrictions(self):
        '''Gets the audience restriction conditions for the assertion.
        
        @return the audience restriction conditions for the assertion
        '''
        raise NotImplementedError()

    def _getOneTimeUse(self):
        '''Gets the OneTimeUse condition for the assertion.
        
        @return the OneTimeUse condition for the assertion
        '''
        raise NotImplementedError()

    def _getProxyRestriction(self):    
        '''Gets the ProxyRestriction condition for the assertion.
        
        @return the ProxyRestriction condition for the assertion
        '''
        raise NotImplementedError()
    
    
class Advice(SAMLObject):
    '''SAML 2.0 Core Advice.
    '''

    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "Advice"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "AdviceType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    def _getChildren(self, typeOrName=None):
        '''
        Gets the list of all child elements attached to this advice.
        
        @return the list of all child elements attached to this advice
        '''
        raise NotImplementedError()

    def _getAssertionIDReferences(self):
        '''Gets the list of AssertionID references used as advice.
        
        @return the list of AssertionID references used as advice
        '''
        raise NotImplementedError()

    def _getAssertionURIReferences(self):
        '''Gets the list of AssertionURI references used as advice.
        
        @return the list of AssertionURI references used as advice
        '''
        raise NotImplementedError()
    
    def _getAssertions(self):
        '''Gets the list of Assertions used as advice.
        
        @return the list of Assertions used as advice
        '''
        raise NotImplementedError()
    
    def _getEncryptedAssertions(self):
        '''Gets the list of EncryptedAssertions used as advice.
        
        @return the list of EncryptedAssertions used as advice
        '''
        raise NotImplementedError()
        

class Assertion(SAMLObject):
    """SAML 2.0 Attribute Assertion for use with NERC DataGrid    
    """    
    ns = "urn:oasis:names:tc:SAML:1.0:assertion"
    nsPfx = "saml"
    issuer = 'http:#badc.nerc.ac.uk'
    attributeName = "urn:mace:dir:attribute-def:eduPersonAffiliation"
    attributeNS = "urn:mace:shibboleth:1.0:attributeNamespace:uri"

    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Assertion"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "AssertionType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Version attribute name.
    VERSION_ATTRIB_NAME = "Version"

    # IssueInstant attribute name.
    ISSUE_INSTANT_ATTRIB_NAME = "IssueInstant"

    # ID attribute name.
    ID_ATTRIB_NAME = "ID"

    def __init__(self):
        # Base class initialisation
        super(Assertion, self).__init__()
        
        self.__version = None
        self.__issueInstant = None
        self.__id = None
        self.__issuer = None
        self.__subject = None
        
        self.__conditions = None
        self.__advice = None
        self.__statements = TypedList(Statement)
        
        # TODO: Implement AuthnStatement and AuthzDecisionStatement classes
        self.__authnStatements = []
        self.__authzDecisionStatements = []
        self.__attributeStatements = TypedList(AttributeStatement)
        
    def _get_version(self):
        '''@return the SAML Version of this assertion.
        '''
        return self.__version
    
    def _set_version(self, version):
        '''@param version the SAML Version of this assertion
        '''
        if not isinstance(version, SAMLVersion):
            raise TypeError("Expecting SAMLVersion type got: %r" % 
                            version.__class__)
        
        self.__version = version
        
    version = property(fget=_get_version,
                       fset=_set_version,
                       doc="SAML Version of the assertion")

    def _get_issueInstant(self):
        '''Gets the issue instance of this assertion.
        
        @return the issue instance of this assertion'''
        return self.__issueInstant
    
    def _set_issueInstant(self, issueInstant):
        '''Sets the issue instance of this assertion.
        
        @param newIssueInstance the issue instance of this assertion
        '''
        if not isinstance(issueInstant, datetime):
            raise TypeError('Expecting "datetime" type for "issueInstant", '
                            'got %r' % issueInstant.__class__)
            
        self.__issueInstant = issueInstant
        
    issueInstant = property(fget=_get_issueInstant, 
                            fset=_set_issueInstant,
                            doc="Issue instant of the assertion")

    def _get_id(self):
        '''Sets the ID of this assertion.
        
        @return the ID of this assertion
        '''
        return self.__id
    
    def _set_id(self, _id):
        '''Sets the ID of this assertion.
        
        @param newID the ID of this assertion
        '''
        if not isinstance(_id, basestring):
            raise TypeError('Expecting basestring derived type for "id", got '
                            '%r' % _id.__class__)
        self.__id = _id
        
    id = property(fget=_get_id, fset=_set_id, doc="ID of assertion")
    
    def _set_issuer(self, issuer):
        """Set issuer"""
        if not isinstance(issuer, Issuer):
            raise TypeError("issuer must be %r, got %r" % (Issuer, 
                                                           type(issuer)))
        self.__issuer = issuer
    
    def _get_issuer(self):
        """Get the issuer name """
        return self.__issuer

    issuer = property(fget=_get_issuer, 
                      fset=_set_issuer,
                      doc="Issuer of assertion")
    
    def _set_subject(self, subject):
        """Set subject string."""
        if not isinstance(subject, Subject):
            raise TypeError("subject must be %r, got %r" % (Subject, 
                                                            type(subject)))

        self.__subject = subject
    
    def _get_subject(self):
        """Get subject string."""
        return self.__subject

    subject = property(fget=_get_subject,
                       fset=_set_subject, 
                       doc="Attribute Assertion subject")
    
    def _get_conditions(self):
        """Get conditions string."""
        return self.__conditions
    
    def _set_conditions(self, value):
        """Get conditions string."""
        if not isinstance(value, Conditions):
            raise TypeError("Conditions must be %r, got %r" % (Conditions, 
                                                               type(value)))

        self.__conditions = value

    conditions = property(fget=_get_conditions,
                          fset=_set_conditions,
                          doc="Attribute Assertion conditions")
    
    def _set_advice(self, advice):
        """Set advice string."""
        if not isinstance(advice, basestring):
            raise TypeError("advice must be a string")

        self.__advice = advice
    
    def _get_advice(self):
        """Get advice string."""
        return self.__advice

    advice = property(fget=_get_advice,
                      fset=_set_advice, 
                      doc="Attribute Assertion advice")
    
    def _get_statements(self):
        """Get statements string."""
        return self.__statements

    statements = property(fget=_get_statements,
                          doc="Attribute Assertion statements")
    
    def _get_authnStatements(self):
        """Get authnStatements string."""
        return self.__authnStatements

    authnStatements = property(fget=_get_authnStatements,
                               doc="Attribute Assertion authentication "
                                   "statements")
    
    def _get_authzDecisionStatements(self):
        """Get authorisation decision statements."""
        return self.__authzDecisionStatements

    authzDecisionStatements = property(fget=_get_authzDecisionStatements,
                                       doc="Attribute Assertion authorisation "
                                           "decision statements")
    
    def _get_attributeStatements(self):
        """Get attributeStatements string."""
        return self.__attributeStatements

    attributeStatements = property(fget=_get_attributeStatements,
                                   doc="Attribute Assertion attribute "
                                       "statements")
    

class AttributeValue(SAMLObject):
    """Base class for Attribute Value type"""
    
    # Element name, no namespace
    DEFAULT_ELEMENT_LOCAL_NAME = "AttributeValue"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)


class XSStringAttributeValue(AttributeValue):
    """XML XS:String Attribute Value type"""
    
    # Local name of the XSI type
    TYPE_LOCAL_NAME = "string"
        
    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.XSD_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.XSD_PREFIX)
    
    DEFAULT_FORMAT = "%s#%s" % (SAMLConstants.XSD_NS, TYPE_LOCAL_NAME)
  
    def __init__(self):
        self.__value = None
        
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Input must be a basestring derived type, got %r" %
                            value.__class__)
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, doc="string value")  


class StatusDetail(SAMLObject):
    '''Implementation of SAML 2.0 StatusDetail'''
    
    # Local Name of StatusDetail.
    DEFAULT_ELEMENT_LOCAL_NAME = "StatusDetail"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusDetailType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)
    
    def __init__(self):
        # child "any" elements.
        self.__unknownChildren = TypedList(SAMLObject)         
        self.__qname = QName(StatusDetail.DEFAULT_ELEMENT_NAME.namespaceURI,
                             StatusDetail.DEFAULT_ELEMENT_NAME,
                             StatusDetail.DEFAULT_ELEMENT_NAME.prefix)
    
    def getUnknownXMLTypes(self, qname=None): 
        if qname is not None:
            if not isinstance(qname, QName):
                raise TypeError("\"qname\" must be a %r derived type, "
                                "got %r" % (QName, type(qname)))
                
            children = []
            for child in self.__unknownChildren:
                childQName = getattr(child, "qname", None)
                if childQName is not None:
                    if childQName.namespaceURI == qname.namespaceURI or \
                       childQName.localPart == qname.localPart:
                        children.append(child)
                        
            return children
        else:
            return self.__unknownChildren
    
    unknownChildren = property(fget=getUnknownXMLTypes,
                               doc="Child objects of Status Detail - may be "
                                   "any type")
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
    

class StatusMessage(SAMLObject):
    '''Implementation of SAML 2.0 Status Message'''

    DEFAULT_ELEMENT_LOCAL_NAME = "StatusMessage"
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)
    
    def __init__(self):
        # Value attribute URI.
        self.__value = None        
        self.__qname = QName(StatusMessage.DEFAULT_ELEMENT_NAME.namespaceURI,
                             StatusMessage.DEFAULT_ELEMENT_NAME.localPart,
                             StatusMessage.DEFAULT_ELEMENT_NAME.prefix)
              
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("\"value\" must be a basestring derived type, "
                            "got %r" % type(value))
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, 
                     doc="Status message value")
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")


class StatusCode(SAMLObject):
    '''Implementation of SAML 2.0 StatusCode.'''
    
    # Local Name of StatusCode.
    DEFAULT_ELEMENT_LOCAL_NAME = "StatusCode"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusCodeType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # Local Name of the Value attribute.
    VALUE_ATTRIB_NAME = "Value"

    # URI for Success status code.
    SUCCESS_URI = "urn:oasis:names:tc:SAML:2.0:status:Success"

    # URI for Requester status code.
    REQUESTER_URI = "urn:oasis:names:tc:SAML:2.0:status:Requester"

    # URI for Responder status code.
    RESPONDER_URI = "urn:oasis:names:tc:SAML:2.0:status:Responder"

    # URI for VersionMismatch status code.
    VERSION_MISMATCH_URI = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

    # URI for AuthnFailed status code.
    AUTHN_FAILED_URI = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

    # URI for InvalidAttrNameOrValue status code.
    INVALID_ATTR_NAME_VALUE_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

    # URI for InvalidNameIDPolicy status code.
    INVALID_NAMEID_POLICY_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

    # URI for NoAuthnContext status code.
    NO_AUTHN_CONTEXT_URI = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

    # URI for NoAvailableIDP status code.
    NO_AVAILABLE_IDP_URI = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

    # URI for NoPassive status code.
    NO_PASSIVE_URI = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"

    # URI for NoSupportedIDP status code.
    NO_SUPPORTED_IDP_URI = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

    # URI for PartialLogout status code.
    PARTIAL_LOGOUT_URI = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

    # URI for ProxyCountExceeded status code.
    PROXY_COUNT_EXCEEDED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

    # URI for RequestDenied status code.
    REQUEST_DENIED_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

    # URI for RequestUnsupported status code.
    REQUEST_UNSUPPORTED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

    # URI for RequestVersionDeprecated status code.
    REQUEST_VERSION_DEPRECATED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"

    # URI for RequestVersionTooHigh status code.
    REQUEST_VERSION_TOO_HIGH_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
    
    # URI for RequestVersionTooLow status code.
    REQUEST_VERSION_TOO_LOW_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

    # URI for ResourceNotRecognized status code.
    RESOURCE_NOT_RECOGNIZED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

    # URI for TooManyResponses status code.
    TOO_MANY_RESPONSES = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

    # URI for UnknownAttrProfile status code.
    UNKNOWN_ATTR_PROFILE_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

    # URI for UnknownPrincipal status code.
    UNKNOWN_PRINCIPAL_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

    # URI for UnsupportedBinding status code.
    UNSUPPORTED_BINDING_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"

    def __init__(self):
        # Value attribute URI.
        self.__value = None
    
        # Nested secondary StatusCode child element.
        self.__childStatusCode = None
        
        self.__qname = QName(StatusCode.DEFAULT_ELEMENT_NAME.namespaceURI,
                             StatusCode.DEFAULT_ELEMENT_NAME.localPart,
                             StatusCode.DEFAULT_ELEMENT_NAME.prefix)

    def _getStatusCode(self): 
        return self.__childStatusCode
    
    def _setStatusCode(self, value):
        if not isinstance(value, StatusCode):
            raise TypeError('Child "statusCode" must be a %r derived type, '
                            "got %r" % (StatusCode, type(value)))
            
        self.__childStatusCode = value

    value = property(fget=_getStatusCode, 
                     fset=_setStatusCode, 
                     doc="Child Status code")
              
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("\"value\" must be a basestring derived type, "
                            "got %r" % value.__class__)
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, doc="Status code value")
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
        

class Status(SAMLObject): 
    '''SAML 2.0 Core Status'''
    
    # Local Name of Status.
    DEFAULT_ELEMENT_LOCAL_NAME = "Status"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    def __init__(self):
        # StatusCode element.
        self.__statusCode = None
    
        # StatusMessage element.
        self.__statusMessage = None
    
        # StatusDetail element. 
        self.__statusDetail = None
        
        self.__qname = QName(Status.DEFAULT_ELEMENT_NAME.namespaceURI,
                             Status.DEFAULT_ELEMENT_NAME.localPart,
                             Status.DEFAULT_ELEMENT_NAME.prefix)
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
        
    def _getStatusCode(self):
        '''
        Gets the Code of this Status.
        
        @return Status StatusCode
        '''
        return self.__statusCode

    def _setStatusCode(self, value):
        '''
        Sets the Code of this Status.
        
        @param newStatusCode the Code of this Status
        '''
        if not isinstance(value, StatusCode):
            raise TypeError('"statusCode" must be a %r derived type, '
                            "got %r" % (StatusCode, type(value)))
            
        self.__statusCode = value
        
    statusCode = property(fget=_getStatusCode,
                          fset=_setStatusCode,
                          doc="status code object")
    
    def _getStatusMessage(self):
        '''
        Gets the Message of this Status.
        
        @return Status StatusMessage
        '''
        return self.__statusMessage

    def _setStatusMessage(self, value):
        '''
        Sets the Message of this Status.
        
        @param newStatusMessage the Message of this Status
        '''
        if not isinstance(value, StatusMessage):
            raise TypeError('"statusMessage" must be a %r derived type, '
                            "got %r" % (StatusMessage, type(value)))
            
        self.__statusMessage = value
        
    statusMessage = property(fget=_getStatusMessage,
                             fset=_setStatusMessage,
                             doc="status message")

    def _getStatusDetail(self):
        '''
        Gets the Detail of this Status.
        
        @return Status StatusDetail
        '''
        return self.__statusDetail
    
    def _setStatusDetail(self, value):
        '''
        Sets the Detail of this Status.
        
        @param newStatusDetail the Detail of this Status
        '''
        self.__statusDetail = value
        
    statusDetail = property(fget=_getStatusDetail,
                            fset=_setStatusDetail,
                            doc="status message")


class RequestAbstractType(SAMLObject): 
    '''SAML 2.0 Core RequestAbstractType'''
    
    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "RequestAbstractType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # ID attribute name.
    ID_ATTRIB_NAME = "ID"

    # Version attribute name.
    VERSION_ATTRIB_NAME = "Version"

    # IssueInstant attribute name.
    ISSUE_INSTANT_ATTRIB_NAME = "IssueInstant"

    # Destination attribute name.
    DESTINATION_ATTRIB_NAME = "Destination"

    # Consent attribute name.
    CONSENT_ATTRIB_NAME = "Consent"

    # Unspecified consent URI.
    UNSPECIFIED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

    # Obtained consent URI.
    OBTAINED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:obtained"

    # Prior consent URI.
    PRIOR_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:prior"

    # Implicit consent URI.
    IMPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:implicit"

    # Explicit consent URI.
    EXPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:explicit"

    # Unavailable consent URI.
    UNAVAILABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unavailable"

    # Inapplicable consent URI.
    INAPPLICABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:inapplicable" 

    def __init__(self):
        # SAML Version of the request. 
        self.__version = None
    
        # Unique identifier of the request. 
        self.__id = None
    
        # Date/time request was issued. 
        self.__issueInstant = None
    
        # URI of the request destination. 
        self.__destination = None
    
        # URI of the SAML user consent type. 
        self.__consent = None
    
        # URI of the SAML user consent type. 
        self.__issuer = None
    
        # Extensions child element. 
        self.__extensions = None
        
    def _get_version(self):
        '''@return the SAML Version of this assertion.
        '''
        return self.__version
    
    def _set_version(self, version):
        '''@param version the SAML Version of this assertion
        '''
        if not isinstance(version, SAMLVersion):
            raise TypeError("Expecting SAMLVersion type got: %r" % 
                            version.__class__)
        
        self.__version = version
        
    version = property(fget=_get_version,
                       fset=_set_version,
                       doc="SAML Version of the assertion")

    def _get_issueInstant(self):
        '''Gets the date/time the request was issued
        
        @return the issue instance of this request'''
        return self.__issueInstant
    
    def _set_issueInstant(self, value):
        '''Sets the date/time the request was issued
        
        @param value the issue instance of this request
        '''
        if not isinstance(value, datetime):
            raise TypeError('Expecting "datetime" type for "issueInstant", '
                            'got %r' % type(value))
            
        self.__issueInstant = value
        
    issueInstant = property(fget=_get_issueInstant, 
                            fset=_set_issueInstant,
                            doc="Issue instant of the request") 

    def _get_id(self):
        '''Sets the unique identifier for this request.
        
        @return the ID of this request
        '''
        return self.__id
    
    def _set_id(self, value):
        '''Sets the unique identifier for this request
        
        @param newID the ID of this assertion
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "id", got '
                            '%r' % type(value))
        self.__id = value
        
    id = property(fget=_get_id, fset=_set_id, doc="ID of request")

    def _get_destination(self):
        '''Gets the URI of the destination of the request.
        
        @return the URI of the destination of the request
        '''
        return self.__destination
    
    def _set_destination(self, value):
        '''Sets the URI of the destination of the request.
        
        @param newDestination the URI of the destination of the request'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for '
                            '"destination", got %r' % type(value))
        self.__destination = value
        
    destination = property(fget=_get_destination, 
                           fset=_set_destination,
                           doc="Destination of request")
     
    def _get_consent(self):
        '''Gets the consent obtained from the principal for sending this 
        request.
        
        @return: the consent obtained from the principal for sending this 
        request
        '''
        return self.__consent
        
    def _set_consent(self, value):
        '''Sets the consent obtained from the principal for sending this 
        request.
        
        @param value: the new consent obtained from the principal for 
        sending this request
        ''' 
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "consent", '
                            'got %r' % type(value))
        self.__consent = value
              
    consent = property(fget=_get_consent, 
                       fset=_set_consent,
                       doc="Consent for request")
   
    def _set_issuer(self, issuer):
        """Set issuer of request"""
        if not isinstance(issuer, Issuer):
            raise TypeError('"issuer" must be a %r, got %r' % (Issuer, 
                                                               type(issuer)))
        
        self.__issuer = issuer
    
    def _get_issuer(self):
        """Get the issuer name """
        return self.__issuer

    issuer = property(fget=_get_issuer, 
                      fset=_set_issuer,
                      doc="Issuer of request")
 
    def _get_extensions(self):
        '''Gets the Extensions of this request.
        
        @return: the Status of this request
        '''
        return self.__extensions
      
    def _set_extensions(self, value):
        '''Sets the Extensions of this request.
        
        @param value: the Extensions of this request
        '''
        self.__extensions = value
        
    extensions = property(fget=_get_extensions, 
                          fset=_set_extensions,
                          doc="Request extensions")


class SubjectQuery(RequestAbstractType):
    """SAML 2.0 Core Subject Query type"""
    
    def __init__(self):
        self.__subject = None
        
    def _getSubject(self):
        '''Gets the Subject of this request.
        
        @return the Subject of this request'''   
        return self.__subject
    
    def _setSubject(self, value):
        '''Sets the Subject of this request.
        
        @param newSubject the Subject of this request'''
        if not isinstance(value, Subject):
            raise TypeError('Setting "subject", got %r, expecting %r' %
                            (Subject, type(value)))
            
        self.__subject = value
        
    subject = property(fget=_getSubject, fset=_setSubject, doc="Query subject")
    
    
class AttributeQuery(SubjectQuery):
    '''SAML 2.0 AttributeQuery'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "AttributeQuery"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "AttributeQueryType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    def __init__(self):
        self.__attributes = TypedList(Attribute)
 
    def _getAttributes(self):
        '''Gets the Attributes of this query.
        
        @return the list of Attributes of this query'''
        return self.__attributes

    def _setAttributes(self, value):
        self.__attributes = value

    attributes = property(fget=_getAttributes, 
                          fset=_setAttributes, 
                          doc="Attributes")


class StatusResponseType(SAMLObject):
    '''SAML 2.0 Core Status Response Type
    '''

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusResponseType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # ID attribute name
    ID_ATTRIB_NAME = "ID"

    # InResponseTo attribute name
    IN_RESPONSE_TO_ATTRIB_NAME = "InResponseTo"

    # Version attribute name
    VERSION_ATTRIB_NAME = "Version"

    # IssueInstant attribute name
    ISSUE_INSTANT_ATTRIB_NAME = "IssueInstant"

    # Destination attribute name
    DESTINATION_ATTRIB_NAME = "Destination"

    # Consent attribute name.
    CONSENT_ATTRIB_NAME = "Consent"

    # Unspecified consent URI
    UNSPECIFIED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

    # Obtained consent URI
    OBTAINED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:obtained"

    # Prior consent URI
    PRIOR_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:prior"

    # Implicit consent URI
    IMPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:implicit"

    # Explicit consent URI
    EXPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:explicit"

    # Unavailable consent URI
    UNAVAILABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unavailable"

    # Inapplicable consent URI
    INAPPLICABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:inapplicable"

    def __init__(self):
        self.__qname = None
        
        self.__version = SAMLVersion(SAMLVersion.VERSION_20)
        self.__id = None
        self.__inResponseTo = None
        self.__issueInstant = None
        self.__destination = None
        self.__consent = None
        self.__issuer = None
        self.__status = None
        self.__extensions = None
        
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")

    def _get_version(self):
        '''@return the SAML Version of this response.
        '''
        return self.__version
    
    def _set_version(self, version):
        '''@param version the SAML Version of this response
        '''
        if not isinstance(version, SAMLVersion):
            raise TypeError("Expecting SAMLVersion type got: %r" % 
                            version.__class__)
        
        self.__version = version
       
    version = property(fget=_get_version,
                       fset=_set_version,
                       doc="SAML Version of the response")

    def _get_id(self):
        '''Sets the ID of this response.
        
        @return the ID of this response
        '''
        return self.__id
    
    def _set_id(self, value):
        '''Sets the ID of this response.
        
        @param value: the ID of this response
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "id", got '
                            '%r' % type(value))
        self.__id = value
        
    id = property(fget=_get_id, fset=_set_id, doc="ID of response")

    def _getInResponseTo(self):
        '''Get the unique request identifier for which this is a response
        
        @return value: the unique identifier of the originating 
        request
        '''
        return self.__inResponseTo
    
    def _setInResponseTo(self, value):
        '''Set the unique request identifier for which this is a response
        
        @param value: the unique identifier of the originating 
        request
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for '
                            '"inResponseTo", got %r' % type(value))
        self.__inResponseTo = value
        
    inResponseTo = property(fget=_getInResponseTo, 
                            fset=_setInResponseTo,
                            doc="unique request identifier for which this is "
                                "a response")

    def _get_issueInstant(self):
        '''Gets the issue instance of this response.
        
        @return the issue instance of this response'''
        return self.__issueInstant
    
    def _set_issueInstant(self, issueInstant):
        '''Sets the issue instance of this response.
        
        @param newIssueInstance the issue instance of this response
        '''
        if not isinstance(issueInstant, datetime):
            raise TypeError('Expecting "datetime" type for "issueInstant", '
                            'got %r' % issueInstant.__class__)
            
        self.__issueInstant = issueInstant
        
    issueInstant = property(fget=_get_issueInstant, 
                            fset=_set_issueInstant,
                            doc="Issue instant of the response")

    def _get_destination(self):
        '''Gets the URI of the destination of the response.
        
        @return the URI of the destination of the response
        '''
        return self.__destination
    
    def _set_destination(self, value):
        '''Sets the URI of the destination of the response.
        
        @param value: the URI of the destination of the response'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for '
                            '"destination", got %r' % type(value))
        self.__destination = value
        
    destination = property(fget=_get_destination, 
                           fset=_set_destination,
                           doc="Destination of response")
     
    def _get_consent(self):
        '''Gets the consent obtained from the principal for sending this 
        response.
        
        @return: the consent obtained from the principal for sending this 
        response
        '''
        return self.__consent
        
    def _set_consent(self, value):
        '''Sets the consent obtained from the principal for sending this 
        response.
        
        @param value: the new consent obtained from the principal for 
        sending this response
        ''' 
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "consent", '
                            'got %r' % type(value))
        self.__consent = value
              
    consent = property(fget=_get_consent, 
                       fset=_set_consent,
                       doc="Consent for response")
   
    def _set_issuer(self, issuer):
        """Set issuer of response"""
        if not isinstance(issuer, Issuer):
            raise TypeError('"issuer" must be a %r, got %r' % (Issuer,
                                                               type(issuer)))
        self.__issuer = issuer
    
    def _get_issuer(self):
        """Get the issuer name """
        return self.__issuer

    issuer = property(fget=_get_issuer, 
                      fset=_set_issuer,
                      doc="Issuer of response")
    
    def _getStatus(self):
        '''Gets the Status of this response.
        
        @return the Status of this response
        '''
        return self.__status

    def _setStatus(self, value):
        '''Sets the Status of this response.
        
        @param newStatus the Status of this response
        '''
        if not isinstance(value, Status):
            raise TypeError('"status" must be a %r, got %r' % (Status,
                                                               type(value)))
        self.__status = value
        
    status = property(fget=_getStatus, fset=_setStatus, doc="Response status")    
        
    def _get_extensions(self):
        '''Gets the Extensions of this response.
        
        @return: the Status of this response
        '''
        return self.__extensions
      
    def _set_extensions(self, value):
        '''Sets the Extensions of this response.
        
        @param value: the Extensions of this response
        '''
        if not isinstance(value, (list, tuple)):
            raise TypeError('Expecting list or tuple for "extensions", got %r'
                            % type(value))
        self.__extensions = value
        
    extensions = property(fget=_get_extensions, 
                          fset=_set_extensions,
                          doc="Response extensions")    


class Response(StatusResponseType):
    '''SAML2 Core Response'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Response"
    
    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME, 
                                 SAMLConstants.SAML20P_PREFIX)
    
    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "ResponseType"
        
    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.SAML20P_PREFIX)
    
    def __init__(self):
        '''''' 
        super(Response, self).__init__()
        
        # Assertion child elements
        self.__indexedChildren = []
    
    def _getAssertions(self): 
        return self.__indexedChildren
    
    assertions = property(fget=_getAssertions,
                          doc="Assertions contained in this response")
