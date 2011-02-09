"""SAML Common XML module

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
__date__ = "23/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from saml.xml import XMLConstants    

class SAMLConstants(XMLConstants):
    '''XML related constants used in the SAML specifications.'''
    
    # HTTP Constants
    
    # HTTP Request Method - POST.
    POST_METHOD = "POST"
    
    # HTTP Method - GET.
    GET_METHOD = "GET"
    
    # OpenSAML 2
    
    # Directory, on the classpath, schemas are located in.
    SCHEMA_DIR = "/schema/"
    
    #    Core XML
    
    # XML core schema system Id.
    XML_SCHEMA_LOCATION = SCHEMA_DIR + "xml.xsd"
    
    #  XML Signature schema Id.
    XMLSIG_SCHEMA_LOCATION = SCHEMA_DIR + "xmldsig-core-schema.xsd"
    
    # XML Encryption schema Id.
    XMLENC_SCHEMA_LOCATION = SCHEMA_DIR + "xenc-schema.xsd"

    
    #    SOAP
    
    #  SOAP 1.1 schema Id.
    SOAP11ENV_SCHEMA_LOCATION = SCHEMA_DIR + SCHEMA_DIR + "soap-envelope.xsd"
    
    #  SOAP 1.1 Envelope XML namespace.
    SOAP11ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
    
    #  SOAP 1.1 Envelope QName prefix.
    SOAP11ENV_PREFIX = "SOAP-ENV"
    
    #  Liberty PAOS XML Namespace.
    PAOS_NS = "urn:liberty:paos:2003-08"
    
    #  Liberty PAOS QName prefix.
    PAOS_PREFIX = "paos"
    
    #    SAML 1.X
    
    # SAML 1.0 Assertion schema system Id.
    SAML10_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-assertion-01.xsd"
    
    # SAML 1.1 Assertion schema system Id.
    SAML11_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-assertion-1.1.xsd"
    
    # SAML 1.X XML namespace.
    SAML1_NS = "urn:oasis:names:tc:SAML:1.0:assertion"
    
    # SAML 1.0 Protocol schema system Id.
    SAML10P_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-protocol-01.xsd"
    
    # SAML 1.1 Protocol schema system Id.
    SAML11P_SCHEMA_LOCATION = SCHEMA_DIR + "cs-sstc-schema-protocol-1.1.xsd"

    # SAML 1.X protocol XML namespace.
    SAML10P_NS = "urn:oasis:names:tc:SAML:1.0:protocol"
    
    # SAML 1.1 protocol XML namespace, used only in SAML 2 metadata protocol
    # SupportEnumeration.
    SAML11P_NS = "urn:oasis:names:tc:SAML:1.1:protocol"
    
    # SAML 1.X Protocol QName prefix.
    SAML1P_PREFIX = "samlp"

    # SAML 1.X Assertion QName prefix.
    SAML1_PREFIX = "saml"
    
    # SAML 1 Metadata extension XML namespace.
    SAML1MD_NS = "urn:oasis:names:tc:SAML:profiles:v1metadata"
    
    # SAML 1 Metadata extension schema system Id.
    SAML1MD_SCHEMA_LOCATION = SCHEMA_DIR + "sstc-saml1x-metadata.xsd"
    
    # SAML 1 Metadata extension namespace prefix.
    SAML1MD_PREFIX = "saml1md"
    
    # URI for SAML 1 Artifact binding.
    SAML1_ARTIFACT_BINDING_URI = \
        "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01"
    
    # URI for SAML 1 POST binding.
    SAML1_POST_BINDING_URI = \
        "urn:oasis:names:tc:SAML:1.0:profiles:browser-post"
    
    # URI for SAML 1 SOAP 1.1 binding.
    SAML1_SOAP11_BINDING_URI = \
        "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding"
    
    #    SAML 2.0
    
    # SAML 2.0 Assertion schema Id.
    SAML20_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-assertion-2.0.xsd"
    
    # SAML 2.0 Assertion XML Namespace.
    SAML20_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
    
    # SAML 2.0 Assertion QName prefix.
    SAML20_PREFIX ="saml"
    
    # SAML 2.0 Protocol schema Id.
    SAML20P_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-protocol-2.0.xsd"
    
    # SAML 2.0 Protocol XML Namespace.
    SAML20P_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
    
    # SAML 2.0 Protocol QName prefix.
    SAML20P_PREFIX ="samlp"
    
    # SAML 2.0 Protocol Third-party extension schema Id.
    SAML20PTHRPTY_SCHEMA_LOCATION = SCHEMA_DIR + \
                                    "sstc-saml-protocol-ext-thirdparty.xsd"
    
    # SAML 2.0 Protocol XML Namespace.
    SAML20PTHRPTY_NS = "urn:oasis:names:tc:SAML:protocol:ext:third-party"
    
    # SAML 2.0 Protocol QName prefix.
    SAML20PTHRPTY_PREFIX ="thrpty"
    
    # SAML 2.0 Metadata schema Id.
    SAML20MD_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-metadata-2.0.xsd"
    
    # SAML 2.0 Metadata XML Namespace.
    SAML20MD_NS ="urn:oasis:names:tc:SAML:2.0:metadata"
    
    # SAML 2.0 Standalone Query Metadata extension XML namespace.
    SAML20MDQUERY_NS = "urn:oasis:names:tc:SAML:metadata:ext:query"
    
    # SAML 2.0 Standalone Query Metadata extension schema system Id.
    SAML20MDQUERY_SCHEMA_LOCATION = SCHEMA_DIR + \
                                    "sstc-saml-metadata-ext-query.xsd"
    
    # SAML 2.0 Standalone Query Metadata extension prefix.
    SAML20MDQUERY_PREFIX = "query"
    
    # SAML 2.0 Metadata QName prefix.
    SAML20MD_PREFIX = "md"
    
    # SAML 2.0 Authentication Context schema Id.
    SAML20AC_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-authn-context-2.0.xsd"
    
    # SAML 2.0 Authentication Context XML Namespace.
    SAML20AC_NS ="urn:oasis:names:tc:SAML:2.0:ac"
    
    # SAML 2.0 Authentication Context QName prefix.
    SAML20AC_PREFIX = "ac"
    
    # SAML 2.0 Enhanced Client/Proxy SSO Profile schema Id.
    SAML20ECP_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-ecp-2.0.xsd"
    
    # SAML 2.0 Enhanced Client/Proxy SSO Profile XML Namespace.
    SAML20ECP_NS = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
    
    # SAML 2.0 Enhanced Client/Proxy SSO Profile QName prefix.
    SAML20ECP_PREFIX = "ecp"
    
    # SAML 2.0 DCE PAC Attribute Profile schema Id.
    SAML20DCE_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-dce-2.0.xsd"
    
    # SAML 2.0 DCE PAC Attribute Profile XML Namespace.
    SAML20DCE_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE"
    
    # SAML 2.0 DCE PAC Attribute Profile QName prefix.
    SAML20DCE_PREFIX = "DCE"
    
    # SAML 2.0 X.500 Attribute Profile schema Id.
    SAML20X500_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-x500-2.0.xsd"
    
    # SAML 2.0 X.500 Attribute Profile XML Namespace.
    SAML20X500_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"
    
    # SAML 2.0 X.500 Attribute Profile QName prefix.
    SAML20X500_PREFIX = "x500"
    
    # SAML 2.0 XACML Attribute Profile schema Id.
    SAML20XACML_SCHEMA_LOCATION = SCHEMA_DIR + "saml-schema-xacml-2.0.xsd"
    
    # SAML 2.0 XACML Attribute Profile XML Namespace.
    SAML20XACML_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML"
    
    # SAML 2.0 XACML Attribute Profile QName prefix.
    SAML20XACML_PREFIX = "xacmlprof"
    
    # URI for SAML 2 Artifact binding.
    SAML2_ARTIFACT_BINDING_URI = \
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
    
    # URI for SAML 2 POST binding.
    SAML2_POST_BINDING_URI = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    
    # URI for SAML 2 POST-SimpleSign binding.
    SAML2_POST_SIMPLE_SIGN_BINDING_URI = \
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
    
    # URI for SAML 2 HTTP redirect binding.
    SAML2_REDIRECT_BINDING_URI = \
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    
    # URI for SAML 2 SOAP binding.
    SAML2_SOAP11_BINDING_URI = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
  
    
class QName(object):
    """XML Qualified Name""" 

    def __init__(self, namespaceURI, localPart, prefix):
        self.namespaceURI = namespaceURI
        self.localPart = localPart
        self.prefix = prefix
    
    def _getPrefix(self):
        return self.__prefix

    def _setPrefix(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "prefix"; got %r' %
                            type(value))
        self.__prefix = value
    
    prefix = property(_getPrefix, _setPrefix, None, "Namespace Prefix")

    def _getLocalPart(self):
        return self.__localPart
    
    def _setLocalPart(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "localPart"; got %r' %
                            type(value))
        self.__localPart = value
        
    localPart = property(_getLocalPart, _setLocalPart, None, "LocalPart")

    def _getNamespaceURI(self):
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "namespaceURI"; got %r' %
                            type(value))
        self.__namespaceURI = value
  
    namespaceURI = property(_getNamespaceURI, _setNamespaceURI, None, 
                            "Namespace URI")

    def __eq__(self, qname):
        """Enable equality check for QName
        @type qname: saml.common.xml.QName
        @param qname: Qualified Name to compare with self 
        """
        if not isinstance(qname, QName):
            raise TypeError('Expecting %r; got %r' % (QName, type(qname)))
                            
        return (self.prefix, self.namespaceURI, self.localPart) == \
               (qname.prefix, qname.namespaceURI, qname.localPart)

    def __ne__(self, qname):
        """Enable equality check for QName
        @type qname: saml.common.xml.QName
        @param qname: Qualified Name to compare with self 
        """
        return not self.__eq__(qname)
