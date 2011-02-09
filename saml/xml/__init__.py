"""Implementation of SAML 2.0 for NDG Security - XML package

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
import logging
log = logging.getLogger(__name__)
   
class XMLConstants(object):
    '''XML related constants.'''

    # XML Tooling

    # Configuration namespace
    XMLTOOLING_CONFIG_NS = "http://www.opensaml.org/xmltooling-config"

    # Configuration namespace prefix
    XMLTOOLING_CONFIG_PREFIX = "xt"
    
    # Name of the object provider used for objects that don't have a registered
    # object provider
    XMLTOOLING_DEFAULT_OBJECT_PROVIDER = "DEFAULT"

    # Core XML

    # XML core namespace
    XML_NS = "http://www.w3.org/XML/1998/namespace"
    
    # XML core prefix for xml attributes
    XML_PREFIX = "xml"

    # XML namespace for xmlns attributes
    XMLNS_NS = "http://www.w3.org/2000/xmlns/"

    # XML namespace prefix for xmlns attributes
    XMLNS_PREFIX = "xmlns"

    # XML Schema namespace
    XSD_NS = "http://www.w3.org/2001/XMLSchema"

    # XML Schema QName prefix
    XSD_PREFIX = "xs"

    # XML Schema Instance namespace
    XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

    # XML Schema Instance QName prefix
    XSI_PREFIX = "xsi"

    # XML XMLSecSignatureImpl namespace
    XMLSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

    # XML XMLSecSignatureImpl QName prefix
    XMLSIG_PREFIX = "ds"

    # XML Encryption namespace
    XMLENC_NS = "http://www.w3.org/2001/04/xmlenc#"

    # XML Encryption QName prefix
    XMLENC_PREFIX = "xenc"
    
    # Local name of EncryptedData element
    XMLENC_ENCDATA_LOCAL_NAME = "EncryptedData"
    
    # Local name of EncryptedKey element
    XMLENC_ENCKEY_LOCAL_NAME = "EncryptedKey"


class XMLTypeError(Exception):
    pass

class XMLTypeParseError(XMLTypeError):
    pass

class UnknownAttrProfile(XMLTypeError):
    """Raise from Attribute Value factory if attribute type is not recognised
    """