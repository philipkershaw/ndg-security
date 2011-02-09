"""SAML 2.0 common package

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
  
class SAMLObject(object):
    """Base class for all SAML types"""
    @classmethod
    def fromXML(cls, xmlObject):
        '''Parse from an XML representation into a SAML object
        @type: XML class e.g. ElementTree or 4Suite XML
        @param: XML representation of SAML Object
        @rtype: saml.saml2.common.SAMLObject derived type
        @return: SAML object
        '''
        raise NotImplementedError()
    
    @classmethod
    def toXML(cls, samlObject):
        '''Convert the input SAML object into an XML representation
        @type: saml.saml2.common.SAMLObject derived type
        @param: SAML object
        @rtype: XML class e.g. ElementTree or 4Suite XML
        @return: XML representation of SAML Object
        '''
        raise NotImplementedError()


class SAMLVersion(SAMLObject):
    """Version helper class"""
    
    VERSION_10 = (1, 0)
    VERSION_11 = (1, 1)
    VERSION_20 = (2, 0)
    KNOWN_VERSIONS = (VERSION_10, VERSION_11, VERSION_20)
    
    def __init__(self, version):
        if isinstance(version, basestring):
            self.__version = SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            self.__version = tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version initialiser; got %r" % version)
    
    def __str__(self):
        return ".".join([str(i) for i in self.__version])
    
    def __eq__(self, version):
        """Test for equality against an input version string, tuple or list"""
                
        if isinstance(version, basestring):
            return self.__version == SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version == tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __ne__(self, version):
        return not self.__eq__(version)
            
    def __gt__(self, version):                
        if isinstance(version, basestring):
            return self.__version > SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version > tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __lt__(self, version):
        if isinstance(version, basestring):
            return self.__version < SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version < tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __ge__(self, version):                
        if isinstance(version, basestring):
            return self.__version >= SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version >= tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __le__(self, version):                
        if isinstance(version, basestring):
            return self.__version <= SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version <= tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
   
    @staticmethod
    def valueOf(version):
        """Parse input string into version tuple
        @type version: version
        @param version: SAML version
        @rtype: tuple
        @return: SAML version tuple"""
        return tuple([int(i) for i in version.split(".")])
