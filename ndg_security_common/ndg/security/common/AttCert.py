"""NDG Attribute Certificate (Authorisation -or Access- Token)

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "05/04/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import types
import os
import re
import copy

# XML Parsing

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

# Time module for use with validity times
from time import strftime, strptime
from datetime import datetime, timedelta

# XML signature module based on M2Crypto, ZSI Canonicalization and DOM
import sys
import warnings
if sys.version_info[:2] < (2, 5, 5):
    from XMLSec import XMLSecDoc, InvalidSignature
else:
    msg = ("ndg.security.common.XMLSec not supported for Python versions 2.5.5 "
           "or later because of PyXML incompatibility")
    warnings.warn(msg)
    class XMLSecDoc(object):
        "XMLSecDoc Stub class: %s" % msg
        def __init__(self):
            self.filePath = None
            
        def parse(self, *arg):
            "XMLSecDoc Stub class parse: %s" % msg
        
        def applyEnvelopedSignature(self, **kw):
            "XMLSecDoc Stub class - no signature applied: %s" % msg
       
        def verifyEnvelopedSignature(self, **kw):
            "XMLSecDoc Stub class - no verification executed: %s" % msg
        
        def toString(self):
            "XMLSecDoc Stub class toString returns None: %s" % msg
            return None
        
    class InvalidSignature(Exception):
        "XMLSecDoc.InvalidSignature Stub class: %s" % msg
        
from X509 import X500DN
from X509 import X500DNError


class AttCertError(Exception):  
    """Exception handling for NDG Attribute Certificate class."""

class AttCertInvalidSignature(AttCertError):
    """Error with certificate signature"""
    
class AttCertNotBeforeTimeError(AttCertError):
    """Current time is before the Attribute Certificate's not before time"""

class AttCertExpired(AttCertError):
    """Current time is after the Attribute Certificate's not after time"""

class AttCertReadOnlyDict(dict):
    def __init__(self, inputDict):
        super(AttCertReadOnlyDict, self).__init__(inputDict)
        
    def __setitem__(self, key, item):
        raise KeyError("Items are read-only in this dictionary")
       
class _MetaAttCert(type):
    """Enable AttCert to have read only class variables e.g.
    
    print AttCert.mappedProvenance is allowed but,
    
    AttCert.mappedProvenance = None
    
    ... raises - AttributeError: can't set attribute"""
    
    def __getVersion(cls):
        '''Version of THIS format for the certificate'''
        return '1.0'

    version = property(fget=__getVersion, 
                       doc="Version of the certificate format")
   
    #_________________________________________________________________________    
    def __getMappedProvenance(cls):
        '''Text for mapped provenance setting of certificate'''
        return 'mapped'

    mappedProvenance = property(fget=__getMappedProvenance,
        doc="Text constant indicating cert has mapped roles from another")

    #_________________________________________________________________________    
    def __getOriginalProvenance(cls):
        '''Text for original provenance setting of certificate'''
        return 'original'
    
    origProvenance = property(fget=__getOriginalProvenance,
        doc="Text constant indicating cert has original and not mapped roles")
    
    
#_____________________________________________________________________________
class AttCert(dict, XMLSecDoc):
    """NDG Attribute Certificate (Authorisation or Access Token).
    
    @type __validProvenanceSettings: tuple
    @cvar __validProvenanceSettings: string constants for allowable certificate provenance settings
    
    @type namespace: string
    @cvar namespace: namespace for Attribute Certificate"""
    
    __metaclass__ = _MetaAttCert

    # Provenance of certificate may be original or mapped from another
    # certificate
    __validProvenanceSettings = ('original', 'mapped')
    namespace = "urn:ndg:security:attributeCertificate"

    #_________________________________________________________________________    
    def __init__(self, provenance='original', lifetime=28800, **xmlSecDocKw):
        """Initialisation - Attribute Certificate file path may be specified.
        Also, holder and issuer details and signing authority key and
        certificate.
        
        @type lifetime: int
        @param lifetime: set the lifetime for the certificate in seconds.
        Defaults to 8 hours.
        
        @type **xmlSecDocKw: dict
        @param **xmlSecDocKw: see XMLSec.XMLSec class for an explanation.
        Keywords include, filePath for the cert. for reading/writing and
        cert./private key settings for digital signature and verification."""

        # Base class initialisation
        dict.__init__(self)
        XMLSecDoc.__init__(self, **xmlSecDocKw)

        #: Data dictionary version of xml
        #:
        #: Nb. RoleSet is an empty list - it will be filled role dictionary
        #: items [{'role': {'name': '<Name>'}}, ... ]
        self.__dat = {
            
            "version":            AttCert.version,
            "holder":             '',
            "issuer":             '',
            "issuerName":         '',
            "issuerSerialNumber": 0,
            "userId":             '',
            "validity":           {"notBefore": '', "notAfter": ''},
            "attributes":         {"roleSet": []},
            "provenance":         ''
        }

        #: Holder X500DN object - instantiated in read method
        self.__issuerDN = None
        #: issuer X500DN object - instantiated in read method
        self.__holderDN = None

        self.__setProvenance(provenance)
        
        #: Certificate life time interval in seconds
        self.__lifetime = lifetime
        
        #: Certificate not before time as datetime type
        self.__dtNotBefore = None
        
        #: Certificate not after time as a datetime type
        self.__dtNotAfter = None


    #_________________________________________________________________________    
    def __repr__(self):
        """Override default behaviour to return internal dictionary content"""
        return str(self.__dat)


    #_________________________________________________________________________    
    def __str__(self):
        """Override XMLSec.XMLSecDoc equivalent"""
        return self.toString()
    
    
    #_________________________________________________________________________
    def toString(self, **kw):
        """Return certificate file content as a string
        
        @param **kw: keywords to XMLSec.XMLSecDoc.toString()
        @rtype: string
        @return: content of document"""

        # If doc hasn't been parsed by parent (ie. not signed) return elements
        # set so far using createXML method
        return super(AttCert, self).toString(**kw) or self.createXML()

                
    #_________________________________________________________________________    
    def __delitem__(self, key):
        "Attribute Certificate keys cannot be removed"
        
        raise AttCertError, 'Keys cannot be deleted from ' + \
                           self.__class__.__name__


    #_________________________________________________________________________    
    def __getitem__(self, key):
        """Get an item from the __dat, __dat['validity'] or 
        __dat['attributes'] dictionaries.  This class behaves as data 
        dictionary of Attribute Certificate properties

        @param key: name of key - key can be specified belonging to validity
        or the attributes sub dictionaries
        @param item: value to set dictionary item to
        """
        
        # Check input key
        if key in self.__dat:

            # key recognised
            item = self.__dat[key]                

        elif key in self.__dat['validity']:

            # Allow indexing via validity keys - a shorthand way of 
            # referencing for convenience
            item = self.__dat['validity'][key]

        elif key in self.__dat['attributes']:

            # Allow indexing via attributes keys - a shorthand way of 
            # referencing for convenience
            item = self.__dat['attributes'][key]

        else:
            # key not recognised as a short or long name version
            raise KeyError, 'Key "%s" not recognised for %s' % \
                               (key, self.__class__.__name__)

        if isinstance(item, dict):
            return AttCertReadOnlyDict(item)
        else:
            return item


    #_________________________________________________________________________    
    def __setitem__(self, key, item):        
        """Set an item from the __dat dictionary.  This class behaves as data 
        dictionary of Attribute Certificate properties

        @type key: string
        @param key: name of key - key can be specified belonging to validity
        or the attributes sub dictionaries
        
        @type item: string / int
        @param item: value to set dictionary item to
        """

        # Check input key
        if key in self.__dat:

            # key recognised - check if setting provenance
            if key == "provenance":
                self.__setProvenance(item)
                
            elif key == "version":
                self.__setVersion(item)
                 
            elif key == "holder":
                self.__setHolder(item)
                
            elif key == "issuer":
                self.__setIssuer(item)
            
            elif key == "issuerName":
                self.__setIssuerName(item)
            
            elif key == "issuerSerialNumber":
                self.__setIssuerSerialNumber(item)
         
            elif key == "userId":
                self.__setUserId(item)
                   
            elif key == "validity":
                raise KeyError, "'%s': use setValidityTime method " % \
                    key + "to set notBefore/notAfter times"
                            
            elif key == "attributes":
                raise KeyError, "'%s': use addRoles method to " % \
                    key + "set list of role attributes"            
            else:    
                raise KeyError, "Key '%s' not recognised for %s'" % \
                               (key, self.__class__.__name__)

        elif key in self.__dat['attributes'] or \
             key in self.__dat['attributes']['roleSet']:

            # To complex to allow direct setting here
            raise KeyError, "'%s': use addRoles method to " % key + \
                            "set list of roles"            

        elif key in self.__dat['validity']:
            # Prevent setting of notBefore/notAfter - restrict to method
            # setValidityTime
            raise KeyError, "'%s': use setValidityTime method " % key + \
                            "to set notBefore/notAfter times"            
        else:
            # key not recognised as a short or long name version
            raise KeyError, "Key '%s' not recognised for %s'" % \
                               (key, self.__class__.__name__)
        

    #_________________________________________________________________________    
    def __eq__(self, attCert):
        """Return true if all elements are the same"""        
        try:
            return min([self.__dat[key] == attCert[key] \
                       for key in self.__dat.keys()])
        except:
            return False
        

    #_________________________________________________________________________    
    def __nonzero__(self):
        """Ensure if <attCertInstance> test yields True"""
        return True
    
    
    #_________________________________________________________________________    
    def clear(self):
        raise AttCertError, "Data cannot be cleared from " + \
                           self.__class__.__name__

    
    #_________________________________________________________________________    
    def copy(self):
        return copy.copy(self)

    
    #_________________________________________________________________________    
    def keys(self):
        return self.__dat.keys()

    #_________________________________________________________________________    
    def items(self):
        return self.__dat.items()

    #_________________________________________________________________________    
    def values(self):
        return self.__dat.values()

    #_________________________________________________________________________    
    def has_key(self, key):
        return self.__dat.has_key(key)

    # 'in' operator
    #_________________________________________________________________________    
    def __contains__(self, key):
        return key in self.__dat


    #
    # Get/Set methods
    #
    # Nb. it's also possible to access the data dictionary parameters via
    # __setitem__ and __getitem__ standard dictionary methods
    #
    #_________________________________________________________________________    
    def __setVersion(self, version):
        """Set the version number to be written to file."""        
        self.__dat['version'] = version
    
    #_________________________________________________________________________    
    def __getVersion(self):
        """Get version number as set in file."""
        return self.__dat['version']

    version = property(fget=__getVersion,
                       fset=__setVersion, 
                       doc="Attribute Certificate version")
    
    #_________________________________________________________________________    
    def __setHolder(self, holder):
        """Set holder's Distinguished Name string."""
        if not isinstance(holder, basestring):
            raise TypeError("holder DN must be a string")

        self.__dat['holder'] = holder
    
    #_________________________________________________________________________    
    def __getHolder(self):
        """Get holder's Distinguished Name string."""
        return self.__dat['holder']

    holder = property(fget=__getHolder,
                      fset=__setHolder, 
                      doc="Attribute Certificate holder DN")

    #_________________________________________________________________________    
    def __getHolderDN(self):
         """Get the holder's Distinguished Name as an X500DN instance"""
         return self.__holderDN
     
    holderDN = property(fget=__getHolderDN,
                        doc="Attribute Certificate holder DN as X500DN type")
    
    #_________________________________________________________________________    
    def __setIssuer(self, issuer):
        """Set issuer's Distinguished Name."""
        if not isinstance(issuer, basestring):
            raise TypeError("issuer DN must be a string")
        
        self.__dat['issuer'] = issuer
    
    #_________________________________________________________________________    
    def __getIssuer(self):
        """Get the issuer's Distinguished Name string"""
        return self.__dat['issuer']

    issuer = property(fget=__getIssuer, 
                      fset=__setIssuer,
                      doc="Certificate Issuer DN")

    #_________________________________________________________________________    
    def __getIssuerDN(self):
         """Get the issuer's Distinguished Name as an X500DN instance"""
         return self.__issuerDN
     
    issuerDN = property(fget=__getIssuerDN,
                        doc="Attribute Certificate issuer DN as X500DN type")
        
    #_________________________________________________________________________    
    def __setIssuerName(self, issuerName):
        """Set the name of the issuer"""
        if not isinstance(issuerName, basestring):
            raise TypeError("issuerName must be a string")
        
        self.__dat['issuerName'] = issuerName
    
    #_________________________________________________________________________    
    def __getIssuerName(self):
        """@rtype: string
        @return: the name of the issuer"""
        return self.__dat['issuerName']

    issuerName = property(fget=__getIssuerName, 
                          fset=__setIssuerName,
                          doc="Certificate Issuer name")
   
    #_________________________________________________________________________    
    def __setIssuerSerialNumber(self, serialNumber):
        """@param serialNumber: the issuer serial number"""
        if not isinstance(serialNumber, (int, long)):
            raise TypeError("issuerSerialNumber must be an integer or a long")

        self.__dat['issuerSerialNumber'] = serialNumber
    
    #_________________________________________________________________________    
    def __getIssuerSerialNumber(self):
        """@rtype: string
        @return: the issuer serial number"""
        return self.__dat['issuerSerialNumber']
    
    issuerSerialNumber = property(fget=__getIssuerSerialNumber, 
                                  fset=__setIssuerSerialNumber,
                                  doc="Certificate Issuer Serial Number")
 
        
    #_________________________________________________________________________    
    def __setUserId(self, userId):
        """Set the name of the userId
        @type userId: string
        @param userId: user identifier"""
        if not isinstance(userId, basestring):
            raise TypeError("userId must be a string")
        
        self.__dat['userId'] = userId
    
    #_________________________________________________________________________    
    def __getUserId(self):
        """@rtype: string
        @return: the user idenitifier"""
        return self.__dat['userId']

    userId = property(fget=__getUserId, 
                      fset=__setUserId,
                      doc="Certificate user identifier")
    

    # Nb. no setValidityNotBefore/setValidityNotAfter methods - use
    # setValidityTime instead.
    
    #_________________________________________________________________________    
    def getValidityNotBefore(self, asDatetime=False):
        """Get the validity Not Before date/time string

        @param asDatetime: boolean to True to return as a datetime type
        Nb. time may not have been set - if so it will be set to None
        
        @rtype: string/datetime
        @return: the not before time"""
        if asDatetime is True:
            return self.__dtNotBefore
        else:
            return self.__dat['validity']['notBefore']

    validityNotBefore = property(fget=getValidityNotBefore, 
                                  doc="Validity not before time as a string")


    #_________________________________________________________________________    
    def getValidityNotAfter(self, asDatetime=False):
        """Get the validity Not After date/time string

        @param asDatetime: boolean set to True to return as a datetime type
        Nb. time may not have been set - if so it will be set to None
        
        @rtype: string/datetime
        @return: the not after time"""
        if asDatetime is True:
            return self.__dtNotAfter
        else:
            return self.__dat['validity']['notAfter']

    validityNotAfter = property(fget=getValidityNotAfter, 
                                doc="Validity not after time as a string")

    
    #_________________________________________________________________________    
    def __getRoleSet(self):
        """@rtype: list of dict type
        @return: the roleSet as a list of role dictionaries."""
        return self.__dat['attributes']['roleSet']

    roleSet = property(fget=__getRoleSet, 
                       doc="Role set dictionary")

    #_________________________________________________________________________    
    def __getRoles(self):
        """Return roles as a list
        
        @rtype: list
        @return: list of roles contained in the certificate"""
        
        try:
            return [i.values()[0].values()[0] \
                    for i in self.__dat['attributes']['roleSet']]
        except:
            return []
        
    roles = property(fget=__getRoles, 
                     doc="List of roles in Attribute Certificate")

        
    #_________________________________________________________________________    
    def __setProvenance(self, provenance):
        """Set the provenance for the certificate: 'original' or 'mapped'.
        
        @param provenance: string provenance setting"""

        if not self.isValidProvenance(provenance):
            raise AttCertError, "Provenance must be set to \"" + \
                   "\" or \"".join(AttCert.__validProvenanceSettings) + "\""
        
        self.__dat['provenance'] = provenance

    
    #_________________________________________________________________________    
    def __getProvenance(self):
        """Get the provenance for the certificate.
        
        @rtype: string
        @return: provenance of certificate mapped or original"""
        return self.__dat['provenance']

    provenance = property(fget=__getProvenance,
                          fset=__setProvenance, 
                          doc="Provenance of the cert. - original or mapped")
   

    #_________________________________________________________________________    
    def isValidProvenance(self, provenance=None):
        """Check provenance is set correctly - to 'original'/'mapped'.

        If no provenance argument is provided, test against the setting in
        the current instance.
        
        @param provenance: by default the current provenance setting is 
        checked i.e. self.__dat['provenance'].  Set this keyword to override
        and check against an alternate provenance setting.
        
        @rtype: bool
        @return: True if certificate has a valid provenance setting
        """
        
        if not provenance:
            provenance = self.__dat['provenance']

        return provenance in AttCert.__validProvenanceSettings
        

    #_________________________________________________________________________    
    def isOriginal(self):
        """Check for original provenance.
        @rtype: bool
        @return: True if certificate has original roles"""
        return self.__dat['provenance'] == self.__class__.origProvenance


    #_________________________________________________________________________    
    def isMapped(self):
        """Check for mapped provenance.
        @rtype: bool
        @return: True if certificate contain roles mapped from another"""
        return self.__dat['provenance'] == self.__class__.mappedProvenance


    #_________________________________________________________________________    
    def addRoles(self, roleName):
        """Add new roles to the roleSet in attributes.
        
        @param roleName: role name or list of role names to add to certificate
        """

        if isinstance(roleName, basestring):
            roleName = [roleName]
            
        self.__dat['attributes']['roleSet'].extend(\
                                [{'role': {'name': i}} for i in roleName])


    #_________________________________________________________________________    
    def parse(self, xmlTxt, rtnRootElem=False):
        """Parse an Attribute Certificate content contained in string input

        @param xmlTxt:     Attribute Certificate XML content as string
        @param rtnRootElem: boolean set to True to return the ElementTree
        root element
        
        @rtype: ElementTree root element
        @return: root element if rtnRootElem keyword is set to True"""
        
        rootElem = ElementTree.XML(xmlTxt)

        # Call generic ElementTree parser
        self.__parse(rootElem)


        # Call base class parser method to initialise DOM objects for
        # signature validation
        try:
            XMLSecDoc.parse(self, xmlTxt)

        except Exception, e:
            raise AttCertError, "Attribute Certificate: %s" % e

        if rtnRootElem:
            return rootElem

        
    #_________________________________________________________________________    
    def read(self, filePath=None, **xmlSecDocKw):
        """Read an Attribute Certificate from file

        @param filePath:   file to be read, if omitted XMLSecDoc.__filePath 
        member variable is used instead"""

        if filePath:
            self.filePath = filePath

        try:    
            tree = ElementTree.parse(self.filePath)
            rootElem = tree.getroot()
        except Exception, e:
            raise AttCertError, "Attribute Certificate: %s" % e
        
        # Call generic ElementTree parser
        self.__parse(rootElem)

        # Call base class read method to initialise libxml2 objects for
        # signature validation
        try:
            XMLSecDoc.read(self, **xmlSecDocKw)

        except Exception, e:
            raise AttCertError, "Attribute Certificate: %s" % e

        
    #_________________________________________________________________________    
    def __parse(self, rootElem):
        """Private XML parsing method accepts a ElementTree.Element type
        as input

        @param rootElem: root element of doc - ElementTree.Element type
        """
        
        # Extract from acInfo tag
        acInfoElem = rootElem.find("acInfo")
        
        if not acInfoElem:
            raise AttCertError, "<acInfo> tag not found in \"%s\"" % \
                               self.filePath


        # Copy all acInfo tags into dictionary
        for elem in acInfoElem:
            if elem.tag not in self.__dat:
                raise AttCertError, '%s: "<%s>" not recognised.' % \
                                    (self.filePath, elem.tag)

            # Make sure not to copy validity and attributes tags - handle 
            # these separately below
            if not elem.getchildren():
                self.__dat[elem.tag] = elem.text

        # Convert issuer and holder into X500DN instances
        try:
            self.__issuerDN = X500DN(dn=self.__dat['issuer'])

        except X500DNError, x500dnErr:
            raise AttCertError, "Issuer DN: %s" % x500dnErr


        try:
            self.__holderDN = X500DN(dn=self.__dat['holder'])
        except IndexError:
            warnings.warn("Error parsing Attribute Certificate holder as an "
                          "X.500 DN, treating as a regular string instead")
            self.__holderDN = None
            
        except X500DNError, x500dnErr:
            raise AttCertError, "Holder DN: %s" % x500dnErr
        
                                 
        # Extract validity and attributes subsets
        self.__dat['validity']['notBefore'] = \
                                rootElem.findtext("acInfo/validity/notBefore")
        
        if self.__dat['validity']['notBefore'] is None:
            raise AttCertError, "<notBefore> tag not found in \"%s\"" % \
                                                               self.filePath
        elif self.__dat['validity']['notBefore'] == '':
            
            # Allow empty string setting but re-initialise corresponding 
            # datetime value
            self.__dtNotBefore = None
        else:
            # Update datetime object equivalent
            self.__dtNotBefore = self.timeStr2datetime(\
                                        self.__dat['validity']['notBefore'])

        
        self.__dat['validity']['notAfter'] = \
                                rootElem.findtext("acInfo/validity/notAfter")
        
        if self.__dat['validity']['notAfter'] is None:
            raise AttCertError, '<notAfter> tag not found in "%s"' % \
                               self.filePath
        elif self.__dat['validity']['notBefore'] == '':
            
            # Allow empty string setting but re-initialise corresponding 
            # datetime value
            self.__dtNotAfter = None
        else:
            # Update datetime object equivalent
            self.__dtNotAfter = self.timeStr2datetime(\
                                        self.__dat['validity']['notAfter'])

        # set up role list
        roleElem = acInfoElem.findall("attributes/roleSet/role/name")
        if roleElem is None:
            raise AttCertError, "<role> tag not found in \"%s\"" % \
                               self.filePath
        
        self.__dat['attributes']['roleSet'] = \
                                [{'role': {'name': i.text}} for i in roleElem]
                    
        
        if not self.isValidVersion():           
            raise AttCertError, 'Attribute Certificate version is ' + \
                               self.__dat['version'] + ' but version ' + \
                               AttCert.version + ' expected'


    #_________________________________________________________________________    
    def createXML(self):
        """Create XML for Attribute Token from current data settings and
        return as a string.  The XML created is MINUS the digital signature.
        To obtain the signed version, run the applyEnvelopedSignature method 
        (inherited from XMLSecDoc) and pass the attCert object reference into 
        str()

        @rtype: string
        @return: formatted XML for certificate as a string"""

        # Nb.
        # * this method is used by AttCert.read()
        # * Signing by Attribute Authority is separate - see AttCert.sign()
        

        # Check for valid provenance
        if not self.isValidProvenance():
            raise AttCertError, "Provenance must be set to \"" + \
                   "\" or \"".join(AttCert.__validProvenanceSettings) + "\""

        
        # Create string of all XML content  
        try:      
            xmlTxt = '<attributeCertificate targetNamespace="%s">' % \
                                                self.__class__.namespace + \
"""
    <acInfo>
        <version>""" + self.__dat['version'] + """</version>
        <holder>""" + self.__dat['holder'] + """</holder>
        <issuer>""" + self.__dat['issuer'] + """</issuer>
        <issuerName>""" + self.__dat['issuerName'] + """</issuerName>
        <issuerSerialNumber>""" + str(self.__dat['issuerSerialNumber']) +\
            """</issuerSerialNumber> 
        <userId>""" + self.__dat['userId'] + """</userId>
	<validity>
  	    <notBefore>""" + self.__dat['validity']['notBefore'] + \
  	    """</notBefore> 
	    <notAfter>""" + self.__dat['validity']['notAfter'] + \
	    """</notAfter> 
	</validity>
	<attributes>
	    <roleSet>
            """ + "".join([\
"""    <role>
	    	    <name>""" + i['role']['name'] + """</name>
		</role>
	    """ for i in self.__dat['attributes']['roleSet']]) + \
	    """</roleSet>
	</attributes>
	<provenance>""" + self.__dat['provenance'] + """</provenance> 
    </acInfo>
</attributeCertificate>"""
        except:
            return ''

        # Return XML file content as a string
        return xmlTxt


    def applyEnvelopedSignature(self, **xmlSecDocKw):
        '''Override super class version to ensure settings have been parsed 
        into a DOM object ready for signature
        
        @param **xmlSecDocKw: keywords applying to 
        XMLSecDoc.applyEnvelopedSignature()
        '''       
        self.parse(self.createXML())
        super(AttCert, self).applyEnvelopedSignature(**xmlSecDocKw)

       
    def setValidityTime(self,
                        dtNotBefore=None, 
                        dtNotAfter=None, 
                        lifetime=None,
                        notBeforeOffset=None):
        """Set the notBefore and notAfter times which determine the window for
        which the Attribute Certificate is valid.  These times are set as
        datetime types and also the correct string format settings are made 
        ready for output.

        Nb. use UTC time.  lifetime and notBeforeOffset are in seconds
        
        @param dtNotBefore: not before time as datetime type.  If omitted,
        it defaults to the current time
        
        @param dtNotAfter: not after time as datetime type.  Defaults to 
        self.__dtNotBefore + self.__lifetime.  If dtNotAfter is set it will
        reset self.__lifetime to self.__dtNotAfter - self.dtNotBefore
        
        @param lifetime: lifetime for certificate in seconds i.e. not after
        time - not before time.  If dtNotAfter is set then this keyword will
        be ignored.
        
        @param notBeforeOffset: skew the not before time by some offset.  This
        is useful in cases where system clocks are not correctly synchronized
        between different hosts.  Set a negative value to skew the offset
        backward in time.
        """

        if dtNotBefore is not None:
            if not isinstance(dtNotBefore, datetime):
                raise AttCertError, \
                                "Input not before time must be datetime type"
            
            self.__dtNotBefore = dtNotBefore
            
        else:
            # Use current UTC +/- offset
            self.__dtNotBefore = datetime.utcnow()
            
        if notBeforeOffset is not None:
            self.__dtNotBefore += timedelta(seconds=notBeforeOffset)
            

        if dtNotAfter is not None:
            if not isinstance(dtNotAfter, datetime):
                raise AttCertError, \
                                "Input not after time must be datetime type"

            # Use input Not After time to calculate a new lifetime setting
            dtDeltaLifeTime = dtNotAfter - self.__dtNotBefore
            if dtDeltaLifeTime < timedelta(0):
                raise AttCertError, "Input Not After time is invalid %s" % \
                                   str(dtNotAfter)

            self.__lifetime = dtDeltaLifeTime.days*86400 + \
                              dtDeltaLifeTime.seconds

            self.__dtNotAfter = dtNotAfter
            
        else:
            # Check for input certificate life time interval
            if lifetime is not None:
                self.__lifetime = lifetime
                
            try:
                # Make a time delta object from the lifetime expressed in
                # seconds
                dtDeltaLifeTime = timedelta(seconds=self.__lifetime)
            except Exception, e:
                raise AttCertError("Invalid Certificate lifetime set %.3f" %
                                   self.__lifetime)
            
            # Add certificate lifetime to calculate not after time
            self.__dtNotAfter = self.__dtNotBefore + dtDeltaLifeTime

        
        self.__dat['validity']['notBefore'] = \
                                    self.datetime2timeStr(self.__dtNotBefore)
        
        self.__dat['validity']['notAfter'] = \
                                    self.datetime2timeStr(self.__dtNotAfter)


    #_________________________________________________________________________    
    def datetime2timeStr(self, dtVal):
        """Convert a datetime object to a notBefore/notAfter time string
        
        @param dtVal: input datetime
        
        @rtype: string
        @return: datetime converted into correct string format for AttCert"""

        if not isinstance(dtVal, datetime):
            raise AttCertError, \
                        "Invalid datetime object for conversion to string"
        
        # Convert from 1-12 to 0-11 month format used in XML file
        #lDateTime = list(dtVal.utctimetuple()[0:6])

        #lDateTime[1] -= 1

        # Format as a single string with no commas or brackets
        #return ''.join(re.findall('[0-9 ]', str(lDateTime)))

        # Use 1-12 format
        # P J Kershaw 09/06/05
        return dtVal.strftime("%Y %m %d %H %M %S")


    #_________________________________________________________________________    
    def timeStr2datetime(self, sTime):
        """Convert a notBefore/notAfter time string to a datetime object
        
        @param sTime: time in string format as used by AttCert
        @rtype: datetime
        @return: datetime type equivalent of string input"""

        try:
            lTime = strptime(sTime, "%Y %m %d %H %M %S")
            return datetime(*lTime[0:6])
        
        except Exception, e:
            raise AttCertError, \
                "Error converting time string into datetime object: %s" % e
        

    #_________________________________________________________________________    
    def isValidTime(self, dtNow=None, raiseExcep=False):
        """Check Attribute Certificate for expiry.  Set raiseExcep to True
        to raise an exception with a message indicating the nature of the 
        time error
        
        @param dtNow: the time to test against in datetime format.  This time
        must be within the range of the not before and not after times in
        order for the certificate to be valid.  Defaults to the current 
        system time
        
        @param raiseExcep: boolean set to True to raise an exception if the 
        time is invalid.  Defaults to False in which case no exception is
        raised if the time is invalid, instead False is returned
        
        @rtype: bool
        @return: boolean True if time is valid, False if invalid.  Also see
        raiseExcep keyword above."""

        if not isinstance(self.__dtNotBefore, datetime):
            raise AttCertError, "Not Before datetime is not set"

        if not isinstance(self.__dtNotAfter, datetime):
            raise AttCertError, "Not After datetime is not set"
       
        if dtNow is None:
            dtNow = datetime.utcnow()
        
        # Testing only
        #
        # P J Kershaw 02/03/06
        #notBefore = self.__dtNotBefore
        #notAfter = self.__dtNotAfter
        #print "Valid Time? = %d" % (dtNow > notBefore and dtNow < notAfter)
        if raiseExcep:
            if dtNow < self.__dtNotBefore:
                raise AttCertError, "Current time %s " % \
                           dtNow.strftime("%d/%m/%Y %H:%M:%S") + \
                           "is before Attribute Certificate's " + \
                           "not before time of %s" % \
                           self.__dtNotBefore.strftime("%d/%m/%Y %H:%M:%S")
            
            if dtNow > self.__dtNotAfter:
                raise AttCertError, "Current time %s " % \
                           dtNow.strftime("%d/%m/%Y %H:%M:%S") + \
                           "is after Attribute Certificate's " + \
                           "expiry time of %s" % \
                           self.__dtNotBefore.strftime("%d/%m/%Y %H:%M:%S")                
            
            return True        
        else:
            return dtNow > self.__dtNotBefore and dtNow < self.__dtNotAfter
        
        
    def isValidVersion(self):
        """Check Attribute Certificate XML file version
        
        @rtype: bool
        @return: boolean True if certificate version matches the expected one,
        False otherwise.
        """
        return self.__dat['version'] == AttCert.version


    def isValid(self,
                raiseExcep=False,
                chkTime=True,
                chkVersion=True,
                chkProvenance=True,
                chkSig=True,
                **xmlSecDocKw):
        """Check Attribute Certificate is valid:

        - Time validity is OK
        - XML file version is OK
        - valid provenance setting
        - Signature is valid.

        @param chkTime: set to True to do time validity check (default is 
        True)

        @param chkVersion: set to True to Attribute Certificate file
        version (default is True)

        @param chkProvenance: set to True to check provenance value is valid
        (default is True)

        @param chkSig: set to True to check digital signature - for
        this certFilePathList must contain the root certificate of the X.509 
        certificate used to sign the AttCert.  Alternatively, certFilePathList
        can be set via __init__ (default chkSig value is True)
                                
        @param raiseExcep: set to true to raise an exception if invalid 
        instead of returning False.  Default is to set this flag to False.

        @param **xmlSecDocKw: Also accepts keyword arguments corresponding to 
        XMLSecDoc.verifyEnvelopedSignature().
        
        @rtype: bool
        @return: boolean True if certificate is valid, False otherwise.  Also
        see explanation for raiseExcep keyword.                         
        """

        # Carry out checks in turn - Specific exception error messages are
        # raised if flag is set
        if chkTime and not self.isValidTime(raiseExcep=raiseExcep):
            return False

        if chkVersion and not self.isValidVersion():
            if raiseExcep:
                raise AttCertError('Attribute Certificate version is %s '
                                   'but version %s expected' %
                                   (self.__dat['version'], AttCert.version))
            return False

        if chkProvenance and not self.isValidProvenance():
            if raiseExcep:
                raise AttCertError('Attribute Certificate Provenance must be '
                                   'set to "%s"' % "\" or \"".join(
                                            AttCert.__validProvenanceSettings))
            return False

        # Handle exception from XMLSecDoc.isValidSig() regardless of
        # raiseExcep flag setting
        if chkSig:
            try:
                self.verifyEnvelopedSignature(**xmlSecDocKw)
        
            except InvalidSignature, e:
                 if raiseExcep:
                     raise AttCertInvalidSignature(e)
                 else:
                     return False
                
        # All tests passed
        return True

    @classmethod
    def Read(cls, filePath):
        """Create a new attribute certificate read in from a file"""
        attCert = cls(filePath=filePath)
        attCert.read()
        
        return attCert

    @classmethod
    def Parse(cls, attCertTxt):
        """Create a new attribute certificate from string of file content"""
        
        attCert = cls()
        attCert.parse(attCertTxt)
        
        return attCert
        
# Alternative AttCert constructors
def AttCertRead(filePath):
    """Create a new attribute certificate read in from a file"""
    
    attCert = AttCert(filePath=filePath)
    attCert.read()
    
    return attCert

def AttCertParse(attCertTxt):
    """Create a new attribute certificate from string of file content"""
    
    attCert = AttCert()
    attCert.parse(attCertTxt)
    
    return attCert
