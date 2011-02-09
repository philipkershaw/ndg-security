"""NDG Attribute Certificate (Authentication -or Access- Token)

NERC Data Grid Project

P J Kershaw 05/04/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

reposID = '$Id$'

import types
import os
import re

# XML Parsing
import cElementTree as ElementTree

# Time module for use with validity times
from time import strftime
from time import strptime
from datetime import datetime
from datetime import timedelta

# XML signature module based on xmlsec and libxml2
from XMLSecDoc import *

from X509 import X500DN
from X509 import X500DNError


class AttCertError(Exception):
    
    """Exception handling for NDG Attribute Certificate class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg
    

class AttCert(dict, XMLSecDoc):

    """NDG Attribute Certificate (Authentication or Access Token)."""

    # Attribute Certificate file version
    __version = "1.0"

    # Provenance of certificate may be original or mapped from another
    # certificate
    __provenance = ('original', 'mapped')


    # Nb. pass XMLSecDoc keyword arguments in xmlSecDocKeys dictionary
    def __init__(self, filePath=None, lifeTime=-1, **xmlSecDocKeys):

        """Initialisation - Attribute Certificate file path may be specified.
        Also, holder and issuer details and signing authority key and
        certificate."""

        # Base class initialisation
        dict.__init__(self)
        XMLSecDoc.__init__(self, **xmlSecDocKeys)


        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise AttCertError("Input file path must be a valid string")
            
            self.filePath = filePath


        # Data dictionary version of xml
        #
        # Nb. RoleSet is an empty list - it will be filled role dictionary
        # items [{'role': {'name': '<Name>'}}, ... ]
        self.__dat = {
            
            "version":            AttCert.__version,
            "holder":             '',
            "issuer":             '',
            "issuerName":         '',
            "issuerSerialNumber": 0,
            "validity":           {"notBefore": '', "notAfter": ''},
            "attributes":         {"roleSet": []},
            "provenance":         ''
        }

        # Holder and issuer X500DN objects - instanciated in read method
        self.__issuerDN = None
        self.__holderDN = None


        # Check for input certificate life time interval - if not set default
        # to one day
        if lifeTime is -1:
            self.__lifeTime = 28800 # 8 hours
        else:
            self.__lifeTime = lifeTime
        
        self.__dtNotBefore = None
        self.__dtNotAfter = None

        
    def __repr__(self):
        """Override default behaviour to return internal dictionary content"""
        return str(self.__dat)

                
    def __delitem__(self, key):
        "Attribute Certificate keys cannot be removed"
        
        raise AttCertError('Keys cannot be deleted from ' + \
                           self.__class__.__name__)


    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of Attribute
        Certificate properties

        Nb. also possible to apply keys belonging validity and attributes
        sub dictionaries
        """
        
        # Check input key
        if self.__dat.has_key(key):

            # key recognised
            return self.__dat[key]                

        elif self.__dat['validity'].has_key(key):

            # Allow indexing via validity keys - a shorthand way of referencing
            # for convenience
            return self.__dat['validity'][key]

        elif self.__dat['attributes'].has_key(key):

            # Allow indexing via attirbutes keys - a shorthand way of 
            # referencing for convenience
            return self.__dat['attributes'][key]

        else:
            # key not recognised as a short or long name version
            raise AttCertError('Key "%s" not recognised for %s' % \
                               (key, self.__class__.__name__))


    def __setitem__(self, key, item):        
        self.__class__.__name__ + """ behaves as data dictionary of Attribute
        Certificate properties

        Nb. also possible to apply keys belonging validity and attributes
        sub dictionaries
        """

        # Check input key
        if self.__dat.has_key(key):

            # key recognised - check if setting provenance
            if key is "provenance" and not self.isValidProvenance(item):
                raise AttCertError("Provenance must be set to \"" + \
                            "\" or \"".join(AttCert.__provenance) + "\"")
            
            self.__dat[key] = item

        elif self.__dat['attributes'].has_key(key):

            # Allow indexing via acInfo keys - a shorthand way of referencing
            # for convenience
            return self.__dat['attributes'][key]

        elif self.__dat['validity'].has_key(key):
                
            # Prevent setting of notBefore/notAfter - restrict to method
            # setValidityTime
            raise AttCertError(\
                "Use setValidityTime method to set notBefore/notAfter times")
            
        else:
            # key not recognised as a short or long name version
            raise AttCertError('Key "%s" not recognised for %s' % \
                               (key, self.__class__.__name__))
        

    def __eq__(self, attCert):
        """Return true if all elements are the same"""
        
        try:
            return min([self.__dat[key] == attCert[key] \
                       for key in self.__dat.keys()])
        except:
            return False
        

    def __nonzero__(self):
        """Ensure if <attCertInstance> test yields True"""
        return True
    
    
    def clear(self):
        raise AttCertError("Data cannot be cleared from " + \
                           self.__class__.__name__)

    
    def copy(self):

        import copy
        return copy.copy(self)

    
    def keys(self):
        return self.__dat.keys()

    def items(self):
        return self.__dat.items()

    def values(self):
        return self.__dat.values()

    def has_key(self, key):
        return self.__dat.has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return key in self.__dat


    def getExptdVersion(self):
        """Return the Attribute Certificate XML expected version."""
        return AttCert.__version


    #
    # Get/Set methods
    #
    # Nb. it's also possible to access the data dictionary parameters via
    # __setitem__ and __getitem__ standard dictionary methods
    #
    def setVersion(self, version):
        """Set the version number to be written to file."""        
        self.__dat['version'] = version
    
    def getVersion(self):
        """Get version number as set in file."""
        return self.__dat['version']
    
    def setHolder(self, holder):
        """Set holder's Distinguished Name string."""
        self.__dat['holder'] = holder
    
    def getHolder(self):
        """Get holder's Distinguished Name string."""
        return self.__dat['holder']

    def getHolderDN(self):
         """Get the holder's Distinguished Name as an X500DN instance"""
         return self.__holderDN
    
    def setIssuer(self, issuer):
        """Set issuer's Distinguished Name."""
        self.__dat['issuer'] = issuer
    
    def getIssuer(self):
        """Get the issuer's Distinguished Name string"""
        return self.__dat['issuer']

    def getIssuerDN(self):
         """Get the issuer's Distinguished Name as an X500DN instance"""
         return self.__issuerDN
        
    def setIssuerName(self, issuerName):
        """Set the name of the issuer"""
        self.__dat['issuerName'] = issuerName
    
    def getIssuerName(self):
        """Get the name of the issuer"""
        return self.__dat['issuerName']
    
    def setIssuerSerialNumber(self, serialNumber):
        """Set the issuer serial number"""
        self.__dat['issuerSerialNumber'] = serialNumber
    
    def getIssuerSerialNumber(self):
        """Get the issuer serial number"""
        return self.__dat['issuerSerialNumber']


    # Nb. no setValidityNotBefore/setValidityNotAfter methods - use
    # setValidityTime instead.
    
    def getValidityNotBefore(self, asDatetime=False):
        """Get the validity Not Before date/time string

        Set asDatetime to True to return as a datetime type
        Nb. time may not have been set - if so it will be set to None"""
        if asDatetime is True:
            return self.__dtNotBefore
        else:
            return self.__dat['validity']['notBefore']


    def getValidityNotAfter(self, asDatetime=False):
        """Get the validity Not After date/time string

        Set asDatetime to True to return as a datetime type
        Nb. time may not have been set - if so it will be set to None"""
        if asDatetime is True:
            return self.__dtNotAfter
        else:
            return self.__dat['validity']['notAfter']

    
    def getRoleSet(self):
        """Get the roleSet as a list of role dictionaries."""
        return self.__dat['attributes']['roleSet']


    def getRoles(self):
        """Return roles as a list"""
        try:
            return [i.values()[0].values()[0] \
                    for i in self.__dat['attributes']['roleSet']]
        except:
            return []

        
    def setProvenance(self, provenance):
        """Set the provenance for the certificate: 'original' or 'mapped'."""

        if not self.isValidProvenance(provenance):
            raise AttCertError("Provenance must be set to \"" + \
                               "\" or \"".join(AttCert.__provenance) + "\"")
        
        self.__dat['provenance'] = provenance

    
    def getProvenance(self):
        """Get the provenance for the certificate."""
        return self.__dat['provenance']
    

    def isValidProvenance(self, provenance=None):
        """Check provenance is set correctly - to 'original'/'mapped'.

        If no provenance argument is provided, test against the setting in
        the current instance.
        """
        
        if not provenance:
            provenance = self.__dat['provenance']

        return provenance in AttCert.__provenance
        

    def isOriginal(self):
        """Check for original provenance."""
        return self.__dat['provenance'] == 'original'


    def isMapped(self):
        """Check for mapped provenance."""
        return self.__dat['provenance'] == 'mapped'


    def addRoles(self, roleName):
        """Add new roles to the roleSet in attributes."""

        if isinstance(roleName, basestring):
            roleName = [roleName]
            
        self.__dat['attributes']['roleSet'].extend(\
                                [{'role': {'name': i}} for i in roleName])


    def parse(self, xmlTxt, rtnRootElem=False):

        """Parse an Attribute Certificate content contained in string input

        xmlTxt:     Attribute Certificate XML content as string"""
        
        rootElem = ElementTree.XML(xmlTxt)

        # Call generic ElementTree parser
        self.__parse(rootElem)


        # Call base class parser method to initialise libxml2 objects for
        # signature validation
        try:
            XMLSecDoc.parse(self, xmlTxt)

        except Exception, e:
            raise AttCertError("Attribute Certificate: %s" % e)

        if rtnRootElem:
            return rootElem

        
    def read(self, filePath=None):

        """Read Attribute Certificate

        filePath:   file to be read, if omitted __filePath member variable is
                    used instead"""

        if filePath:
            if not isinstance(filePath, basestring):
                raise AttCertError("Input file path must be a string.")

            self.filePath = filePath
        else:
            filePath = self.filePath


        try:    
            tree = ElementTree.parse(filePath)
            rootElem = tree.getroot()
        except Exception, e:
            raise AttCertError("Attribute Certificate: %s" % e)
        
        # Call generic ElementTree parser
        self.__parse(rootElem)


        # Call base class read method to initialise libxml2 objects for
        # signature validation
        try:
            XMLSecDoc.read(self)

        except Exception, e:
            raise AttCertError("Attribute Certificate: %s" % e)



        
    def __parse(self, rootElem):

        """Private XML parsing method accepts a ElementTree.Element type
        as input

        rootElem:       ElementTree.Element type
        """
        
        # Extract from acInfo tag
        acInfoElem = rootElem.find("acInfo")
        
        if not acInfoElem:
            raise AttCertError("<acInfo> tag not found in \"%s\"" % \
                               self.filePath)


        # Copy all acInfo tags into dictionary
        for elem in acInfoElem:
        
            if not self.__dat.has_key(elem.tag):
                raise AttCertError(self.filePath + "\": <" + \
                                   elem.tag + "> not recognised.")

            # Make sure not to copy validity and attributes tags - handle 
            # these separately below
            if not elem.getchildren():
                self.__dat[elem.tag] = elem.text

        # Convert issuer and holder into X500DN instances
        try:
            self.__issuerDN = X500DN(dn=self.__dat['issuer'])

        except X500DNError, x500dnErr:
            raise AttCertError("Issuer DN: %s" % x500dnErr)


        try:
            self.__holderDN = X500DN(dn=self.__dat['holder'])

        except X500DNError, x500dnErr:
            raise AttCertError("Holder DN: %s" % x500dnErr)
        
                                 
        # Extract validity and attributes subsets
        self.__dat['validity']['notBefore'] = \
                                rootElem.findtext("acInfo/validity/notBefore")
        
        if self.__dat['validity']['notBefore'] is None:
            raise AttCertError("<notBefore> tag not found in \"%s\"" % \
                               self.filePath)

        # Update datetime object equivalent
        self.__dtNotBefore = self.timeStr2datetime(\
                                        self.__dat['validity']['notBefore'])

        
        self.__dat['validity']['notAfter'] = \
                                rootElem.findtext("acInfo/validity/notAfter")
        
        if self.__dat['validity']['notAfter'] is None:
            raise AttCertError("<notAfter> tag not found in \"%s\"" %
                               self.filePath)


        # Update datetime object equivalent
        self.__dtNotAfter = self.timeStr2datetime(\
                                        self.__dat['validity']['notAfter'])


        # set up role list
        roleElem = acInfoElem.findall("attributes/roleSet/role/name")
        if roleElem is None:
            raise AttCertError("<role> tag not found in \"%s\"" % \
                               self.filePath)
        
        self.__dat['attributes']['roleSet'] = \
                                [{'role': {'name': i.text}} for i in roleElem]
                    
        
        if not self.isValidVersion():           
            raise AttCertError('Attribute Certificate version is ' + \
                               self.__dat['version'] + ' but version ' + \
                               AttCert.__version + ' expected')




    def createXML(self):

        """Create XML for Attribute Token from current data settings and
        return as a string.  The XML created is MINUS the digital signature.
        To obtain the signed version, run the sign method and pass the attCert
        object reference into str()

        Implementation of virtual method defined in XMLSecDoc base class"""

        # Nb.
        # * this method is used by AttCert.read()
        # * Signing by Attribute Authority is separate - see AttCert.sign()
        

        # Check for valid provenance
        if not self.isValidProvenance():
            raise AttCertError("Provenance must be set to \"" + \
                               "\" or \"".join(AttCert.__provenance) + "\"")

        
        # Create string of all XML content        
        xmlTxt = \
"""<attributeCertificate>
    <acInfo>
        <version>""" + self.__dat['version'] + """</version>
        <holder>""" + self.__dat['holder'] + """</holder>
        <issuer>""" + self.__dat['issuer'] + """</issuer>
        <issuerName>""" + self.__dat['issuerName'] + """</issuerName>
        <issuerSerialNumber>""" + str(self.__dat['issuerSerialNumber']) +\
            """</issuerSerialNumber> 
	<validity>
  	    <notBefore>""" + self.__dat['validity']['notBefore'] + \
  	    """</notBefore> 
	    <notAfter>""" + self.__dat['validity']['notAfter'] + \
	    """</notAfter> 
	</validity>
	<attributes>
	    <roleSet>
                """ + \
        "".join(["""<role>
	    	    <name>""" + i['role']['name'] + """</name>
		</role>
	    """ for i in self.__dat['attributes']['roleSet']]) +\
	    """</roleSet>
	</attributes>
	<provenance>""" + self.__dat['provenance'] + """</provenance> 
    </acInfo>
</attributeCertificate>"""


        # Return XML file content as a string
        return xmlTxt




    def setValidityTime(self,
                        dtNotBefore=None, 
                        dtNotAfter=None, 
                        lifeTime=None,
                        notBeforeOffset=None):

        """Set the notBefore and notAfter times which determine the window for
        which the Attribute Certificate is valid

        Nb. use UTC time.  lifeTime and notBeforeOffset are in seconds
        """

        if dtNotBefore is not None:
            if not isinstance(dtNotBefore, datetime):
                raise AttCertError(\
                                "Input not before time must be datetime type")
            
            self.__dtNotBefore = dtNotBefore
            
        else:
            # Use current UTC +/- offset
            self.__dtNotBefore = datetime.utcnow()
            
            if notBeforeOffset is not None:
                self.__dtNotBefore += timedelta(seconds=notBeforeOffset)
            


        if dtNotAfter is not None:
            if not isinstance(dtNotAfter, datetime):
                raise AttCertError(\
                                "Input not after time must be datetime type")

            # Use input Not After time to calculate a new lifetime setting
            dtDeltaLifeTime = dtNotAfter - self.__dtNotBefore
            if dtDeltaLifeTime < timedelta(0):
                raise AttCertError("Input Not After time is invalid %s" % \
                                   str(dtNotAfter))

            self.__lifeTime = dtDeltaLifeTime.days*86400 + \
                              dtDeltaLifeTime.seconds

            self.__dtNotAfter = dtNotAfter
            
        else:
            # Check for input certificate life time interval
            if lifeTime is not None:
                self.__lifeTime = lifeTime
                
            try:
                # Make a time delta object from the lifetime expressed in
                # seconds
                dtDeltaLifeTime = timedelta(seconds=self.__lifeTime)
            except Exception, e:
                raise AttCertError("Invalid Certificate lifetime set %.3f" % \
                                   self.__lifeTime)
            
            # Add certificate lifetime to calculate not after time
            self.__dtNotAfter = self.__dtNotBefore + dtDeltaLifeTime

        
        self.__dat['validity']['notBefore'] = \
                                    self.datetime2timeStr(self.__dtNotBefore)
        
        self.__dat['validity']['notAfter'] = \
                                    self.datetime2timeStr(self.__dtNotAfter)




    def datetime2timeStr(self, dtVal):

        """Convert a datetime object to a notBefore/notAfter time string"""

        if not isinstance(dtVal, datetime):
            raise AttCertError(\
                        "Invalid datetime object for conversion to string")
        
        # Convert from 1-12 to 0-11 month format used in XML file
        #lDateTime = list(dtVal.utctimetuple()[0:6])

        #lDateTime[1] -= 1

        # Format as a single string with no commas or brackets
        #return ''.join(re.findall('[0-9 ]', str(lDateTime)))

        # Use 1-12 format
        # P J Kershaw 09/06/05
        return dtVal.strftime("%Y %m %d %H %M %S")

    

    def timeStr2datetime(self, sTime):

        """Convert a notBefore/notAfter time string to a datetime object"""

        # Convert from 0-11 to 1-12 month format used by datetime()
        try:
            #lTime = [int(i) for i in sTime.split()]
            lTime = strptime(sTime, "%Y %m %d %H %M %S")
            
            # Use 1-12 format
            # P J Kershaw 09/05/05
            #lTime[1] += 1
        
            return datetime(lTime[0], lTime[1], lTime[2],
                            lTime[3], lTime[4], lTime[5])
        except Exception, e:
            raise AttCertError(\
                "Error converting time string into datetime object: %s" % e)
        



    def isValidTime(self, raiseExcep=False):
        """Check Attribute Certificate for expiry.  Set raiseExcep to True
        to raise an exception with a message indicating the nature of the 
        time error"""

        if not isinstance(self.__dtNotBefore, datetime):
            raise AttCertError("Not Before datetime is not set")

        if not isinstance(self.__dtNotAfter, datetime):
            raise AttCertError("Not After datetime is not set")
       
        dtNow = datetime.utcnow()
        
        # Testing only
        #
        # P J Kershaw 02/03/06
        #notBefore = self.__dtNotBefore
        #notAfter = self.__dtNotAfter
        #print "Valid Time? = %d" % (dtNow > notBefore and dtNow < notAfter)
        if raiseExcep:
            if dtNow < self.__dtNotBefore:
                raise AttCertError(\
            "Current time is before Attribute Certificate's not before time")
            
            if dtNow > self.__dtNotAfter:
                raise AttCertError(\
                            "Attribute Certificate validity time has expired")                
            
            return True        
        else:
            return dtNow > self.__dtNotBefore and dtNow < self.__dtNotAfter


        
        
    def isValidVersion(self):

        """Check Attribute Certificate XML file version"""
        return self.__dat['version'] == AttCert.__version




    def isValid(self,
                raiseExcep=False,
                chkTime=True,
                chkVersion=True,
                chkProvenance=True,
                chkSig=True,
                **xmlSecDocKeys):

        """Check Attribute Certificate is valid:

        - Time validity is OK
        - XML file version is OK
        - valid provenance setting
        - Signature is valid.

        chkTime:                set to True to do time validity check (default
                                is True)

        chkVersion:             set to True to Attribute Certificate file
                                version (default is True)

        chkProvenance:          set to True to check provenance value is valid
                                (default is True)

        chkSig:                 set to True to check digital signature - for
                                this certFilePathList must contain the root
                                certificate of the X.509 certificate used to
                                sign the AttCert.  Alternatively,
                                certFilePathList can be set via __init__
                                (default chkSig value is True)
                                
        raiseExcep:             set to true to raise an exception if invalid
                                instead of returning False.  Default is to set
                                this flag to False.

        Also accepts keyword arguments corresponding to XMLSecDoc.isValidSig:
        
        xmlTxt:                 string buffer containing the text from the XML
                                file to be checked.  If omitted, the
                                filePath argument is used instead.

        filePath:               file path to XML file to be checked.  This
                                argument is used if no xmlTxt was provided.
                                If filePath itself is omitted the file set
                                by self.__filePath is read instead.

        certFilePathList:       list of files paths must contain certificate 
                                of trusted authority used to validate the
                                signature.  If set, it is copied into 
                                self.__certFilePathList.  If omitted
                                self.__certFilePathList is used unchanged.                             
        """

        # Carry out checks in turn - Specific exception error messages are
        # raised if flag is set
        if chkTime and not self.isValidTime(raiseExcep=raiseExcep):
            return False

        
        if chkVersion and not self.isValidVersion():
            if raiseExcep:
                raise AttCertError('Attribute Certificate version is ' + \
                                   self.__dat['version'] + ' but version ' + \
                                   AttCert.__version + ' expected')
            
            return False


        if chkProvenance and not self.isValidProvenance():
            if raiseExcep:
                raise AttCertError(\
                    "Attribute Certificate Provenance must be set to \"" + \
                    "\" or \"".join(AttCert.__provenance) + "\"")
                
            return False


        # Handle exception from XMLSecDocc.isValidSig() regardless of
        # raiseExcep flag setting
        try:            
            if chkSig and not self.isValidSig(**xmlSecDocKeys):
                if raiseExcep:
                    raise AttCertError(\
                                "Attribute Certificate signature is invalid")
                
                return False
        
        except Exception, e:
            raise AttCertError(str(e))
        

        # All tests passed
        return True



#_____________________________________________________________________________
# Alternative AttCert constructors
#
def AttCertRead(filePath):
    """Create a new attribute certificate read in from a file"""
    
    attCert = AttCert(filePath)
    attCert.read()
    
    return attCert




def AttCertParse(attCertTxt):
    """Create a new attribute certificate from string of file content"""
    
    attCert = AttCert()
    attCert.parse(attCertTxt)
    
    return attCert
