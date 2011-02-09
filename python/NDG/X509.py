"""X.509 certificate handling class encapsulates M2Crypto.X509

Nerc Data Grid Project

P J Kershaw 05/04/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

cvsID = '$Id$'


import types
import re

# Handle not before and not after strings
from time import strftime
from time import strptime
from datetime import datetime

import M2Crypto


class X509CertError(Exception):

    """Exception handling for NDG X.509 Certificate handling class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




class X509Cert(object):
    "NDG X509 Certificate Handling"

    def __init__(self, filePath=None):

	# Set certificate file path
	if filePath is not None:

            if not isinstance(filePath, basestring):
                raise X509CertError(\
                    "Certificate File Path input must be a valid string")
            
	self.__filePath = filePath
        self.__m2CryptoX509 = None
        self.__dn = None
        self.__dtNotBefore = None
        self.__dtNotAfter = None
        

    def __str__(self):
        """Override to display current certificate file setting."""

        if self.__filePath is None:
            return '<X509 Cert>'
        else:
            return '<X509 Cert \'%s\'>' % self.__filePath


    def __repr__(self):
        """Override to display current certificate file setting."""
        
        return str(self)
        

    def read(self, filePath=None):
        """Read a certificate from file"""
        
 	# Check for optional input certificate file path
	if filePath is not None:

            if not isinstance(filePath, basestring):
                raise X509CertError(\
                    "Certificate File Path input must be a valid string")
            
            self.__filePath = filePath
       
        try:
            self.__m2CryptoX509 = M2Crypto.X509.load_cert(self.__filePath)
        except Exception, e:
            raise X509CertError("Error loading certificate \"%s\": %s" % \
                                (self.__filePath, str(e)))

        # Update DN and validity times from M2Crypto X509 object just
        # created
        self.__setFromM2Crypto()



        
    def parse(self, certTxt):
        """Read a certificate input as a string"""

        try:
            # Create M2Crypto memory buffer and pass to load certificate
            # method
            #
            # Nb. input converted to standard string - buffer method won't
            # accept unicode type strings
            certBIO = M2Crypto.BIO.MemoryBuffer(str(certTxt))
            self.__m2CryptoX509 = M2Crypto.X509.load_cert_bio(certBIO)
            
        except Exception, e:
            raise X509CertError("Error loading certificate: %s" % str(e))

        # Update DN and validity times from M2Crypto X509 object just
        # created
        self.__setFromM2Crypto()


        
        
    def __setFromM2Crypto(self):
        """Private method allows class members to be updated from the
        current M2Crypto object.  __m2CryptoX509 must have been set."""
        
        # Get distinguished name
        m2CryptoX509Name = self.__m2CryptoX509.get_subject()

        # Instantiate X500 Distinguished name
        self.__dn = X500DN(m2CryptoX509Name=m2CryptoX509Name)


        # Get not before and not after validity times
        #
        # Only option for M2Crypto seems to be to return the times as
        # formatted strings and then parse them in order to create a datetime
        # type
        
        try:
            m2CryptoNotBefore = self.__m2CryptoX509.get_not_before()
            self.__dtNotBefore=self.__m2CryptoUTC2datetime(m2CryptoNotBefore)
                                        
        except Exception, e:
            raise X509CertError("Not Before time: " + str(e))

        
        try:
            m2CryptoNotAfter = self.__m2CryptoX509.get_not_after()
            self.__dtNotAfter = self.__m2CryptoUTC2datetime(m2CryptoNotAfter)
                                    
        except Exception, e:
            raise X509CertError("Not After time: " + str(e))



        
    def asString(self, filePath=None):
        """Return certificate file content as a string"""
        
        # Check M2Crypto.X509 object has been instantiated - if not call
        # read method
        if self.__m2CryptoX509 is None:
            self.read(filePath)
            
        return self.__m2CryptoX509.Print()

    
    #_________________________________________________________________________
    # Make some attributes accessible as read-only
    def __getDN(self):
        """Get X500 Distinguished Name."""
        return self.__dn

    dn = property(fget=__getDN, doc="X.509 Distinguished Name")


    def __getVersion(self):
        """Get X.509 Certificate version"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__m2CryptoX509.get_version()

    version = property(fget=__getVersion, doc="X.509 Certificate version")
	
	
    def __getSerialNumber(self):
        """Get Serial Number"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__m2CryptoX509.get_serial_number()
    
    serialNumber = property(fget=__getSerialNumber, 
                            doc="X.509 Certificate Serial Number")
	

    def __getNotBefore(self):
        """Get not before validity time as datetime type"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__dtNotBefore

    notBefore = property(fget=__getNotBefore, 
                         doc="Not before validity time as datetime type")
	
	
    def __getNotAfter(self):
        """Get not after validity time as datetime type"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__dtNotAfter

    notAfter = property(fget=__getNotAfter, 
                         doc="Not after validity time as datetime type")
	
	
    def __getPubKey(self):
        """Get public key"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__m2CryptoX509.get_pubkey()

    pubKey = property(fget=__getPubKey,  doc="Public Key")
	
	
    def __getIssuer(self):
        """Get Certificate issuer"""
        if self.__m2CryptoX509 is None:
            return None
        
        # Return as X500DN type
        return X500DN(m2CryptoX509Name=self.__m2CryptoX509.get_issuer())

    issuer = property(fget=__getIssuer,  doc="Certificate Issuer")
	
    
    def __getSubject(self):
        """Get Certificate subject"""
        if self.__m2CryptoX509 is None:
            return None

        # Return as X500DN type
        return X500DN(m2CryptoX509Name=self.__m2CryptoX509.get_subject())
    
    subject = property(fget=__getSubject,  doc="Certificate subject")


    def isValidTime(self, raiseExcep=False):
        """Check Certificate for expiry

        raiseExcep: set True to raise an exception if certificate is invalid"""

        if not isinstance(self.__dtNotBefore, datetime):
            raise AttCertError("Not Before datetime is not set")

        if not isinstance(self.__dtNotAfter, datetime):
            raise AttCertError("Not After datetime is not set")
       
        dtNow = datetime.utcnow()

        if raiseExcep:
            if dtNow < self.__dtNotBefore:
                raise X509Error("Current time is before the " + \
                                "certificate's Not Before Time")
            
            elif dtNow > self.__dtNotAfter:
                raise X509Error("Certificate has expired")
        else:
            return dtNow > self.__dtNotBefore and dtNow < self.__dtNotAfter




    def __m2CryptoUTC2datetime(self, m2CryptoUTC):
        """Convert M2Crypto UTC time string as returned by get_not_before/
        get_not_after methods into datetime type"""
        
        datetimeRE = "([a-zA-Z]{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}).*"
        sM2CryptoUTC = None
        
        try:
            # Convert into string
            sM2CryptoUTC = str(m2CryptoUTC)
            
            # Check for expected format - string may have trailing GMT - ignore
            sTime = re.findall(datetimeRE, sM2CryptoUTC)[0]

            # Convert into a tuple
            lTime = strptime(sTime, "%b %d %H:%M:%S %Y")[0:6]

            return datetime(lTime[0], lTime[1], lTime[2],
                            lTime[3], lTime[4], lTime[5])
                                    
        except Exception, e:
            msg = "Error parsing M2Crypto UTC"
            if sM2CryptoUTC is not None:
                msg += ": " + sM2CryptoUTC
                
            raise X509CertError(msg)
	


#_____________________________________________________________________________
# Alternative AttCert constructors
#
def X509CertRead(filePath):
    """Create a new X509 certificate read in from a file"""

    x509Cert = X509Cert(filePath)
    x509Cert.read()
    
    return x509Cert




def X509CertParse(x509CertTxt):
    """Create a new X509 certificate from string of file content"""

    x509Cert = X509Cert()
    x509Cert.parse(x509CertTxt)
    
    return x509Cert




#_____________________________________________________________________________
class X500DNError(Exception):
    """Exception handling for NDG X.500 DN class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg



#_____________________________________________________________________________
# For use with parseSeparator method:
import re


class X500DN(dict):
    "NDG X500 Distinguished name"
    
    # Class attribute - look-up mapping short name attributes to their long
    # name equivalents
    # * private *
    __shortNameLUT = {  'commonName':               'CN',
                        'OrganisationalUnitName':   'OU',
                        'Organisation':             'O',
                        'CountryName':	    	    'C',
                        'EmailAddress':             'EMAILADDRESS',
                        'localityName':	    	    'L',
                        'stateOrProvinceName':	    'ST',
                        'streetAddress':            'STREET',
                        'domainComponent':	    'DC',
                        'userid':	    	    'UID'}

    
    def __init__(self,
                 dn=None,
                 m2CryptoX509Name=None,
                 separator=None):

        """Create a new X500 Distinguished Name

        m2CryptoX509Name:   initialise using using an M2Crypto.X509.X509_Name
        dn:                 initialise using a distinguished name string
        separator:          separator used to delimit dn fields - usually
                            '/' or ','.  If dn is input and separator is
                            omitted the separator character will be
                            automatically parsed from the dn string.
                            """
        # Private key data
	self.__dat = {  'CN':	    	'',
                        'OU':	    	'',
                        'O':	    	'',
                        'C':	    	'',
                        'EMAILADDRESS': '',
                        'L':	    	'',
                        'ST':	    	'',
                        'STREET':   	'',
                        'DC':	    	'',
                        'UID':	    	''}

        dict.__init__(self)


        self.__separator = None
        
        # Check for separator from input
  	if separator is not None:
            if not isinstance(separator, basestring):
                raise X500DNError("dn Separator must be a valid string")

            # Check for single character but allow trailing space chars
            if len(separator.lstrip()) is not 1:
                raise X500DNError("dn separator must be a single character")

            self.__separator = separator

	    
        if m2CryptoX509Name is not None:
	
            # the argument is an x509 dn in m2crypto format
            self.__dat['CN'] = m2CryptoX509Name.CN

            # M2Crypto seems to default Email and L variables to None - in
            # this case avoid making an assignment because it upsets calls to
            # __cmp__() - None could be compared to '' conceptually the same
            # but not equal progammatically
            #
            # P J Kershaw 13/06/05
            if m2CryptoX509Name.L is not None:
                self.__dat['L'] = m2CryptoX509Name.L

            self.__dat['O'] = m2CryptoX509Name.O
            self.__dat['OU'] = m2CryptoX509Name.OU

            if m2CryptoX509Name.Email is not None:
                self.__dat['EMAILADDRESS'] = m2CryptoX509Name.Email

        elif dn is not None:

            # Separator can be parsed from the input DN string - only attempt
            # if no explict separator was input
            if self.__separator is None:
                self.__separator = self.parseSeparator(dn)
                
            # Split Distinguished name string into constituent fields
            self.deserialise(dn)


    def __repr__(self):
        """Override default behaviour to return internal dictionary content"""
        return self.serialise()


    def __str__(self):
        """Behaviour for print and string statements - convert DN into
        serialised format."""
        return self.serialise()

        
    def __eq__(self, x500dn):

        """Return true if the all the fields of the two DNs are equal"""
        
        if not isinstance(x500dn, X500DN):
            return False

        return self.__dat.items() == x500dn.items()

        
    def __cmp__(self, x500dn):

        """Return true if the all the fields of the two DNs are equal"""
        
        if not isinstance(x500dn, X500DN):
            return False

        return cmp(self.__dat, x500dn.get())

    
    def __delitem__(self, key):

        """Prevent keys from being deleted."""
        raise X500DNError('Keys cannot be deleted from the X500DN')


    def __getitem__(self, key):

        # Check input key
        if self.__dat.has_key(key):

            # key recognised
            return self.__dat[key]
        
        elif X500DN.__shortNameLUT.has_key(key):

            # key not recognised - but a long name version of the key may
            # have been passed
            shortName = X500DN.__shortNameLUT[key]
            return self.__dat[shortName]

        else:
            # key not recognised as a short or long name version
            raise X500DNError('Key "' + key + '" not recognised for X500DN')


    def __setitem__(self, key, item):
        
        # Check input key
        if self.__dat.has_key(key):

            # key recognised
            self.__dat[key] = item
            
        elif X500DN.__shortNameLUT.has_key(key):
                
            # key not recognised - but a long name version of the key may
            # have been passed
            shortName = X500DN.__shortNameLUT[key]
            self.__dat[shortName] = item
            
        else:
            # key not recognised as a short or long name version
            raise X500DNError('Key "' + key + '" not recognised for X500DN')


    def clear(self):
        raise X500DNError("Data cannot be cleared from " + self.__class__.__name__)

    
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
        return key in self.__tags


    def get(self):
        """Get Distinguished name as a data dictionary."""
        return self.__dat

    
    def serialise(self, separator=None):

        """Combine fields in Distinguished Name into a single string."""
        
        if separator:
            if not isinstance(separator, basestring):
                raise X500DNError("Separator must be a valid string")
		
            self.__separator = separator
            
        else:
            # Default to / if no separator is set
            separator = '/'


        # If using '/' then prepend DN with an initial '/' char
        if separator == '/':
            sDN = separator
        else:
            sDN = ''
            

        sDN += separator.join(["%s=%s" % field \
                                for field in self.__dat.items() if field[1]])
                                
        return sDN


    def deserialise(self, dn, separator=None):

        """Break up a DN string into it's constituent fields and use to
        update the object's dictionary"""
        
        if separator:
            if not isinstance(separator, basestring):
                raise X500DNError("Separator must be a valid string")

            self.__separator = separator


        # If no separator has been set, parse if from the DN string            
        if self.__separator is None:
            self.__separator = self.parseSeparator(dn)

        try:
            dnFields = dn.split(self.__separator)
            if len(dnFields) < 2:
                raise X500DNError("Error parsing DN string: \"%s\"" % dn)

            
            # Split fields into key/value and also filter null fields if
            # found e.g. a leading '/' in the DN would yield a null field
            # when split
            keyVals = [field.split('=') for field in dnFields if field]

            # Reset existing dictionary values
            self.__dat.fromkeys(self.__dat, '')
            
            # Strip leading and trailing space chars and convert into a
            # dictionary
            parsedDN = dict([(keyVal[0].strip(), keyVal[1].strip()) \
                                                      for keyVal in keyVals])

            # Copy matching DN fields
            for i in parsedDN.items():
                if not self.__dat.has_key(i[0]):
                    raise X500DNError(\
                        "Invalid field \"%s\" in input DN string" % i[0])

                self.__dat[i[0]] = i[1]

                
        except Exception, excep:
            raise X500DNError("Error de-serialising DN \"%s\": %s" % \
                              (dn, str(excep)))


    def parseSeparator(self, dn):

        """Attempt to parse the separator character from a given input
        DN string.  If not found, return None

        DNs don't use standard separators e.g.

        /C=UK/O=eScience/OU=CLRC/L=DL/CN=AN Other
        CN=SUM Oneelse,L=Didcot, O=RAL,OU=SSTD

        This function isolates and identifies the character.  - In the above,
        '/' and ',' respectively"""


        # Make a regular expression containing all the possible field
        # identifiers with equal sign appended and 'or'ed together.  \W should
        # match the separator which preceeds the field name. \s* allows any
        # whitespace between field name and field separator to be taken into
        # account.
        #
        # The resulting match should be a list.  The first character in each
        # element in the list should be the field separator and should be the
        # same
        regExpr = '|'.join(['\W\s*'+i+'=' for i in self.__dat.keys()])
        match = re.findall(regExpr, dn)
            
        # In the first example above, the resulting match is:
        # ['/C=', '/O=', '/OU=', '/L=']
        # In each element the first character is the separator
        sepList = [i[0:1] for i in match]

        # All separators should be the same character - return None if they
        # don't match
        if not [i for i in sepList if i != sepList[0]]:
            return sepList[0]
        else:
            return None
