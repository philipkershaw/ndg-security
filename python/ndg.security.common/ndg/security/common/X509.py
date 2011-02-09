"""X.509 certificate handling class encapsulates M2Crypto.X509

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/04/05"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'


import types
import re

# Handle not before and not after strings
from time import strftime
from time import strptime
from datetime import datetime

import M2Crypto


class X509CertError(Exception):
    """Exception handling for NDG X.509 Certificate handling class."""

class X509CertInvalidNotBeforeTime(X509CertError):
    """Call from X509Cert.isValidTime if certificates not before time is
    BEFORE the current system time"""
    
class X509CertExpired(X509CertError):
    """Call from X509Cert.isValidTime if certificate has expired"""

   
class X509Cert(object):
    "NDG X509 Certificate Handling"

    def __init__(self, filePath=None, m2CryptoX509=None):

        # Set certificate file path
        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise X509CertError, \
                        "Certificate File Path input must be a valid string"
            
        self.__filePath = filePath            
        self.__dn = None
        self.__dtNotBefore = None
        self.__dtNotAfter = None
        
        if m2CryptoX509:
            self.__setM2CryptoX509(m2CryptoX509)
        

    def read(self, filePath=None):
        """Read a certificate from file"""
        
     	# Check for optional input certificate file path
    	if filePath is not None:
            if not isinstance(filePath, basestring):
                raise X509CertError, \
                    "Certificate File Path input must be a valid string"
            
            self.__filePath = filePath
       
        try:
            self.__m2CryptoX509 = M2Crypto.X509.load_cert(self.__filePath)
        except Exception, e:
            raise X509CertError, "Error loading certificate \"%s\": %s" % \
                                (self.__filePath, str(e))

        # Update DN and validity times from M2Crypto X509 object just
        # created
        self.__setM2CryptoX509()


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
            raise X509CertError, "Error loading certificate: %s" % str(e)

        # Update DN and validity times from M2Crypto X509 object just
        # created
        self.__setM2CryptoX509()


        
        
    def __setM2CryptoX509(self, m2CryptoX509=None):
        """Private method allows class members to be updated from the
        current M2Crypto object.  __m2CryptoX509 must have been set."""
        
        if m2CryptoX509 is not None:
            if not isinstance(m2CryptoX509, M2Crypto.X509.X509):
                raise TypeError, \
                    "Incorrect type for input M2Crypto.X509.X509 object"
                    
            self.__m2CryptoX509 = m2CryptoX509
            
            
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
            raise X509CertError, "Not Before time: " + str(e)

        
        try:
            m2CryptoNotAfter = self.__m2CryptoX509.get_not_after()
            self.__dtNotAfter = self.__m2CryptoUTC2datetime(m2CryptoNotAfter)
                                    
        except Exception, e:
            raise X509CertError, "Not After time: " + str(e)


    #_________________________________________________________________________
    def __getM2CryptoX509(self, m2CryptoX509=None):
        "Return M2Crypto X.509 cert object"
        return self.__m2CryptoX509
    
    
    m2CryptoX509 = property(fset=__setM2CryptoX509,
                            fget=__getM2CryptoX509,
                            doc="M2Crypto.X509.X509 type")

        
    def toString(self, **kw):
        """Return certificate file content as a PEM format 
        string"""
        return self.asPEM(**kw)
        
    def asPEM(self, filePath=None):
        """Return certificate file content as a PEM format 
        string"""
        
        # Check M2Crypto.X509 object has been instantiated - if not call
        # read method
        if self.__m2CryptoX509 is None:
            self.read(filePath)
            
        return self.__m2CryptoX509.as_pem()

        
    def asDER(self):
        """Return certificate file content in DER format"""
        
        # Check M2Crypto.X509 object has been instantiated 
        assert(self.__m2CryptoX509)
        return self.__m2CryptoX509.as_der()

    
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
        """Get public key
        
        @return: RSA public key for certificate
        @rtype: M2Crypto.RSA.RSA_pub"""
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
            raise X509CertError("Not Before datetime is not set")

        if not isinstance(self.__dtNotAfter, datetime):
            raise X509CertError("Not After datetime is not set")
       
        dtNow = datetime.utcnow()

        if raiseExcep:
            if dtNow < self.__dtNotBefore:
                raise X509CertInvalidNotBeforeTime, \
                    "Current time is before the certificate's Not Before Time"
            
            elif dtNow > self.__dtNotAfter:
                raise X509CertExpired, \
                    "Certificate has expired: the time now is %s " % dtNow + \
                    "and the certificate expiry is %s" % self.__dtNotAfter
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
	
    def verify(self, pubKey, **kw):
        """Verify a certificate against the public key of the
        issuer
        
        @param pubKey: public key of cert that issued self
        @type pubKey: M2Crypto.RSA.RSA_pub
        @param **kw: keywords to pass to M2Crypto.X509.X509 -
        'pkey'
        @type: dict
        @return: True if verifies OK, False otherwise
        @rtype: bool
        """
        return bool(self.__m2CryptoX509.verify(pubKey, **kw))

#_____________________________________________________________________________
# Alternative AttCert constructors
#
def X509CertRead(filePath):
    """Create a new X509 certificate read in from a file"""

    x509Cert = X509Cert(filePath=filePath)
    x509Cert.read()
    
    return x509Cert


#_____________________________________________________________________________
def X509CertParse(x509CertTxt):
    """Create a new X509 certificate from string of file content"""

    x509Cert = X509Cert()
    x509Cert.parse(x509CertTxt)
    
    return x509Cert


#_____________________________________________________________________________
class X509StackError(Exception):
    """Error from X509Stack type"""

#_____________________________________________________________________________
class CertIssuerNotFound(X509StackError):
    """Raise from verifyCertChain if no certificate can be found to verify the
    input"""

class SelfSignedCert(X509StackError):
    """Raise from verifyCertChain if cert. is self-signed and 
    rejectSelfSignedCert=True"""
       
#_____________________________________________________________________________
class X509Stack(object):
    """Wrapper for M2Crypto X509_Stack"""
    
    def __init__(self, m2X509Stack=None):
        """Initialise from an M2Crypto stack object
        
        @param m2X509Stack: M2Crypto X.509 stack object
        @type m2X509Stack: M2Crypto.X509.X509_Stack"""
        
        self.__m2X509Stack = m2X509Stack or M2Crypto.X509.X509_Stack()
        
    def __len__(self):
        """@return: length of stack
        @rtype: int"""
        return self.__m2X509Stack.__len__()

    def __getitem__(self, idx):
        """Index stack as an array
        @param idx: stack index
        @type idx: int
        @return: X.509 cert object
        @rtype: ndg.security.common.X509.X509Cert"""
        
        return X509Cert(m2CryptoX509=self.__m2X509Stack.__getitem__(idx))
    
    def __iter__(self):
        """@return: stack iterator
        @rtype: listiterator"""
        return iter([X509Cert(m2CryptoX509=i) for i in self.__m2X509Stack])

    def push(self, x509Cert):
        """Push an X509 certificate onto the stack.
        
        @param x509Cert: X509 object.
        @type x509Cert: M2Crypto.X509.X509,
        ndg.security.common.X509.X509Cert or basestring
        @return: The number of X509 objects currently on the stack.
        @rtype: int"""
        if isinstance(x509Cert, M2Crypto.X509.X509):
            return self.__m2X509Stack.push(x509Cert)
        
        elif isinstance(x509Cert, X509Cert):
            return self.__m2X509Stack.push(x509Cert.m2CryptoX509)
        
        elif isinstance(x509Cert, basestring):
            return self.__m2X509Stack.push(\
                                       X509CertParse(x509Cert).m2CryptoX509)            
        else:
            raise X509StackError, "Expecting M2Crypto.X509.X509, " + \
                "ndg.security.common.X509.X509Cert or string type"
                
    def pop(self):
        """Pop a certificate from the stack.
        
        @return: X509 object that was popped, or None if there is nothing
        to pop.
        @rtype: ndg.security.common.X509.X509Cert
        """
        return X509Cert(m2CryptoX509=self.__m2X509Stack.pop())


    def asDER(self):
        """Return the stack as a DER encoded string
        @return: DER string
        @rtype: string"""
        return self.__m2X509Stack.as_der()


    def verifyCertChain(self, 
                        x509Cert2Verify=None, 
                        caX509Stack=[],
                        rejectSelfSignedCert=True):
        """Treat stack as a list of certificates in a chain of
        trust.  Validate the signatures through to a single root issuer.  

        @param x509Cert2Verify: X.509 certificate to be verified default is
        last in the stack
        @type x509Cert2Verify: X509Cert
        
        @param caX509Stack: X.509 stack containing CA certificates that are
        trusted.
        @type caX509Stack: X509Stack
        
        @param rejectSelfSignedCert: Set to True (default) to raise an 
        SelfSignedCert exception if a certificate in self's stack is 
        self-signed.  
        @type rejectSelfSignedCert: bool"""
        
        n2Validate = len(self)
        if x509Cert2Verify:
            # One more to validate in addition to stack content
            n2Validate += 1
        else:
            # Validate starting from last on stack - but check first that it's
            # populated
            if n2Validate == 0:
                raise X509StackError, \
                "Empty stack and no x509Cert2Verify set: no cert.s to verify"

            x509Cert2Verify = self[-1]
             
                
        # Exit loop if all certs have been validated or if find a self 
        # signed cert.
        nValidated = 0
        issuerX509Cert = None
        while nValidated < n2Validate:                
            issuerX509Cert = None
            issuerDN = x509Cert2Verify.issuer
            
            # Search for issuing certificate in stack
            for x509Cert in self:
                if x509Cert.dn == issuerDN:
                    # Match found - the cert.'s issuer has been found in the 
                    # stack
                    issuerX509Cert = x509Cert
                    break
                    
            if issuerX509Cert:
                # An issuing cert. has been found - use it to check the 
                # signature of the cert. to be verified
                if not x509Cert2Verify.verify(issuerX509Cert.pubKey):
                    X509CertError, 'Signature is invalid for cert. "%s"' % \
                                    x509Cert2Verify.dn
                
                # In the next iteration the issuer cert. will be checked:
                # 1) search for a cert. in the stack that issued it
                # 2) If found use the issuing cert. to verify
                x509Cert2Verify = issuerX509Cert
                nValidated += 1
            else:
                # All certs in the stack have been searched
                break


        if issuerX509Cert:            
            # Check for self-signed certificate
            if nValidated == 1 and rejectSelfSignedCert and \
               issuerX509Cert.dn == issuerX509Cert.issuer:

                # If only one iteration occured then it must be a self
                # signed certificate
                raise SelfSignedCert, "Certificate is self signed"
           
            if not caX509Stack:
                caX509Stack = [issuerX509Cert]
                         
        elif not caX509Stack:
            raise CertIssuerNotFound, \
                    'No issuer cert. found for cert. "%s"'%x509Cert2Verify.dn
            
        for caCert in caX509Stack:
            issuerDN = x509Cert2Verify.issuer
            if caCert.dn == issuerDN:
                issuerX509Cert = caCert
                break
        
        if issuerX509Cert:   
            if not x509Cert2Verify.verify(issuerX509Cert.pubKey):
                X509CertError, 'Signature is invalid for cert. "%s"' % \
                                x509Cert2Verify.dn
            
            # Chain is validated through to CA cert
            return
        else:
            raise CertIssuerNotFound, 'No issuer cert. found for cert. "%s"'%\
                                x509Cert2Verify.dn
        
        # If this point is reached then an issuing cert is missing from the
        # chain        
        raise X509CertError, 'Can\'t find issuer cert "%s" for cert "%s"' % \
                          (x509Cert2Verify.issuer, x509Cert2Verify.dn)  


#_____________________________________________________________________________
def X509StackParseFromDER(derString):
    """Make a new stack from a DER string
    
    @param derString: DER formatted X.509 stack data
    @type derString: string
    @return: new stack object
    @rtype: X509Stack""" 
    return X509Stack(m2X509Stack=M2Crypto.X509.new_stack_from_der(derString))


#_____________________________________________________________________________
class X500DNError(Exception):
    """Exception handling for NDG X.500 DN class."""


#_____________________________________________________________________________
# For use with parseSeparator method:
import re


class X500DN(dict):
    "NDG X500 Distinguished name"
    
    # Class attribute - look-up mapping short name attributes to their long
    # name equivalents
    # * private *
    __shortNameLUT = {  'commonName':               'CN',
                        'organisationalUnitName':   'OU',
                        'organisation':             'O',
                        'countryName':	    	    'C',
                        'emailAddress':             'EMAILADDRESS',
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
            #
            # Hack required here because M2Crypto doesn't
            # correctly separate emailAddress fields e.g.
            #
            # C=SG, ST=Singapore, O=BMTAP Pte Ltd, 
            # OU=Environmental Development, 
            # CN=www.bmtap.com.sg/emailAddress=sjamsul.lakau@bmtasia.com.sg
            #                    ^
            # - The slash is left in place
            #
            # TODO: re-check this for future M2Crypto releases
            dnTxt = ', '.join(m2CryptoX509Name.as_text().split('/'))            
            # End hack
            
            self.deserialise(dnTxt)
            
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

        
    def __ne__(self, x500dn):
        """Return true if the all the fields of the two DNs are equal"""
        
        if not isinstance(x500dn, X500DN):
            return False

        return self.__dat.items() != x500dn.items()

    
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


    def get(self, kw):
        return self.__dat.get(kw)

    
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
     
        dnList = []
        for (key, val) in self.__dat.items():
            if val:
                if isinstance(val, tuple):
                    dnList += [separator.join(["%s=%s" % (key, valSub) \
                                            for valSub in val])]
                else:
                    dnList += ["%s=%s" % (key, val)]
                
        sDN += separator.join(dnList)
                                
        return sDN

    serialize = serialise
    
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
            
            items = [field.split('=') for field in dnFields if field]

            # Reset existing dictionary values
            self.__dat.fromkeys(self.__dat, '')
            
            # Strip leading and trailing space chars and convert into a
            # dictionary
            parsedDN = {}
            for (key, val) in items:
                key = key.strip()
                if key in parsedDN:
                    if isinstance(parsedDN[key], tuple):
                        parsedDN[key] = tuple(list(parsedDN[key]) + [val])                    
                    else:
                        parsedDN[key] = (parsedDN[key], val)
                else:
                    parsedDN[key] = val
                
            # Copy matching DN fields
            for key, val in parsedDN.items():
                if key not in self.__dat and key not in self.__shortNameLUT:
                    raise X500DNError, \
                        "Invalid field \"%s\" in input DN string" % key

                self.__dat[key] = val

                
        except Exception, excep:
            raise X500DNError("Error de-serialising DN \"%s\": %s" % \
                              (dn, str(excep)))

    deserialize = deserialise
    
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
