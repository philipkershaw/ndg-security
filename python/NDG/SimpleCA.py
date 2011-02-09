"""NDG wrapper to Globus SimpleCA.  

NERC Data Grid Project

P J Kershaw 02/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

# Call Globus SimpleCA executables
from subprocess import *

# Use pipes for stdin/stdout for MyProxy commands
import os

# Certificate lifetime calculation for MyProxy
from datetime import datetime
from datetime import timedelta
from time import strptime

# Temporaries files created for SimpleCA executables I/O
import tempfile

# Get list of certificate files
from glob import glob

# For parsing of properties file
import cElementTree as ElementTree




#_____________________________________________________________________________
class SimpleCAError(Exception):
    
    """Exception handling for NDG SimpleCA class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class SimpleCAPassPhraseError(SimpleCAError):
    """Specific exception for CA pass-phrase check"""
    pass


#_____________________________________________________________________________
class SimpleCA(dict):
    """Wrapper to Globus SimpleCA - administer NDG user X.509 Certificates"""

    # valid configuration property keywords
    __validKeys = [ 'certLifetimeDays',
                    'certExpiryDate',
                    'certTmpDir',
                    'caCertFile',
                    'chkCAPassPhraseExe',
                    'signExe',
                    'path'  ]
    
    __gridCASubDir = ".globus/simpleCA"
    __gridCAConfigFile = "grid-ca-ssl.conf"


    def __init__(self,
                 propFilePath=None,
                 configFilePath=None,
                 caPassPhrase=None,
                 **prop):
        """Initialise environment for calling SimpleCA executables

        propFilePath:                   XML file containing SimpleCA
                                        settings.
                                        
        configFilePath|caPassPhrase:    pass phrase for SimpleCA's certificate.
                                        Set via file or direct string input
                                        respectively.
                                        
        **prop:                         optional keywords for SimpleCA
                                        settings.  These correspond exactly to
                                        the tags in properties file.  If the
                                        later is set, its settings will
                                        override those set by keyword"""


        # Base class initialisation
        dict.__init__(self)


        self.__prop = {}
        self.__dtCertExpiry = None
        
        # Set pass-phrase from file or string input
        if configFilePath is not None:
            try:
                caPassPhrase = open(configFilePath).read().strip()
            except Exception, e:
                raise SimpleCAError("Reading configuration file: %s" % e)
            
        if caPassPhrase is not None:
            self.__setCAPassPhrase(caPassPhrase)

        
        # Make a copy of the environment and then reset the path to the above
        #
        # Use copy as direct assignment seems to take a reference to
        # os.environ - if self.__env is changed, so is os.environ
        self.__env = os.environ.copy()

        self.setProperties(**prop)


        # If properties file is set any parameters settings in file will
        # override those set by input keyword
        if propFilePath is not None:
            self.readProperties(propFilePath)

        
        if not 'GLOBUS_LOCATION' in os.environ or \
           not os.environ['GLOBUS_LOCATION']:
            raise SimpleCAError(\
                "Environment variable \"GLOBUS_LOCATION\" is not set")


        # Set-up CA directory - use in chkCAPassPhrase()
        if not 'HOME' in os.environ or not os.environ['HOME']:
            raise SimpleCAError(\
                "Environment variable \"HOME\" is not set")
                
        self.__gridCAConfigFilePath = os.path.join(os.environ['HOME'], 
                                                   self.__gridCASubDir,
                                                   self.__gridCAConfigFile)


    #_________________________________________________________________________
    def __call__(self):
        """Return file properties dictionary"""
        return self.__prop


    #_________________________________________________________________________
    # dict derived methods ...
    #
    # Nb. read only - no __setitem__() method
    def __delitem__(self, key):
        "SimpleCA Properties keys cannot be removed"        
        raise SimpleCAError('Keys cannot be deleted from ' + \
                            self.__class__.__name__)

    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of SimpleCA 
        file properties"""
        
        # Check input key
        if key in self.__prop:
            return self.__prop[key]                
        else:
            raise SimpleCAError("Property with key '%s' not found" % key)
        
    def clear(self):
        raise SimpleCAError("Data cannot be cleared from " + \
                            self.__class__.__name__)
    
    def keys(self):
        return self.__prop.keys()

    def items(self):
        return self.__prop.items()

    def values(self):
        return self.__prop.values()

    def has_key(self, key):
        return self.__prop.has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return key in self.__prop

    #_________________________________________________________________________
    # End of dict derived methods <--


    def __setCAPassPhrase(self, caPassPhrase):
        """Give this instance the pass-phrase for the SimpleCA"""
        self.chkCAPassPhrase(caPassPhrase)        
        self.__caPassPhrase = caPassPhrase
           
    caPassPhrase = property(fset=__setCAPassPhrase,
                            doc="Enter pass-phrase for Simple CA")
                            
                            
    #_________________________________________________________________________
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise SimpleCAError("Property name \"%s\" is invalid" % key)
                
        self.__prop.update(prop)


        # Update path
        if 'path' in prop:
            self.__env['PATH'] = self.__prop['path']


        # Set expiry date as datetime type
        if 'certExpiryDate' in prop:
            try:
                self.__dtCertExpiry = strptime(prop['certExpiryDate'],
                                               "%Y %m %d %H %M %S")
                
                return datetime(*self.__dtCertExpiry[0:6])
            
            except Exception, e:
                raise SimpleCAError("certExpiryDate has the format " + \
                                    "YYYY mm dd HH MM SS. Year, month, " + \
                                    "day, hour minute, second respectively.")           


    #_________________________________________________________________________   
    def readProperties(self, propFilePath=None, propElem=None):

        """Read the configuration properties for the Attribute Authority
        
        propFilePath|propertiesElem

        propFilePath: set to read from the specified file
        propertiesElem:     set to read beginning from a cElementTree node"""      

        if propFilePath is not None:

            try:
                tree = ElementTree.parse(propFilePath)
                propElem = tree.getroot()
                
            except IOError, e:
                raise SimpleCAError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror))

            except Exception, e:
                raise SimpleCAError("Error parsing properties file: %s" % \
                                    str(e))

        if propElem is None:
            raise SimpleCAError("Root element for parsing is not defined")


        # Read properties into a dictionary
        prop = dict([(elem.tag, elem.text) for elem in propElem])

        # Ensure Certificate Lifetime is converted into a numeric type
        if 'certLifetimeDays' in prop and \
           isinstance(prop['certLifetimeDays'], basestring):
            prop['certLifetimeDays'] = eval(prop['certLifetimeDays'])


        # Check for missing properties
        propKeys = prop.keys()
        missingKeys = [key for key in SimpleCA.__validKeys \
                       if key not in propKeys]
        if missingKeys != [] and \
           'certExpiryDate' in missingKeys and \
           'certLifetimeDays' in missingKeys:
            raise SimpleCAError("The following properties are missing " + \
                                "from the properties file: " + \
                                ', '.join(missingKeys))
                                
        self.setProperties(**prop)


    #_________________________________________________________________________
    def chkCAPassPhrase(self, caPassPhrase=None):
        """Check given pass-phrase is correct for CA private key
        
        This method allows checking of the pass-phrase without having to
        call sign() to sign a new certificate.  It makes use of an openssl
        call where the pass-phrase is required - creation of a CRL
        (Certificate Revokation List)"""
        
        
        if caPassPhrase is None:
            caPassPhrase = self.__caPassPhrase
        else:
            if not isinstance(caPassPhrase, basestring):
                raise SimpleCAError("CA Pass-phrase must be a valid string")
        
        chkCAPassPhraseCmd = [
            self.__prop['chkCAPassPhraseExe'],
            'ca',
            '-config',  self.__gridCAConfigFilePath,
            '-gencrl',
            '-passin', 'stdin']

        errMsgTmpl = "Verifying CA pass-phrase: %s"

        
        # Create sign new certificate using grid-ca-sign
        try:
            try:
                # open pipe to pass to stdin
                chkCAPassPhraseR, chkCAPassPhraseW = os.pipe()
                os.write(chkCAPassPhraseW, caPassPhrase)
                
                chkCAPassPhraseProc = Popen(chkCAPassPhraseCmd,
                                       stdin=chkCAPassPhraseR,
                                       stdout=PIPE,
                                       stderr=STDOUT,
                                       close_fds=True)
            finally:
                try:
                    os.close(chkCAPassPhraseR)
                    os.close(chkCAPassPhraseW)
                except: pass


            # File must be closed + close_fds set to True above otherwise
            # wait() call will hang                
            if chkCAPassPhraseProc.wait():
                errMsg = chkCAPassPhraseProc.stdout.read()
            else:
                errMsg = None
                                        
        except IOError, e:               
            raise SimpleCAError(errMsgTmpl % e.strerror)
        
        except OSError, e:
            raise SimpleCAError(errMsgTmpl % e.strerror)
       
        except Exception, e:
            raise SimpleCAError(errMsgTmpl % e)
        
        
        if errMsg is not None:
            raise SimpleCAPassPhraseError(errMsg)


    #_________________________________________________________________________
    def sign(self,
             certReq=None,
             certReqFilePath=None,
             configFilePath=None,
             caPassPhrase=None,
             **prop):
        
        """Sign a certificate request

        certReq|certReqFilePath:        pass certReq - the string text of the
                                        certificate request or else the path
                                        to a file containing the certificate
                                        request
        configFilePath|caPassPhrase:    pass phrase for SimpleCA's 
                                        certificate.
                                        Set via file or direct string input
                                        respectively.  Set here to override
                                        setting [if any] made at object
                                        creation.
        **prop:                         keywords corresponding to properties
                                        file parameters.  Set these to
                                        override previous settings
        """

        # Set pass phrase via from file        
        if configFilePath is not None:
            try:
                caPassPhrase = open(configFilePath).read().strip()
            except Exception, e:
                raise SimpleCAError("Reading configuration file: " + str(e))

        # ... or from string input
        if caPassPhrase is not None:
            self.__setCAPassPhrase(caPassPhrase)
            
        if self.__caPassPhrase is None:
            raise SimpleCAError("CA Pass-phrase must be set in order to " + \
                                "sign a certificate request")

        
        if certReq is not None:
            if not isinstance(certReq, basestring):
                raise SimpleCAError("certReq input must be a valid string")

            # Certificate request has been passed in a string - write it to
            # a temporary file for input into the grid-ca-sign executable
            certReqFile = tempfile.NamedTemporaryFile('w', -1, '.pem',
                                                    'certReq-',
                                                    self.__prop['certTmpDir'])
            
            open(certReqFile.name, 'w').write(certReq)
            certReqFilePath = certReqFile.name

        elif certReqFilePath is not None:

            # Certificate request has been input as a file - check it
            if not isinstance(certReqFilePath, basestring):
                raise SimpleCAError(\
                    "certReqFilePath input must be a valid string")           
        else:
            # The certificate request msut be input via either of the two
            # options above
            raise SimpleCAError("No input Certificate Request provided")

        
        # If no expiry date was set, use life time in days parameter
        if self.__dtCertExpiry is None:
            if 'certLifetimeDays' not in self.__prop:
                raise SimpleCAError("No certLifetimeDays parameter set")
                
            self.__dtCertExpiry = datetime.utcnow() + \
                            timedelta(days=self.__prop['certLifetimeDays'])


        certFile = tempfile.NamedTemporaryFile('w', -1, '.pem', 'cert-',
                                               self.__prop['certTmpDir'])

        gridCaSignCmd = [
            self.__prop['signExe'],
            '-in',  certReqFilePath,
            '-out', certFile.name,
            '-enddate', self.__dtCertExpiry.strftime("%y%m%d%H%M%SZ"),
            '-passin', 'stdin',
            '-force']

        errMsgTmpl = "Signing certificate request: %s"

        
        # Create sign new certificate using grid-ca-sign
        try:
            try:
                # open pipe to pass to stdin
                gridCaSignR, gridCaSignW = os.pipe()
                os.write(gridCaSignW, self.__caPassPhrase)
                
                gridCaSignProc = Popen(gridCaSignCmd,
                                       stdin=gridCaSignR,
                                       stdout=PIPE,
                                       stderr=STDOUT,
                                       close_fds=True)
            finally:
                try:
                    os.close(gridCaSignR)
                    os.close(gridCaSignW)
                except: pass


            # File must be closed + close_fds set to True above otherwise
            # wait() call will hang                
            if gridCaSignProc.wait():
                errMsg = gridCaSignProc.stdout.read()
                raise SimpleCAError(errMsg)
                                        
        except IOError, e:               
            raise SimpleCAError(errMsgTmpl % e.strerror)
        
        except OSError, e:
            raise SimpleCAError(errMsgTmpl % e.strerror)
        
        except Exception, e:
            raise SimpleCAError(errMsgTmpl % e)


        try:
            # Return the certificate file content
            return open(certFile.name).read()

        except Exception, e:
            raise SimpleCAError(
            "Reading output certificate file \"%s\": %s" % (certFile.name, e))

            
def simpleCATest():
    sCA = SimpleCA()