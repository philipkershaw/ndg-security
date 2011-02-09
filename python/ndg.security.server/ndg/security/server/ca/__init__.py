"""NDG Security CA server side code

- acts as a wrapper to Globus SimpleCA.  

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

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

# Certificate request generation
from M2Crypto import X509, BIO, RSA, EVP, m2

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

from ndg.security.common.openssl import OpenSSLConfig


#_____________________________________________________________________________
class SimpleCAError(Exception):
    """Exception handling for NDG SimpleCA class."""


#_____________________________________________________________________________
class SimpleCAPassPhraseError(SimpleCAError):
    """Specific exception for CA pass-phrase check"""


#_____________________________________________________________________________
class SimpleCA(dict):
    """Wrapper to Globus SimpleCA - administer NDG user X.509 Certificates
    
    @type __validKeys: tuple
    @cvar __validKeys: valid configuration property keywords used in file
    and keyword input to __init__ and setProperties()
    
    @type __gridCAConfigFile: string
    @cvar __gridCAConfigFile: name of file containing SSL configuration 
    settings for CA
        
    @type __confDir: string
    @cvar __confDir: configuration directory under $NDGSEC_DIR - default location
    for properties file 
    
    @type __propFileName: string
    @cvar __propFileName: default file name for properties file under 
    __confDir"""

    __validKeys = ( 'portNum',
                    'useSSL',
                    'sslCertFile',
                    'sslKeyFile',
                    'caCertFile',
                    'certFile',
                    'keyFile',
                    'keyPwd',
                    'clntCertFile',
                    'openSSLConfigFilePath',
                    'certLifetimeDays',
                    'certExpiryDate',
                    'certTmpDir',
                    'caCertFile',
                    'chkCAPassphraseExe',
                    'signExe',
                    'path'  )
    
    __gridCASubDir = os.path.join(".globus", "simpleCA")
    __gridCAConfigFile = "grid-ca-ssl.conf"

    __confDir = "conf"
    __propFileName = "simpleCAProperties.xml"


    def __init__(self,
                 propFilePath=None,
                 passphraseFilePath=None,
                 caPassphrase=None,
                 **prop):
        """Initialise environment for calling SimpleCA executables

        SimpleCA([propFilePath=p, ][passphraseFilePath=pp|caPassphrase=cp, ]
                 [ ... ])
         
        @type propFilePath: string       
        @param propFilePath: XML file containing SimpleCA settings.
           
        @type caPassphrase: string
        @param caPassphrase: pass-phrase for SimpleCA's private key.
        
        @type passphraseFilePath: string
        @param passphraseFilePath: alternative to caPassphrase, Set 
        pass-phrase from a file.
                                        
        **prop: optional keywords for SimpleCA settings.  These correspond 
        exactly to the tags in properties file (SimpleCA.__validKeys).  If 
        propFilePath is set, its settings will override those set by these 
        keywords"""


        # Base class initialisation
        dict.__init__(self)


        self.__prop = {}
        self.__dtCertExpiry = None

        
        # Make a copy of the environment and then reset the path to the above
        #
        # Use copy as direct assignment seems to take a reference to
        # os.environ - if self.__env is changed, so is os.environ
        self.__env = os.environ.copy()


        # Set-up parameter names for certificate request
        self.__openSSLConfig = OpenSSLConfig()

        self.setProperties(**prop)

        
        # Set from input or use defaults based or environment variables
        self.setPropFilePath(propFilePath)

        # If properties file is set any parameters settings in file will
        # override those set by input keyword
        self.readProperties()


        # Make config file path default setting if not already set 
        if 'openSSLConfigFilePath' not in self.__prop:
            self.__openSSLConfig.filePath = os.path.join(\
                                                   self.__openSSLConfig.caDir,
                                                   self.__gridCAConfigFile)
            self.__openSSLConfig.read()

            
        if not os.environ.get('GLOBUS_LOCATION'):
            raise SimpleCAError, \
                        "Environment variable \"GLOBUS_LOCATION\" is not set"
       
        
        # Set pass-phrase from file or string input - Check HERE because
        # property settings made by readProperties and setProperties need to
        # be in place first
        if passphraseFilePath is not None:
            try:
                caPassphrase = open(passphraseFilePath).read().strip()
            except Exception, e:
                raise SimpleCAError, "Reading configuration file: %s" % e
        
        self.__caPassphrase = None    
        if caPassphrase is not None:
            self.__setCAPassphrase(caPassphrase)


    #_________________________________________________________________________
    def __call__(self):
        """Return file properties dictionary"""
        return self.__prop


    #_________________________________________________________________________
    # dict derived methods ...
    def __repr__(self):
        """Return file properties dictionary as representation"""
        return repr(self.__prop)

    # Nb. read only - no __setitem__() method
    def __delitem__(self, key):
        "SimpleCA Properties keys cannot be removed"        
        raise KeyError, 'Keys cannot be deleted from ' + \
                            self.__class__.__name__

    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of SimpleCA 
        file properties"""
        
        # Check input key
        if key in self.__prop:
            return self.__prop[key]                
        else:
            raise KeyError, "Property with key '%s' not found" % key
    
    def get(self):
        return self.__prop.get(kw)
        
    def clear(self):
        raise KeyError, "Data cannot be cleared from " + \
                            self.__class__.__name__
    
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


    def __setCAPassphrase(self, caPassphrase):
        """Give this instance the pass-phrase for the SimpleCA"""
        self.chkCAPassphrase(caPassphrase)        
        self.__caPassphrase = caPassphrase
           
    caPassphrase = property(fset=__setCAPassphrase,
                            doc="Enter pass-phrase for Simple CA")


    #_________________________________________________________________________
    def __getOpenSSLConfig(self):
        "Get OpenSSLConfig object property method"
        return self.__openSSLConfig
    
    openSSLConfig = property(fget=__getOpenSSLConfig,
                             doc="OpenSSLConfig object")


    #_________________________________________________________________________
    def setPropFilePath(self, val=None):
        """Set properties file from input or based on environment variable
        settings"""
        if not val:
            if 'NDGSEC_CA_PROPFILEPATH' in os.environ:
                val = os.environ['NDGSEC_CA_PROPFILEPATH']
                
            elif 'NDGSEC_DIR' in os.environ:
                val = os.path.join(os.environ['NDGSEC_DIR'], 
                                   self.__class__.__confDir,
                                   self.__class__.__propFileName)
            else:
                raise AttributeError, 'Unable to set default Session ' + \
                    'Manager properties file path: neither ' + \
                    '"NDGSEC_CA_PROPFILEPATH" or "NDGSEC_DIR" environment ' + \
                    'variables are set'
                
        if not isinstance(val, basestring):
            raise AttributeError, "Input Properties file path " + \
                                  "must be a valid string."
      
        self.__propFilePath = val
        
    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            doc="Set the path to the properties file")   
                            
                            
    #_________________________________________________________________________
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise SimpleCAError, "Property name \"%s\" is invalid" % key
                
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
                raise SimpleCAError, "certExpiryDate has the format " + \
                                    "YYYY mm dd HH MM SS. Year, month, " + \
                                    "day, hour minute, second respectively." 


        if 'openSSLConfigFilePath' in prop:
            self.__openSSLConfig.filePath = prop['openSSLConfigFilePath']
            self.__openSSLConfig.read()
            
            
    #_________________________________________________________________________   
    @staticmethod                               
    def __filtTxt(tag, txt):          
        if isinstance(txt, basestring):
            if txt.isdigit():
                return int(txt)
            
            elif tag != 'keyPwd': 
                # Password may contain leading/trailing spaces
                return os.path.expandvars(txt.strip())
        
        return txt


    #_________________________________________________________________________   
    def readProperties(self, propElem=None):
        """Read the configuration properties for the Certificate Authority
        
        readProperties([propElem=p])

        @type propElem: ElementTree node
        @param propElem: set to read beginning from a ElementTree node.
        If not set, file self.__propFilePath will be read"""      

        if propElem is None:
            try:
                tree = ElementTree.parse(self.__propFilePath)
                propElem = tree.getroot()
                
            except IOError, e:
                raise SimpleCAError, \
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror)

            except Exception, e:
                raise SimpleCAError, "Error parsing properties file: %s" % \
                                    str(e)


        # Read properties into a dictionary
        prop = dict([(elem.tag, self.__filtTxt(elem.tag, elem.text)) \
                     for elem in propElem])

        # Ensure Certificate Lifetime is converted into a numeric type
        if 'certLifetimeDays' in prop and \
           isinstance(prop['certLifetimeDays'], basestring):
            prop['certLifetimeDays'] = eval(prop['certLifetimeDays'])


        # Check for missing properties
        propKeys = prop.keys()
        missingKeys = [key for key in self.__class__.__validKeys \
                       if key not in propKeys]
        if missingKeys != [] and \
           'certExpiryDate' in missingKeys and \
           'certLifetimeDays' in missingKeys:
            raise SimpleCAError, "The following properties are missing " + \
                                 "from the properties file: " + \
                                 ', '.join(missingKeys)
                                
        self.setProperties(**prop)


    def chkCAPassphrase(self, caPassphrase=None):        
        
        if caPassphrase is None:
            caPassphrase = self.__caPassphrase
        else:
            if not isinstance(caPassphrase, basestring):
                raise SimpleCAPassPhraseError, \
                                    "CA Pass-phrase must be a valid string"
                                    
        try:
            priKeyFilePath = self.__openSSLConfig.get('CA_default', 
                                                      'private_key')
            priKeyFile = BIO.File(open(priKeyFilePath))
            
        except Exception, e:
            raise SimpleCAError, \
                        "Reading private key for pass-phrase check: %s" % e
        try:    
            RSA.load_key_bio(priKeyFile,callback=lambda *ar,**kw:caPassphrase)
        except:
            raise SimpleCAPassPhraseError, "Invalid pass-phrase"
            
            
    #_________________________________________________________________________
    def OldchkCAPassphrase(self, caPassphrase=None):
        """Check given pass-phrase is correct for CA private key
        
        This method allows checking of the pass-phrase without having to
        call sign() to sign a new certificate.  It makes use of an openssl
        call where the pass-phrase is required - creation of a CRL
        (Certificate Revokation List)"""
        
        
        if caPassphrase is None:
            caPassphrase = self.__caPassphrase
        else:
            if not isinstance(caPassphrase, basestring):
                raise SimpleCAPassPhraseError, \
                                    "CA Pass-phrase must be a valid string"
        
        chkCAPassphraseCmd = [
            self.__prop['chkCAPassphraseExe'],
            'ca',
            '-config',  self.__openSSLConfig.filePath,
            '-gencrl',
            '-passin', 'stdin']

        errMsgTmpl = "Verifying CA pass-phrase: %s"

        
        # Create sign new certificate using grid-ca-sign
        try:
            try:
                # open pipe to pass to stdin
                chkCAPassphraseR, chkCAPassphraseW = os.pipe()
                os.write(chkCAPassphraseW, caPassphrase)
                
                chkCAPassphraseProc = Popen(chkCAPassphraseCmd,
                                           stdin=chkCAPassphraseR,
                                           stdout=PIPE,
                                           stderr=STDOUT,
                                           close_fds=True)
            finally:
                try:
                    os.close(chkCAPassphraseR)
                    os.close(chkCAPassphraseW)
                except: pass


            # File must be closed + close_fds set to True above otherwise
            # wait() call will hang                
            if chkCAPassphraseProc.wait():
                errMsg = chkCAPassphraseProc.stdout.read()
            else:
                errMsg = None
                                        
        except IOError, e:               
            raise SimpleCAError, errMsgTmpl % e.strerror
        
        except OSError, e:
            raise SimpleCAError, errMsgTmpl % e.strerror
       
        except Exception, e:
            raise SimpleCAError, errMsgTmpl % e
        
        
        if errMsg is not None:
            raise SimpleCAPassPhraseError, errMsg
                 
                 
    #_________________________________________________________________________        
    def _createCertReq(self, CN, nBitsForKey=1024, messageDigest="md5"):
        """
        Create a certificate request.
        
        @param CN: Common Name for certificate - effectively the same as the
        username for the MyProxy credential
        @param nBitsForKey: number of bits for private key generation - 
        default is 1024
        @param messageDigest: message disgest type - default is MD5
        @return tuple of certificate request PEM text and private key PEM text
        """
        
        # Check all required certifcate request DN parameters are set                
        # Create certificate request
        req = X509.Request()
    
        # Generate keys
        key = RSA.gen_key(nBitsForKey, m2.RSA_F4)
    
        # Create public key object
        pubKey = EVP.PKey()
        pubKey.assign_rsa(key)
        
        # Add the public key to the request
        req.set_version(0)
        req.set_pubkey(pubKey)
        
        defaultReqDN = self.__openSSLConfig.reqDN        
            
        # Set DN
        x509Name = X509.X509_Name()
        x509Name.CN = CN
        x509Name.OU = defaultReqDN['OU']
        x509Name.O = defaultReqDN['O']
                        
        req.set_subject_name(x509Name)
        
        req.sign(pubKey, messageDigest)
        
        return req, key


    #_________________________________________________________________________
    def sign(self,
             passphraseFilePath=None,
             caPassphrase=None,
             certReq=None,
             certReqFilePath=None,
             CN=None,
             **createCertReqKw):
        
        """Sign a certificate request

        @type caPassphrase: string
        @param caPassphrase: pass-phrase for SimpleCA's private key.
        
        @type passphraseFilePath: string
        @param passphraseFilePath: alternative to caPassphrase, Set 
        pass-phrase from a file.
       
        @type CN: string
        @param CN: common name component of Distinguished Name for new
        cert.  This keyword is ignored if certReq keyword is set.

        @type certReq: M2Crypto.X509.Request
        @param certReq: certificate request
        
        @type **createCertReqKw: dict
        @param **createCertReqKw: keywords to call to _createCertReq - only
        applies if certReq is not set.
        
        @rtype: tuple
        @return: signed certificate and private key.  Private key will be 
        None if certReq keyword was passed in
        """
        
        # Set pass phrase via from file        
        if passphraseFilePath is not None:
            try:
                caPassphrase = open(passphraseFilePath).read().strip()
            except Exception, e:
                raise SimpleCAError, "Reading pass-phrase file: " + str(e)

        # ... or from string input
        if caPassphrase is not None:
            self.__setCAPassphrase(caPassphrase)
            
        if self.__caPassphrase is None:
            raise SimpleCAError, "CA Pass-phrase must be set in order to " + \
                                "sign a certificate request"


        priKey = None
                
        if certReq is not None:
            if isinstance(certReq, X509.Request):
                certReq = certReq.as_pem()
                
            elif not isinstance(certReq, basestring):
                raise SimpleCAError, "certReq input must be a valid string"

        elif certReqFilePath is not None:

            # Certificate request has been input as a file - check it
            if not isinstance(certReqFilePath, basestring):
                raise SimpleCAError, \
                    "certReqFilePath input must be a valid string"           
        elif CN is not None:
            
            certReq, priKey = self._createCertReq(CN, **createCertReqKw)
            certReq = certReq.as_pem()
        else:
            # The certificate request must be input via either of the 
            # options above
            raise SimpleCAError, "No input Certificate Request provided"


        if certReqFilePath is None:
            # Certificate request has been passed in as a string or 
            # X509.Request object - write it to a temporary file for input 
            # into the grid-ca-sign executable
            certReqFile = tempfile.NamedTemporaryFile('w', -1, '.pem',
                                                    'certReq-',
                                                    self.__prop['certTmpDir'])
            
            open(certReqFile.name, 'w').write(certReq)
            certReqFilePath = certReqFile.name
       
       
        # If no expiry date was set, use life time in days parameter
        if self.__dtCertExpiry is None:
            if 'certLifetimeDays' not in self.__prop:
                raise SimpleCAError, "No certLifetimeDays parameter set"
                
            self.__dtCertExpiry = datetime.utcnow() + \
                            timedelta(days=self.__prop['certLifetimeDays'])


        certFile = tempfile.NamedTemporaryFile('w', -1, '.pem', 'cert-',
                                               self.__prop['certTmpDir'])

	req = X509.load_request(certReqFilePath)
        priKeyFilePath = self.__openSSLConfig.get('CA_default', 'private_key')
        pwdCallback = lambda *ar, **kw: self.__caPassphrase
        priKey = EVP.load_key(priKeyFilePath, callback=pwdCallback)

        try:
            cert = req.sign(priKey, 'sha1')
        except Exception, e:
	    raise SimpleCAError, str(e)

        gridCASignCmd = [
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
                gridCASignR, gridCASignW = os.pipe()
                os.write(gridCASignW, self.__caPassphrase)
                
                gridCaSignProc = Popen(gridCASignCmd,
                                       stdin=gridCASignR,
                                       stdout=PIPE,
                                       stderr=STDOUT,
                                       close_fds=True)
            finally:
                try:
                    os.close(gridCASignR)
                    os.close(gridCASignW)
                except: pass


            # File must be closed + close_fds set to True above otherwise
            # wait() call will hang                
            if gridCaSignProc.wait():
                errMsg = gridCaSignProc.stdout.read()
                raise SimpleCAError, errMsg
                                        
        except IOError, e:               
            raise SimpleCAError, errMsgTmpl % e.strerror
        
        except OSError, e:
            raise SimpleCAError, errMsgTmpl % e.strerror
        
        except Exception, e:
            raise SimpleCAError, errMsgTmpl % e


        try:
            # Return the certificate file content
            return open(certFile.name).read(), priKey

        except Exception, e:
            raise SimpleCAError, \
            "Reading output certificate file \"%s\": %s" % (certFile.name, e)


    #_________________________________________________________________________
    def revokeCert(self):
        """Revoke an existing certificate"""
     
     
    #_________________________________________________________________________   
    def genCRL(self):
        """Generate a Certificate Revocation List"""
