"""NDG wrapper to MyProxy.  Also contains OpenSSLConfigFile class, a
wrapper to the openssl configuration file.

NERC Data Grid Project

P J Kershaw 02/06/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

reposID = '$Id$'

# Use pipes for stdin/stdout for MyProxy commands
import os

# Get hostname to check MyProxy server running on localhost
import socket

# Seeding for random number generator
import time

# Temporaries files created for MyProxy executables I/O
import tempfile

# Call MyProxy executables
from subprocess import *

import re

# Optionally include X509 certificate reading for addUser method
try:
    from X509 import *
except:
    pass

simpleCAdebug = False

# SimpleCA may be called locally or via Web Service
simpleCAImport = False
try:
    # Using SimpleCA service local to current machine
    from SimpleCA import *
    simpleCAImport = True
    if simpleCAdebug:
        print "NDG.SimpleCA loaded"
    
except ImportError, e:
    if simpleCAdebug:
        print "Skipping NDG.SimpleCA: %s" % e
    pass

try:
    # Local SimpleCA not needed - may be using Web Service instead
    from SimpleCAClient import *
    simpleCAImport = True
    if simpleCAdebug:
        print "NDG.SimpleCAClient loaded"
    
except ImportError, e:
    if simpleCAdebug:
        print "Skipping NDG.SimpleCAClient: %s" % e
    pass

if not simpleCAImport:
    raise ImportError(\
        "Either SimpleCA or SimpleCAClient module must be present")


# For parsing of properties file
import cElementTree as ElementTree


#_____________________________________________________________________________
class MyProxyError(Exception):
    
    """Exception handling for NDG MyProxy class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
class MyProxy:
    """NDG wrapper to MyProxy server interface - use to serve proxy
    certificate from user sign on"""

    # valid configuration property keywords
    __validKeys = ['myProxyServer',
                   'gridSecurityDir',
                   'credStorageDir',
                   'openSSLConfFileName',
                   'tmpDir',
                   'path',
                   'proxyCertMaxLifetime',
                   'proxyCertLifetime',
                   'simpleCACltProp',
                   'simpleCASrvProp']

    # For checking whether MyProxy server name is localhost
    __localHostname = socket.gethostname()
    __localHostnames = (__localHostname,
                        __localHostname.split('.')[0],
                        "localhost", 
                        "127.0.0.1")
    
    
    def __init__(self, propFilePath=None, **prop):
        """Initialise proxy certificate generation settings

        propFilePath:   set properties via a configuration file
        prop:           set properties via keywords"""


        self.__prop = {}

        
        # Make a copy of the environment and then reset path restricting for
        # use of MyProxy executables
        #
        # Use copy as direct assingment seems to take a reference to
        # os.environ - if self.__env is changed, so is os.environ
        self.__env = os.environ.copy()

        # Configuration file used to get default subject when generating a
        # new certificate
        self.__openSSLConf = OpenSSLConfigFile()

        
        # Properties set via input keywords
        self.setProperties(**prop)

        # If properties file is set any parameters settings in file will
        # override those set by input keyword
        if propFilePath is not None:
            self.readProperties(propFilePath)
        

        # Grid security directory - environment setting overrides
        if 'GRID_SECURITY_DIR' in self.__env:
            self.__prop['gridSecurityDir'] = self.__env['GRID_SECURITY_DIR']            

            openSSLConfFilePath = os.path.join(self.__prop['gridSecurityDir'],
                                            self.__prop['openSSLConfFileName'])
            
            self.__openSSLConf.setFilePath(openSSLConfFilePath)

        
        if os.environ['GLOBUS_LOCATION'] is None:
            raise MyProxyError(\
                        "Environment variable \"GLOBUS_LOCATION\" is not set")


        # Server host name - environment setting overrides
        if 'MYPROXY_SERVER' in self.__env:
            self.__prop['myProxyServer'] = self.__env['MYPROXY_SERVER'] 


        # Executables - for getDelegation:  
        self.__getDelegExe = "myproxy-get-delegation"

        # ... and for addUser:
        self.__gridCertReqExe = 'openssl'
        self.__adminLoadCredExe = 'myproxy-admin-load-credential'
        self.__userIsRegExe = 'myproxy-admin-query'
           

    #_________________________________________________________________________
    def setProperties(self, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise MyProxyError("Property name \"%s\" is invalid" % key)
                
        self.__prop.update(prop)


        # Update path
        if 'path' in prop:
            self.__env['PATH'] = self.__prop['path']

        # Update openssl conf file path
        if 'gridSecurityDir' in prop or 'openSSLConfFileName' in prop:
            
            openSSLConfFilePath = os.path.join(self.__prop['gridSecurityDir'],
                                            self.__prop['openSSLConfFileName'])
            
            self.__openSSLConf.setFilePath(openSSLConfFilePath)


    #_________________________________________________________________________
    def readProperties(self, propFilePath=None, propElem=None):
        """Read XML properties from a file or cElementTree node
        
        propFilePath|propertiesElem

        propFilePath: set to read from the specified file
        propertiesElem:     set to read beginning from a cElementTree node"""

        if propFilePath is not None:

            try:
                tree = ElementTree.parse(propFilePath)
                propElem = tree.getroot()
                
            except IOError, e:
                raise MyProxyError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror))

                
            except Exception, e:
                raise MyProxyError("Error parsing properties file: %s" % \
                                    str(e))

        if propElem is None:
            raise MyProxyError("Root element for parsing is not defined")


        # Get properties as a data dictionary
        prop = {}
        for elem in propElem:

            # Check for environment variables in file paths
            tagCaps = elem.tag.upper()
            if 'FILE' in tagCaps or 'PATH' in tagCaps or 'DIR' in tagCaps:
                elem.text = os.path.expandvars(elem.text)

            prop[elem.tag] = elem.text
            

        # Check for SimpleCA properties - should be either WS client or
        # local server property settings
        if 'simpleCACltProp' in prop:

            tagElem = propElem.find('simpleCACltProp')
            if not tagElem:
                raise MyProxyError("Tag %s not found in file" % \
                                   'simpleCACltProp')
            
            try:
                simpleCAClt = SimpleCAClient()
                simpleCAClt.readProperties(propElem=tagElem)
                
            except Exception, e:
                raise MyProxyError("Setting SimpleCAClient properties: %s"%e)

            prop['simpleCACltProp'] = simpleCAClt()
            
        elif 'simpleCASrvProp' in prop:

            tagElem = propElem.find('simpleCASrvProp')
            if not tagElem:
                raise MyProxyError("Tag %s not found in file" % \
                                   'simpleCASrvProp')
            
            try:
                simpleCA = SimpleCA()
                simpleCA.readProperties(propElem=tagElem)
                
            except Exception, e:
                raise MyProxyError("Setting SimpleCA properties: %s" % e)

            prop['simpleCASrvProp'] = simpleCA()

        else:
            raise MyProxyError(\
                "Neither %s or %s tags found in properties file" % \
                ('simpleCACltProp', 'simpleCASrvProp'))


        self.setProperties(**prop)


    #_________________________________________________________________________
    def getDelegation(self, userName, passPhrase):
        """Generate a proxy certificate given the MyProxy username and
        passphrase"""

        errMsgTmpl = "Getting delegation for %s: %s"

            
        # Call proxy request command 
        try:
            try:
                # Create a temporary to hold the proxy certificate file output
                proxyCertFile = tempfile.NamedTemporaryFile()

                
                # Set up command + arguments
                #
                # TODO: -s <hostname> arg needed? - MYPROXY_SERVER environment
                # variable is set via __env
                #
                # P J Kershaw 27/06/05
                getDelegCmd = [self.__getDelegExe,
                               '-S',
                               '-s', self.__prop['myProxyServer'],
                               '-l', userName,
                               '-t', str(self.__prop['proxyCertLifetime']),
                               '-o', proxyCertFile.name]

                # Open a pipe to send the pass phrase through stdin - avoid
                # exposing pass phrase as a command line arg for security
                getDelegPipeR, getDelegPipeW = os.pipe()
                os.write(getDelegPipeW, passPhrase)
                
                getDelegProc = Popen(getDelegCmd,
                                     stdin=getDelegPipeR,
                                     stdout=PIPE,
                                     stderr=PIPE,
                                     close_fds=True,
                                     env=self.__env)                
            finally:
                try:
                    os.close(getDelegPipeR)
                    os.close(getDelegPipeW)
                except: pass


            # File must be closed + close_fds set to True above otherwise
            # wait() call will hang                
            if getDelegProc.wait():
                errMsg = getDelegProc.stderr.read()
                raise MyProxyError(errMsg)

            # Get certificate created
            sProxyCert = open(proxyCertFile.name).read()
               
        except IOError, e:               
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except OSError, e:
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except Exception, e:
            raise MyProxyError(errMsgTmpl % (userName, str(e)))


        return sProxyCert


    #_________________________________________________________________________
    def addUser(self,
                userName,
                userPassPhrase,
                cn=None,
                retDN=False,
                caPassPhrase=None,
                caConfigFilePath=None,
                **prop):        
        """Add a new user generating a new certificate and adding it to the
        MyProxy repository

        userName:                       user name or new user - must be unique
                                        to the repository                               
        userPassPhrase:                 pass phrase to be used with the user
                                        name
        cn:                             Common name to be used on the
                                        certificate to be generated
                                
        retDN:                          if set to True, return the
                                        Distinguished Name for the new user.
                                        By default, a dictionary is returned
                                        containing a key, 'keyFile' set to the
                                        text of the private key generated for
                                        the new user.  If retDN is set too,
                                        then an additional key 'dn' will be
                                        included in the dictionary, set to the
                                        DN for the new user.

        caConfigFilePath|caPassPhrase:  pass phrase for SimpleCA's
                                        certificate.  Set via file or direct
                                        string input respectively.  Set here
                                        to override setting [if any] made at
                                        object creation.
        
                                        Passphrase is only required if
                                        SimpleCA is instantiated on the local
                                        machine.  If SimpleCA WS is called no
                                        passphrase is required.
                                
        **prop:                         keywords corresponding to
                                        configuration properties normally set
                                        in properties file.  Set here to
                                        override.
        """

        if not self.__myProxyServerAtLocalHost():
            raise NotImplementedError("addUser method must be called " + \
                                      "with MyProxy server set " + \
                                      "to the local host")
        
        
        # Default Common name to the username
        if cn is None: cn = userName

            
        # Check user name doesn't already exist
        if self.userIsRegistered(userName):
            raise MyProxyError("Username '%s' already exists" % userName)


        self.setProperties(**prop)


        # addUSer returns a dictionary containing the key 'keyFile' which is
        # the text of the private key generated by the certificate request
        # but also, if the retDN input flag is set to True, a key 'dn' set to
        # the distinguished name of the new user
        user = {}


        # Error message prefix for certificate request call
        errMsgTmpl = "Certificate request for new user '%s': %s"


        # Create certificate request and key files as temporary files.  Once
        # the new certificate has been uploaded to the proxy server they may
        # be discarded.
        #
        # Using NamedTemporaryFile, they are deleted when the temp file
        # objects go out of scope
        keyFile = tempfile.NamedTemporaryFile('w', -1, '.pem', 'key-',
                                              self.__prop['tmpDir'])
        certReqFile = tempfile.NamedTemporaryFile('w', -1, '.pem', 'certReq-',
                                                  self.__prop['tmpDir'])


        # Read default DN parameters from the Globud Open SSL configuration
        # file
        reqDN = self.__openSSLConf.getReqDN()

        # Make into a string adding in the Common Name
        reqDnTxt = \
"""%(0.organizationName)s
%(0.organizationalUnitName)s
""" % reqDN + cn + os.linesep


        try:
            try:
                # Open a pipe to send the required DN text in via stdin
                reqDnR, reqDnW = os.pipe()
                os.write(reqDnW, reqDnTxt)

                # Create a temporary file
                addUserTmp = tempfile.NamedTemporaryFile()
                open(addUserTmp.name, 'w').write(userPassPhrase)

                # Files to seed random number generation - this is a loose
                # copy of what grid-cert-request shell script does
                randFile = self.__mkRandTmpFile()
                randFileList = randFile.name + \
                               ":/var/adm/wtmp:/var/log/messages"
                
                # Using openssl command rather than grid-cert-request wrapper
                # as latter doesn't include the command line options needed
                gridCertReqCmd = [self.__gridCertReqExe,
                                  "req",
                                  "-new",
                                  "-keyout", keyFile.name,
                                  "-out", certReqFile.name,
                                  "-passout", "file:" + addUserTmp.name,
                                  "-config", self.__openSSLConf.getFilePath(),
                                  "-rand", randFileList]
                
                gridCertReqProc = Popen(gridCertReqCmd,
                                        stdin=reqDnR,
                                        stdout=PIPE,
                                        stderr=STDOUT,
                                        close_fds=True,
                                        env=self.__env)
                
                if gridCertReqProc.wait():
                    errMsg = gridCertReqProc.stdout.read()
                    raise MyProxyError(errMsg)

            finally:
                try:
                    os.close(reqDnR)
                    os.close(reqDnW)

                    # Read key file into string buffer to be returned
                    user['keyFile'] = open(keyFile.name).read()
                    
                    # Closing temporary files deletes them.
                    addUserTmp.close()
                    randFile.close()
                except: pass
                
        except IOError, e:               
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except OSError, e:
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except Exception, e:
            raise MyProxyError(errMsgTmpl % (userName, e))

        
        # Get the SimpleCA to sign the request - call locally or via WS
        # depending on which properties were set
        # WS call has precedence
        if 'simpleCACltProp' in self.__prop: 

            # Client properties were set - initiate client to SimpleCA web
            # service
            try:
                simpleCAClt = SimpleCAClient(**self.__prop['simpleCACltProp'])
                sCert = simpleCAClt.reqCert(certReqFilePath=certReqFile.name)
                
            except Exception, e:
                raise MyProxyError("Calling SimpleCA WS for user '%s': %s" % \
                                   (userName, e))
            
        elif 'simpleCASrvProp' in self.__prop:
            
            # Server properties were set - Create local instance SimpleCA
            # server
            try:
                simpleCA = SimpleCA(**self.__prop['simpleCASrvProp'])
                sCert = simpleCA.sign(certReqFilePath=certReqFile.name,
                                      configFilePath=caConfigFilePath,
                                      caPassPhrase=caPassPhrase)
                
            except Exception, e:
                raise MyProxyError("Calling SimpleCA for user '%s': %s" % \
                                   (userName, e))
        else:
            raise MyProxyError(\
                "Either Simple CA WS client or Simple CA server must be set")


        # Copy new certificate into temporary file ready for call to load
        # credential
        certFile = tempfile.NamedTemporaryFile('r', -1, '.pem', 'cert-',
                                               self.__prop['tmpDir'])
        try:
            open(certFile.name, "w").write(sCert)
            
        except Exception, e:
            raise MyProxyError(\
                        "Writing certificate temporary file \"%s\": %s" % \
                        (certFile.name, e))
        
        # Upload to MyProxy
        errMsgTmpl = "Uploading certificate to MyProxy for new user '%s': %s"

        adminLoadCredCmd = [self.__adminLoadCredExe,
                            '-l', userName,
                            '-c', certFile.name,
                            '-y', keyFile.name,
                            '-t', str(self.__prop['proxyCertMaxLifetime']),
                            '-s', self.__prop['credStorageDir']]

        try:
            try:
                adminLoadCredProc = Popen(adminLoadCredCmd,
                                          stdout=PIPE,
                                          stderr=STDOUT,
                                          env=self.__env)
                
                if adminLoadCredProc.wait():
                    errMsg = adminLoadCredProc.stdout.read()
                    raise MyProxyError(errMsg)
            finally:
                try:
                    keyFile.close()
                except:
                    pass
                
        except IOError, e:               
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except OSError, e:
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except Exception, e:
            raise MyProxyError(errMsgTmpl % (userName, e))


        if retDN:
            try:
                # Add an additional key to the dictionary output containing
                # the new user's DN
                user['dn'] = X509CertRead(certFile.name).dn.serialise()
                
            except Exception, e:
                raise MyProxyError(\
                    "Error returning DN for new certificate for user: " + \
                    userName)

        return user

    
    #_________________________________________________________________________
    def userIsRegistered(self, userName):
        """Return True if given username is registered in the repository"""
        
        if not self.__myProxyServerAtLocalHost():
            raise NotImplementedError("userIsRegistered method must " + \
                                      "be called with MyProxy server set " + \
                                      "to the local host")
        
        
        errMsgTmpl = "Checking for user '%s': %s"
        userIsRegCmd = [self.__userIsRegExe,
                        '-l', userName,
                        '-s', self.__prop['credStorageDir']]

        try:
            userIsRegProc = Popen(userIsRegCmd, stdout=PIPE, stderr=STDOUT)
            
            if userIsRegProc.wait():
                errMsg = userIsRegProc.stdout.read()
                raise MyProxyError(errMsg)
            
            # Search for text matching expected output for username found
            # Exit status from command seems to be 0 regardless of whether the
            # username is found or not
            outMsg = userIsRegProc.stdout.read()
            if outMsg.find("username: " + userName) != -1:
                return True
            else:
                return False
                                       
        except IOError, e:               
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except OSError, e:
            raise MyProxyError(errMsgTmpl % (userName, e.strerror))
        
        except Exception, e:
            raise MyProxyError(errMsgTmpl % (userName, e))


    #_________________________________________________________________________        
    def __mkRandTmpFile(self):
        """Make a file containing random data to seed the random number
        generator used for the certificate request generation in addUser"""

        randomTmpFile = tempfile.NamedTemporaryFile()

        f = open(randomTmpFile.name, 'w')
        f.write(os.urandom(1000))
        f.write(time.asctime())
        f.write(''.join(os.listdir(tempfile.tempdir)))
        f.write(''.join(os.listdir(os.environ['HOME'])))
        f.close()
        
        return randomTmpFile
    

    #_________________________________________________________________________        
    def __myProxyServerAtLocalHost(self):
        """Check setting for MyProxy server address - if it's not the 
        local machine myproxy-admin-* commands won't work.  This affects
        addUser and userIsRegistered commands"""        
        return self.__prop['myProxyServer'] in self.__class__.__localHostnames
            

    
#_____________________________________________________________________________        
class OpenSSLConfigFile:
    """NDG Wrapper to OpenSSL Configuration file"""
    
    __reqDnRE = '\[ req_distinguished_name \].*\['
    
    def __init__(self, filePath=None):

        self.setFilePath(filePath)

            
    def setFilePath(self, filePath=None):
        """Set file path for OpenSSL configuration file"""
        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise MyProxyError(\
                    "Input Grid Certificate file path must be a string")

            self.__filePath = filePath
                    
            try:
                if not os.access(self.__filePath, os.R_OK):
                    raise MyProxyError("not found or no read access")
                                         
            except Exception, e:
                raise MyProxyError(\
                    "Grid Certificate file path is not valid: \"%s\": %s" % \
                    (self.__filePath, str(e)))


    def getFilePath(self):
        """Get file path for OpenSSL configuration file"""
        return self.__filePath


    def read(self):
        """Read OpenSSL configuration file and return as string"""

        file = open(self.__filePath, 'r')
        fileTxt = file.read()
        file.close()
        
        return fileTxt


    def getReqDN(self):
        """Read Required DN parameters from the configuration file returning
        them in a dictionary"""
        
        # Nb. Match over line boundaries
        reqDnTxt = re.findall(self.__reqDnRE, self.read(), re.S)[0]

        # Separate lines
        reqDnLines = reqDnTxt.split(os.linesep)
        
        # Match the '*_default' entries and make a dictionary
        #
        # Make sure comment lies are omitted - P J Kershaw 22/07/05
        return dict([re.split('_default\s*=\s*', line) for line in reqDnLines\
                     if re.match('[^#].*_default\s*=', line)]) 
