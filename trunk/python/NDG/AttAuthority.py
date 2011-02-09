"""NDG Attribute Authority handles security authentication and authorization

NERC Data Grid Project

P J Kershaw 15/04/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

reposID = '$Id$'

import types


# Create unique names for attribute certificates
import tempfile
import os

# Alter system path for dynamic import of user roles class
import sys

# For parsing of properties file
import cElementTree as ElementTree

# X509 Certificate handling
from X509 import *

# NDG Attribute Certificate
from AttCert import *

# Format for XML messages passed over WS
from AttAuthorityIO import *


#_____________________________________________________________________________
class AttAuthorityError(Exception):
    """Exception handling for NDG Attribute Authority class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




#_____________________________________________________________________________
class AttAuthorityAccessDenied(AttAuthorityError):
    """NDG Attribute Authority - access denied exception.

    Raise from authorise method where no roles are available for the user
    but that the request is otherwise valid.  In all other error cases raise
    AttAuthorityError"""   
    pass



#_____________________________________________________________________________
class AttAuthority(dict):

    """NDG Attribute Authority - server for user authentication/authorization.
    """

    # Code designed from NERC Data Grid Enterprise and Information Viewpoint
    # documents.
    #
    # Also, draws from Neil Bennett's ACServer class used in the Java
    # implementation of NDG Security

    # valid configuration property keywords
    __validKeys = [ 'name',
                    'keyFile',
                    'keyPwd',
                    'certFile',
                    'caCertFile',
                    'attCertLifeTime',
                    'attCertNotBeforeOff',
                    'attCertFilePfx',
                    'attCertFileSfx',
                    'mapConfigFile',
                    'attCertDir',
                    'dnSeparator',
                    'usrRolesModFilePath',
                    'usrRolesModName',
                    'usrRolesClassName',
                    'usrRolesPropFile']
    
    def __init__(self, propFilePath, bReadMapConfig=True):
        """Create new NDG Attribute Authority instance

        propFilePath:   path to file containing Attribute Authority
                        configuration parameters.
        bReadMapConfig: by default the Map Configuration file is read.  Set
                        this flag to False to override.
        """

        # Base class initialisation
        dict.__init__(self)
        
        if not isinstance(propFilePath, basestring):
            raise AttAuthorityError("Input Properties file path " + \
                                    "must be a valid string.")


        # Initialise role mapping look-ups - These are set in readMapConfig()
        self.__mapConfig = None
        self.__localRole2RemoteRole = None
        self.__remoteRole2LocalRole = None


        # Configuration file properties are held together in a dictionary
        self.__prop = {}

        # Read Attribute Authority Properties file
        self.readProperties(propFilePath)

        # Read the Map Configuration file
        if bReadMapConfig:
            self.readMapConfig()

        # Instantiate Certificate object
        self.__cert = X509Cert(self.__prop['certFile'])
        self.__cert.read()

        # Check it's valid
        try:
            self.__cert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttAuthorityError(\
                    "Attribute Authority's certificate is invalid: " + str(e))
        
        # Check CA certificate
        caCert = X509Cert(self.__prop['caCertFile'])
        caCert.read()
        
        try:
            caCert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttAuthorityError("CA certificate is invalid: " + str(e))
        
        # Issuer details - serialise using the separator string set in the
        # properties file
        self.__issuer = \
            self.__cert.dn.serialise(separator=self.__prop['dnSeparator'])

        self.__issuerSerialNumber = self.__cert.serialNumber

        
        # Set-up user roles interface
        try:
            try:
                # Temporarily extend system path ready for import
                sysPathBak = sys.path[:]
                sys.path.append(self.__prop['usrRolesModFilePath'])
                
                # Import module name specified in properties file
                usrRolesMod = __import__(self.__prop['usrRolesModName'],
                                         globals(),
                                         locals(),
                                         [self.__prop['usrRolesClassName']])
    
                usrRolesClass = eval('usrRolesMod.' + \
                                     self.__prop['usrRolesClassName'])
            finally:
                sys.path[:] = sysPathBak
                                
        except Exception, e:
            raise AttAuthorityError('Importing User Roles module: %s' % e)

        # Check class inherits from AAUserRoles abstract base class
        if not issubclass(usrRolesClass, AAUserRoles):
            raise AttAuthorityError(\
                "User Roles class %s must be derived from AAUserRoles" % \
                self.__prop['usrRolesClassName'])


        # Instantiate custom class
        try:
            self.__usrRoles = usrRolesClass(self.__prop['usrRolesPropFile'])
            
        except Exception, e:
            raise AttAuthorityError(\
                "Error instantiating User Roles interface: " + str(e))
     
        
    #_________________________________________________________________________
    # Methods for Attribute Authority dictionary like behaviour        
    def __delitem__(self, key):
        self.__class__.__name__ + " keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from '+self.__class__.__name__)


    def __getitem__(self, key):
        self.__class__.__name__ + """ behaves as data dictionary of Attribute
        Authority properties
        """
        if key not in self.__prop:
            raise KeyError("Invalid key " + key)
        
        return self.__prop[key]
        

    def clear(self):
        raise KeyError("Data cannot be cleared from "+self.__class__.__name__)
   
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
    def authorise(self,
                  reqXMLtxt=None, 
                  proxyCertFilePath=None,
                  userAttCertFilePath=None,
                  **reqKeys):

        """Request a new Attribute Certificate for authorisation

        reqXMLtxt:              input keywords as tags in formatted XML string
                                String must follow format for 
                                AttAuthorityIO.AuthorisationReq class to
                                parse.
                                
        proxyCertFilePath|proxyCert:

                                user's proxy certificate use appropriate
                                keyword for input as a file path or as the
                                text content respectively.
                                
                                Nb. proxyCert is set via reqKeys
                                
        userAttCertFilePath|userAttCert:
        
                                externally provided attribute certificate
                                from another data centre.  This is only
                                necessary if the user is not registered with
                                this attribute authority.

                                Pass in either the file path or a string
                                containing the certificate XML content.
                                
                                Nb. userAttCert is set via reqKeys
                                """

        if reqXMLtxt is not None:
            # Parse XML text into keywords corresponding to the input
            # parameters
            if not isinstance(reqXMLtxt, basestring):
                raise AttAuthorityError(\
                            "XML Authorisation request must be a string")
                                       
            # Parse and decrypt as necessary
            try:
                # 1st assume that the request was encrypted
                reqKeys = AuthorisationReq(encrXMLtxt=reqXMLtxt,
                                    encrPriKeyFilePath=self.__prop['keyFile'],
                                    encrPriKeyPwd=self.__prop['keyPwd'])
            except Exception, e:
                
                # Error occured decrypting - Trying parsing again, but this 
                # time assuming non-encrypted
                try:
                    reqKeys = AuthorisationReq(xmlTxt=reqXMLtxt)
                    
                except Exception, e:
                    raise AttAuthorityError(\
                        "Error parsing authorisation request: %s" % e)


        # Read proxy certificate
        try:
            usrProxyCert = X509Cert()
            
            if proxyCertFilePath is not None and \
               isinstance(proxyCertFilePath, basestring):

                # Proxy Certificate input as a file 
                usrProxyCert.read(proxyCertFilePath)
                
            elif reqKeys['proxyCert'] is not None:

                # Proxy Certificate input as string text
                usrProxyCert.parse(reqKeys['proxyCert'])

            else:
                raise AttAuthorityError(\
                    "no input proxy certificate file path or file text")
            
        except Exception, e:
            raise AttAuthorityError("User Proxy Certificate: %s" % e)


        # Check proxy certificate hasn't expired
        try:
            usrProxyCert.isValidTime(raiseExcep=True)
            
        except Exception, e:
            raise AttAuthorityError("User Proxy Certificate is invalid: " + \
                                    str(e))

            
        # Get Distinguished name from certificate as an X500DN type
        usrDN = usrProxyCert.dn
        
        
        # Make a new Attribute Certificate instance passing in certificate
        # details for later signing
        #
        # Nb. new attribute certificate file path is created from the
        # Credentials Repository
        certFilePathList = [self.__prop['certFile'],self.__prop['caCertFile']]
        attCert = AttCert(self.__newAttCertFilePath(),
                          signingKeyFilePath=self.__prop['keyFile'],
                          certFilePathList=certFilePathList)


        # Set holder's (user's) Distinguished Name
        try:
            attCert['holder'] = \
                        usrDN.serialise(separator=self.__prop['dnSeparator'])
            
        except Exception, e:
            raise AttAuthorityError("User DN: %s" % e)

        
        # Set Issuer details from Attribute Authority
        issuerDN = self.__cert.dn
        try:
            attCert['issuer'] = \
                    issuerDN.serialise(separator=self.__prop['dnSeparator'])
            
        except Exception, e:
            raise AttAuthorityError("Issuer DN: %s" % e)
        
        attCert['issuerName'] = self.__prop['name']
        attCert['issuerSerialNumber'] = self.__issuerSerialNumber


        # Set validity time
        try:
            attCert.setValidityTime(\
                        lifeTime=self.__prop['attCertLifeTime'],
                        notBeforeOffset=self.__prop['attCertNotBeforeOff'])

            # Check against the proxy certificate's expiry
            dtUsrProxyNotAfter = usrProxyCert.notAfter
            
            if attCert.getValidityNotAfter(asDatetime=True) > \
               dtUsrProxyNotAfter:

                # Adjust the attribute certificate's expiry date time
                # so that it agrees with that of the proxy certificate
                # ... but also make ensure that the not before skew is still
                # applied
                attCert.setValidityTime(dtNotAfter=dtUsrProxyNotAfter,
                        notBeforeOffset=self.__prop['attCertNotBeforeOff'])
            
        except Exception, e:
            raise AttAuthorityError("Error setting validity time: %s" % e)
        

        # Check name is registered with this Attribute Authority - if no
        # user roles are found, the user is not registered
        usrRoles = self.getRoles(str(usrDN))
        if usrRoles:            
            # Set as an Original Certificate
            #
            # User roles found - user is registered with this data centre
            # Add roles for this user for this data centre
            attCert.addRoles(usrRoles)

            # Mark new Attribute Certificate as an original
            attCert['provenance'] = AttCert.origProvenance

        else:            
            # Set as a Mapped Certificate
            #
            # No roles found - user is not registered with this data centre
            # Check for an externally provided certificate from another
            # trusted data centre
            if userAttCertFilePath:
                
                # Read externally provided certificate
                try:
                    extAttCert = AttCertRead(userAttCertFilePath)
                    
                except Exception, e:
                    raise AttAuthorityError(\
                            "Reading external Attribute Certificate: %s" + e)
                                
            elif 'userAttCert' in reqKeys and reqKeys['userAttCert']:
                extAttCert = reqKeys['userAttCert']
                
            else:
                raise AttAuthorityAccessDenied(\
                    "User \"%s\" is not registered " % attCert['holder'] + \
                    "and no external attribute certificate is available " + \
                    "to make a mapping.")


            # Check it's an original certificate - mapped certificates can't
            # be used to make further mappings
            if extAttCert.isMapped():
                raise AttAuthorityError(\
                    "External Attribute Certificate must have an " + \
                    "original provenance in order to make further mappings.")


            # Check it's valid and signed
            try:
                # Give path to CA cert to allow check
                extAttCert.isValid(raiseExcep=True,
                                   certFilePathList=self.__prop['caCertFile'])
                
            except Exception, e:
                raise AttAuthorityError(\
                            "Invalid Remote Attribute Certificate: " + str(e))        


            # Check that's it's holder matches the user certificate DN
            try:
                holderDN = X500DN(dn=extAttCert['holder'])
                
            except Exception, e:
                raise AttAuthorityError(\
                    "Error creating X500DN for holder: %s" + e)
            
            if holderDN != usrDN:
                raise AttAuthorityError(\
                    "User certificate and Attribute Certificate DNs " + \
                    "don't match: " + str(usrDN) + " and " + str(holderDN))
            
  
            # Get roles from external Attribute Certificate
            trustedHostRoles = extAttCert.getRoles()


            # Map external roles to local ones
            localRoles = self.mapRemoteRoles2LocalRoles(\
                                                    extAttCert['issuerName'],
                                                    trustedHostRoles)
            if not localRoles:
                raise AttAuthorityAccessDenied, \
                    "No local roles mapped to the %s roles: %s" % \
                    (extAttCert['issuerName'], ', '.join(trustedHostRoles))

            attCert.addRoles(localRoles)
            
            
            # Mark new Attribute Certificate as mapped
            attCert['provenance'] = AttCert.mappedProvenance

            # End set mapped certificate block
            

        try:
            # Digitally sign certificate using Attribute Authority's
            # certificate and private key
            attCert.sign(signingKeyPwd=self.__prop['keyPwd'])
            
            # Check the certificate is valid
            attCert.isValid(raiseExcep=True)
            
            # Write out certificate to keep a record of it for auditing
            attCert.write()

            # Return the cert to caller
            return attCert
        
        except Exception, e:
            raise AttAuthorityError, "New Attribute Certificate \"%s\": %s" %\
                                    (attCert.filePath, e)
       
        
    #_________________________________________________________________________     
    def readProperties(self, propFilePath=None):

        """Read the configuration properties for the Attribute Authority

        propFilePath: file path to properties file
        """
        
        if propFilePath is not None:
            if not isinstance(propFilePath, basestring):
                raise AttAuthorityError, "Input Properties file path " + \
                                        "must be a valid string."
            
            self.__propFilePath = propFilePath


        try:
            tree = ElementTree.parse(self.__propFilePath)
            
        except IOError, ioErr:
            raise AttAuthorityError, \
                                "Error parsing properties file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror)

        
        aaProp = tree.getroot()
        if aaProp is None:
            raise AttAuthorityError, \
            "Parsing properties file \"%s\": root element is not defined" % \
            self.__propFilePath


        # Copy properties from file into a dictionary
        self.__prop = {}
        missingKeys = []
        try:
            for elem in aaProp:
                if elem.tag in self.__class__.__validKeys:
                
                    if elem.tag != 'keyPwd' and elem.text: 
                        self.__prop[elem.tag] = \
                                        os.path.expandvars(elem.text.strip())
                    else:
                        self.__prop[elem.tag] = elem.text
                else:
                    missingKeys.append(elem.tag)
                
        except Exception, e:
            raise AttAuthorityError, \
                "Error parsing tag \"%s\" in properties file \"%s\": %s" % \
                (elem.tag, self.__propFilePath, e)
 
        if missingKeys != []:
            raise AttAuthorityError, "The following properties are " + \
                                     "missing from the properties file: " + \
                                     ', '.join(missingKeys)
 
        # Ensure Certificate time parameters are converted to numeric type
        self.__prop['attCertLifeTime'] = float(self.__prop['attCertLifeTime'])
        self.__prop['attCertNotBeforeOff'] = \
                                    float(self.__prop['attCertNotBeforeOff'])

        
        # Check directory path
        try:
            dirList = os.listdir(self.__prop['attCertDir'])

        except OSError, osError:
            raise AttAuthorityError, \
                "Invalid directory path Attribute Certificates store: %s" % \
                osError.strerror
       
        
    #_________________________________________________________________________     
    def readMapConfig(self, mapConfigFilePath=None):
        """Parse Map Configuration file.

        mapConfigFilePath:  file path for map configuration file.  If omitted,
                            use member variable __mapConfigFilePath.
        """
        
        if mapConfigFilePath is not None:
            if not isinstance(mapConfigFilePath, basestring):
                raise AttAuthorityError, \
                "Input Map Configuration file path must be a valid string."
            
            self.__prop['mapConfigFile'] = mapConfigFilePath


        try:
            tree = ElementTree.parse(self.__prop['mapConfigFile'])
            rootElem = tree.getroot()
            
        except IOError, e:
            raise AttAuthorityError, \
                            "Error parsing properties file \"%s\": %s" % \
                            (e.filename, e.strerror)
            
        except Exception, e:
            raise AttAuthorityError, \
                "Error parsing Map Configuration file: \"%s\": %s" % \
                (self.__prop['mapConfigFile'], e)

            
        trustedElem = rootElem.findall('trusted')
        if not trustedElem:   
            raise AttAuthorityError, \
            "\"trusted\" tag not found in Map Configuration file \"%s\"" % \
            self.__prop['mapConfigFile']

        # Dictionaries:
        # 1) to hold all the data
        self.__mapConfig = {'thisHost': {}, 'trustedHosts': {}}

        # ... look-up
        # 2) hosts corresponding to a given role and
        # 3) roles of external data centre to this data centre
        self.__localRole2TrustedHost = {}
        self.__localRole2RemoteRole = {}
        self.__remoteRole2LocalRole = {}


        # Information about this host
        try:
            thisHostElem = rootElem.findall('thisHost')[0]
            
        except Exception, e:
            raise AttAuthorityError, \
            "\"thisHost\" tag not found in Map Configuration file \"%s\"" % \
            self.__prop['mapConfigFile']

        try:
            hostName = thisHostElem.attrib.values()[0]
            
        except Exception, e:
            raise AttAuthorityError, "\"name\" attribute of \"thisHost\" " + \
                        "tag not found in Map Configuration file \"%s\"" % \
                        self.__prop['mapConfigFile']


        # hostname is also stored in the AA's config file in the 'name' tag.  
        # Check the two match as the latter is copied into Attribute 
        # Certificates issued by this AA
        #
        # TODO: would be better to rationalise this so that the hostname is 
        # stored in one place only.
        #
        # P J Kershaw 14/06/06
        if hostName != self.__prop['name']:
            raise AttAuthorityError, "\"name\" attribute of \"thisHost\" " + \
                "tag in Map Configuration file doesn't match config file " + \
                "\"name\" tag"
        
        self.__mapConfig['thisHost'][hostName] = \
        {
            'loginURI':     thisHostElem.findtext('loginURI'),
            'wsdl':         thisHostElem.findtext('wsdl')
        }        
        
        
        # Information about trusted hosts
        for elem in trustedElem:

            roleElem = elem.findall('role')
            if not roleElem:
                raise AttAuthorityError("\"role\" tag not found in \"%s\"" % \
                                        self.__prop['mapConfigFile'])

            try:
                trustedHost = elem.attrib.values()[0]
                
            except Exception, e:
                raise AttAuthorityError, \
                                    "Error reading trusted host name: %s" % e

            
            # Add signatureFile and list of roles
            #
            # (Currently Optional) additional tag allows query of the URI
            # where a user would normally login at the trusted host.  Added
            # this feature to allow users to be forwarded to their home site
            # if they are accessing a secure resource and are not 
            # authenticated
            #
            # P J Kershaw 25/05/06
            self.__mapConfig['trustedHosts'][trustedHost] = \
            {
                'loginURI':     elem.findtext('loginURI'),
                'wsdl':         elem.findtext('wsdl'),
                'role':         [dict(i.items()) for i in roleElem]
            }

                    
            self.__localRole2RemoteRole[trustedHost] = {}
            self.__remoteRole2LocalRole[trustedHost] = {}
            
            for role in self.__mapConfig['trustedHosts'][trustedHost]['role']:

                localRole = role['local']
                remoteRole = role['remote']
                
                # Role to host look-up
                if localRole in self.__localRole2TrustedHost:
                    
                    if trustedHost not in \
                       self.__localRole2TrustedHost[localRole]:
                        self.__localRole2TrustedHost[localRole].\
                                                        append(trustedHost)                        
                else:
                    self.__localRole2TrustedHost[localRole] = [trustedHost]


                # Trusted Host to local role and trusted host to trusted role
                # map look-ups
                try:
                    self.__remoteRole2LocalRole[trustedHost][remoteRole].\
                                                            append(localRole)                  
                except KeyError:
                    self.__remoteRole2LocalRole[trustedHost][remoteRole] = \
                                                                [localRole]
                    
                try:
                    self.__localRole2RemoteRole[trustedHost][localRole].\
                                                            append(remoteRole)                  
                except KeyError:
                    self.__localRole2RemoteRole[trustedHost][localRole] = \
                                                                [remoteRole]                  
       
        
    #_________________________________________________________________________     
    def usrIsRegistered(self, usrDN):
        """Check a particular user is registered with the Data Centre that the
        Attribute Authority represents"""
        return self.__usrRoles.usrIsRegistered(usrDN)
       
        
    #_________________________________________________________________________     
    def getRoles(self, dn):
        """Get the roles available to the registered user identified usrDN.
        """

        # Call to AAUserRoles derived class.  Each Attribute Authority
        # should define it's own roles class derived from AAUserRoles to
        # define how roles are accessed
        try:
            return self.__usrRoles.getRoles(dn)

        except Exception, e:
            raise AttAuthorityError("Getting user roles: %s" % e)
       
        
    #_________________________________________________________________________     
    def __getHostInfo(self):
        """Return the host that this Attribute Authority represents: its ID,
        the user login URI and WSDL address.  Call this method via the
        'hostInfo' property"""
        
        return self.__mapConfig['thisHost']
        
    hostInfo = property(fget=__getHostInfo, 
                        doc="Return information about this host")
       
        
    #_________________________________________________________________________     
    def getTrustedHostInfo(self, role=None):
        """Return a dictionary of the hosts that have trust relationships
        with this AA.  The dictionary is indexed by the trusted host name
        and contains WSDL URIs and the roles that map to the
        given input local role.

        If no role is input, return all the AA's trusted hosts with all
        their possible roles

        Returns emoty dictionary if role isn't recognised"""
                                         
        if not self.__localRole2RemoteRole:
            raise AttAuthorityError("Roles to host look-up is not set - " + \
                                    "ensure readMapConfig() has been called.")


        if role is None:
            # No role input - return all trusted hosts with their WSDL URIs
            # and the remote roles they map to
            #
            # Nb. {}.fromkeys([...]).keys() is a fudge to get unique elements
            # from a list i.e. convert the list elements to a dict eliminating
            # duplicated elements and convert the keys bacl into a list.
            trustedHostInfo = dict(\
            [\
                (\
                    k, \
                    {
                        'wsdl':        v['wsdl'], \
                        'loginURI':    v['loginURI'], \
                        'role':        {}.fromkeys(\
                            [\
                                role['remote'] for role in v['role']
                            ]\
                        ).keys()
                    }
                ) for k, v in self.__mapConfig['trustedHosts'].items()
            ])

        else:           
            # Get trusted hosts for given input local role        
            try:
                trustedHosts = self.__localRole2TrustedHost[role]
            except:
                return {}
    
    
            # Get associated WSDL URI and roles for the trusted hosts 
            # identified and return as a dictionary indexed by host name
            trustedHostInfo = dict(\
   [(\
        host, \
        {
            'wsdl':     self.__mapConfig['trustedHosts'][host]['wsdl'],
            'loginURI': self.__mapConfig['trustedHosts'][host]['loginURI'],
            'role':     self.__localRole2RemoteRole[host][role]
        }\
    ) for host in trustedHosts])
                         
        return trustedHostInfo
       
        
    #_________________________________________________________________________     
    def mapRemoteRoles2LocalRoles(self, trustedHost, trustedHostRoles):
        """Map roles of trusted hosts to roles for this data centre

        trustedHost:        name of external trusted data centre
        trustedHostRoles:   list of external roles to map"""

        if not self.__remoteRole2LocalRole:
            raise AttAuthorityError("Roles map is not set - ensure " + \
                                    "readMapConfig() has been called.")


        # Check the host name is a trusted one recorded in the map
        # configuration
        if not self.__remoteRole2LocalRole.has_key(trustedHost):
            return []

        # Add local roles, skipping if no mapping is found
        localRoles = []
        for trustedRole in trustedHostRoles:
            if trustedRole in self.__remoteRole2LocalRole[trustedHost]:
                localRoles.extend(\
                        self.__remoteRole2LocalRole[trustedHost][trustedRole])
                
        return localRoles
       
        
    #_________________________________________________________________________     
    def __newAttCertFilePath(self):
        """Create a new unique attribute certificate file path"""
        
        attCertFd, attCertFilePath = \
                   tempfile.mkstemp(suffix=self.__prop['attCertFileSfx'],
                                    prefix=self.__prop['attCertFilePfx'],
                                    dir=self.__prop['attCertDir'],
                                    text=True)

        # The file is opened - close using the file descriptor returned in the
        # first element of the tuple
        os.close(attCertFd)

        # The file path is the 2nd element
        return attCertFilePath




#_____________________________________________________________________________
class AAUserRolesError(Exception):

    """Exception handling for NDG Attribute Authority User Roles interface
    class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg



#_____________________________________________________________________________
class AAUserRoles:

    """An abstract base class to define the user roles interface to an
    Attribute Authority.

    Each NDG data centre should implement a derived class which implements
    the way user roles are provided to its representative Attribute Authority.
    
    Roles are expected to indexed by user Distinguished Name (DN).  They
    could be stored in a database or file."""

    # User defined class may wish to specify a URI for a database interface or
    # path for a user roles configuration file
    def __init__(self, dbURI=None, filePath=None):
        """User Roles abstract base class - derive from this class to define
        roles interface to Attribute Authority"""
        raise NotImplementedError(\
            self.__init__.__doc__.replace('\n       ',''))


    def usrIsRegistered(self, dn):
        """Derived method should return True if user is known otherwise
        False"""
        raise NotImplementedError(
            self.UserIsRegistered.__doc__.replace('\n       ',''))


    def getRoles(self, dn):
        """Derived method should return the roles for the given user's
        DN or else raise an exception"""
        raise NotImplementedError(
            self.getRoles.__doc__.replace('\n       ',''))
                         