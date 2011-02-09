"""NDG Gatekeeper - A PDP (Policy Decision Point) determines whether
a given Attribute Certificate can access a given resource.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/05/06"
__copyright__ = "(C) 2007 STFC & NERC"
__contact__ = "P.J.Kershaw@rl.ac.uk"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id:gatekeeper.py 3079 2007-11-30 09:39:46Z pjkersha $"

import logging
log = logging.getLogger(__name__)

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

# Alter system path for dynamic import of resource interface class
import sys

# Expand environment vars in paths
import os

from ndg.security.common.AttCert import *


#_____________________________________________________________________________
class GatekeeperError(Exception):
    """Exception handling for NDG Gatekeeper class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg

            
#_____________________________________________________________________________
class Gatekeeper(object):
    """NDG Gatekeeper class - determines whether a given Attribute 
    Certificate can access a given resource."""
    
    __validKeys = ( 'resrcID',
                    'resrcModFilePath',
                    'resrcModName',
                    'resrcClassName',
                    'resrcPropFile',
                    'caCertFilePath')
    
    #_________________________________________________________________________
    def __init__(self, propFilePath=None, **prop):
         
        self.__propFilePath = propFilePath               
        self.__resrcObj = None
        self.__prop = {}.fromkeys(self.__validKeys)
        
        if propFilePath:
            self.readProperties(propFilePath)
            
        # Any keywords set will override equivalent file property settings
        if prop:
            invalidKeys = [key for key in prop if key not in self.__validKeys]
            if invalidKeys:
                raise GatekeeperError("Invalid property or properties: " + \
                                      ", ".join(invalidKeys))
            self.__prop.update(prop)
            
            
        if max(self.__prop.values()) is not None:
            # Initialize if all required resource URI class properties are set
            self.initResrcInterface()
       
        
    #_________________________________________________________________________
    def initResrcInterface(self):
        """Set-up Resource URI interface to Gatekeeper"""
        
        try:
            try:
                # Temporarily extend system path ready for import
                sysPathBak = sys.path[:]
                sys.path.append(self.__prop['resrcModFilePath'])
                
                # Import module name specified in properties file
                resrcMod = __import__(self.__prop['resrcModName'],
                                      globals(),
                                      locals(),
                                      [self.__prop['resrcClassName']])
    
                resrcClass = eval('resrcMod.' + self.__prop['resrcClassName'])
                
            finally:
                sys.path[:] = sysPathBak
                                
        except KeyError, e:
            raise GatekeeperError(\
                'Importing Resource URI module, key not recognised: %s' % e)
                                
        except Exception, e:
            raise GatekeeperError('Importing Resource URI module: %s' % e)


        # Check class inherits from GatekeeperResrc abstract base class
        if not issubclass(resrcClass, GatekeeperResrc):
            raise GatekeeperError, \
                "Resource interface class %s must be derived from " % \
                self.__prop['resrcClassName'] + "GatekeeperResrc"


        # Instantiate custom class
        try:
            self.__resrcObj = resrcClass(\
                                    resrcID=self.__prop['resrcID'],
                                    filePath=self.__prop['resrcPropFile'])            
        except Exception, e:
            raise GatekeeperError(\
                "Error instantiating Resource URI interface: " + str(e))


    #_________________________________________________________________________
    def readProperties(self, propFilePath=None):

        """Read the configuration properties for the Attribute Authority

        propFilePath: file path to properties file
        """
        
        if propFilePath is not None:
            if not isinstance(propFilePath, basestring):
                raise GatekeeperError("Input Properties file path " + \
                                        "must be a valid string.")
            
            self.__propFilePath = propFilePath


        try:
            elems = ElementTree.parse(self.__propFilePath).getroot()
            
        except IOError, ioErr:
            raise GatekeeperError(\
                                "Error parsing properties file \"%s\": %s" % \
                                (ioErr.filename, ioErr.strerror))
                                
        # Copy properties from file as dictionary
        #
        # Nb. # Allow for environment variables in paths
        self.__prop.update(dict([(elem.tag, 
                                  os.path.expandvars(elem.text.strip())) \
                                 for elem in elems if elem.text is not None]))


        # Check for missing properties
        propKeys = self.__prop.keys()
        missingKeys = [key for key in Gatekeeper.__validKeys \
                       if key not in propKeys]
        if missingKeys != []:
            raise GatekeeperError("The following properties are " + \
                                  "missing from the properties file: " + \
                                  ', '.join(missingKeys))


    def __formatInput(self, input):
        """Convert generic input into a list of roles - use with access
        routines"""
        
        if isinstance(input, list):
            # Input is list of roles
            return input
              
        elif isinstance(input, basestring):
            # Input is a role
            return [input]
            
        elif isinstance(input, AttCert):
            # Input is an Attribute Certificate
            # Check signature of AttCert
            try:
                input.isValid(raiseExcep=True, 
                              certFilePathList=self.__prop['caCertFilePath'])
            except Exception, e:
                raise GatekeeperError, "Access denied for input: %s" % str(e)
            
            return input.roles
        else:
            raise GatekeeperError("Input must be a role, role list or " + \
                                  "Attribute Certificate type")

   
    #_________________________________________________________________________
    def __call__(self, input):
        """Get the permissions for the input file, list of roles or 
        Attribute Certificate containing roles.  A Dictionary of permissions
        are returned indexed by role name.  Permissions are expressed as a 
        tuple containing the relevant permissions flags e.g. ('r', 'w', 'x')
        for read/write/execute permission or e.g. ('x') for exceute only
        permission"""
        
        roleList = self.__formatInput(input)
                                      
        return dict([(role, self.__resrcObj.getPermissions(role)) \
                     for role in roleList])
        
    
    getPermissions = __call__
    
    
    #_________________________________________________________________________
    def readAccess(self, input):
        """Determine read access permitted against the given
        input role/role list or Attribute Certificate roles
        
        Return a dictionary of booleans for access granted/denied keyed
        by role name"""
        
        roleList = self.__formatInput(input)
        
        return dict([(role, self.__resrcObj.readAccess(role)) \
                     for role in roleList])
    
    
    #_________________________________________________________________________
    def writeAccess(self, input):
        """Determine write access permitted against the given
        input role/role list or Attribute Certificate roles
        
        Return a dictionary of booleans for access granted/denied keyed
        by role name"""
        
        roleList = self.__formatInput(input)
        
        return dict([(role, self.__resrcObj.writeAccess(role)) \
                     for role in roleList])
    
    
    #_________________________________________________________________________
    def executeAccess(self, input):
        """Determine execute access permitted against the given
        input role/role list or Attribute Certificate roles
        
        Return a dictionary of booleans for access granted/denied keyed
        by role name"""
        
        roleList = self.__formatInput(input)
        
        return dict([(role, self.__resrcObj.executeAccess(role)) \
                     for role in roleList])
                     

#_____________________________________________________________________________
class GatekeeperResrcError(GatekeeperError):
    """Exception handling for NDG Gatekeeper Resource interface class
    class."""
    pass


#_____________________________________________________________________________
class GatekeeperResrc:
    """An abstract base class to define the resource -> role interface 
    for the Gatekeeper.

    Each NDG resource should implement a derived class which implements
    the way a resource roles is served from the given resource."""

    # User defined class may wish to specify a URI or path for a configuration
    # file
    def __init__(self, resrcID=None, filePath=None):
        """Abstract base class - derive from this class to define
        resource role interface to Gatekeeper"""
        raise NotImplementedError(\
            self.__init__.__doc__.replace('\n       ',''))
    

    def getPermissions(self, role):
        """Derived method should return the permissions for the given resource
        role.  Format is a tuple e.g.
            
        ('r', 'w', 'x'): read, write and execute permission granted for this
                         role
        ():              access denied
        ('r',):          read only access
        ('r', 'x'):      read and execute permission granted
        
        This method is needed for the interface to the Gatekeeper class"""
        raise NotImplementedError(
            self.__getPermissions.__doc__.replace('\n       ',''))


    def readAccess(self, role):
        """Derived method should return the role for read access to the 
        resource - should return boolean for access granted/denied"""
        raise NotImplementedError(
            self.readAccess.__doc__.replace('\n       ',''))


    def writeAccess(self, role):
        """Derived method should return the role for write access to the 
        resource - should return boolean for access granted/denied"""
        raise NotImplementedError(
            self.writeAccess.__doc__.replace('\n       ',''))


    def executeAccess(self, role):
        """Derived method should return the role for execute access to the 
        resource - should return boolean for access granted/denied"""
        raise NotImplementedError(
            self.executeAccess.__doc__.replace('\n       ',''))
   
    
import sys # tracefile config param may be set to e.g. sys.stderr
import urllib2
import socket

from ndg.security.common.SessionMgr import SessionMgrClient, SessionNotFound,\
    SessionCertTimeError, SessionExpired, InvalidSession, \
    AttributeRequestDenied
    
def HandleSecurity(*args):
    return PullModelHandler(*args)()

class URLCannotBeOpened(Exception):
    """Raise from canURLBeOpened PullModelHandler class method
    if URL is invalid - this method is used to check the AA
    service"""

class PullModelHandler(object):
    """Make access control decision based on CSML constraint and user security
    token"""
    
    AccessAllowedMsg = "Access Allowed"
    InvalidAttributeCertificate = \
            "The certificate containing your authorisation roles is invalid"
    NotLoggedInMsg = 'Not Logged in'
    SessionExpiredMsg = 'Session has expired.  Please re-login'
    InvalidSessionMsg = 'Session is invalid.  Please try re-login'
    InvalidSecurityCondition = 'Invalid Security Condition'

    def __init__(self, uri, securityElement, securityTokens):
        """Initialise settings for WS-Security and SSL for SOAP
        call to Session Manager
        
        @type uri: string
        @param uri: URI corresponding to data granule ID
        
        @type securityElement: ElementTree Element
        @param securityElement: MOLES security constraint containing role and
        Attribute Authority URI. In xml, could look like:
        <moles:effect>allow</moles:effect>
            <moles:simpleCondition>
            <moles:dgAttributeAuthority>https://glue.badc.rl.ac.uk/AttributeAuthority</moles:dgAttributeAuthority>
            <moles:attrauthRole>coapec</moles:attrauthRole>
        </moles:simpleCondition>
        NB: xmlns:moles="http://ndg.nerc.ac.uk/moles
        
        @type: pylons.session
        @param securityTokens: dict-like session object containing security 
        tokens"""
        
        self.uri = uri
        self.securityElement = securityElement
        self.securityTokens = securityTokens


    def __call__(self, **kw):
        """Convenience wrapper for checkAccess"""
        return self.checkAccess(**kw)


    def checkAccess(self, 
                    uri=None, 
                    securityElement=None, 
                    securityTokens=None):
        """Make an access control decision based on whether the user is
        authenticated and has the required roles
        
        @type uri: string
        @param uri: URI corresponding to data granule ID
        
        @type: ElementTree Element
        @param securityElement: MOES security constraint containing role and
        Attribute Authority URI. In xml, could look like:
        <moles:effect>allow</moles:effect>
            <moles:simpleCondition>
            <moles:dgAttributeAuthority>https://glue.badc.rl.ac.uk/AttributeAuthority</moles:dgAttributeAuthority>
            <moles:attrauthRole>coapec</moles:attrauthRole>
        </moles:simpleCondition>
        NB: xmlns:moles="http://ndg.nerc.ac.uk/moles"
        
        @type: pylons.session
        @param securityTokens: dict-like session object containing security 
        tokens.  Resets equivalent object attribute."""
          
        # tokens and element may be set from __init__ or as args to this 
        # method.  If the latter copy them into self  
        if uri:
            self.uri = uri
            
        if securityTokens:
            self.securityTokens = securityTokens
                            
        if securityElement:
            self.securityElement=securityElement
     
        # Check self.securityTokens - if not set then the user mustn't be 
        # logged in.  This situation is possible if a user has been denied
        # access to data and then tried to logout - after log out they are
        # redirected back to the page where they tried accessing data but this
        # time they will have no security credential set
        if not self.securityTokens:
            # Try to recover and do something sensible
            #
            # TODO: this adds insult to injury if the person has just been
            # denied access to data.  Instead do a redirect back to the 
            # discovery page?
            # P J Kershaw 10/08/07
            log.info("Exiting from Gatekeeper: user is not logged in")
            return False, self.__class__.NotLoggedInMsg
            
        xpathr='{http://ndg.nerc.ac.uk/moles}simpleCondition/{http://ndg.nerc.ac.uk/moles}attrauthRole'
        xpathaa='{http://ndg.nerc.ac.uk/moles}simpleCondition/{http://ndg.nerc.ac.uk/moles}dgAttributeAuthority'
        roleE,aaE=self.securityElement.find(xpathr),self.securityElement.find(xpathaa)
        if roleE is None:
            log.error("Gatekeeper: role not found in dataset element: %s" % \
                      self.securityElement)
            return False, self.__class__.InvalidSecurityCondition
        
        self.reqRole=roleE.text
        
        # Check Attribute Authority address
        try:
            PullModelHandler.urlCanBeOpened(aaE.text)
        except (URLCannotBeOpened, AttributeError):
            # Catch situation where either Attribute Authority address in the
            # data invalid or none was set.  In this situation verify
            # against the Attribute Authority set in the config
            log.info('Gatekeeper: Attribute Authority address is invalid ' + \
                     'in data "%s" - defaulting to config file setting' % \
                     self.securityElement)
            self.reqAAURI = g.securityCfg.aaURI
    
        # Create Session Manager client
        self.smClnt = SessionMgrClient(uri=self.securityTokens['h'],
                    sslCACertFilePathList=g.securityCfg.sslCACertFilePathList,
                    sslPeerCertCN=g.securityCfg.sslPeerCertCN,
                    signingCertFilePath=g.securityCfg.wssCertFilePath,
                    signingPriKeyFilePath=g.securityCfg.wssPriKeyFilePath,
                    signingPriKeyPwd=g.securityCfg.wssPriKeyPwd,
                    caCertFilePathList=g.securityCfg.wssCACertFilePathList,
                    tracefile=g.securityCfg.tracefile)       
        
        return self.__pullSessionAttCert()
            
            
    def __pullSessionAttCert(self):
        """Check to see if the Session Manager can deliver an Attribute 
        Certificate with the required role to gain access to the resource
        in question"""
            
        try:
            # Make request for attribute certificate
            attCert = self.smClnt.getAttCert(attAuthorityURI=self.reqAAURI,
                                         sessID=self.securityTokens['sid'],
                                         reqRole=self.reqRole)
        except AttributeRequestDenied, e:
            log.info(\
                "Gatekeeper - request for attribute certificate denied: %s"%e)
            return False, str(e)
        
        except SessionNotFound, e:
            log.info("Gatekeeper - no session found: %s" % e)
            return False, self.__class__.NotLoggedInMsg

        except SessionExpired, e:
            log.info("Gatekeeper - session expired: %s" % e)
            return False, self.__class__.SessionExpiredMsg

        except SessionCertTimeError, e:
            log.info("Gatekeeper - session cert. time error: %s" % e)
            return False, self.__class__.InvalidSessionMsg
            
        except InvalidSession, e:
            log.info("Gatekeeper - invalid user session: %s" % e)
            return False, self.__class__.InvalidSessionMsg

        except Exception, e:
            raise GateKeeperError, "Gatekeeper request for attribute certificate: "+\
                            str(e)
                            
        # Check attribute certificate is valid
        attCert.certFilePathList = g.securityCfg.acCACertFilePathList
        attCert.isValid(raiseExcep=True)
            
        # Check it's issuer is as expected
        if attCert.issuer != g.securityCfg.acIssuer:
            log.info('Gatekeeper - access denied: Attribute Certificate ' + \
                'issuer DN, "%s" ' % attCert.issuer + \
                'must match this data provider\'s Attribute Authority ' + \
                'DN: "%s"' % g.securityCfg.acIssuer)
            return False, self.__class__.InvalidAttributeCertificate
        
        log.info('Gatekeeper - access granted for user "%s" '%attCert.userId+\
                 'to "%s" secured with role "%s" ' % (self.uri,self.reqRole)+\
                 'using attribute certificate:\n\n%s' % attCert)
                     
        return True, self.__class__.AccessAllowedMsg

    @classmethod
    def urlCanBeOpened(cls, url, timeout=5, raiseExcep=True):
       """Check url can be opened - adapted from 
       http://mail.python.org/pipermail/python-list/2004-October/289601.html
       """
    
       found = False
       defTimeOut = socket.getdefaulttimeout()
       try:
           socket.setdefaulttimeout(timeout)

           try:
               urllib2.urlopen(url)
           except (urllib2.HTTPError, urllib2.URLError,
                   socket.error, socket.sslerror):
               if raiseExcep:
                   raise URLCannotBeOpened
           
           found = True
         
       finally:
           socket.setdefaulttimeout(defTimeOut)
           
       return found
   

class SecurityConfigError(Exception):
    """Handle errors from parsing security config items"""
       
class SecurityConfig(object):
    """Get Security related parameters from the Pylons NDG config file"""
    
    def parse(self, cfg, section='NDG_SECURITY'):
        '''Get PKI settings for Attribute Authority and Session Manager from
        the configuration file
        
        @type cfg: ConfigParser object
        @param cfg: reference to configuration file.'''
        
        tracefileExpr = cfg.get(section, 'tracefile')
        if tracefileExpr:
            self.tracefile = eval(tracefileExpr)

        self.smURI = cfg.get(section, 'sessionMgrURI')        
        self.aaURI = cfg.get(section, 'attAuthorityURI')

        try:
            self.wssCACertFilePathList = \
                cfg.get(section, 'wssCACertFilePathList').split()
                
        except AttributeError:
            raise SecurityConfigError, \
                                'No "wssCACertFilePathList" security setting'

        # Attribute Certificate Issuer
        self.acIssuer = cfg.get(section, 'acIssuer')
        
        # verification of X.509 cert back to CA
        try:
            self.acCACertFilePathList = cfg.get(section, 
                                            'acCACertFilePathList').split()          
        except AttributeError:
            raise SecurityConfigError, \
                                'No "acCACertFilePathList" security setting'

             
    def __repr__(self):
        return '\n'.join(["%s=%s" % (k,v) for k,v in self.__dict__.items() \
                if k[:2] != "__"])
     