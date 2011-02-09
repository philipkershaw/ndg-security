"""NDG Security MSI Resource Policy module 

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/04/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
log = logging.getLogger(__name__)

import traceback
import warnings
try:
    from xml.etree import ElementTree

except ImportError:
    warnings.warn("xml.etree not available, importing from elementtree egg "
                  "instead")
    from elementtree import ElementTree

from ndg.security.common.utils import TypedList
from ndg.security.common.utils.etree import QName


class PolicyParseError(Exception):
    """Error reading policy attributes from file"""

class InvalidPolicyXmlNsError(Exception):
    """Invalid XML namespace for policy document"""

class PolicyComponent(object):
    """Base class for Policy and Policy subelements"""
    VERSION_1_0_XMLNS = "urn:ndg:security:authz:1.0:policy"
    VERSION_1_1_XMLNS = "urn:ndg:security:authz:1.1:policy"
    XMLNS = (VERSION_1_0_XMLNS, VERSION_1_1_XMLNS)
    __slots__ = ('__xmlns', )

    def __init__(self):
        self.__xmlns = None
        
    def _getXmlns(self):
        return self.__xmlns

    def _setXmlns(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "xmlns" '
                            'attribute; got %r' % type(value))
        self.__xmlns = value

    xmlns = property(_getXmlns, _setXmlns, 
                     doc="XML Namespace for policy the document")
    
    @property
    def isValidXmlns(self):
        return self.xmlns in PolicyComponent.XMLNS
    
    
class Policy(PolicyComponent):
    """NDG MSI Policy."""   
    DESCRIPTION_LOCALNAME = "Description"
    TARGET_LOCALNAME = "Target"
    
    __slots__ = (
        '__policyFilePath',
        '__description',
        '__targets',
    )
    
    def __init__(self, policyFilePath=None):
        super(Policy, self).__init__()
        self.__policyFilePath = policyFilePath
        self.__description = None
        self.__targets = TypedList(Target)

    def _getPolicyFilePath(self):
        return self.__policyFilePath

    def _setPolicyFilePath(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "policyFilePath" '
                            'attribute; got %r' % type(value))
            
        self.__policyFilePath = value

    policyFilePath = property(_getPolicyFilePath, _setPolicyFilePath, 
                              doc="Policy file path")

    def _getTargets(self):
        return self.__targets

    def _setTargets(self, value):
        if (not isinstance(value, TypedList) and 
            not issubclass(value.elementType, Target.__class__)):
            raise TypeError('Expecting TypedList(Target) for "targets" '
                            'attribute; got %r' % type(value))
        self.__targets = value

    targets = property(_getTargets, _setTargets, 
                       doc="list of Policy targets")

    def _getDescription(self):
        return self.__description

    def _setDescription(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "description" '
                            'attribute; got %r' % type(value))
        self.__description = value

    description = property(_getDescription, _setDescription, 
                           doc="Policy Description text")
   
    def parse(self):
        """Parse the policy file set in policyFilePath attribute
        """
        elem = ElementTree.parse(self.policyFilePath)
        root = elem.getroot()
        
        self.xmlns = QName.getNs(root.tag)
        if not self.isValidXmlns:
            raise InvalidPolicyXmlNsError("Namespace %r is recognised; valid "
                                          "namespaces are: %r" %
                                          (self.xmlns, Policy.XMLNS))
            
        for elem in root:
            localName = QName.getLocalPart(elem.tag)
            if localName == Policy.DESCRIPTION_LOCALNAME:
                self.description = elem.text.strip()
                
            elif localName == Policy.TARGET_LOCALNAME:
                self.targets.append(Target.Parse(elem))
                
            else:
                raise PolicyParseError("Invalid policy attribute: %s" % 
                                        localName)
                
    @classmethod
    def Parse(cls, policyFilePath):
        policy = cls(policyFilePath=policyFilePath)
        policy.parse()
        return policy


class TargetParseError(PolicyParseError):
    """Error reading resource attributes from file"""

import re
   
class Target(PolicyComponent):
    """Define access behaviour for a resource match a given URI pattern"""
    URI_PATTERN_LOCALNAME = "URIPattern"
    ATTRIBUTES_LOCALNAME = "Attributes"
    ATTRIBUTE_AUTHORITY_LOCALNAME = "AttributeAuthority"
    
    __slots__ = (
        '__uriPattern',
        '__attributes',
        '__regEx'       
    )

    ATTRIBUTE_AUTHORITY_LOCALNAME_DEPRECATED_MSG = """\
Use of a <%r/> child element within Target elements will be deprecated for future
releases.  Put the Attribute Authority setting in an Attribute 
<AttributeAuthorityURI/> element e.g.

<Target>
    <uriPattern>^/.*</uriPattern>
    <Attributes>
        <Attribute>
            <Name>myattribute</Name>
            <AttributeAuthorityURI>https://myattributeauthority.ac.uk</AttributeAuthorityURI>
        </Attribute>
    </Attributes>
</Target>
"""  % ATTRIBUTE_AUTHORITY_LOCALNAME  
    
    def __init__(self):
        super(Target, self).__init__()
        self.__uriPattern = None
        self.__attributes = []
        self.__regEx = None
        
    def getUriPattern(self):
        return self.__uriPattern

    def setUriPattern(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "uriPattern" '
                            'attribute; got %r' % type(value))
        self.__uriPattern = value

    uriPattern = property(getUriPattern, 
                          setUriPattern, 
                          doc="URI Pattern to match this target")

    def getAttributes(self):
        return self.__attributes

    def setAttributes(self, value):
        if (not isinstance(value, TypedList) and 
            not issubclass(value.elementType, Attribute.__class__)):
            raise TypeError('Expecting TypedList(Attribute) for "attributes" '
                            'attribute; got %r' % type(value))
        self.__attributes = value

    attributes = property(getAttributes, 
                          setAttributes,  
                          doc="Attributes restricting access to this target")

    def getRegEx(self):
        return self.__regEx

    def setRegEx(self, value):
        self.__regEx = value

    regEx = property(getRegEx, setRegEx, doc="RegEx's Docstring")
        
    def parse(self, root):
        
        self.xmlns = QName.getNs(root.tag)
        version1_0attributeAuthorityURI = None
        
        for elem in root:
            localName = QName.getLocalPart(elem.tag)
            if localName == Target.URI_PATTERN_LOCALNAME:
                self.uriPattern = elem.text.strip()
                self.regEx = re.compile(self.uriPattern)
                
            elif localName == Target.ATTRIBUTES_LOCALNAME:
                for attrElem in elem:
                    if self.xmlns == Target.VERSION_1_1_XMLNS:
                        self.attributes.append(Attribute.Parse(attrElem))
                    else:
                        attribute = Attribute()
                        attribute.name = attrElem.text.strip()
                        self.attributes.append(attribute)
                    
            elif localName == Target.ATTRIBUTE_AUTHORITY_LOCALNAME:
                # Expecting first element to contain the URI
                warnings.warn(
                        Target.ATTRIBUTE_AUTHORITY_LOCALNAME_DEPRECATED_MSG,
                        PendingDeprecationWarning)
                
                version1_0attributeAuthorityURI = elem[-1].text.strip()
            else:
                raise TargetParseError("Invalid Target attribute: %s" % 
                                       localName)
                
        if self.xmlns == Target.VERSION_1_0_XMLNS:
            msg = ("Setting all attributes with Attribute Authority "
                   "URI set read using Version 1.0 schema.  This will "
                   "be deprecated in future releases")
            
            warnings.warn(msg, PendingDeprecationWarning)
            log.warning(msg)
            
            if version1_0attributeAuthorityURI is None:
                raise TargetParseError("Assuming version 1.0 schema "
                                       "for Attribute Authority URI setting "
                                       "but no URI has been set")
                
            for attribute in self.attributes:
                attribute.attributeAuthorityURI = \
                    version1_0attributeAuthorityURI
    
    @classmethod
    def Parse(cls, root):
        resource = cls()
        resource.parse(root)
        return resource
    
    def __str__(self):
        return str(self.uriPattern)


class AttributeParseError(PolicyParseError):
    """Error parsing a Policy Attribute element"""
    

class Attribute(PolicyComponent):
    """encapsulate a target attribute including the name and an Attribute
    Authority from which user attribute information may be queried
    """
    NAME_LOCALNAME = "Name"
    ATTRIBUTE_AUTHORITY_URI_LOCALNAME = "AttributeAuthorityURI"
    
    __slots__ = ('__name', '__attributeAuthorityURI')
    
    def __init__(self):
        super(Attribute, self).__init__()
        self.__name = ''
        self.__attributeAuthorityURI = None

    def __str__(self):
        return self.__name
    
    def _getName(self):
        return self.__name

    def _setName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "name"; got %r' %
                            type(value))
        self.__name = value

    name = property(fget=_getName, 
                    fset=_setName, 
                    doc="Attribute name")
        
    def _getAttributeAuthorityURI(self):
        return self.__attributeAuthorityURI

    def _setAttributeAuthorityURI(self, value):
        self.__attributeAuthorityURI = value

    attributeAuthorityURI = property(_getAttributeAuthorityURI, 
                                     _setAttributeAuthorityURI, 
                                     doc="Attribute Authority URI")
        
    def parse(self, root):
        """Parse from an ElementTree Element"""
        self.xmlns = QName.getNs(root.tag)
        
        for elem in root:
            localName = QName.getLocalPart(elem.tag)
            if localName == Attribute.ATTRIBUTE_AUTHORITY_URI_LOCALNAME:
                self.attributeAuthorityURI = elem.text.strip()
                
            elif localName == Attribute.NAME_LOCALNAME:
                self.name = elem.text.strip()
            else:
                raise AttributeParseError("Invalid Attribute element name: %s" % 
                                          localName)
    
    @classmethod
    def Parse(cls, root):
        """Parse from an ElementTree Element and return a new instance"""
        resource = cls()
        resource.parse(root)
        return resource
 
       
class _AttrDict(dict):
    """Utility class for holding a constrained list of attributes governed
    by a namespace list"""
    namespaces = ()
    def __init__(self, **attributes):
        invalidAttributes = [attr for attr in attributes
                             if attr not in self.__class__.namespaces]
        if len(invalidAttributes) > 0:
            raise TypeError("The following attribute namespace(s) are not "
                            "recognised: %s" % invalidAttributes)
            
        self.update(attributes)

    def __setitem__(self, key, val):
        if key not in self.__class__.namespaces:
            raise KeyError('Namespace "%s" not recognised.  Valid namespaces '
                           'are: %s' % self.__class__.namespaces)
            
        dict.__setitem__(self, key, val)


    def update(self, d, **kw):        
        for dictArg in (d, kw):
            for k in dictArg:
                if k not in self.__class__.namespaces:
                    raise KeyError('Namespace "%s" not recognised.  Valid '
                                   'namespaces are: %s' % 
                                   self.__class__.namespaces)
        
        dict.update(self, d, **kw)


class Subject(_AttrDict):
    '''Subject designator'''
    namespaces = (
        "urn:ndg:security:authz:1.0:attr:subject:userId",
        "urn:ndg:security:authz:1.0:attr:subject:sessionId",
        "urn:ndg:security:authz:1.0:attr:subject:sessionManagerURI",
        "urn:ndg:security:authz:1.0:attr:subject:roles"        
    )
    (USERID_NS, SESSIONID_NS, SESSIONMANAGERURI_NS, ROLES_NS) = namespaces


class Resource(_AttrDict):
    '''Resource designator'''
    namespaces = (
        "urn:ndg:security:authz:1.0:attr:resource:uri",
    )
    (URI_NS,) = namespaces

           
class Request(object):
    '''Request to send to a PDP'''
    def __init__(self, subject=Subject(), resource=Resource()):
        self.subject = subject
        self.resource = resource

    def _getSubject(self):
        return self.__subject
    
    def _setSubject(self, subject):
        if not isinstance(subject, Subject,):
            raise TypeError("Expecting %s type for Request subject; got %r" %
                            (Subject.__class__.__name__, subject))
        self.__subject = subject

    subject = property(fget=_getSubject,
                       fset=_setSubject,
                       doc="Subject type object representing subject accessing "
                           "a resource")

    def _getResource(self):
        return self.__resource
    
    def _setResource(self, resource):
        if not isinstance(resource, Resource):
            raise TypeError("Expecting %s for Request Resource; got %r" %
                            (Resource.__class__.__name__, resource))
        self.__resource = resource

    resource = property(fget=_getResource,
                        fset=_setResource,
                        doc="Resource to be protected")


class Response(object):
    '''Response from a PDP'''
    decisionValues = range(4)
    (DECISION_PERMIT,
     DECISION_DENY,
     DECISION_INDETERMINATE,
     DECISION_NOT_APPLICABLE) = decisionValues

    # string versions of the 4 Decision types used for encoding
    DECISIONS = ("Permit", "Deny", "Indeterminate", "NotApplicable")
    
    decisionValue2String = dict(zip(decisionValues, DECISIONS))
    
    def __init__(self, status, message=None):
        self.__status = None
        self.__message = None
        
        self.status = status
        self.message = message

    def _setStatus(self, status):
        if status not in Response.decisionValues:
            raise TypeError("Status %s not recognised" % status)
        
        self.__status = status
        
    def _getStatus(self):
        return self.__status
    
    status = property(fget=_getStatus,
                      fset=_setStatus,
                      doc="Integer response code; one of %r" % decisionValues)

    def _setMessage(self, message):
        if not isinstance(message, (basestring, type(None))):
            raise TypeError('Expecting string or None type for "message"; got '
                            '%r' % type(message))
        
        self.__message = message
        
    def _getMessage(self):
        return self.__message
    
    message = property(fget=_getMessage,
                       fset=_setMessage,
                       doc="Optional message associated with response")
        
        
from ndg.security.common.AttCert import (AttCertInvalidSignature, 
    AttCertNotBeforeTimeError, AttCertExpired, AttCertError)
      
from ndg.security.common.sessionmanager import (SessionManagerClient, 
    SessionNotFound, SessionCertTimeError, SessionExpired, InvalidSession, 
    AttributeRequestDenied)

from ndg.security.common.attributeauthority import (AttributeAuthorityClient, 
    NoTrustedHosts, NoMatchingRoleInTrustedHosts, 
    InvalidAttributeAuthorityClientCtx)
from ndg.security.common.attributeauthority import AttributeRequestDenied as \
    AA_AttributeRequestDenied
                   
from ndg.security.common.authz.pdp import (PDPUserNotLoggedIn, 
    PDPUserAccessDenied)
    
    
class SubjectRetrievalError(Exception):
    """Generic exception class for errors related to information about the
    subject"""
    
class InvalidAttributeCertificate(SubjectRetrievalError):
    "The certificate containing authorisation roles is invalid"
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       InvalidAttributeCertificate.__doc__)

class AttributeCertificateInvalidSignature(SubjectRetrievalError):
    ("There is a problem with the signature of the certificate containing "
     "authorisation roles")
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                AttributeCertificateInvalidSignature.__doc__)
              
class AttributeCertificateNotBeforeTimeError(SubjectRetrievalError):
    ("There is a time issuing error with certificate containing authorisation "
    "roles")
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                AttributeCertificateNotBeforeTimeError.__doc__)
        
class AttributeCertificateExpired(SubjectRetrievalError):
    "The certificate containing authorisation roles has expired"
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       AttributeCertificateExpired.__doc__)
            
class SessionExpiredMsg(SubjectRetrievalError):
    'Session has expired.  Please re-login at your home organisation'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or SessionExpiredMsg.__doc__)

class SessionNotFoundMsg(SubjectRetrievalError):
    'No session was found.  Please try re-login with your home organisation'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       SessionNotFoundMsg.__doc__)

class InvalidSessionMsg(SubjectRetrievalError):
    'Session is invalid.  Please try re-login with your home organisation'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       InvalidSessionMsg.__doc__)

class InitSessionCtxError(SubjectRetrievalError):
    'A problem occurred initialising a session connection'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       InitSessionCtxError.__doc__)

class AttributeCertificateRequestError(SubjectRetrievalError):
    'A problem occurred requesting a certificate containing authorisation roles'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                    AttributeCertificateRequestError.__doc__)

class PIPAttributeQuery(_AttrDict):
    '''Policy Information Point Query class.'''
    namespaces = (
        "urn:ndg:security:authz:1.0:attr:subject",
        "urn:ndg:security:authz:1.0:attr:attributeAuthorityURI",
    )  
    (SUBJECT_NS, ATTRIBUTEAUTHORITY_NS) = namespaces    

class PIPAttributeResponse(dict):
    '''Policy Information Point Response class.'''
    namespaces = (
        Subject.ROLES_NS,
    )


class PIPBase(object):
    """Policy Information Point base class.  PIP enables PDP to get user 
    attribute information in order to make access control decisions 
    """
    def __init__(self, prefix='', **cfg):
        '''Initialise settings for connection to an Attribute Authority'''
        raise NotImplementedError(PIPBase.__init__.__doc__)
    
    def attributeQuery(self, attributeQuery):
        """Query the Attribute Authority specified in the request to retrieve
        the attributes if any corresponding to the subject
        
        @type attributeResponse: PIPAttributeQuery
        @param attributeResponse: 
        @rtype: PIPAttributeResponse
        @return: response containing the attributes retrieved from the
        Attribute Authority"""
        raise NotImplementedError(PIPBase.attributeQuery.__doc__)
    

from ndg.security.common.wssecurity import WSSecurityConfig

class NdgPIP(PIPBase):
    """Policy Information Point - this implementation enables the PDP to 
    retrieve attributes about the Subject"""
    wsseSectionName = 'wssecurity'
    
    def __init__(self, prefix='', **cfg):
        '''Set-up WS-Security and SSL settings for connection to an
        Attribute Authority
        
        @type **cfg: dict
        @param **cfg: keywords including 'sslCACertFilePathList' used to set a
        list of CA certificates for an SSL connection to the Attribute
        Authority if used and also WS-Security settings as used by
        ndg.security.common.wssecurity.WSSecurityConfig
        '''
        self.wssecurityCfg = WSSecurityConfig()
        wssePrefix = prefix + NdgPIP.wsseSectionName
        self.wssecurityCfg.update(cfg, prefix=wssePrefix)
                 
        # List of CA certificates used to verify peer certificate with SSL
        # connections to Attribute Authority
        self.sslCACertFilePathList = cfg.get(prefix+'sslCACertFilePathList', [])
        
        # List of CA certificates used to verify the signatures of 
        # Attribute Certificates retrieved
        self.caCertFilePathList = cfg.get(prefix + 'caCertFilePathList', [])

    def attributeQuery(self, attributeQuery):
        """Query the Attribute Authority specified in the request to retrieve
        the attributes if any corresponding to the subject
        
        @type attributeResponse: PIPAttributeQuery
        @param attributeResponse: 
        @rtype: PIPAttributeResponse
        @return: response containing the attributes retrieved from the
        Attribute Authority"""
        
        subject = attributeQuery[PIPAttributeQuery.SUBJECT_NS]
        username = subject[Subject.USERID_NS]
        sessionId = subject[Subject.SESSIONID_NS]
        attributeAuthorityURI = attributeQuery[
                                    PIPAttributeQuery.ATTRIBUTEAUTHORITY_NS]
        
        sessionId = subject[Subject.SESSIONID_NS]
        
        log.debug("PIP: received attribute query: %r", attributeQuery)
        
        attributeCertificate = self._getAttributeCertificate(
                    attributeAuthorityURI,
                    username=username,
                    sessionId=sessionId,
                    sessionManagerURI=subject[Subject.SESSIONMANAGERURI_NS])

        attributeResponse = PIPAttributeResponse()
        attributeResponse[Subject.ROLES_NS] = attributeCertificate.roles
        
        log.debug("PIP.attributeQuery response: %r", attributeResponse)
        
        return attributeResponse
    
    def _getAttributeCertificate(self,
                                 attributeAuthorityURI,
                                 username=None,
                                 sessionId=None,
                                 sessionManagerURI=None):
        '''Retrieve an Attribute Certificate

        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @type username: basestring
        @param username: subject user identifier - could be an OpenID        
        @type sessionId: basestring
        @param sessionId: Session Manager session handle
        @type sessionManagerURI: basestring
        @param sessionManagerURI: URI to remote session manager service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''

        if sessionId and sessionManagerURI:
            attrCert = self._getAttributeCertificateFromSessionManager(
                                                     attributeAuthorityURI,
                                                     sessionId,
                                                     sessionManagerURI)
        else:
            attrCert = self._getAttributeCertificateFromAttributeAuthority(
                                                     attributeAuthorityURI,
                                                     username)
        
        try:
            attrCert.certFilePathList = self.caCertFilePathList
            attrCert.isValid(raiseExcep=True)
        
        except AttCertInvalidSignature, e:
            log.exception(e)
            raise AttributeCertificateInvalidSignature()
        
        except AttCertNotBeforeTimeError, e:   
            log.exception(e)
            raise AttributeCertificateNotBeforeTimeError()
        
        except AttCertExpired, e:   
            log.exception(e)
            raise AttributeCertificateExpired()

        except AttCertError, e:
            log.exception(e)
            raise InvalidAttributeCertificate()
        
        return attrCert
            
    def _getAttributeCertificateFromSessionManager(self,
                                                   attributeAuthorityURI,
                                                   sessionId,
                                                   sessionManagerURI):
        '''Retrieve an Attribute Certificate using the subject's Session
        Manager
        
        @type sessionId: basestring
        @param sessionId: Session Manager session handle
        @type sessionManagerURI: basestring
        @param sessionManagerURI: URI to remote session manager service
        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''
        
        log.debug("PIP._getAttributeCertificateFromSessionManager ...")
        
        try:
            # Create Session Manager client - if a file path was set, setting
            # are read from a separate config file section otherwise, from the
            # PDP config object
            smClnt = SessionManagerClient(
                            uri=sessionManagerURI,
                            sslCACertFilePathList=self.sslCACertFilePathList,
                            cfg=self.wssecurityCfg)
        except Exception, e:
            log.error("Creating Session Manager client: %s" % e)
            raise InitSessionCtxError()
             
        try:
            # Make request for attribute certificate
            return smClnt.getAttCert(
                                attributeAuthorityURI=attributeAuthorityURI,
                                sessID=sessionId)
        
        except AttributeRequestDenied, e:
            log.error("Request for attribute certificate denied: %s" % e)
            raise PDPUserAccessDenied()
        
        except SessionNotFound, e:
            log.error("No session found: %s" % e)
            raise SessionNotFoundMsg()

        except SessionExpired, e:
            log.error("Session expired: %s" % e)
            raise SessionExpiredMsg()

        except SessionCertTimeError, e:
            log.error("Session cert. time error: %s" % e)
            raise InvalidSessionMsg()
            
        except InvalidSession, e:
            log.error("Invalid user session: %s" % e)
            raise InvalidSessionMsg()

        except Exception, e:
            log.error("Request from Session Manager [%s] to Attribute "
                      "Authority [%s] for attribute certificate: %s: %s" % 
                      (sessionManagerURI,
                       attributeAuthorityURI,
                       e.__class__, e))
            raise AttributeCertificateRequestError()
            
    def _getAttributeCertificateFromAttributeAuthority(self,
                                                       attributeAuthorityURI,
                                                       username):
        '''Retrieve an Attribute Certificate direct from an Attribute
        Authority.  This method is invoked if no session ID or Session 
        Manager endpoint where provided
        
        @type username: basestring
        @param username: user identifier - may be an OpenID URI
        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''
        
        log.debug("PIP._getAttributeCertificateFromAttributeAuthority ...")
       
        try:
            # Create Attribute Authority client - if a file path was set, 
            # settingare read  from a separate config file section otherwise, 
            # from the PDP config object
            aaClnt = AttributeAuthorityClient(
                            uri=attributeAuthorityURI,
                            sslCACertFilePathList=self.sslCACertFilePathList,
                            cfg=self.wssecurityCfg)
        except Exception:
            log.error("Creating Attribute Authority client: %s",
                      traceback.format_exc())
            raise InitSessionCtxError()
        
         
        try:
            # Make request for attribute certificate
            return aaClnt.getAttCert(userId=username)
        
        
        except AA_AttributeRequestDenied:
            log.error("Request for attribute certificate denied: %s",
                      traceback.format_exc())
            raise PDPUserAccessDenied()
        
        # TODO: handle other specific Exception types here for more fine
        # grained response info

        except Exception, e:
            log.error("Request to Attribute Authority [%s] for attribute "
                      "certificate: %s: %s", attributeAuthorityURI,
                      e.__class__, traceback.format_exc())
            raise AttributeCertificateRequestError()
        
# Backwards compatibility
PIP = NdgPIP

          
class PDP(object):
    """Policy Decision Point"""
    
    def __init__(self, policy, pip):
        """Read in a file which determines access policy"""
        self.policy = policy
        self.pip = pip

    def _getPolicy(self):
        if self.__policy is None:
            raise TypeError("Policy object has not been initialised")
        return self.__policy
    
    def _setPolicy(self, policy):
        if not isinstance(policy, (Policy, None.__class__)):
            raise TypeError("Expecting %s or None type for PDP policy; got %r"%
                            (Policy.__class__.__name__, policy))
        self.__policy = policy

    policy = property(fget=_getPolicy,
                      fset=_setPolicy,
                      doc="Policy type object used by the PDP to determine "
                          "access for resources")

    def _getPIP(self):
        if self.__pip is None:
            raise TypeError("PIP object has not been initialised")
        
        return self.__pip
    
    def _setPIP(self, pip):
        if not isinstance(pip, (PIPBase, None.__class__)):
            raise TypeError("Expecting %s or None type for PDP PIP; got %r"%
                            (PIPBase.__class__.__name__, pip))
        self.__pip = pip

    pip = property(fget=_getPIP,
                   fset=_setPIP,
                   doc="Policy Information Point - PIP type object used by "
                       "the PDP to retrieve user attributes")
   
    def evaluate(self, request):
        '''Make access control decision'''
        
        if not isinstance(request, Request):
            raise TypeError("Expecting %s type for request; got %r" %
                            (Request.__class__.__name__, request))
        
        # Look for matching targets to the given resource
        resourceURI = request.resource[Resource.URI_NS]
        matchingTargets = [target for target in self.policy.targets 
                           if target.regEx.match(resourceURI) is not None]
        numMatchingTargets = len(matchingTargets)
        if numMatchingTargets == 0:
            log.debug("PDP.evaluate: granting access - no targets matched "
                      "the resource URI path [%s]", 
                      resourceURI)
            return Response(status=Response.DECISION_PERMIT)
        
        # Iterate through matching targets checking for user access
        request.subject[Subject.ROLES_NS] = []
        permitForAllTargets = [Response.DECISION_PERMIT]*numMatchingTargets
        
        # Keep a look-up of the decisions for each target
        status = []
        
        # Make a query object for querying the Policy Information Point
        attributeQuery = PIPAttributeQuery()
        attributeQuery[PIPAttributeQuery.SUBJECT_NS] = request.subject
        
        # Keep a cache of queried Attribute Authorities to avoid calling them 
        # multiple times
        queriedAttributeAuthorityURIs = []
        
        # Iterate through the targets gathering user attributes from the
        # relevant attribute authorities
        for matchingTarget in matchingTargets:
            
            # Make call to the Policy Information Point to pull user
            # attributes applicable to this resource 
            for attribute in matchingTarget.attributes:
                if (attribute.attributeAuthorityURI in 
                    queriedAttributeAuthorityURIs): 
                    continue
                          
                attributeQuery[
                    PIPAttributeQuery.ATTRIBUTEAUTHORITY_NS
                ] = attribute.attributeAuthorityURI
            
                # Exit from function returning indeterminate status if a 
                # problem occurs here
                try:
                    attributeResponse = self.pip.attributeQuery(attributeQuery)
                    
                except SubjectRetrievalError, e:
                    # i.e. a defined exception within the scope of this
                    # module
                    log.error("SAML Attribute Query %s: %s", 
                              type(e), traceback.format_exc())
                    return Response(Response.DECISION_INDETERMINATE, 
                                    message=traceback.format_exc())
                                
                except Exception, e:
                    log.error("SAML Attribute Query %s: %s", 
                              type(e), traceback.format_exc())
                    return Response(Response.DECISION_INDETERMINATE,
                                    message="An internal error occurred")
                                
                # Accumulate attributes retrieved from multiple attribute
                # authorities
                request.subject[Subject.ROLES_NS] += attributeResponse[
                                                            Subject.ROLES_NS]
               
            # Match the subject's attributes against the target
            # One of any rule - at least one of the subject's attributes
            # must match one of the attributes restricting access to the
            # resource.
            log.debug("PDP.evaluate: Matching subject attributes %r against "
                      "resource attributes %r ...", 
                      request.subject[Subject.ROLES_NS],
                      matchingTarget.attributes)
            
            status.append(PDP._match(matchingTarget.attributes, 
                                     request.subject[Subject.ROLES_NS]))
            
        # All targets must yield permit status for access to be granted
        if status == permitForAllTargets:
            return Response(Response.DECISION_PERMIT)
        else:    
            return Response(Response.DECISION_DENY,
                            message="Insufficient privileges to access the "
                                    "resource")
        
    @staticmethod
    def _match(resourceAttr, subjectAttr):
        """Helper method to iterate over user and resource attributes
        If one at least one match is found, a permit response is returned
        """
        for attr in resourceAttr:
            if attr.name in subjectAttr:
                return Response.DECISION_PERMIT
            
        return Response.DECISION_DENY

        