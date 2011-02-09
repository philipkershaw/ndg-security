"""SAML 2.0 bindings module implements SOAP binding for subject query

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from datetime import datetime, timedelta
from uuid import uuid4

from ndg.saml.common import SAMLObject
from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (SubjectQuery, StatusCode, Response,
                             Issuer, Subject, SAMLVersion, NameID)

from ndg.saml.utils import str2Bool
from ndg.saml.saml2.binding.soap.client import (SOAPBinding,
    SOAPBindingInvalidResponse)


class SubjectQueryResponseError(SOAPBindingInvalidResponse):
    """SAML Response error from Subject Query"""
    

class IssueInstantInvalid(SubjectQueryResponseError):
    """Issue instant of SAML artifact is invalid"""

  
class ResponseIssueInstantInvalid(IssueInstantInvalid):
    """Issue instant of a response is after the current time"""

    
class AssertionIssueInstantInvalid(IssueInstantInvalid):
    """Issue instant of an assertion is after the current time"""


class AssertionConditionNotBeforeInvalid(SubjectQueryResponseError):
    """An assertion condition notBefore time is set after the current clock
    time"""
    

class AssertionConditionNotOnOrAfterInvalid(SubjectQueryResponseError):
    """An assertion condition notOnOrAfter time is set before the current clock
    time"""

   
class SubjectQuerySOAPBinding(SOAPBinding): 
    """SAML Subject Query SOAP Binding
    """
    SUBJECT_ID_OPTNAME = 'subjectID'
    SUBJECT_ID_FORMAT_OPTNAME = 'subjectIdFormat'
    ISSUER_NAME_OPTNAME = 'issuerName'
    ISSUER_FORMAT_OPTNAME = 'issuerFormat'
    CLOCK_SKEW_OPTNAME = 'clockSkewTolerance'
    VERIFY_TIME_CONDITIONS_OPTNAME = 'verifyTimeConditions'
    
    CONFIG_FILE_OPTNAMES = (
        SUBJECT_ID_OPTNAME,
        SUBJECT_ID_FORMAT_OPTNAME,
        ISSUER_NAME_OPTNAME, 
        ISSUER_FORMAT_OPTNAME,                
        CLOCK_SKEW_OPTNAME,
        VERIFY_TIME_CONDITIONS_OPTNAME            
    )
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = tuple([__PRIVATE_ATTR_PREFIX + i 
                       for i in CONFIG_FILE_OPTNAMES + ('query', )])
    del i
    
    QUERY_TYPE = SubjectQuery
    
    def __init__(self, **kw):
        '''Create SOAP Client for a SAML Subject Query'''       
        self.__clockSkewTolerance = timedelta(seconds=0.)
        self.__verifyTimeConditions = True
        
        self._initQuery()
        
        super(SubjectQuerySOAPBinding, self).__init__(**kw)

    def _initQuery(self):
        """Initialise query settings"""
        self.__query = self.__class__.QUERY_TYPE()
        self.__query.version = SAMLVersion(SAMLVersion.VERSION_20)
        
        # These properties access the __query instance
        self.issuerFormat = Issuer.X509_SUBJECT
        self.subjectIdFormat = NameID.UNSPECIFIED

    def _getQuery(self):
        return self.__query

    def _setQuery(self, value):
        if not isinstance(value, self.__class__.QUERY_TYPE):
            raise TypeError('Expecting %r query type got %r instead' %
                            (self.__class__, type(value)))
        self.__query = value

    query = property(_getQuery, _setQuery, 
                     doc="SAML Subject Query or derived query type")

    def _getSubjectID(self):
        if self.__query.subject is None or self.__query.subject.nameID is None:
            return None
        else:
            return self.__query.subject.nameID.value

    def _setSubjectID(self, value):
        if self.__query.subject is None:
            self.__query.subject = Subject()
            
        if self.__query.subject.nameID is None:
            self.__query.subject.nameID = NameID()
            
        self.__query.subject.nameID.value = value

    subjectID = property(_getSubjectID, _setSubjectID, 
                         doc="ID to be sent as query subject")
    
    def _getSubjectIdFormat(self):
        if self.__query.subject is None or self.__query.subject.nameID is None:
            return None
        else:
            return self.__query.subject.nameID.format

    def _setSubjectIdFormat(self, value):
        if self.__query.subject is None:
            self.__query.subject = Subject()
            
        if self.__query.subject.nameID is None:
            self.__query.subject.nameID = NameID()
            
        self.__query.subject.nameID.format = value

    subjectIdFormat = property(_getSubjectIdFormat, _setSubjectIdFormat, 
                               doc="Subject Name ID format")

    def _getIssuerFormat(self):
        if self.__query.issuer is None:
            return None
        else:
            return self.__query.issuer.value

    def _setIssuerFormat(self, value):
        if self.__query.issuer is None:
            self.__query.issuer = Issuer()
            
        self.__query.issuer.format = value

    issuerFormat = property(_getIssuerFormat, _setIssuerFormat, 
                            doc="Issuer format")

    def _getIssuerName(self):
        if self.__query.issuer is None:
            return None
        else:
            return self.__query.issuer.value

    def _setIssuerName(self, value):
        if self.__query.issuer is None:
            self.__query.issuer = Issuer()
            
        self.__query.issuer.value = value

    issuerName = property(_getIssuerName, _setIssuerName, 
                          doc="Name of issuer of SAML Subject Query")

    def _getVerifyTimeConditions(self):
        return self.__verifyTimeConditions

    def _setVerifyTimeConditions(self, value):
        if isinstance(value, bool):
            self.__verifyTimeConditions = value
            
        if isinstance(value, basestring):
            self.__verifyTimeConditions = str2Bool(value)
        else:
            raise TypeError('Expecting bool or string type for '
                            '"verifyTimeConditions"; got %r instead' % 
                            type(value))

    verifyTimeConditions = property(_getVerifyTimeConditions, 
                                    _setVerifyTimeConditions, 
                                    doc='Set to True to verify any time '
                                        'Conditions set in the returned '
                                        'response assertions')  

    def _getClockSkewTolerance(self):
        return self.__clockSkewTolerance

    def _setClockSkewTolerance(self, value):
        if isinstance(value, timedelta):
            self.__clockSkewTolerance = value
            
        elif isinstance(value, (float, int, long)):
            self.__clockSkewTolerance = timedelta(seconds=value)
            
        elif isinstance(value, basestring):
            self.__clockSkewTolerance = timedelta(seconds=float(value))
        else:
            raise TypeError('Expecting timedelta, float, int, long or string '
                            'type for "clockSkewTolerance"; got %r' % 
                            type(value))

    clockSkewTolerance = property(fget=_getClockSkewTolerance, 
                                  fset=_setClockSkewTolerance, 
                                  doc="Allow a tolerance in seconds for SAML "
                                      "Query issueInstant parameter check and "
                                      "assertion condition notBefore and "
                                      "notOnOrAfter times to allow for clock "
                                      "skew")
    
    def _validateQueryParameters(self):
        """Perform sanity check immediately before creating the query and 
        sending it"""
        errors = []
        
        if self.issuerName is None:
            errors.append('issuer name')

        if self.issuerFormat is None:
            errors.append('issuer format')
        
        if self.subjectID is None:
            errors.append('subject')
        
        if self.subjectIdFormat is None:
            errors.append('subject format')
        
        if errors:
            raise AttributeError('Missing attribute(s) for SAML Query: %s' %
                                 ', '.join(errors))

    def _initSend(self):
        """Perform any final initialisation prior to sending the query - derived
        classes may overload to specify as required"""
        self.__query.issueInstant = datetime.utcnow()
        
        # Set ID here to ensure it's unique for each new call
        self.__query.id = str(uuid4())

    def _verifyTimeConditions(self, response):
        """Verify time conditions set in a response
        @param response: SAML Response returned from remote service
        @type response: ndg.saml.saml2.core.Response
        @raise SubjectQueryResponseError: if a timestamp is invalid
        """
        
        if not self.verifyTimeConditions:
            log.debug("Skipping verification of SAML Response time conditions")
            
        utcNow = datetime.utcnow() 
        nowMinusSkew = utcNow - self.clockSkewTolerance
        nowPlusSkew = utcNow + self.clockSkewTolerance
        
        if response.issueInstant > nowPlusSkew:
            msg = ('SAML Attribute Response issueInstant [%s] is after '
                   'the clock time [%s] (skewed +%s)' % 
                   (response.issueInstant, 
                    SAMLDateTime.toString(nowPlusSkew),
                    self.clockSkewTolerance))
             
            samlRespError = ResponseIssueInstantInvalid(msg)
            samlRespError.response = response
            raise samlRespError
        
        for assertion in response.assertions:
            if assertion.issueInstant is None:
                samlRespError = AssertionIssueInstantInvalid("No issueInstant "
                                                             "set in response "
                                                             "assertion")
                samlRespError.response = response
                raise samlRespError
            
            elif nowPlusSkew < assertion.issueInstant:
                msg = ('The clock time [%s] (skewed +%s) is before the '
                       'SAML Attribute Response assertion issue instant [%s]' % 
                       (SAMLDateTime.toString(utcNow),
                        self.clockSkewTolerance,
                        assertion.issueInstant))
                samlRespError = AssertionIssueInstantInvalid(msg)
                samlRespError.response = response
                raise samlRespError
            
            if assertion.conditions is not None:
                if nowPlusSkew < assertion.conditions.notBefore:            
                    msg = ('The clock time [%s] (skewed +%s) is before the '
                           'SAML Attribute Response assertion conditions not '
                           'before time [%s]' % 
                           (SAMLDateTime.toString(utcNow),
                            self.clockSkewTolerance,
                            assertion.conditions.notBefore))
                              
                    samlRespError = AssertionConditionNotBeforeInvalid(msg)
                    samlRespError.response = response
                    raise samlRespError
                 
                if nowMinusSkew >= assertion.conditions.notOnOrAfter:           
                    msg = ('The clock time [%s] (skewed -%s) is on or after '
                           'the SAML Attribute Response assertion conditions '
                           'not on or after time [%s]' % 
                           (SAMLDateTime.toString(utcNow),
                            self.clockSkewTolerance,
                            assertion.conditions.notOnOrAfter))
                    
                    samlRespError = AssertionConditionNotOnOrAfterInvalid(msg) 
                    samlRespError.response = response
                    raise samlRespError
                
    def send(self, **kw):
        '''Make an attribute query to a remote SAML service
        
        @type uri: basestring 
        @param uri: uri of service.  May be omitted if set from request.url
        @type request: ndg.security.common.soap.UrlLib2SOAPRequest
        @param request: SOAP request object to which query will be attached
        defaults to ndg.security.common.soap.client.UrlLib2SOAPRequest
        '''
        self._validateQueryParameters() 
        self._initSend()
           
        response = super(SubjectQuerySOAPBinding, self).send(self.query, **kw)

        # Perform validation
        if response.status.statusCode.value != StatusCode.SUCCESS_URI:
            msg = ('Return status code flagged an error, %r.  '
                   'The message is, %r' %
                   (response.status.statusCode.value,
                    response.status.statusMessage.value))
            samlRespError = SubjectQueryResponseError(msg)
            samlRespError.response = response
            raise samlRespError
        
        # Check Query ID matches the query ID the service received
        if response.inResponseTo != self.query.id:
            msg = ('Response in-response-to ID %r, doesn\'t match the original '
                   'query ID, %r' % (response.inResponseTo, query.id))
            
            samlRespError = SubjectQueryResponseError(msg)
            samlRespError.response = response
            raise samlRespError
        
        self._verifyTimeConditions(response)
            
        return response 
