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

from ndg.saml.saml2.core import SubjectQuery, Subject, NameID
from ndg.saml.saml2.binding.soap.client import SOAPBindingInvalidResponse
from ndg.saml.saml2.binding.soap.client.requestbase import (
    RequestBaseSOAPBinding,)

class SubjectQueryResponseError(SOAPBindingInvalidResponse):
    """SAML Response error from Subject Query"""
    

class SubjectQuerySOAPBinding(RequestBaseSOAPBinding):
    """SAML Subject Query SOAP Binding
    """
    SUBJECT_ID_OPTNAME = 'subjectID'
    SUBJECT_ID_FORMAT_OPTNAME = 'subjectIdFormat'
    
    CONFIG_FILE_OPTNAMES = (
        SUBJECT_ID_OPTNAME,
        SUBJECT_ID_FORMAT_OPTNAME
    )
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = tuple([__PRIVATE_ATTR_PREFIX + i 
                       for i in CONFIG_FILE_OPTNAMES])
    del i
    
    QUERY_TYPE = SubjectQuery
    
    def __init__(self, **kw):
        '''Create SOAP Client for a SAML Subject Query'''       
        super(SubjectQuerySOAPBinding, self).__init__(**kw)

    def _getSubjectID(self):
        if self.query.subject is None or self.query.subject.nameID is None:
            return None
        else:
            return self.query.subject.nameID.value

    def _setSubjectID(self, value):
        if self.query.subject is None:
            self.query.subject = Subject()
            
        if self.query.subject.nameID is None:
            self.query.subject.nameID = NameID()
            
        self.query.subject.nameID.value = value

    subjectID = property(_getSubjectID, _setSubjectID, 
                         doc="ID to be sent as query subject")
    
    def _getSubjectIdFormat(self):
        if self.query.subject is None or self.query.subject.nameID is None:
            return None
        else:
            return self.query.subject.nameID.format

    def _setSubjectIdFormat(self, value):
        if self.query.subject is None:
            self.query.subject = Subject()
            
        if self.query.subject.nameID is None:
            self.query.subject.nameID = NameID()
            
        self.query.subject.nameID.format = value

    subjectIdFormat = property(_getSubjectIdFormat, _setSubjectIdFormat, 
                               doc="Subject Name ID format")
