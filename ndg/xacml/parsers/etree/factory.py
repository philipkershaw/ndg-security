"""NDG XACML ElementTree reader module containing reader base class 

NERC DataGrid
"""
__author__ = "P J Kershaw"
__date__ = "19/03/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ndg.xacml.parsers import AbstractReaderFactory
from ndg.xacml.utils.factory import importModuleObject

from ndg.xacml.core.policy import Policy
from ndg.xacml.core.target import Target
from ndg.xacml.core.rule import Rule

# Target child elements
from ndg.xacml.core.subject import Subject
from ndg.xacml.core.action import Action
from ndg.xacml.core.resource import Resource
from ndg.xacml.core.environment import Environment


class ReaderFactory(AbstractReaderFactory):
    """Parser factory for ElementTree based parsers for XACML types"""
    
    @classmethod
    def getReader(cls, xacmlType):
        """Return ElementTree based Reader class for the given input
        
        @param xacmlType: XACML type to return a parser class for
        @type xacmlType: type
        @return: ElementTree based reader for the input XACML type.  The class
        and module containing the class are infered from the XACML class name
        input e.g. 
        
        ndg.xacml.core.Subject => ndg.xacml.parsers.etree.subjectreader.SubjectReader
        
        @rtype: ndg.xacml.parsers.etree.reader.ETreeAbstractReader derived
        type
        @raise ImportError: if no reader class found for input type
        """
        xacmlTypeName = xacmlType.__name__
        readerClassName = 'ndg.xacml.parsers.etree.%sreader.%sReader' % (
                                                        xacmlTypeName.lower(),
                                                        xacmlTypeName)
        readerClass = importModuleObject(readerClassName)
        return readerClass
            
