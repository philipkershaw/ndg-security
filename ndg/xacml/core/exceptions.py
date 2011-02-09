"""NDG XACML exception types for policy parsing

NERC DataGrid
"""
__author__ = "P J Kershaw"
__date__ = "01/04/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.xacml import XacmlError


class UnsupportedFunctionError(XacmlError):
    """Encountered a function type that is not supported in this implementation
    """
 
class UnsupportedStdFunctionError(UnsupportedFunctionError): 
    """Encountered a function type that is not supported even though it is part
    of the XACML spec."""