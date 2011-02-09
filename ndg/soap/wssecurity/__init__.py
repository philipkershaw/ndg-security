"""NDG SOAP WS-Security package

NERC DataGrid Project 
"""
__author__ = "P J Kershaw"
__date__ = "26/01/2010"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
class WSSecurityError(Exception):
    """For WS-Security generic exceptions not covered by other exception
    classes in this module"""
    
        
class WSSecurityConfigError(WSSecurityError):
    """Configuration error with WS-Security setting or settings"""


class InvalidCertChain(WSSecurityError):    
    """Raised from SignatureHandler.verify if the certificate submitted to
    verify a signature is not from a known CA"""
 
 
class TimestampError(WSSecurityError):
    """Raised from SignatureHandler._verifyTimestamp if there is a problem with
    the created or expiry times in an input message Timestamp"""


class MessageExpired(TimestampError):
    """Raised from SignatureHandler._verifyTimestamp if the timestamp of
    the message being processed is before the current time.  Can be caught in
    order to set a wsu:MessageExpired fault code"""
