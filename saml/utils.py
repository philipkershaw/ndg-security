"""Utilities module for NDG Security SAML implementation

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "10/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
try:
    from datetime import strptime
except ImportError:
    # Allow for Python < 2.5
    from time import strptime as _strptime
    strptime = lambda datetimeStr, format: datetime(*(_strptime(datetimeStr, 
                                                                format)[0:6]))
from datetime import datetime, timedelta
        
        
class SAMLDateTime(object):
    """Generic datetime formatting utility for SAML timestamps - XMLSchema
    Datetime format
    """
    DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
    
    @classmethod
    def toString(cls, dtValue):
        """Convert issue instant datetime to correct string type for output
        @type dtValue: datetime.datetime
        @param dtValue: issue instance as a datetime
        @rtype: basestring
        @return: issue instance as a string
        """
        if not isinstance(dtValue, datetime):
            raise TypeError("Expecting datetime type for string conversion, "
                            "got %r" % dtValue)
            
        # isoformat provides the correct formatting
#        return dtIssueInstant.strftime(cls.DATETIME_FORMAT)
        return datetime.isoformat(dtValue)+'Z'

    @classmethod
    def fromString(cls, strDateTime):
        """Convert issue instant string to datetime type
        @type strDateTime: basestring
        @param strDateTime: issue instance as a string
        @rtype: datetime.datetime
        @return: issue instance as a datetime
        """
        if not isinstance(strDateTime, basestring):
            raise TypeError("Expecting basestring derived type for string "
                            "conversion, got %r" % strDateTime)
        
        # Workaround for seconds fraction as strptime doesn't seem able to deal
        # with this 
        strDateTimeFraction, strSecondsFraction = strDateTime.split('.')
        dtValue = datetime.strptime(strDateTimeFraction, cls.DATETIME_FORMAT)
        secondsFraction = float("0." + strSecondsFraction.replace('Z', ''))
        dtValue += timedelta(seconds=secondsFraction)
        return dtValue


class TypedList(list):
    """Extend list type to enabled only items of a given type.  Supports
    any type where the array type in the Standard Library is restricted to 
    only limited set of primitive types
    """
    
    def __init__(self, elementType, *arg, **kw):
        """
        @type elementType: type/tuple
        @param elementType: object type or types which the list is allowed to
        contain.  If more than one type, pass as a tuple
        """
        self.__elementType = elementType
        super(TypedList, self).__init__(*arg, **kw)
    
    def _getElementType(self):
        return self.__elementType
    
    elementType = property(fget=_getElementType, 
                           doc="The allowed type or types for list elements")
     
    def extend(self, iter):
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                
        return super(TypedList, self).extend(iter)
        
    def __iadd__(self, iter):
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                    
        return super(TypedList, self).__iadd__(iter)
         
    def append(self, item):
        if not isinstance(item, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
    
        return super(TypedList, self).append(item)
