"""NDG Attribute Authority User Roles class - acts as an interface between
the data centre's user roles configuration and the Attribute Authority
                                                                                
NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/07/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:siteBUserRoles.py 4371 2008-10-29 09:44:51Z pjkersha $'


from ndg.security.server.attributeauthority import AttributeInterface


class TestUserRoles(AttributeInterface):
    """Test User Roles class dynamic import for Attribute Authority"""

    def __init__(self, propertiesFilePath=None):
        pass


    def userIsRegistered(self, userId):
        return False


    def getRoles(self, userId):
        # Make so that Site B never returns any roles - the only way to
        # get an Attribute Certificate is then through the role mapping
        return [] 
