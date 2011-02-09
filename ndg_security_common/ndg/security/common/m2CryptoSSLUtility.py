"""Code moved to ndg.security.common.utils.m2crypto

NERC DataGrid Project"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import warnings
warnings.warn("Module moved use ndg.security.common.utils.m2crypto instead of "
              "%s" % __file__, PendingDeprecationWarning)

from ndg.security.common.utils.m2crypto import *
