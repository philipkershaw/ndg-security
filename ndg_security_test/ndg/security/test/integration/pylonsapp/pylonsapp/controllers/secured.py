"""NDG Security example Pylons controller with decorators

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "18/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging

from pylons import request, response, session, tmpl_context as c
from pylons.controllers.util import abort, redirect_to

from pylonsapp.lib.base import BaseController, render

from ndg.security.server.utils.pylons_ext import AuthenticationDecorators

log = logging.getLogger(__name__)

class SecuredController(BaseController):

    def index(self):
        # Return a rendered template
        return render('/secured.mako')
    
    @AuthenticationDecorators.login        
    def login(self):
        redirect_to('/secured/index')
      
    @AuthenticationDecorators.logout      
    def logout(self):
        log.warning('Got to logout action')
