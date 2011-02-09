#!/usr/bin/env python
"""NDG Security Paster template classes

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/10/2010"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import os
import socket
import base64
from paste.script.templates import Template, var, _skip_variables
_hostTuple = socket.gethostbyaddr(socket.gethostname())
try:
    # Get first alias from list if present
    _hostname = _hostTuple[1][0]
except TypeError:
    # ... or default to hostname
    _hostname = _hostTuple[0]
    
vars = [
    var('siteName', 
        ('Full name for this site used by the Attribute Authority to describe '
         'this site'),
        default='NDG Partner Site'),
    var('attributeAuthorityID', 
        ('Unique identity by which this Attribute Authority will be known by '
         'other trusted sites'),
        default=_hostname)
]

class DefaultDeploymentTemplate(Template):
    _template_dir = 'default_deployment'
    summary = 'NERC DataGrid Security services deployment template'
    vars = vars

# Single Sign On Service not included in this template
#    def write_files(self, command, output_dir, vars):
#        '''Extend to enable substitutions for Single Sign On Service config
#        file'''
#        if output_dir.startswith('./'):
#            outDir = output_dir.lstrip('./')
#        else:
#            outDir = output_dir
#            
#        vars['ssoConfigDir'] = os.path.join(os.getcwd(), outDir, 'sso')
#        super(DefaultDeploymentTemplate, self).write_files(command, 
#                                                           output_dir, 
#                                                           vars)
        
class FullDeploymentTemplate(Template):
    _template_dir = 'full_deployment'
    summary = ('NERC DataGrid Security services full deployment template '
               'including the Single Sign On Service')
    vars = vars

    def write_files(self, command, output_dir, vars):
        '''Extend to enable substitutions for Single Sign On Service config
        file'''
        if output_dir.startswith('./'):
            outDir = output_dir.lstrip('./')
        else:
            outDir = output_dir
            
        vars['installDir'] = os.path.join(os.getcwd(), outDir)
        super(FullDeploymentTemplate, self).write_files(command, 
                                                        output_dir, 
                                                        vars)

        
class SecuredAppTemplate(Template):
    _template_dir = 'full_deployment'
    summary = (
        'Template to secure an application with NERC DataGrid Security '
        'authentication and authorisation filters')
    vars = [
        var('hostname', 
            ('Virtual host name to mount services on'),
            default=_hostname),

        var('authkitCookieSecret', 
            ('Cookie secret for AuthKit authentication middleware (if using a '
             'separate SSL based OpenID Relying Party then this value MUST '
             'agree with the one used for that ini file'),
            default=base64.b64encode(os.urandom(32))[:32]),

        var('beakerSessionSecret', 
            ('Cookie secret for keeping security session state'),
            default=base64.b64encode(os.urandom(32))[:32])
    ]

    def write_files(self, command, output_dir, vars):
        '''Extend to enable substitutions for Single Sign On Service config
        file'''
        if output_dir.startswith('./'):
            outDir = output_dir.lstrip('./')
        else:
            outDir = output_dir
            
        vars['installDir'] = os.path.join(os.getcwd(), outDir)
        super(FullDeploymentTemplate, self).write_files(command, 
                                                        output_dir, 
                                                        vars)
       
        