#!/usr/bin/env python

from paste.script.templates import Template, var, _skip_variables
import os
import socket
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