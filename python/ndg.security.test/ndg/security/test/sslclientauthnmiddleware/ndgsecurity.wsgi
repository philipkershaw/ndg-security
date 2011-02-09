"""WSGI container for loading NDG Security applications

For use with SSL Client Authentication Middleware unit tests.  Requires 
mod_wsgi to be installed and this file to be deployed so that it can be loaded
e.g.
<VirtualHost localhost:443 ...:443>
.
.
.
		SSLVerifyClient optional_no_ca
		SSLVerifyDepth  10
		SSLOptions +StdEnvVars +ExportCertData
.
.
.
        WSGIDaemonProcess localhost processes=2 threads=15 display-name=%{GROUP} python-path=...
        WSGIProcessGroup localhost
        WSGIScriptAlias /ndgsecurity /var/www/wsgi/ndgSecurity.wsgi
        
        <Directory /usr/local/www/wsgi>
            Order allow,deny
            Allow from all
        </Directory>
.
.
.
</VirtualHost>


NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "11/12/08"
__copyright__ = "(C) 2008 STFC & NERC"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import ndg.security.server.wsgi.apploader
from ndg.security.server.wsgi.apploader import AppLoaderMiddleware

application = AppLoaderMiddleware(configFilePath='/var/www/wsgi/ndg-security.ini')