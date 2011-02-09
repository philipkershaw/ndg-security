"""NDG Security common package - contains dependencies common to
server and client packages

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/10/06"
__copyright__ = "(C) 2007 STFC & NERC"
__contact__ = "P.J.Kershaw@rl.ac.uk"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"

# Enable from ndg.security.common import * for client and server modules.
# Leave out SQLObject because it's an optional module and requires 
# installation of SQLObject
__all__ = [
    'authz',
    'AttAuthority',
    'AttCert',
    'CredWallet',
    'm2CryptoSSLUtility',
    'openssl',
    'sessionCookie',
    'SessionMgr',
    'wsSecurity',
    'X509',
    'XMLSec',
    'zsi_utils'
    ]