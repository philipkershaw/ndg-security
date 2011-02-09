"""SOAP Server helper module for unit test

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.security.test.unit.soap.test_soap import SOAPBindingMiddleware
from paste.httpserver import serve

if __name__ == "__main__":
    app = SOAPBindingMiddleware()
    serve(app, host='0.0.0.0', port=10080)

