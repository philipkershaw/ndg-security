"""Encryption Handler package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/06/2009"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
from ZSI.wstools.Namespaces import ENCRYPTION

# Conditional import as this is required for the encryption
# handler
try:
    # For shared key encryption
    from Crypto.Cipher import AES, DES3
except:
    from warnings import warn
    warn('Crypto.Cipher not available: EncryptionHandler disabled!',
         RuntimeWarning)
    class AES:
        MODE_ECB = None
        MODE_CBC = None
        
    class DES3: 
        MODE_CBC = None
        
class _ENCRYPTION(ENCRYPTION):
    '''Derived from ENCRYPTION class to add in extra 'tripledes-cbc' - is this
    any different to 'des-cbc'?  ENCRYPTION class implies that it is the same
    because it's assigned to 'BLOCK_3DES' ??'''
    BLOCK_TRIPLEDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"