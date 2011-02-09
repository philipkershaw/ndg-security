#
# NERC Data Grid Project
#
# @author P J Kershaw 25/01/07
#
# Copy proxy cert and private key to set up Attribute Authority unit test.
#
# @copyright (C) 2007 CCLRC & NERC
#
# @license This software may be distributed under the terms of the Q Public
# License, version 1.0 or later.
#
# $Id:$
PROXYFILES=proxy-cert.pem proxy-key.pem
PYTHONPATH=/usr/bin/python

initAttAuthorityClientUnittest:
	@echo Set-up AttAuthority unit test by copying proxy file output from this test...
	${PYTHONPATH} ./MyProxyClientTest.py MyProxyClientTestCase.test2GetDelegation
	cp ${PROXYFILES} ../AttAuthority
