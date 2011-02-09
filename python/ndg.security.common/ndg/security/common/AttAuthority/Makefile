#
# NERC Data Grid Project
#
# @author P J Kershaw 24/01/07
#
# Generate web service stubs from WSDL for Attribute Authority client and
# server side code
#
# @copyright (C) 2007 CCLRC & NERC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
WSDL_FILE=../../../../../www/html/attAuthority.wsdl
CMD=wsdl2py
OPTS=-be -f

generateStubs: ${WSDL_FILE}
	@echo Generate stub ...
	${CMD} ${OPTS} ${WSDL_FILE}
	@echo Done.
	