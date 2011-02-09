#
# NERC Data Grid Project
#
# @author P J Kershaw 05/12/07
#
# Generate web service stubs from WSDL for Attribute Authority client and
# server side code
#
# @copyright (C) 2007 STFC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
WSDL_FILE=../echo.wsdl
CMD1=wsdl2py
OPTS1=-be -f
CMD2=wsdl2dispatch
OPTS2=-e -f


STUB_FILE=EchoService_services_server.py
TMP_FILE=EchoService_services_server.py.tmp

ORIG1=from Echo_services import
REPL1=from ndg.security.test.wsSecurity.server.Echo_services import

generateStubs: ${WSDL_FILE}
	@echo Generate stub ...
	${CMD1} ${OPTS1} ${WSDL_FILE}
	${CMD2} ${OPTS2} ${WSDL_FILE}
	@echo Make substitutions for compatibility for correct NDG import ...
	@cat ${STUB_FILE}|sed  s/"${ORIG1}"/"${REPL1}"/g > ${TMP_FILE}
	@mv ${TMP_FILE} ${STUB_FILE}
	@echo Done.
