#!/bin/bash
#
# NDG Security Nose tests helper script
#
# NERC DataGrid
#
# Author: P J Kershaw
#
# Date: 05/08/09
#
# Copyright: STFC 2009
#
# Licence: BSD - See top-level LICENCE file for licence details
#
# These services must be running prior to execution(!).  They should be
# launched in separate terminals if you want to monitor the output:
#
# $ ../config/attributeauthority/sitea/siteAServerApp.py
# $ ../config/attributeauthority/siteb/siteBServerApp.py
# $ ../config/sessionmanager/sessionManagerServerApp.py
# $ ./wssecurity/dom/server/echoServer.py
# $ ./wssecurity/foursuite/server/echoServer.py
# $ ./soap/soap_server.py
#
# http_proxy setting interferes with connections to localhost:
unset http_proxy
${NOSETESTS:-nosetests} --config ./nosetests.ini $@

