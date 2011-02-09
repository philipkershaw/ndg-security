#!/bin/bash
#
# NERC Data Grid Project
#                                                                                
# Certificate Authority client unit test - start server
#
#@author P J Kershaw 09/02/07
#                                                                                
#@copyright (C) 2007 CCLRC & NERC
#                                                                                
#@licence: This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
export NDGSEC_CA_PROPFILEPATH=${PWD}/simpleCAProperties.xml
export NDGSEC_CA_UNITTEST_DIR=${PWD}

srvDir1=../../server/ca
srvDir2=../../../../../ndg.security.server/ndg/security/server/ca

if [ -d $srvDir1 ]; then
	SRV_DIR=$srvDir1

elif [ -d $srvDir2 ]; then
	SRV_DIR=$srvDir2
fi

cd $SRV_DIR 
exec ./start-container.sh "$@"

