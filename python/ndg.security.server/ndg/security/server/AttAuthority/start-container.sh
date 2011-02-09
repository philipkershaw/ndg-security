#! /bin/sh
#
# NDG Security Script to start twisted with container for Attribute Authority
# 
# NERC Data Grid Project
#
# @author P J Kershaw 23/11/06
#
# @copyright (C) 2007 CCLRC & NERC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
EXEC=twistd 
OPTIONS="--pidfile=twistd-$$.pid -noy"

prefixDir=$(dirname $(dirname $(type -p python)))
srvSubDir=lib/site-packages/ndg/security/server/AttAuthority

if [ ! -d ${prefixDir} ]; then
	echo "Path to tac file not found"
	exit 1;
fi

installPath=${HOME}/Development/security/python/ndg.security.server/ndg/security/server/AttAuthority
#installPath=${pythonPrefixDir}/${srvSubDir}
if [ -d ${installPath} ]; then
	CONFIG=${installPath}/server-config.tac
else
	CONFIG=./server-config.tac
fi

set - ${EXEC} ${OPTIONS} ${CONFIG} "$@"
exec "$@"
