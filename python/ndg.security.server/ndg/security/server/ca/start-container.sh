#! /bin/sh
#
# NDG Security Script to start twisted with container for Certificate 
# Authority
# 
# NERC Data Grid Project
#
# @author P J Kershaw 12/02/07
#
# @copyright (C) 2007 CCLRC & NERC
#
# @license This software may be distributed under the terms of the Q Public 
# License, version 1.0 or later.
#
# $Id:$
EXEC=twistd 
OPTIONS=-noy
CONFIG=server-config.tac

set - ${EXEC} ${OPTIONS} ${CONFIG} "$@"
exec "$@"
