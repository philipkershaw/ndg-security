#! /bin/bash
#
# Set-up script for NDG security software
#
# Run this script to initialise the environment for
# NDG security
#
# NERC Data Grid Project
#
# P J Kershaw 21/10/05
#
# Copyright (C) 2005 CCLRC & NERC
#
# This software may be distributed under the terms of the Q Public License,
# version 1.0 or later.
#
# $Id$

# NDG Installation directory
export NDG_DIR=<NDG location>


# NDG Custom Python installation
if [ ! `echo ${PATH} | grep "${NDG_DIR}<python location>"` ]; then

    export PATH=${NDG_DIR}<python location>:$PATH
fi

# Globus Toolkit and MyProxy Server
export GLOBUS_LOCATION=<Globus location>
export MYPROXY_SERVER=<hostname>

if [ ! `echo ${PATH} | grep "${GLOBUS_LOCATION}/bin"` ]; then

    export PATH=${PATH}:${GLOBUS_LOCATION}/bin
fi

if [ ! `echo ${PATH} | grep "${GLOBUS_LOCATION}/sbin/"` ]; then

    export PATH=${PATH}:${GLOBUS_LOCATION}/sbin/
fi


# MySQL 
if [ ! `echo ${PATH} | grep "/usr/local/mysql/bin"` ]; then

    export PATH=/usr/local/mysql/bin:$PATH
fi
