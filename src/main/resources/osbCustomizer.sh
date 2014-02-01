#!/bin/bash


WL_HOME="/opt/app/oracle/products/Middleware11gPS6_01/wlserver_10.3"
OSB_HOME="/opt/app/oracle/products/Middleware11gPS6_01/Oracle_OSB1"
export JAVA_HOME="/opt/app/oracle/products/jrockit-jdk1.6.0_29-R28.2.2-4.1.0"
export PATH=${JAVA_HOME}/bin:$PATH

export CLASSPATH=${WL_HOME}/server/lib/weblogic.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-kernel-common.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-kernel-resources.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-kernel-api.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-kernel-impl.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-kernel-wls.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-transports-main.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/sb-transports-http-wls.jar:$CLASSPATH
export CLASSPATH=${OSB_HOME}/lib/modules/*:$CLASSPATH
export CLASSPATH=${OSB_HOME}/modules/*:$CLASSPATH
export CLASSPATH=${OSB_HOME}/modules/features/*:$CLASSPATH
export CLASSPATH=./*.jar:$CLASSPATH

echo $CLASSPATH

java weblogic.WLST -i osbCustomizer.py $1
