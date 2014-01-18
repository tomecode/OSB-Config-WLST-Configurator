@ECHO OFF


SET OSB_HOME=D:\Oracle\Middleware11gPS6\Oracle_OSB1ps6
SET WL_HOME=D:\Oracle\Middleware11gPS6\wlserver_10.3
@REM CALL "%WL_HOME%\server\bin\setWLSEnv.cmd"

SET CLASSPATH=%WL_HOME%\server\lib\weblogic.jar
@REM SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\common\lib\customizer.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-kernel-api.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-kernel-common.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-kernel-impl.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-kernel-resources.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-kernel-wls.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-transports-http-wls.jar
SET CLASSPATH=%CLASSPATH%;%OSB_HOME%\lib\sb-transports-main.jar
SET CLASSPATH=%CLASSPATH%;%~p0\osb-wlst-customization-0.0.2-SNAPSHOT.jar


SETLOCAL enabledelayedexpansion

for %%i in (%OSB_HOME%\lib\modules\*.jar) do call :AddToPath %%i
for %%i in (%OSB_HOME%\modules\*.jar) do call :AddToPath %%i

java -Dfile.encoding=UTF-8 -Dweblogic.wlstHome=%temp%\osbCustomizer\ weblogic.WLST -i osbCustomizer.py %*

:AddToPath
SET CLASSPATH=%CLASSPATH%;%1
GOTO :EOF
