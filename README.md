OSB-Config-WLST-Configurator
===================


The OSB-Config-WLST-Configurator is a simple the WLST script that contains several features for a more detailed customization of SBConfig Jar file, before deploying to the OSB. The WLST script to read existing SBConfig jar and modify (customize) it according to the settings in the properties and generate a new SBConfig JAR. The WLST script allow you change e.g.: enpoint URI, enable or disble transactions, transport level security, timeout, retry count, etc.

![OSB-Config-WLST-Configurator](http://osb-config-wlst-configurator.tomecode.com/OSB-Config-WLST-Configurator.png)


**OSB-Config-WLST-Configurator supports customization of the following OSB resources:**
* Proxy Service
* Business Service
* (Static) Service Account
* SMTP
* JNDI
* UDDI
* Proxy Server
* Alert Destination
* Service (Key) Provider
* GlobalOperationSettings
* MQConnection

**OSB-Config-WLST-Configurator supports customization of the following OSB transports:**
* LOCAL
* HTTP
* JMS
* MQ
* FTP
* SFTP
* EMAIL
* SB

For more information about [OSB-Config-WLST-Configurator](http://osb-config-wlst-configurator.tomecode.com/), please visit [wiki pages](https://github.com/tomecode/OSB-Config-WLST-Configurator/wiki/OSB-Config-WLST-Configurator) or download latest [OSB-Config-WLST-Configurator release](https://github.com/tomecode/OSB-Config-WLST-Configurator/releases).

[![Build Status](https://travis-ci.org/TrentBartlem/OSB-Config-WLST-Configurator.svg?branch=master)](https://travis-ci.org/TrentBartlem/OSB-Config-WLST-Configurator)


This project is member of [OSB utilities](https://github.com/tomecode/osb-utilities)
