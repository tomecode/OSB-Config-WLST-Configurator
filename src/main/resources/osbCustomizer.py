####################################################################
#
#	Author:                         Tomas (Tome) Frastia
#	Web:                            http://www.TomeCode.com
#	Version:                        3.0
#	Description:					
#
####################################################################

import sys, traceback
import os
import os.path
import time

from java.io import ByteArrayInputStream;
from java.io import ByteArrayOutputStream;
from java.io import FileOutputStream;
from java.util.jar import JarInputStream
from java.util.jar import JarOutputStream
from java.util.jar import JarEntry;

#from com.tomecode.utils import Utils



from com.bea.wli.domain.config import OperationalSettings;
from com.bea.wli.sb.resources.config import SmtpServerEntry;

from com.bea.wli.sb.resources.config import JndiProviderEntry;
from com.bea.wli.sb.resources.config import ServiceAccountUserPassword;
from com.bea.wli.sb.resources.config import UserPassword;
from com.bea.wli.sb.services import ServiceAccountDocument;
from com.bea.wli.sb.services import ServiceDefinition;
from com.bea.wli.sb.services import StaticServiceAccount;
from com.bea.wli.sb.transports import EndPointConfiguration;
from com.bea.wli.sb.transports import URIType;

from com.bea.wli.sb.transports.http import AuthenticationConfigurationType;
from com.bea.wli.sb.transports.http import HttpBasicAuthenticationType;
from com.bea.wli.sb.transports.http import HttpEndPointConfiguration;
from com.bea.wli.sb.transports.http import HttpInboundPropertiesType;
from com.bea.wli.sb.transports.http import HttpOutboundPropertiesType;
from com.bea.wli.sb.transports.http import HttpRequestMethodEnum;

from com.bea.wli.sb.transports.jms import JmsEndPointConfiguration;
from com.bea.wli.sb.transports.jms import JmsResponsePatternEnum
from com.bea.wli.sb.transports.jms import JmsMessageTypeEnum

from com.bea.wli.sb.uddi import UDDIRegistryEntry;

from com.bea.wli.sb.security.accesscontrol.config import PolicyContainerType;
from com.bea.wli.sb.security.accesscontrol.config import ProviderPolicyContainerType;




from com.bea.wli.sb.util import Refs
from com.bea.wli.config.customization import Customization
from com.bea.wli.sb.management.importexport import ALSBImportOperation
from com.bea.wli.sb.management.configuration import SessionManagementMBean
from com.bea.wli.sb.management.configuration import ServiceConfigurationMBean
from com.bea.wli.sb.management.configuration import ALSBConfigurationMBean
from com.bea.wli.sb.management.query import ProxyServiceQuery




#===================================================================
# Jar Entry
#===================================================================
class OsbJarEntry:
	name=''
	directory=False;
	data=None
	def __init__(self,n,d,b):
		self.data=b
		self.directory=d
		self.name=n
		
	def getName(self):
		return self.name
		
	def getData(self):
		return self.data
	
	def setData(self, d):
		self.data=d
	
	def getServiceDefinition(self):
		return ServiceDefinition.Factory.parse(ByteArrayInputStream(self.data))

	def setServiceDefinition(self, serviceDefinition):
		self.data=serviceDefinition.toString().encode('utf-8')


def findOsbJarEntry(indexName,osbJarEntries):
	for entry in osbJarEntries:
		if entry.getName()==indexName:
			return entry;
		
	return None
	

#===================================================================
# Parse sbconfig file
#===================================================================
def parseOsbJar(data):
	osbJarEntries=[]
	jis = None
	jis = JarInputStream(ByteArrayInputStream(data))

	entry = jis.getNextJarEntry()
	print str(entry)
	while (entry != None):
		if (entry.isDirectory()):
			osbJarEntries.append(OsbJarEntry(entry.toString(), entry.isDirectory(), None))
		else:
			osbJarEntries.append(OsbJarEntry(entry.toString(), entry.isDirectory(), Utils.readJarEntryToBytes(jis,entry)))
		entry = jis.getNextJarEntry()
	
	jis.close()
	return osbJarEntries
	
def convertToTuple(values):
	list=[]
	if '<type \'str\'>' in str(type(values)):
		list.append(str(values))
	else:
		for val in values:
			list.append(val)
	return list

#===================================================================
# Generating a new sbconfig file
#===================================================================
def generateNewSBConfig(osbJarEntries):
	baos = ByteArrayOutputStream()
	jos = None
	try:
		jos = JarOutputStream(baos)
		for entry in osbJarEntries:
			jarEntry = JarEntry(entry.getName())
			jos.putNextEntry(jarEntry)
			if entry.getData() != None:
				jos.write(entry.getData(), 0, len(entry.getData()));
			jos.closeEntry()
	except Exception, err:
		print traceback.format_exc()
	jos.close()
	return baos.toByteArray()


#===================================================================
# Read binary file (Sbconfig)
#===================================================================
def readBinaryFile(fileName):
    file = open(fileName, 'rb')
    bytes = file.read()
    return bytes

#===================================================================
# Write binary file (Sbconfig)
#===================================================================
def writeToFile(fName, data):
	fos = FileOutputStream(fName)
	fos.write(data)
	fos.flush()
	fos.close()
	
		
def deployNewSBconfig(sbFileName,data):		
	index=sbFileName.rfind('.')
	newSbFileName= sbFileName[0:index] + '-' + time.strftime('%Y%m%d_%H%M%S')+'.jar'
	print ' New customizated sbconfig is: ' + newSbFileName
	writeToFile(newSbFileName,data)
	return newSbFileName

#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------



#===================================================================
# Connect to the Admin Server
#===================================================================
def connectToOSB():
	print ' --- Connecting to OSB server '
	uri = 't3://' + SB_SERVER['ListenAddress'] + ':' + str(SB_SERVER['ListenPort'])
	try:
		connect(SB_SERVER['Username'],SB_SERVER['Password'],uri)
		domainRuntime()
		return True
	except WLSTException:
		print ' --- No server is running at '+ uri+ ' !\n Deploy cancelled!'
		return False


#===================================================================
# Utility function to load a session MBeans
#===================================================================
def createOSBSession():
	sessionName  = "ScriptSession" + str(System.currentTimeMillis())
	sessionMBean = findService(SessionManagementMBean.NAME, SessionManagementMBean.TYPE)
	sessionMBean.createSession(sessionName)
	print '	..OSB Session Created: ' + sessionName
	return sessionMBean, sessionName

def createImportProject(ALSBConfigurationMBean):
	alsbJarInfo = ALSBConfigurationMBean.getImportJarInfo()
	alsbImportPlan = alsbJarInfo.getDefaultImportPlan()
	#alsbImportPlan.setPassphrase(None)
	alsbImportPlan.setPreserveExistingAccessControlPolicies(False)
	alsbImportPlan.setPreserveExistingCredentials(False)
	alsbImportPlan.setPreserveExistingOperationalValues(False)
	alsbImportPlan.setPreserveExistingEnvValues(False)
	alsbImportPlan.setPreserveExistingSecurityAndPolicyConfig(False)
	return ALSBConfigurationMBean.importUploaded(alsbImportPlan)

def uploadSbCofnigToOSB(ALSBConfigurationMBean, sbConfigJar):
	ALSBConfigurationMBean.uploadJarFile(readBinaryFile(sbConfigJar))
	print '		..Uploaded: ' + sbConfigJar
	importResult= createImportProject(ALSBConfigurationMBean)


def deployToOsb(file):
	print '	Deploying to OSB: '+ file
	
	try:
		connectToOSB()

		#create new session
		sessionMBean, sessionName = createOSBSession()
		
		ALSBConfigurationMBean = findService(String("ALSBConfiguration.").concat(sessionName), "com.bea.wli.sb.management.configuration.ALSBConfigurationMBean")

		#simple import without customization
		uploadSbCofnigToOSB(ALSBConfigurationMBean,file)

			
		print '		..Commiting session, please wait, this can take a while...'
		sessionMBean.activateSession(sessionName, "Import from wlst") 
		print '		..Session was successfully committed!'
		print '	'
	except java.lang.Exception, e:
		print '	Import to OSB: Failed, please see logs...' + '\n	' 
		
		dumpStack()	
		if sessionMBean != None:
			sessionMBean.discardSession(sessionName)

#################################################################

class OsbJarEntry:
	name=''
	directory=False;
	data=None
	def __init__(self,n,d,b):
		self.data=b
		self.directory=d
		self.name=n
		
	def getName(self):
		return self.name
		
	def getData(self):
		return self.data
	
	def setData(self, d):
		self.data=d
	
	def getServiceDefinition(self):
		return ServiceDefinition.Factory.parse(ByteArrayInputStream(self.data))

	def setServiceDefinition(self, serviceDefinition):
		self.data=serviceDefinition.toString().encode('utf-8')


def findOsbJarEntry(indexName,osbJarEntries):
	for entry in osbJarEntries:
		if entry.getName()==indexName:
			return entry;
		
	return None
	

def parseOsbJar(data):
	osbJarEntries=[]
	jis = None
	jis = JarInputStream(ByteArrayInputStream(data))

	entry = jis.getNextJarEntry()
	while (entry != None):
		if (entry.isDirectory()):
			osbJarEntries.append(OsbJarEntry(entry.toString(), entry.isDirectory(), None))
		else:
			osbJarEntries.append(OsbJarEntry(entry.toString(), entry.isDirectory(), Utils.readJarEntryToBytes(jis,entry)))
		entry = jis.getNextJarEntry()
	
	jis.close()
	return osbJarEntries


def generateNewSBConfig(osbJarEntries):
	baos = ByteArrayOutputStream()
	jos = None
	try:
		jos = JarOutputStream(baos)
		for entry in osbJarEntries:
			jarEntry = JarEntry(entry.getName())
			jos.putNextEntry(jarEntry)
			if entry.getData() != None:
				jos.write(entry.getData(), 0, len(entry.getData()));
			jos.closeEntry()
	except Exception, err:
		print traceback.format_exc()
	jos.close()
	return baos.toByteArray()


#################################################################

def readBinaryFile(fileName):
    file = open(fileName, 'rb')
    bytes = file.read()
    return bytes

def writeToFile(fName, data):
	fos = FileOutputStream(fName)
	fos.write(data)
	fos.flush()
	fos.close()
	
	
#################################################################
#################################################################


def policeExpression(policeConfig):
	expression = ''
	
	if 'Users' in policeConfig:
		print 'users'
		for user in policeConfig['Users']:
			expression += '| Usr('+ str(user) + ')'
	
	if 'Groups' in policeConfig:
		for group in policeConfig['Groups']:
			expression += '| Grp('+ str(group) + ')'
	
	if 'Roles' in policeConfig:
		for role in policeConfig['Roles']:
			expression += '| Rol('+ str(role) + ')'

	expression=expression.strip()
	if expression.startswith('|'):
		expression=expression[2:len(expression)]
		
	print ''
	print expression
	print ''
		
	return expression


def changeEndpointUri( endpoints,serviceDefinition):
	endpointConfiguration = serviceDefinition.getEndpointConfig()
	if len(endpointConfiguration.getURIArray()) >= 1:
		#uris=URIType[0]
		endpointConfiguration.setURIArray([])
		
	for uri in endpoints:
		endpointConfiguration.addNewURI().setValue(uri)

		
def getHttpInboundProperties(serviceDefinition):
	httpEndPointConfiguration = getHttpEndPointConfiguration(serviceDefinition)
	httpInboundProperties= httpEndPointConfiguration.getInboundProperties()
	if httpInboundProperties == None:
		httpInboundProperties= httpEndPointConfiguration.addNewInboundProperties();
	return httpInboundProperties


def getHttpOutboundProperties(serviceDefinition):
	httpEndPointConfiguration = getHttpEndPointConfiguration(serviceDefinition)
	httpOutboundProperties= httpEndPointConfiguration.getOutboundProperties()
	if httpOutboundProperties == None:
		httpOutboundProperties= httpEndPointConfiguration.addNewOutboundProperties();
	return httpOutboundProperties


def getJmsInboundProperties(serviceDefinition):
	jmsEndPointConfiguration=getJmsEndPointConfiguration(serviceDefinition)
	jmsInboundProperties= jmsEndPointConfiguration.getInboundProperties()
	if jmsInboundProperties == None:
		jmsInboundProperties= jmsEndPointConfiguration.addNewInboundProperties();
	return jmsInboundProperties

	
def getTransactions(serviceDefinition):
	transactions=serviceDefinition.getCoreEntry().getTransactions()
	if transactions==None:
		return serviceDefinition.getCoreEntry().addNewTransactions()
	return transactions



def getHttpEndPointConfiguration(serviceDefinition):
	HttpEndPointConfiguration=serviceDefinition.getEndpointConfig().getProviderSpecific()
	return HttpEndPointConfiguration


def getJmsEndPointConfiguration(serviceDefinition):
	JmsEndPointConfiguration=serviceDefinition.getEndpointConfig().getProviderSpecific()
	return JmsEndPointConfiguration
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
	
def customizeUddi(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize UUID Service: ' + str(service)

		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: Not found service: ' + str(service)+ ' in SBconfig file'
			continue

		uddi = UDDIRegistryEntry.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
			
		serviceProperties=serviceType[service]

		for property in serviceProperties:		
			if 'Description' in property:
				uddi.setDescription(serviceProperties[property])
				print '		--> set Description'
			elif 'PublishUrl' in property:
				uddi.setPublishUrl(serviceProperties[property])
				print '		--> set PublishUrl'
			elif 'SubscriptionUrl' in property:
				uddi.setSubscriptionUrl(serviceProperties[property])
				print '		--> set Url'
			elif 'SecurityUrl' in property:
				uddi.setSecurityUrl(serviceProperties[property])
				print '		--> set SecurityUrl'
			elif 'Url' in property:
				uddi.setUrl(serviceProperties[property])
				print '		--> set Url'
			elif 'Username' in property:
				uddi.setUsername(serviceProperties[property])
				print '		--> set Username'
			elif 'Password' in property:
				uddi.setPassword(serviceProperties[property])
				print '		--> set Password'
			elif 'AutoImport' in property:
				uddi.setAutoImport(serviceProperties[property])
				print '		--> set AutoImport'
			elif 'LoadtModels' in property:
				uddi.setLoadtModels(serviceProperties[property])
				print '		--> set LoadtModels'
			else:
				print '		--> Warning: '+property+' property is not supported'
		
		jarEntry.setData(uddi.toString().encode('utf-8'))

	
		
def customizeSmtp(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize Service: ' + str(service)
		
		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: Not found service: ' + str(service)+ ' in SBconfig file'
			continue

		smtpServerEntry = SmtpServerEntry.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
			
		serviceProperties=serviceType[service]

		for property in serviceProperties:
			if 'Description' in property:
				smtpServerEntry.setDescription(serviceProperties[property])
				print '		--> set Description'
			elif 'IsDefault' in property:
				smtpServerEntry.setIsDefault(serviceProperties[property])
				print '		--> set IsDefault'
			elif 'Password' in property:
				smtpServerEntry.setPassword(serviceProperties[property])
				print '		--> set Password'
			elif 'PortNumber' in property:
				smtpServerEntry.setPortNumber(serviceProperties[property])
				print '		--> set PortNumber'
			elif 'ServerURL' in property:
				smtpServerEntry.setServerURL(serviceProperties[property])
				print '		--> set ServerURL'
			elif 'Username' in property:
				smtpServerEntry.setUsername(serviceProperties[property])
				print '		--> set Username'
			else:
				print '		--> Warning: '+property+' property is not supported'
		
		jarEntry.setData(smtpServerEntry.toString().encode('utf-8'))


def customizeGlobalOperationalSettings(serviceType,osbJarEntries):

	jarEntry= findOsbJarEntry('System/Operator_Settings/GlobalOperationalSettings.Operations',osbJarEntries)
	if jarEntry==None:
		print '	--> Warning: Not found Global Operational Settings: ' + str(serviceType)+ ' in SBconfig file'
	else:
		print ' Customize: System/Operator_Settings/GlobalOperationalSettings.Operations'
		operationalSettings = OperationalSettings.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
		
		for property in serviceType:
			if 'Logging' in property:
				operationalSettings.setLogging(serviceType[property])
				print '		--> set Logging'
			elif 'Monitoring' in property:
				operationalSettings.setMonitoring(serviceType[property])
				print '		--> set Monitoring'
			elif 'PipelineAlerting' in property:
				operationalSettings.setPipelineAlerting(serviceType[property])
				print '		--> set PipelineAlerting'
			elif 'Reporting' in property:
				operationalSettings.setReporting(serviceType[property])
				print '		--> set Reporting'
			elif 'ResultCaching' in property:
				operationalSettings.setResultCaching(serviceType[property])
				print '		--> set ResultCaching'
			elif 'SlaAlerting' in property:
				operationalSettings.setSlaAlerting(serviceType[property])
				print '		--> set SlaAlerting'
			else:
				print '		--> Warning: '+property+' property is not supported'

		jarEntry.setData(operationalSettings.toString().encode('utf-8'))


def customizeServiceAccount(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize Service Account:' + str(service)

		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: '+str(service)+ ' not found Service Account'
			continue
				
		#parse service account
		serviceAccountDocument = ServiceAccountDocument.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
		serviceAccount = serviceAccountDocument.getServiceAccount()
		
		serviceAccountUserPassword = serviceAccount.getStaticAccount()
		#replace user/pass
		
		serviceProperties=serviceType[service]
				
		for property in serviceProperties:
			if 'Username' in property:
				serviceAccountUserPassword.setUsername(serviceProperties[property])
				print '		--> set Username'
			elif 'Password' in property:
				serviceAccountUserPassword.setPassword(serviceProperties[property])
				print '		--> set Password'
			elif 'Description' in property:
				serviceAccount.setDescription(serviceProperties[property])
				print '		--> set Description'
			else:
				print '		--> Warning: '+property+' property is not supported'

		jarEntry.setData(serviceAccountDocument.toString().encode('utf-8'))


def customizeLOCAL(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize Service:' + str(service)
		
		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: ' + str(service)+ ' not found service'
			continue
		
		#get service definition
		serviceDefinition=jarEntry.getServiceDefinition()

		serviceProperties=serviceType[service]
				
		for property in serviceProperties:
		
			if 'IsRequired' in property:
				getTransactions(serviceDefinition).setIsRequired(serviceProperties[property])
				print '		--> set IsRequired'
			elif 'SameTxForResponse' in property:
				getTransactions(serviceDefinition).setSameTxForResponse(serviceProperties[property])
				print '		--> set SameTxForResponse'
			elif 'Description' in property:
				serviceDefinition.getCoreEntry().setDescription(serviceProperties[property])
				print '		--> set Description'
			else:
				print '		--> Warning: '+property+' property is not supported'
	
		#update servicedefinition
		jarEntry.setServiceDefinition(serviceDefinition)


def customizeJms(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize Service:' + str(service)
		
		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: Not found service: ' + str(service)+ ' in SBconfig file'
			continue
		
		#get service definition
		serviceDefinition=jarEntry.getServiceDefinition()

		serviceProperties=serviceType[service]
				
		for property in serviceProperties:
		
			
			if 'EndpointUri' in property:
				changeEndpointUri(convertToTuple(serviceProperties[property]),serviceDefinition)
				print '		--> set EndpointUri'
			elif 'DispatchPolicy' in property:
				getJmsEndPointConfiguration(serviceDefinition).setDispatchPolicy(serviceProperties[property])
				print '		--> set DispatchPolicy'
			elif 'RequestEncoding' in property:
				getJmsEndPointConfiguration(serviceDefinition).setRequestEncoding(serviceProperties[property])
				print '		--> set RequestEncoding'
			elif 'JNDITimeout' in property:
				getJmsEndPointConfiguration(serviceDefinition).setJndiTimeout(serviceProperties[property])
				print '		--> set JNDITimeout'
			elif 'UseSSL' in property:
				getJmsEndPointConfiguration(serviceDefinition).setIsSecure(serviceProperties[property])
				print '		--> set UseSSL'
			elif 'IsXARequired' in property:
				getJmsInboundProperties(serviceDefinition).setXARequired(serviceProperties[property])
				print '		--> set IsXARequired'
			elif 'ErrorDestination' in property:
				getJmsInboundProperties(serviceDefinition).setErrorDestination(serviceProperties[property])
				print '		--> set ErrorDestination'
			elif 'MessageSelector' in property:
				getJmsInboundProperties(serviceDefinition).setMessageSelector(serviceProperties[property])
				print '		--> set MessageSelector'
			elif 'RetryCount' in property:
				getJmsInboundProperties(serviceDefinition).setRetryCount(serviceProperties[property])
				print '		--> set RetryCount'
			elif 'RetryInterval' in property:
				getJmsInboundProperties(serviceDefinition).setRetryInterval(serviceProperties[property])
				print '		--> set RetryInterval'
			elif 'IsResponseRequired' in property:
				getJmsInboundProperties(serviceDefinition).setResponseRequired(serviceProperties[property])			
			elif 'IsRequired' in property:
				getTransactions(serviceDefinition).setIsRequired(serviceProperties[property])
				print '		--> set IsRequired'
			elif 'SameTxForResponse' in property:
				getTransactions(serviceDefinition).setSameTxForResponse(serviceProperties[property])
				print '		--> set SameTxForResponse'
			elif 'Description' in property:
				serviceDefinition.getCoreEntry().setDescription(serviceProperties[property])
				print '		--> set Description'
			
			#
			#Destination Type: Queue
			elif 'DestinationTypeQueue' in property:
				print '		--> set Destination-Type-Queue'
				subConfig=serviceProperties[property]
				
				print str(subConfig)
				print '-----------------------------'
				for subProperty in subConfig:
					if 'ResponseEncoding' in subProperty:
						getJmsEndPointConfiguration(serviceDefinition).setResponseEncoding(subConfig[subProperty])
						print '		--> set ResponseEncoding'
					elif 'ResponsePattern' in subProperty:
						if "JMS_CORRELATION_ID" in subConfig[subProperty]:
							getJmsInboundProperties(serviceDefinition).setResponsePattern(JmsResponsePatternEnum.JMS_CORRELATION_ID)
							print '		--> set ResponsePattern'
						elif "JMS_MESSAGE_ID" in subConfig[subProperty]:
							getJmsInboundProperties(serviceDefinition).setResponsePattern(JmsResponsePatternEnum.JMS_MESSAGE_ID)						
							print '		--> set ResponsePattern'
						else:
							print '		--> Warning: Value: '+property+' for property: '+ResponsePattern+' is not supported'							
					elif 'ResponseMessageType' in subProperty:
						if "BYTES" in subConfig[subProperty]:
							getJmsInboundProperties(serviceDefinition).setResponseMessageType(JmsMessageTypeEnum.BYTES)
							print '		--> set ResponseMessageType'
						elif "TEXT" in subConfig[subProperty]:
							getJmsInboundProperties(serviceDefinition).setResponseMessageType(JmsMessageTypeEnum.TEXT)				
							print '		--> set ResponseMessageType'
						else:
							print '		--> Warning: Value: '+property+' for property: '+ResponsePattern+' is not supported'							
					elif 'ResponseURI' in subProperty:
						getJmsInboundProperties(serviceDefinition).setResponseURI(subConfig[subProperty])
					else:
						print '		--> Warning: Subproperty: '+subProperty+' in property: '+property+' is not supported'
					
			else:
				print '		--> Warning: '+property+' property is not supported'

		#update servicedefinition
		jarEntry.setServiceDefinition(serviceDefinition)


		
def customizeHttp(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize HTTP Proxy Service:' + str(service)
		
		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: Not found service: ' + str(service)+ ' in SBconfig file'
			continue
		
		#get service definition
		serviceDefinition=jarEntry.getServiceDefinition()
		
		serviceProperties=serviceType[service]
				
		for property in serviceProperties:
			if 'EndpointUri' in property:
				changeEndpointUri(convertToTuple(serviceProperties[property]),serviceDefinition)
				print '		--> set EndpointUri'
			elif 'UseHttps' in property:
				getHttpInboundProperties(serviceDefinition).setUseHttps(serviceProperties[property])
				print '		--> set UseHttps'
			elif 'TRANSPORT-LEVEL-POLICE' in property:
				policyExpression, provider= createPolicyExpression(serviceProperties[property],serviceDefinition)
				setupPolicyExpression(policyExpression,provider,serviceDefinition)
				print '		--> set TRANSPORT-LEVEL-POLICE'
			elif 'Security' in property:
				authType = serviceProperties[property]
				if 'BasicAuthentication' in authType:
					getHttpInboundProperties(serviceDefinition).setClientAuthentication(HttpBasicAuthenticationType.Factory.newInstance())
					print '		--> set BasicAuthentication'
				else:
					print '		--> Authentification '  + str(authType) + ' is not supported or not implemented in HTTP'
			elif 'RequestEncoding' in property:
				getHttpEndPointConfiguration(serviceDefinition).setRequestEncoding(serviceProperties[property])
				print '		--> set RequestEncoding'
			elif 'ResponseEncoding' in property:
				getHttpEndPointConfiguration(serviceDefinition).setResponseEncoding(serviceProperties[property])
				print '		--> set ResponseEncoding'
			elif 'DispatchPolicy' in property:
				getHttpEndPointConfiguration(serviceDefinition).setDispatchPolicy(serviceProperties[property])
				print '		--> set DispatchPolicy'
			#elif 'ChunkedStreamingMode' in property:
			#	getHttpOutboundProperties(serviceDefinition).setChunkedStreamingMode(serviceProperties[property])
			#	print '		--> set ChunkedStreamingMode'
			#elif 'ConnectionTimeout' in property:
				#getHttpOutboundProperties(serviceDefinition).setConnectionTimeout(serviceProperties[property])
				#print '		--> set ConnectionTimeout'
			elif 'IsRequired' in property:
				getTransactions(serviceDefinition).setIsRequired(serviceProperties[property])
				print '		--> set IsRequired'
			elif 'SameTxForResponse' in property:
				getTransactions(serviceDefinition).setSameTxForResponse(serviceProperties[property])
				print '		--> set SameTxForResponse'
			elif 'Description' in property:
				serviceDefinition.getCoreEntry().setDescription(serviceProperties[property])
				print '		--> set Description'
			else:
				print '		--> Warning: Property is not supported: '+ property

		#update servicedefinition
		jarEntry.setServiceDefinition(serviceDefinition)



def customizeJNDI(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize Service:' + str(service)
		
		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: Not found JNDI: ' + str(service)+ ' in SBconfig file'
			continue
			
		#parse jndi provider
		jndiProviderEntry = JndiProviderEntry.Factory.parse(ByteArrayInputStream(jarEntry.getData()))

		serviceProperties=serviceType[service]
				
		for property in serviceProperties:
			#replace privider URL
			if 'ProviderURL' in property:
				jndiProviderEntry.setProviderUrl(serviceProperties[property])
				print '		--> set ProviderURL'
			elif 'Username' in property:
				jndiProviderEntry.getUserPassword().setUsername(serviceProperties[property])
				print '		--> set Username'
			elif 'Password' in property:
				jndiProviderEntry.getUserPassword().setPassword(serviceProperties[property])
				print '		--> set Password'
			elif 'CacheValues' in property:
				jndiProviderEntry.setCacheValues(serviceProperties[property])
				print '		--> set CacheValues'
			elif 'RequestTimeout' in property:
				jndiProviderEntry.setRequestTimeout(serviceProperties[property])
				print '		--> set RequestTimeout'
			elif 'Description' in property:
				jndiProviderEntry.setDescription(serviceProperties[property])
				print '		--> set Description'
			else:
				print '		--> Warning: Property is not supported: '+ property

		jarEntry.setData(jndiProviderEntry.toString().encode('utf-8'))


	
#===================================================================
# Setup policy expression in service
#===================================================================
def setupPolicyExpression(policyExpression, provider,serviceDefinition):
			
	if len(policyExpression.strip())!=0 and len(provider.strip())!=0:
		security = serviceDefinition.getCoreEntry().getSecurity()
		if security == None:
			security = serviceDefinition.getCoreEntry().addNewSecurity()

		accessControlPolicyBindingType = security.getAccessControlPolicies()
		if accessControlPolicyBindingType==None:
			accessControlPolicyBindingType = security.addNewAccessControlPolicies()

		transportLevelPolicy = accessControlPolicyBindingType.getTransportLevelPolicy()
		if accessControlPolicyBindingType.getTransportLevelPolicy() == None:
			transportLevelPolicy = accessControlPolicyBindingType.addNewTransportLevelPolicy()


			policyContainerType = ProviderPolicyContainerType.Factory.newInstance()
			policy = policyContainerType.addNewPolicy()
			policy.setProviderId(provider)
			policy.setPolicyExpression(policyExpression)

			transportLevelPolicy.set(policyContainerType)
		else:
			policyContainerType = transportLevelPolicy;
			policyContainerType.getPolicyArray()[0].setProviderId(provider)
			policyContainerType.getPolicyArray()[0].setPolicyExpression(policyExpression)
			
#===================================================================
# cretae new policy expression
#===================================================================
def createPolicyExpression(serviceProperties,serviceDefinition):
	expression = ''
	provider =''
	
	if 'Police' in serviceProperties:
		policeConfig= serviceProperties['Police']
		
		if 'Provider' in policeConfig:
			provider=policeConfig['Provider']
		if 'Users' in policeConfig:
			for user in convertToTuple(policeConfig['Users']):
				expression += '| Usr('+ str(user) + ')'
		
		if 'Groups' in policeConfig:
			for group in convertToTuple(policeConfig['Groups']):
				expression += '| Grp('+ str(group) + ')'
		
		if 'Roles' in policeConfig:
			for role in convertToTuple(policeConfig['Roles']):
				expression += '| Rol('+ str(role) + ')'


	expression=expression.strip()
	if expression.startswith('|'):
		expression=expression[2:len(expression)]	
	return expression,provider


		
#===================================================================
# customize transport-level-police (poloce expression)
#===================================================================
def customizeTransportLevelPolice(serviceType,osbJarEntries):
	for service in serviceType:
		print ' Customize Transport Level Police:' + str(service)
		
		jarEntry= findOsbJarEntry(str(service),osbJarEntries)
		if jarEntry==None:
			print '	--> Warning: Not found service: ' + str(service)+ ' in SBconfig file'
			continue
		
		#get service definition
		serviceDefinition=jarEntry.getServiceDefinition()
		
		serviceProperties=serviceType[service]
		
		
		
		for property in serviceProperties:
			policyExpression, provider= createPolicyExpression(serviceProperties,serviceDefinition)
			setupPolicyExpression(policyExpression,provider,serviceDefinition)

		jarEntry.setServiceDefinition(serviceDefinition)


	
#################################################################
#
#################################################################
def customizeSbConfigFile(sbFile,path):

	osbJarEntries=parseOsbJar(readBinaryFile(path))
	
	#customize services by transport type...
	for serviceType in sbFile:
		serviceDescriptor=sbFile[serviceType]
	
		if 'HTTP'==str(serviceType):
			customizeHttp(serviceDescriptor,osbJarEntries)
		elif 'JMS'==str(serviceType):
			customizeJms(serviceDescriptor,osbJarEntries)
		elif 'SERVICEACCOUNT'==str(serviceType):
			customizeServiceAccount(serviceDescriptor,osbJarEntries)
		elif 'JNDI'==str(serviceType):
			customizeJNDI(serviceDescriptor,osbJarEntries)
		elif 'LOCAL'==str(serviceType):
			customizeLOCAL(serviceDescriptor,osbJarEntries)
		elif 'GlobalOperationalSettings'==str(serviceType):
			customizeGlobalOperationalSettings(serviceDescriptor,osbJarEntries)
		elif 'SMTP'==str(serviceType):
			customizeSmtp(serviceDescriptor,osbJarEntries)
		elif 'UDDI'==str(serviceType):
			customizeUddi(serviceDescriptor,osbJarEntries)
		elif 'TRANSPORT-LEVEL-POLICE'==str(serviceType):
			customizeTransportLevelPolice(serviceDescriptor,osbJarEntries)
		else:
			print '	--> Warning: '+ str(serviceType)+ ' Protocol is not supported'

	#generate new SB Config
	return osbJarEntries
	
		
def executeCustomization():
	for sbFileName in SB_CUSTOMIZATOR:
		print ''
		print '------------------------------------'
		print ' Customize Config: '+str(sbFileName)
		sbFile=SB_CUSTOMIZATOR[sbFileName]
		#customize 
		path=str(sbFileName)
		path= os.path.abspath(path)
		if os.path.isfile(path) and os.path.exists(path):
			osbJarEntries= customizeSbConfigFile(sbFile,sbFileName)
			
			#generate new sbconfig file
			data=generateNewSBConfig(osbJarEntries)
			
			#deploy
			return deployNewSBconfig(sbFileName,data)
		else:
			print '	--> Error: ' + path + ' SB Config file not found'

try:
	print '################################################################################'
	print ''
	print '		OSB Config Customizator'
	print '	'
	print '	'
	
	if len(sys.argv)!=2:
		print '	Not found OSB Customization file!'
		print '	Execute: ./osbCustomizer.(sh/cmd) osbCustomizer.properties'
		print '	'
		print '	'
		exit()


	f=sys.argv[1]
	
	from string import Template
	s = Template('$who likes $what')
	print s.substitute(who='tim', what='kung pao')
	exit()
	
	print ' Load customization file: '  + f
	f = os.path.abspath(f)
	exec open(str(f),'r')

	
	
	
except Exception, err:
	print ' Failed Execute customization file: '+ f 
	traceback.print_exc()
	#or
	print sys.exc_info()[0]

exit()