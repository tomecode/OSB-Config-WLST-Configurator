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

from com.tomecode.utils import Utils

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

from com.bea.wli.sb.resources.proxyserver.config import ProxyServerDocument;
from com.bea.wli.sb.resources.proxyserver.config import ProxyServerParams;


from com.bea.wli.sb.util import Refs
from com.bea.wli.config.customization import Customization
from com.bea.wli.sb.management.importexport import ALSBImportOperation
from com.bea.wli.sb.management.configuration import SessionManagementMBean
from com.bea.wli.sb.management.configuration import ServiceConfigurationMBean
from com.bea.wli.sb.management.configuration import ALSBConfigurationMBean
from com.bea.wli.sb.management.query import ProxyServiceQuery


#===================================================================
LOG_CUST_FILE = ' --> '
LOG_CUST_FUNCTION = '   --> '

#===================================================================


#===================================================================
# Jar Entry
#===================================================================
class OsbJarEntry:
	name=''
	directory=False;
	data=None
	extension=None
	
	def __init__(self,n,d,b):
		self.name=n
		self.directory=d
		self.data=b
		#get extensio name
		self.extension=os.path.splitext(self.name)[1][1:]
		
	def getName(self):
		return self.name
		
	def getData(self):
		return self.data
	
	def setData(self, d):
		self.data=d
		
	def getExtension(self):
		return self.extension.lower()


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

	
def isDict(val):
	return ('<type \'dict\'>' in str(type(val)))

def reverseDict(val):
	if val==None:
		return []
	list=val.keys()
	list.reverse();
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
	
		
def saveNewSbConfigNoFS(sbFileName,data):		
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



####	###############################################################################################################################################
####	###############################################################################################################################################
####								
####							Customization functions
####
####	###############################################################################################################################################
####	###############################################################################################################################################

def getJmsEndPointConfiguration(serviceDefinition):
	JmsEndPointConfiguration=serviceDefinition.getEndpointConfig().getProviderSpecific()
	return JmsEndPointConfiguration

def getJmsInboundProperties(serviceDefinition):
	jmsEndPointConfiguration=getJmsEndPointConfiguration(serviceDefinition)
	jmsInboundProperties= jmsEndPointConfiguration.getInboundProperties()
	if jmsInboundProperties == None:
		jmsInboundProperties= jmsEndPointConfiguration.addNewInboundProperties();
	return jmsInboundProperties


def changeEndpointUri(endpoints,serviceDefinition):
	endpointConfiguration = serviceDefinition.getEndpointConfig()
	if len(endpointConfiguration.getURIArray()) >= 1:
		#uris=URIType[0]
		endpointConfiguration.setURIArray([])
		
	for uri in endpoints:
		endpointConfiguration.addNewURI().setValue(uri)
	
def getTransactions(serviceDefinition):
	transactions=serviceDefinition.getCoreEntry().getTransactions()
	if transactions==None:
		return serviceDefinition.getCoreEntry().addNewTransactions()
	return transactions

def getHttpInboundProperties(serviceDefinition):
	httpEndPointConfiguration = getHttpEndPointConfiguration(serviceDefinition)
	httpInboundProperties= httpEndPointConfiguration.getInboundProperties()
	if httpInboundProperties == None:
		httpInboundProperties= httpEndPointConfiguration.addNewInboundProperties();
	return httpInboundProperties

def getHttpOutboundProperties(serviceDefinition):
	httpEndPointConfiguration = getHttpEndPointConfiguration(serviceDefinition)
	outboundProperties= httpEndPointConfiguration.getOutboundProperties()
	if outboundProperties == None:
		outboundProperties= httpEndPointConfiguration.addNewOutboundProperties();
	return outboundProperties
def getHttpEndPointConfiguration(serviceDefinition):
	HttpEndPointConfiguration=serviceDefinition.getEndpointConfig().getProviderSpecific()
	return HttpEndPointConfiguration

####	###############################################################################################################################################
####	###############################################################################################################################################
####								
####							Customization Start
####
####	###############################################################################################################################################
####	###############################################################################################################################################


#===================================================================
####	Global Operation Settings
#===================================================================

def globaloperationalsettings_operations_monitoring(entry, val):
	entry.setMonitoring(val)

def globaloperationalsettings_operations_slaalerting(entry, val):
	entry.setSlaAlerting(val)

def globaloperationalsettings_operations_pipelinealerting(entry, val):
	entry.setPipelineAlerting(val)

def globaloperationalsettings_operations_resultcaching(entry, val):
	entry.setResultCaching(val)

def globaloperationalsettings_operations_reporting(entry, val):
	entry.setReporting(val)
	
def globaloperationalsettings_operations_logging(entry, val):
	entry.setLogging(val)

#===================================================================
####	Service Account: Static
#===================================================================

def serviceaccount_serviceaccount_description(entry, val):
	serviceAccount = entry.getServiceAccount()
	serviceAccount.setDescription(val)

def serviceaccount_serviceaccount_password(entry, val):
	serviceAccountUserPassword = entry.getServiceAccount().getStaticAccount()
	serviceAccountUserPassword.setPassword(val)
	
def serviceaccount_serviceaccount_username(entry, val):
	serviceAccountUserPassword = entry.getServiceAccount().getStaticAccount()
	serviceAccountUserPassword.setUsername(val)
	
#===================================================================
####	UDDI
#===================================================================

def uddi_uddiregistry_loadtmodels(entry, val):
	entry.setLoadtModels(val)

def  uddi_uddiregistry_autoimport(entry, val):
	entry.setAutoImport(val)

def  uddi_uddiregistry_password(entry, val):
	entry.setPassword(val)

def uddi_uddiregistry_publishurl(entry, val):
	entry.setPublishUrl(val)

def uddi_uddiregistry_subscriptionurl(entry, val):
	entry.setSubscriptionUrl(val)
	
def uddi_uddiregistry_username(entry, val):
	entry.setUsername(val)

def uddi_uddiregistry_securityurl(entry, val):
	entry.setSecurityUrl(val)
	
def uddi_uddiregistry_url(entry, val):
	entry.setUrl(val)
	
def uddi_uddiregistry_description(entry, val):
	entry.setDescription(val)

#===================================================================
####	JNDI
#===================================================================

def jndi_foreignjndiprovider_cachevalues(entry, val):
	entry.setCacheValues(val)

def jndi_foreignjndiprovider_requesttimeout(entry, val):
	entry.setRequestTimeout(val)
	
def jndi_foreignjndiprovider_providerurl(entry, val):
	entry.setProviderUrl(val)

def jndi_foreignjndiprovider_username(entry, val):
	entry.getUserPassword().setUsername(val)

def jndi_foreignjndiprovider_password(entry, val):
	entry.getUserPassword().setPassword(val)

def jndi_foreignjndiprovider_description(entry, val):
	entry.setDescription(val)
	

#===================================================================
####	SMTP
#===================================================================

def smtp_smtpserver_description(entry, val):
	entry.setDescription(val)

def smtp_smtpserver_isdefault(entry, val):
	entry.setIsDefault(val)

def smtp_smtpserver_portnumber(entry, val):
	entry.setPortNumber(val)

def smtp_smtpserver_serverurl(entry, val):
	entry.setServerURL(val)
	
def smtp_smtpserver_username(entry, val):
	entry.setUsername(val)
	
def smtp_smtpserver_password(entry, val):
	entry.setPassword(val)

#===================================================================
####	Proxy Server
#===================================================================
	
def proxyserver_proxyserver_description(entry, val):
	entry.getProxyServer().setDescription(val)

def proxyserver_proxyserver_username(entry, val):
	entry.getProxyServer().setUsername(val)

def proxyserver_proxyserver_password(entry, val):
	entry.getProxyServer().setPassword(val)

def proxyserver_proxyserver_servertable(entry, val):
	entry.getProxyServer().getServerTable().setServerArray(None)
	list=[]
	for v in val:
		param  = ProxyServerParams.Factory.newInstance()
		param.setHost(v)
		params=val[v]
		for p in params:
			if p =='Port':
				param.setPort(params[p])
			elif p =='SslPort':
				param.setSslPort(params[p])
			else:
				print 'dd'
				
		list.append(param)
	entry.getProxyServer().getServerTable().setServerArray(list)


#===================================================================
####	Proxy Service: LOCAL
#===================================================================

def local_proxyservice_sametxforresponse(entry, val):
	getTransactions(entry).setSameTxForResponse(val)

def local_proxyservice_description(entry, val):
	entry.getCoreEntry().setDescription(val)

def local_proxyservice_isrequired(entry, val):
	getTransactions(entry).setIsRequired(val)

#===================================================================	
####	Proxy Service: Transport Type: HTTP
#===================================================================

def http_proxyservice_description(entry, val):
	entry.getCoreEntry().setDescription(val)

def http_proxyservice_usehttps(entry, val):
	getHttpInboundProperties(entry).setUseHttps(val)

def http_proxyservice_endpointuri(entry, val):
	changeEndpointUri(convertToTuple(val),entry)

def http_proxyservice_requestencoding(entry, val):
	getHttpEndPointConfiguration(entry).setRequestEncoding(val)
def http_proxyservice_responseencoding(entry, val):
	getHttpEndPointConfiguration(entry).setResponseEncoding(val)

def http_proxyservice_dispatchpolicy(entry, val):
	getHttpEndPointConfiguration(entry).setDispatchPolicy(val)

def http_proxyservice_isrequired(entry, val):
	getTransactions(entry).setIsRequired(val)

def http_proxyservice_sametxforresponse(entry, val):
	getTransactions(entry).setSameTxForResponse(val)

#===================================================================	
####	Proxy Service: Transport Type: JMS
#===================================================================

def jms_proxyservice_retrycount(entry, val):
	getJmsInboundProperties(entry).setRetryCount(val)

def jms_proxyservice_endpointuri(entry, val):
	changeEndpointUri(convertToTuple(val),entry)

def jms_proxyservice_dispatchpolicy(entry, val):
	getJmsEndPointConfiguration(entry).setDispatchPolicy(val)

def jms_proxyservice_requestencoding(entry, val):
	getJmsEndPointConfiguration(entry).setRequestEncoding(val)

def jms_proxyservice_jnditimeout(entry, val):
	getJmsEndPointConfiguration(entry).setJndiTimeout(val)

def jms_proxyservice_usessl(entry, val):
	getJmsEndPointConfiguration(entry).setIsSecure(val)

def jms_proxyservice_isxarequired(entry, val):
	getJmsInboundProperties(entry).setXARequired(val)

def jms_proxyservice_errordestination(entry, val):
	getJmsInboundProperties(entry).setErrorDestination(val)

def jms_proxyservice_messageselector(entry, val):
	getJmsInboundProperties(entry).setMessageSelector(val)

def jms_proxyservice_retryinterval(entry, val):
	getJmsInboundProperties(entry).setRetryInterval(val)

def jms_proxyservice_isresponserequired(entry, val):
	getJmsInboundProperties(entry).setResponseRequired(val)

def jms_proxyservice_isrequired(entry, val):
	getTransactions(entry).setIsRequired(val)

def jms_proxyservice_sametxforresponse(entry, val):
	getTransactions(entry).setSameTxForResponse(val)
	
def jms_proxyservice_destinationtypequeue(entry, val):
	lookupCustomizationFunction(sys._getframe().f_code.co_name, val, entry)


def jms_proxyservice_destinationtypequeue_responsepattern(entry, val):
	if val == 'JMS_CORRELATION_ID':
		getJmsInboundProperties(entry).setResponsePattern(JmsResponsePatternEnum.JMS_CORRELATION_ID)
	else:
		getJmsInboundProperties(entry).setResponsePattern(JmsResponsePatternEnum.JMS_MESSAGE_ID)

def jms_proxyservice_destinationtypequeue_responseuri(entry, val):
	getJmsInboundProperties(entry).setResponseURI(val)

def jms_proxyservice_destinationtypequeue_responseencoding(entry, val):
	getJmsEndPointConfiguration(entry).setResponseEncoding(val)

def jms_proxyservice_destinationtypequeue_responsemessagetype(entry, val):
	if val == 'BYTES':
		getJmsInboundProperties(entry).setResponseMessageType(JmsMessageTypeEnum.BYTES)
	else:
		getJmsInboundProperties(entry).setResponseMessageType(JmsMessageTypeEnum.TEXT)

def jms_proxyservice_description(entry, val):
	entry.getCoreEntry().setDescription(val)


#===================================================================	
####	BusinessService: Transport Type: HTTP
#===================================================================

def http_businessservice_description(entry, val):
	entry.getCoreEntry().setDescription(val)	

def http_businessservice_endpointuri(entry, val):
	changeEndpointUri(convertToTuple(val),entry)

def http_businessservice_readtimeout(entry, val):
	getHttpOutboundProperties(entry).setTimeout(val)
	
def http_businessservice_requestencoding(entry, val):
	getHttpEndPointConfiguration(entry).setRequestEncoding(val)

def http_businessservice_responseencoding(entry, val):
	getHttpEndPointConfiguration(entry).setResponseEncoding(val)

def http_businessservice_connectiontimeout(entry, val):
	getHttpOutboundProperties(entry).setConnectionTimeout(val)

####	###############################################################################################################################################
####	###############################################################################################################################################
####								
####							Customization End
####
####	###############################################################################################################################################
####	###############################################################################################################################################


def loadEntryFactory(jarEntry):
	if jarEntry.getExtension()=='proxyservice' or jarEntry.getExtension()=='businessservice':
		return ServiceDefinition.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
	elif jarEntry.getExtension()=='serviceaccount':
		return ServiceAccountDocument.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
	elif jarEntry.getExtension()=='Operations'.lower():
		return OperationalSettings.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
	elif jarEntry.getExtension()=='UDDIRegistry'.lower():
		return UDDIRegistryEntry.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
	elif jarEntry.getExtension()=='ForeignJNDIProvider'.lower():
		return JndiProviderEntry.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
	elif jarEntry.getExtension()=='SMTPServer'.lower():
		return SmtpServerEntry.Factory.parse(ByteArrayInputStream(jarEntry.getData()))
	elif jarEntry.getExtension()=='ProxyServer'.lower():
		return ProxyServerDocument.Factory.parse(ByteArrayInputStream(jarEntry.getData()))	
	else:
		return None


def lookupCustomizationFunction(functionName, parent,entry):
	for setFunction in reverseDict(parent):
		impleSetFunction= functionName + '_' + setFunction
		
		#if isDict(parent[setFunction]):
			#lookupCustomizationFunction(impleSetFunction, parent[setFunction],entry)
			#globals()[impleSetFunction.lower()](entry, parent[setFunction])
		
		globals()[impleSetFunction.lower()](entry, parent[setFunction])
		print LOG_CUST_FUNCTION + setFunction


def customizeSbConfigFile(customizationFile,path):
	osbJarEntries=parseOsbJar(readBinaryFile(path))
	
	print 'Customize the following files:'

	#customize services by transport type...	
	for customizationType in reverseDict(customizationFile):
		#print '--> '+ customizationType
		customizationEntries=customizationFile[customizationType];
			

		for custEntryFile in reverseDict(customizationEntries):
			#find sbconfigEntry		
			jarEntry=findOsbJarEntry(custEntryFile,osbJarEntries)
				
			if jarEntry==None:
				print LOG_CUST_FILE + 'Not found Entry: ' + custEntryFile
			else:
				print LOG_CUST_FILE + jarEntry.getName()
				sbentry=loadEntryFactory(jarEntry)
				if sbentry!=None:
					#
					execFunctionName = customizationType.lower()+'_'+jarEntry.getExtension().lower()
					#execute customization
					lookupCustomizationFunction(execFunctionName,customizationEntries[custEntryFile],sbentry)
					#update jar entry
					jarEntry.setData(sbentry.toString().encode('utf-8'))
				else:
					print LOG_CUST_FUNCTION + 'Customization is not supported!'

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
			return saveNewSbConfigNoFS(sbFileName,data)
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
	
	print ' Load customization file: '  + f
	f = os.path.abspath(f)
	exec open(str(f),'r')

	
	deployFile=executeCustomization()
	#if deployFile!=None:
	#	deployToOsb(deployFile)
	
except Exception, err:
	print ' Failed Execute customization file: '+ f 
	traceback.print_exc()
	#or
	print sys.exc_info()[0]

	
exit()