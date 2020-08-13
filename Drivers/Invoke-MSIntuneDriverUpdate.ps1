<#
.SYNOPSIS

    The purpose of this script is to automate the driver update process when enrolling devices through
    Microsoft Intune.

.DESCRIPTION

    This script will determine the model of the computer, manufacturer and operating system used then download,
    extract & install the latest driver package from the manufacturer. At present Dell, HP and Lenovo devices
    are supported.
	
.NOTES

    FileName:    Invoke-MSIntuneDriverUpdate.ps1

    Author:      Maurice Daly
    Contact:     @MoDaly_IT
    Created:     2017-12-03
    Updated:     2017-12-05

    Version history:

    1.0.0 - (2017-12-03) Script created
	1.0.1 - (2017-12-05) Updated Lenovo matching SKU value and added regex matching for Computer Model values. 
	1.0.2 - (2017-12-05) Updated to cater for language differences in OS architecture returned
#>

# // =================== GLOBAL VARIABLES ====================== //

$TempLocation = Join-Path $env:SystemDrive "Temp\SCConfigMgr"

# Set Temp & Log Location
[string]$TempDirectory = Join-Path $TempLocation "\Temp"
[string]$LogDirectory = Join-Path $TempLocation "\Logs"

# Create Temp Folder 
if ((Test-Path -Path $TempDirectory) -eq $false) {
	New-Item -Path $TempDirectory -ItemType Dir
}

# Create Logs Folder 
if ((Test-Path -Path $LogDirectory) -eq $false) {
	New-Item -Path $LogDirectory -ItemType Dir
}

# Logging Function
function global:Write-CMLogEntry {
	param (
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]
		$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]
		$FileName = "Invoke-MSIntuneDriverUpdate.log"
	)
	# Determine log file location
	$LogFilePath = Join-Path -Path $LogDirectory -ChildPath $FileName
	# Construct time stamp for log entry
	$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	# Construct date for log entry
	$Date = (Get-Date -Format "MM-dd-yyyy")
	# Construct context for log entry
	$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	# Construct final log entry
	$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""DriverAutomationScript"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	# Add value to log file
	try {
		Add-Content -Value $LogText -LiteralPath $LogFilePath -ErrorAction Stop
	}
	catch [System.Exception] {
		Write-Warning -Message "Unable to append log entry to Invoke-DriverUpdate.log file. Error message: $($_.Exception.Message)"
	}
}

# // =================== DELL VARIABLES ================ //

# Define Dell Download Sources
$DellDownloadList = "http://downloads.dell.com/published/Pages/index.html"
$DellDownloadBase = "http://downloads.dell.com"
$DellDriverListURL = "http://en.community.dell.com/techcenter/enterprise-client/w/wiki/2065.dell-command-deploy-driver-packs-for-enterprise-client-os-deployment"
$DellBaseURL = "http://en.community.dell.com"

# Define Dell Download Sources
$DellXMLCabinetSource = "http://downloads.dell.com/catalog/DriverPackCatalog.cab"
$DellCatalogSource = "http://downloads.dell.com/catalog/CatalogPC.cab"

# Define Dell Cabinet/XL Names and Paths
$DellCabFile = [string]($DellXMLCabinetSource | Split-Path -Leaf)
$DellCatalogFile = [string]($DellCatalogSource | Split-Path -Leaf)
$DellXMLFile = $DellCabFile.Trim(".cab")
$DellXMLFile = $DellXMLFile + ".xml"
$DellCatalogXMLFile = $DellCatalogFile.Trim(".cab") + ".xml"

# Define Dell Global Variables
$DellCatalogXML = $null
$DellModelXML = $null
$DellModelCabFiles = $null

# // =================== HP VARIABLES ================ //

# Define HP Download Sources
$HPXMLCabinetSource = "http://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab"
$HPSoftPaqSource = "http://ftp.hp.com/pub/softpaq/"
$HPPlatFormList = "http://ftp.hp.com/pub/caps-softpaq/cmit/imagepal/ref/platformList.cab"

# Define HP Cabinet/XL Names and Paths
$HPCabFile = [string]($HPXMLCabinetSource | Split-Path -Leaf)
$HPXMLFile = $HPCabFile.Trim(".cab")
$HPXMLFile = $HPXMLFile + ".xml"
$HPPlatformCabFile = [string]($HPPlatFormList | Split-Path -Leaf)
$HPPlatformXMLFile = $HPPlatformCabFile.Trim(".cab")
$HPPlatformXMLFile = $HPPlatformXMLFile + ".xml"

# Define HP Global Variables
$global:HPModelSoftPaqs = $null
$global:HPModelXML = $null
$global:HPPlatformXML = $null

# // =================== LENOVO VARIABLES ================ //

# Define Lenovo Download Sources
$global:LenovoXMLSource = "https://download.lenovo.com/cdrt/td/catalog.xml"

# Define Lenovo Cabinet/XL Names and Paths
$global:LenovoXMLFile = [string]($global:LenovoXMLSource | Split-Path -Leaf)

# Define Lenovo Global Variables
$global:LenovoModelDrivers = $null
$global:LenovoModelXML = $null
$global:LenovoModelType = $null
$global:LenovoSystemSKU = $null

# // =================== COMMON VARIABLES ================ //

# Determine manufacturer
$ComputerManufacturer = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer).Trim()
Write-CMLogEntry -Value "Manufacturer determined as: $($ComputerManufacturer)" -Severity 1

# Determine manufacturer name and hardware information
switch -Wildcard ($ComputerManufacturer) {
	"*HP*" {
		$ComputerManufacturer = "Hewlett-Packard"
		$ComputerModel = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
		$SystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct
	}
	"*Hewlett-Packard*" {
		$ComputerManufacturer = "Hewlett-Packard"
		$ComputerModel = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
		$SystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct
	}
	"*Dell*" {
		$ComputerManufacturer = "Dell"
		$ComputerModel = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
		$SystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku
	}
	"*Lenovo*" {
		$ComputerManufacturer = "Lenovo"
		$ComputerModel = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version
		$SystemSKU = ((Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI | Select-Object -ExpandProperty BIOSVersion).SubString(0, 4)).Trim()
	}
}
Write-CMLogEntry -Value "Computer model determined as: $($ComputerModel)" -Severity 1

if (-not [string]::IsNullOrEmpty($SystemSKU)) {
	Write-CMLogEntry -Value "Computer SKU determined as: $($SystemSKU)" -Severity 1
}

# Get operating system name from version
switch -wildcard (Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version) {
	"10.0*" {
		$OSName = "Windows 10"
	}
	"6.3*" {
		$OSName = "Windows 8.1"
	}
	"6.1*" {
		$OSName = "Windows 7"
	}
}
Write-CMLogEntry -Value "Operating system determined as: $OSName" -Severity 1

# Get operating system architecture
switch -wildcard ((Get-CimInstance Win32_operatingsystem).OSArchitecture) {
	"64-*" {
		$OSArchitecture = "64-Bit"
	}
	"32-*" {
		$OSArchitecture = "32-Bit"
	}
}

Write-CMLogEntry -Value "Architecture determined as: $OSArchitecture" -Severity 1

$WindowsVersion = ($OSName).Split(" ")[1]

function DownloadDriverList {
	global:Write-CMLogEntry -Value "======== Download Model Link Information ========" -Severity 1
	if ($ComputerManufacturer -eq "Hewlett-Packard") {
		if ((Test-Path -Path $TempDirectory\$HPCabFile) -eq $false) {
			global:Write-CMLogEntry -Value "======== Downloading HP Product List ========" -Severity 1
			# Download HP Model Cabinet File
			global:Write-CMLogEntry -Value "Info: Downloading HP driver pack cabinet file from $HPXMLCabinetSource" -Severity 1
			try {
				Start-BitsTransfer -Source $HPXMLCabinetSource -Destination $TempDirectory
				# Expand Cabinet File
				global:Write-CMLogEntry -Value "Info: Expanding HP driver pack cabinet file: $HPXMLFile" -Severity 1
				Expand "$TempDirectory\$HPCabFile" -F:* "$TempDirectory\$HPXMLFile"
			}
			catch {
				global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
			}
		}
		# Read XML File
		if ($global:HPModelSoftPaqs -eq $null) {
			global:Write-CMLogEntry -Value "Info: Reading driver pack XML file - $TempDirectory\$HPXMLFile" -Severity 1
			[xml]$global:HPModelXML = Get-Content -Path $TempDirectory\$HPXMLFile
			# Set XML Object
			$global:HPModelXML.GetType().FullName | Out-Null
			$global:HPModelSoftPaqs = $HPModelXML.NewDataSet.HPClientDriverPackCatalog.ProductOSDriverPackList.ProductOSDriverPack
		}
	}
	if ($ComputerManufacturer -eq "Dell") {
		if ((Test-Path -Path $TempDirectory\$DellCabFile) -eq $false) {
			global:Write-CMLogEntry -Value "Info: Downloading Dell product list" -Severity 1
			global:Write-CMLogEntry -Value "Info: Downloading Dell driver pack cabinet file from $DellXMLCabinetSource" -Severity 1
			# Download Dell Model Cabinet File
			try {
				Start-BitsTransfer -Source $DellXMLCabinetSource -Destination $TempDirectory
				# Expand Cabinet File
				global:Write-CMLogEntry -Value "Info: Expanding Dell driver pack cabinet file: $DellXMLFile" -Severity 1
				Expand "$TempDirectory\$DellCabFile" -F:* "$TempDirectory\$DellXMLFile"
			}
			catch {
				global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
			}
		}
		if ($DellModelXML -eq $null) {
			# Read XML File
			global:Write-CMLogEntry -Value "Info: Reading driver pack XML file - $TempDirectory\$DellXMLFile" -Severity 1
			[xml]$DellModelXML = (Get-Content -Path $TempDirectory\$DellXMLFile)
			# Set XML Object
			$DellModelXML.GetType().FullName | Out-Null
		}
		$DellModelCabFiles = $DellModelXML.driverpackmanifest.driverpackage
		
	}
	if ($ComputerManufacturer -eq "Lenovo") {
		if ($global:LenovoModelDrivers -eq $null) {
			try {
				[xml]$global:LenovoModelXML = Invoke-WebRequest -Uri $global:LenovoXMLSource
			}
			catch {
				global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
			}
			
			# Read Web Site
			global:Write-CMLogEntry -Value "Info: Reading driver pack URL - $global:LenovoXMLSource" -Severity 1
			
			# Set XML Object 
			$global:LenovoModelXML.GetType().FullName | Out-Null
			$global:LenovoModelDrivers = $global:LenovoModelXML.Products
		}
	}
}

function FindLenovoDriver {
	
<#
 # This powershell file will extract the link for the specified driver pack or application
 # param $URI The string version of the URL
 # param $64bit A boolean to determine what version to pick if there are multiple
 # param $os A string containing 7, 8, or 10 depending on the os we are deploying 
 #           i.e. 7, Win7, Windows 7 etc are all valid os strings
 #>
	param (
		[parameter(Mandatory = $true, HelpMessage = "Provide the URL to parse.")]
		[ValidateNotNullOrEmpty()]
		[string]
		$URI,
		[parameter(Mandatory = $true, HelpMessage = "Specify the operating system.")]
		[ValidateNotNullOrEmpty()]
		[string]
		$OS,
		[string]
		$Architecture
	)
	
	#Case for direct link to a zip file
	if ($URI.EndsWith(".zip")) {
		return $URI
	}
	
	$err = @()
	
	#Get the content of the website
	try {
		$html = Invoke-WebRequest –Uri $URI
	}
	catch {
		global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
	}
	
	#Create an array to hold all the links to exe files
	$Links = @()
	$Links.Clear()
	
	#determine if the URL resolves to the old download location
	if ($URI -like "*olddownloads*") {
		#Quickly grab the links that end with exe
		$Links = (($html.Links | Where-Object {
					$_.href -like "*exe"
				}) | Where class -eq "downloadBtn").href
	}
	
	$Links = ((Select-string '(http[s]?)(:\/\/)([^\s,]+.exe)(?=")' -InputObject ($html).Rawcontent -AllMatches).Matches.Value)
	
	if ($Links.Count -eq 0) {
		return $null
	}
	
	# Switch OS architecture
	switch -wildcard ($Architecture) {
		"*64*" {
			$Architecture = "64"
		}
		"*86*" {
			$Architecture = "32"
		}
	}
	
	#if there are multiple links then narrow down to the proper arc and os (if needed)
	if ($Links.Count -gt 0) {
		#Second array of links to hold only the ones we want to target
		$MatchingLink = @()
		$MatchingLink.clear()
		foreach ($Link in $Links) {
			if ($Link -like "*w$($OS)$($Architecture)_*" -or $Link -like "*w$($OS)_$($Architecture)*") {
				$MatchingLink += $Link
			}
		}
	}
	
	if ($MatchingLink -ne $null) {
		return $MatchingLink
	}
	else {
		return "badLink"
	}
}

function Get-RedirectedUrl {
	Param (
		[Parameter(Mandatory = $true)]
		[String]
		$URL
	)
	
	$Request = [System.Net.WebRequest]::Create($URL)
	$Request.AllowAutoRedirect = $false
	$Request.Timeout = 3000
	$Response = $Request.GetResponse()
	
	if ($Response.ResponseUri) {
		$Response.GetResponseHeader("Location")
	}
	$Response.Close()
}

function LenovoModelTypeFinder {
	param (
		[parameter(Mandatory = $false, HelpMessage = "Enter Lenovo model to query")]
		[string]
		$ComputerModel,
		[parameter(Mandatory = $false, HelpMessage = "Enter Operating System")]
		[string]
		$OS,
		[parameter(Mandatory = $false, HelpMessage = "Enter Lenovo model type to query")]
		[string]
		$ComputerModelType
	)
	try {
		if ($global:LenovoModelDrivers -eq $null) {
			[xml]$global:LenovoModelXML = Invoke-WebRequest -Uri $global:LenovoXMLSource
			# Read Web Site
			global:Write-CMLogEntry -Value "Info: Reading driver pack URL - $global:LenovoXMLSource" -Severity 1
			
			# Set XML Object
			$global:LenovoModelXML.GetType().FullName | Out-Null
			$global:LenovoModelDrivers = $global:LenovoModelXML.Products
		}
	}
	catch {
		global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
	}
	
	if ($ComputerModel.Length -gt 0) {
		$global:LenovoModelType = ($global:LenovoModelDrivers.Product | Where-Object {
				$_.Queries.Version -match "$ComputerModel"
			}).Queries.Types | Select -ExpandProperty Type | Select -first 1
		$global:LenovoSystemSKU = ($global:LenovoModelDrivers.Product | Where-Object {
				$_.Queries.Version -match "$ComputerModel"
			}).Queries.Types | select -ExpandProperty Type | Get-Unique
	}
	
	if ($ComputerModelType.Length -gt 0) {
		$global:LenovoModelType = (($global:LenovoModelDrivers.Product.Queries) | Where-Object {
				($_.Types | Select -ExpandProperty Type) -match $ComputerModelType
			}).Version | Select -first 1
	}
	Return $global:LenovoModelType
}

function InitiateDownloads {
	
	$Product = "Intune Driver Automation"
	
	# Driver Download ScriptBlock
	$DriverDownloadJob = {
		Param ([string]
			$TempDirectory,
			[string]
			$ComputerModel,
			[string]
			$DriverCab,
			[string]
			$DriverDownloadURL
		)
		
		try {
			# Start Driver Download	
			Start-BitsTransfer -DisplayName "$ComputerModel-DriverDownload" -Source $DriverDownloadURL -Destination "$($TempDirectory + '\Driver Cab\' + $DriverCab)"
		}
		catch [System.Exception] {
			global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
		}
	}
	
	global:Write-CMLogEntry -Value "======== Starting Download Processes ========" -Severity 1
	global:Write-CMLogEntry -Value "Info: Operating System specified: Windows $($WindowsVersion)" -Severity 1
	global:Write-CMLogEntry -Value "Info: Operating System architecture specified: $($OSArchitecture)" -Severity 1
	
	# Operating System Version
	$OperatingSystem = ("Windows " + $($WindowsVersion))
	
	# Vendor Make
	$ComputerModel = $ComputerModel.Trim()
	
	# Get Windows Version Number
	switch -Wildcard ((Get-WmiObject -Class Win32_OperatingSystem).Version) {
		"*10.0.16*" {
			$OSBuild = "1709"
		}
		"*10.0.15*" {
			$OSBuild = "1703"
		}
		"*10.0.14*" {
			$OSBuild = "1607"
		}
	}
	global:Write-CMLogEntry -Value "Info: Windows 10 build $OSBuild identified for driver match" -Severity 1
	
	# Start driver import processes
	global:Write-CMLogEntry -Value "Info: Starting Download,Extract And Import Processes For $ComputerManufacturer Model: $($ComputerModel)" -Severity 1
	
	# =================== DEFINE VARIABLES =====================
	
	if ($ComputerManufacturer -eq "Dell") {
		global:Write-CMLogEntry -Value "Info: Setting Dell variables" -Severity 1
		if ($DellModelCabFiles -eq $null) {
			[xml]$DellModelXML = Get-Content -Path $TempDirectory\$DellXMLFile
			# Set XML Object
			$DellModelXML.GetType().FullName | Out-Null
			$DellModelCabFiles = $DellModelXML.driverpackmanifest.driverpackage
		}
		if ($SystemSKU -ne $null) {
			global:Write-CMLogEntry -Value "Info: SystemSKU value is present, attempting match based on SKU - $SystemSKU)" -Severity 1
			
			$ComputerModelURL = $DellDownloadBase + "/" + ($DellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like "*$WindowsVersion*") -and ($_.SupportedSystems.Brand.Model.SystemID -eq $SystemSKU)
				}).delta
			$ComputerModelURL = $ComputerModelURL.Replace("\", "/")
			$DriverDownload = $DellDownloadBase + "/" + ($DellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like "*$WindowsVersion*") -and ($_.SupportedSystems.Brand.Model.SystemID -eq $SystemSKU)
				}).path
			$DriverCab = (($DellModelCabFiles | Where-Object {
						((($_.SupportedOperatingSystems).OperatingSystem).osCode -like "*$WindowsVersion*") -and ($_.SupportedSystems.Brand.Model.SystemID -eq $SystemSKU)
					}).path).Split("/") | select -Last 1
		}
		elseif ($SystemSKU -eq $null -or $DriverCab -eq $null) {
			global:Write-CMLogEntry -Value "Info: Falling back to matching based on model name" -Severity 1
			
			$ComputerModelURL = $DellDownloadBase + "/" + ($DellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like "*$WindowsVersion*") -and ($_.SupportedSystems.Brand.Model.Name -like "*$ComputerModel*")
				}).delta
			$ComputerModelURL = $ComputerModelURL.Replace("\", "/")
			$DriverDownload = $DellDownloadBase + "/" + ($DellModelCabFiles | Where-Object {
					((($_.SupportedOperatingSystems).OperatingSystem).osCode -like "*$WindowsVersion*") -and ($_.SupportedSystems.Brand.Model.Name -like "*$ComputerModel")
				}).path
			$DriverCab = (($DellModelCabFiles | Where-Object {
						((($_.SupportedOperatingSystems).OperatingSystem).osCode -like "*$WindowsVersion*") -and ($_.SupportedSystems.Brand.Model.Name -like "*$ComputerModel")
					}).path).Split("/") | select -Last 1
		}
		$DriverRevision = (($DriverCab).Split("-")[2]).Trim(".cab")
		$DellSystemSKU = ($DellModelCabFiles.supportedsystems.brand.model | Where-Object {
				$_.Name -match ("^" + $ComputerModel + "$")
			} | Get-Unique).systemID
		if ($DellSystemSKU.count -gt 1) {
			$DellSystemSKU = [string]($DellSystemSKU -join ";")
		}
		global:Write-CMLogEntry -Value "Info: Dell System Model ID is : $DellSystemSKU" -Severity 1
	}
	if ($ComputerManufacturer -eq "Hewlett-Packard") {
		global:Write-CMLogEntry -Value "Info: Setting HP variables" -Severity 1
		if ($global:HPModelSoftPaqs -eq $null) {
			[xml]$global:HPModelXML = Get-Content -Path $TempDirectory\$HPXMLFile
			# Set XML Object
			$global:HPModelXML.GetType().FullName | Out-Null
			$global:HPModelSoftPaqs = $global:HPModelXML.NewDataSet.HPClientDriverPackCatalog.ProductOSDriverPackList.ProductOSDriverPack
		}
		if ($SystemSKU -ne $null) {
			$HPSoftPaqSummary = $global:HPModelSoftPaqs | Where-Object {
				($_.SystemID -match $SystemSKU) -and ($_.OSName -like "$OSName*$OSArchitecture*$OSBuild*")
			} | Sort-Object -Descending | select -First 1
		}
		else {
			$HPSoftPaqSummary = $global:HPModelSoftPaqs | Where-Object {
				($_.SystemName -match $ComputerModel) -and ($_.OSName -like "$OSName*$OSArchitecture*$OSBuild*")
			} | Sort-Object -Descending | select -First 1
		}
		if ($HPSoftPaqSummary -ne $null) {
			$HPSoftPaq = $HPSoftPaqSummary.SoftPaqID
			$HPSoftPaqDetails = $global:HPModelXML.newdataset.hpclientdriverpackcatalog.softpaqlist.softpaq | Where-Object {
				$_.ID -eq "$HPSoftPaq"
			}
			$ComputerModelURL = $HPSoftPaqDetails.URL
			# Replace FTP for HTTP for Bits Transfer Job
			$DriverDownload = ($HPSoftPaqDetails.URL).TrimStart("ftp:")
			$DriverCab = $ComputerModelURL | Split-Path -Leaf
			$DriverRevision = "$($HPSoftPaqDetails.Version)"
		}
		else{
			Write-CMLogEntry -Value "Unsupported model / operating system combination found. Exiting." -Severity 3; exit 1
		}
	}
	if ($ComputerManufacturer -eq "Lenovo") {
		global:Write-CMLogEntry -Value "Info: Setting Lenovo variables" -Severity 1
		$global:LenovoModelType = LenovoModelTypeFinder -ComputerModel $ComputerModel -OS $WindowsVersion
		global:Write-CMLogEntry -Value "Info: $ComputerManufacturer $ComputerModel matching model type: $global:LenovoModelType" -Severity 1
		
		if ($global:LenovoModelDrivers -ne $null) {
			[xml]$global:LenovoModelXML = (New-Object System.Net.WebClient).DownloadString("$global:LenovoXMLSource")
			# Set XML Object
			$global:LenovoModelXML.GetType().FullName | Out-Null
			$global:LenovoModelDrivers = $global:LenovoModelXML.Products
			if ($SystemSKU -ne $null) {
				$ComputerModelURL = (($global:LenovoModelDrivers.Product | Where-Object {
							($_.Queries.smbios -match $SystemSKU -and $_.OS -match $WindowsVersion)
						}).driverPack | Where-Object {
						$_.id -eq "SCCM"
					})."#text"
			}
			else {
				$ComputerModelURL = (($global:LenovoModelDrivers.Product | Where-Object {
							($_.Queries.Version -match ("^" + $ComputerModel + "$") -and $_.OS -match $WindowsVersion)
						}).driverPack | Where-Object {
						$_.id -eq "SCCM"
					})."#text"
			}
			global:Write-CMLogEntry -Value "Info: Model URL determined as $ComputerModelURL" -Severity 1
			$DriverDownload = FindLenovoDriver -URI $ComputerModelURL -os $WindowsVersion -Architecture $OSArchitecture
			If ($DriverDownload -ne $null) {
				$DriverCab = $DriverDownload | Split-Path -Leaf
				$DriverRevision = ($DriverCab.Split("_") | Select -Last 1).Trim(".exe")
				global:Write-CMLogEntry -Value "Info: Driver cabinet download determined as $DriverDownload" -Severity 1
			}
			else {
				global:Write-CMLogEntry -Value "Error: Unable to find driver for $Make $Model" -Severity 1
			}
		}
	}
	
	# Driver location variables
	$DriverSourceCab = ($TempDirectory + "\Driver Cab\" + $DriverCab)
	$DriverExtractDest = ("$TempDirectory" + "\Driver Files")
	global:Write-CMLogEntry -Value "Info: Driver extract location set - $DriverExtractDest" -Severity 1
	
	# =================== INITIATE DOWNLOADS ===================			
	
	global:Write-CMLogEntry -Value "======== $Product - $ComputerManufacturer $ComputerModel DRIVER PROCESSING STARTED ========" -Severity 1
	
	# =============== ConfigMgr Driver Cab Download =================				
	global:Write-CMLogEntry -Value "$($Product): Retrieving ConfigMgr driver pack site For $ComputerManufacturer $ComputerModel" -Severity 1
	global:Write-CMLogEntry -Value "$($Product): URL found: $ComputerModelURL" -Severity 1
	
	if (($ComputerModelURL -ne $null) -and ($DriverDownload -ne "badLink")) {
		# Cater for HP / Model Issue
		$ComputerModel = $ComputerModel -replace '/', '-'
		$ComputerModel = $ComputerModel.Trim()
		Set-Location -Path $TempDirectory
		# Check for destination directory, create if required and download the driver cab
		if ((Test-Path -Path $($TempDirectory + "\Driver Cab\" + $DriverCab)) -eq $false) {
			if ((Test-Path -Path $($TempDirectory + "\Driver Cab")) -eq $false) {
				New-Item -ItemType Directory -Path $($TempDirectory + "\Driver Cab")
			}
			global:Write-CMLogEntry -Value "$($Product): Downloading $DriverCab driver cab file" -Severity 1
			global:Write-CMLogEntry -Value "$($Product): Downloading from URL: $DriverDownload" -Severity 1
			Start-Job -Name "$ComputerModel-DriverDownload" -ScriptBlock $DriverDownloadJob -ArgumentList ($TempDirectory, $ComputerModel, $DriverCab, $DriverDownload)
			sleep -Seconds 5
			$BitsJob = Get-BitsTransfer | Where-Object {
				$_.DisplayName -match "$ComputerModel-DriverDownload"
			}
			while (($BitsJob).JobState -eq "Connecting") {
				global:Write-CMLogEntry -Value "$($Product): Establishing connection to $DriverDownload" -Severity 1
				sleep -seconds 30
			}
			while (($BitsJob).JobState -eq "Transferring") {
				if ($BitsJob.BytesTotal -ne $null) {
					$PercentComplete = [int](($BitsJob.BytesTransferred * 100)/$BitsJob.BytesTotal);
					global:Write-CMLogEntry -Value "$($Product): Downloaded $([int]((($BitsJob).BytesTransferred)/ 1MB)) MB of $([int]((($BitsJob).BytesTotal)/ 1MB)) MB ($PercentComplete%). Next update in 30 seconds." -Severity 1
					sleep -seconds 30
				}
				else {
					global:Write-CMLogEntry -Value "$($Product): Download issues detected. Cancelling download process" -Severity 2
					Get-BitsTransfer | Where-Object {
						$_.DisplayName -eq "$ComputerModel-DriverDownload"
					} | Remove-BitsTransfer
				}
			}
			Get-BitsTransfer | Where-Object {
				$_.DisplayName -eq "$ComputerModel-DriverDownload"
			} | Complete-BitsTransfer
			global:Write-CMLogEntry -Value "$($Product): Driver revision: $DriverRevision" -Severity 1
		}
		else {
			global:Write-CMLogEntry -Value "$($Product): Skipping $DriverCab. Driver pack already downloaded." -Severity 1
		}
		
		# Cater for HP / Model Issue
		$ComputerModel = $ComputerModel -replace '/', '-'
		
		if (((Test-Path -Path "$($TempDirectory + '\Driver Cab\' + $DriverCab)") -eq $true) -and ($DriverCab -ne $null)) {
			global:Write-CMLogEntry -Value "$($Product): $DriverCab File exists - Starting driver update process" -Severity 1
			# =============== Extract Drivers =================
			
			if ((Test-Path -Path "$DriverExtractDest") -eq $false) {
				New-Item -ItemType Directory -Path "$($DriverExtractDest)"
			}
			if ((Get-ChildItem -Path "$DriverExtractDest" -Recurse -Filter *.inf -File).Count -eq 0) {
				global:Write-CMLogEntry -Value "==================== $PRODUCT DRIVER EXTRACT ====================" -Severity 1
				global:Write-CMLogEntry -Value "$($Product): Expanding driver CAB source file: $DriverCab" -Severity 1
				global:Write-CMLogEntry -Value "$($Product): Driver CAB destination directory: $DriverExtractDest" -Severity 1
				if ($ComputerManufacturer -eq "Dell") {
					global:Write-CMLogEntry -Value "$($Product): Extracting $ComputerManufacturer drivers to $DriverExtractDest" -Severity 1
					Expand "$DriverSourceCab" -F:* "$DriverExtractDest"
				}
				if ($ComputerManufacturer -eq "Hewlett-Packard") {
					global:Write-CMLogEntry -Value "$($Product): Extracting $ComputerManufacturer drivers to $HPTemp" -Severity 1
					# Driver Silent Extract Switches
					$HPSilentSwitches = "-PDF -F" + "$DriverExtractDest" + " -S -E"
					global:Write-CMLogEntry -Value "$($Product): Using $ComputerManufacturer silent switches: $HPSilentSwitches" -Severity 1
					Start-Process -FilePath "$($TempDirectory + '\Driver Cab\' + $DriverCab)" -ArgumentList $HPSilentSwitches -Verb RunAs
					$DriverProcess = ($DriverCab).Substring(0, $DriverCab.length - 4)
					
					# Wait for HP SoftPaq Process To Finish
					While ((Get-Process).name -contains $DriverProcess) {
						global:Write-CMLogEntry -Value "$($Product): Waiting for extract process (Process: $DriverProcess) to complete..  Next check in 30 seconds" -Severity 1
						sleep -Seconds 30
					}
				}
				if ($ComputerManufacturer -eq "Lenovo") {
					# Driver Silent Extract Switches
					$global:LenovoSilentSwitches = "/VERYSILENT /DIR=" + '"' + $DriverExtractDest + '"' + ' /Extract="Yes"'
					global:Write-CMLogEntry -Value "$($Product): Using $ComputerManufacturer silent switches: $global:LenovoSilentSwitches" -Severity 1
					global:Write-CMLogEntry -Value "$($Product): Extracting $ComputerManufacturer drivers to $DriverExtractDest" -Severity 1
					Unblock-File -Path $($TempDirectory + '\Driver Cab\' + $DriverCab)
					Start-Process -FilePath "$($TempDirectory + '\Driver Cab\' + $DriverCab)" -ArgumentList $global:LenovoSilentSwitches -Verb RunAs
					$DriverProcess = ($DriverCab).Substring(0, $DriverCab.length - 4)
					# Wait for Lenovo Driver Process To Finish
					While ((Get-Process).name -contains $DriverProcess) {
						global:Write-CMLogEntry -Value "$($Product): Waiting for extract process (Process: $DriverProcess) to complete..  Next check in 30 seconds" -Severity 1
						sleep -seconds 30
					}
				}
			}
			else {
				global:Write-CMLogEntry -Value "Skipping. Drivers already extracted." -Severity 1
			}
		}
		else {
			global:Write-CMLogEntry -Value "$($Product): $DriverCab file download failed" -Severity 3
		}
	}
	elseif ($DriverDownload -eq "badLink") {
		global:Write-CMLogEntry -Value "$($Product): Operating system driver package download path not found.. Skipping $ComputerModel" -Severity 3
	}
	else {
		global:Write-CMLogEntry -Value "$($Product): Driver package not found for $ComputerModel running Windows $WindowsVersion $Architecture. Skipping $ComputerModel" -Severity 2
	}
	global:Write-CMLogEntry -Value "======== $PRODUCT - $ComputerManufacturer $ComputerModel DRIVER PROCESSING FINISHED ========" -Severity 1
	
	
	if ($ValidationErrors -eq 0) {
		
	}
}

function Update-Drivers {
	$DriverPackagePath = Join-Path $TempDirectory "Driver Files"
	Write-CMLogEntry -Value "Driver package location is $DriverPackagePath" -Severity 1
	Write-CMLogEntry -Value "Starting driver installation process" -Severity 1
	Write-CMLogEntry -Value "Reading drivers from $DriverPackagePath" -Severity 1
	# Apply driver maintenance package
	try {
		if ((Get-ChildItem -Path $DriverPackagePath -Filter *.inf -Recurse).count -gt 0) {
			try {
				Start-Process "$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -WorkingDirectory $DriverPackagePath -ArgumentList "pnputil /add-driver *.inf /subdirs /install | Out-File -FilePath (Join-Path $LogDirectory '\Install-Drivers.txt') -Append" -NoNewWindow -Wait
				Write-CMLogEntry -Value "Driver installation complete. Restart required" -Severity 1
			}
			catch [System.Exception]
			{
				Write-CMLogEntry -Value "An error occurred while attempting to apply the driver maintenance package. Error message: $($_.Exception.Message)" -Severity 3; exit 1
			}
		}
		else {
			Write-CMLogEntry -Value "No driver inf files found in $DriverPackagePath." -Severity 3; exit 1
		}
	}
	catch [System.Exception] {
		Write-CMLogEntry -Value "An error occurred while attempting to apply the driver maintenance package. Error message: $($_.Exception.Message)" -Severity 3; exit 1
	}
	Write-CMLogEntry -Value "Finished driver maintenance." -Severity 1
	Return $LastExitCode
}

if ($OSName -eq "Windows 10") {
	# Download manufacturer lists for driver matching
	DownloadDriverList
	# Initiate matched downloads
	InitiateDownloads
	# Update driver repository and install drivers
	Update-Drivers
}
else {
	Write-CMLogEntry -Value "An upsupported OS was detected. This script only supports Windows 10." -Severity 3; exit 1
}
