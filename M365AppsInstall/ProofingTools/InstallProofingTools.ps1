<#
.SYNOPSIS
  Script to install Proofingtools as a Win32 App 

.DESCRIPTION
    Script to install Proofingtools as a Win32 App by downloading the latest Office Deployment Toolkit
    Running Setup.exe from downloaded files with provided config.xml file. 

.PARAMETER LanguageID
    Set the language ID in the correct formatting (like nb-no or en-us)
.PARAMETER Action 
    Supported actions are Install or Uninstall 

.EXAMPLE 
    InstallProofingTools.ps1 -LanguageID "nb-no" -Action Install
    InstallProofingTools.ps1 -LanguageID "nb-no" -Action Uninstall

.NOTES
  Version:       3.0
  Author:         Jan Ketil Skanke
  Creation Date:  01.07.2021
  Purpose/Change: Initial script development
  Author:      Jan Ketil Skanke
  Contributor Sandy Zeng 
  Contact:     @JankeSkanke @sandytsang
Updated:     2022-22-09
    Version history:
    1.0 - (2020-10-11) Script created
    2.0 - (2022-15-06) MultiLanguageSupport via parameter 
    2.1 - (2022-20-06) Dynamically change configuration.xml based on LanguageID Parameter
    2.2 - (2022-22-09) Adding support for uninstall, now equires 2 xml files - uninstall.xml and install.xml
#>

#region parameters
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [string]$LanguageID,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action 
)
#endregion parameters

#Region Functions
function Write-LogEntry {
	param (
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]$FileName = $LogFileName
	)
	# Determine log file location
	$LogFilePath = Join-Path -Path $env:SystemRoot -ChildPath $("Temp\$FileName")
	
	# Construct time stamp for log entry
	$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	
	# Construct date for log entry
	$Date = (Get-Date -Format "MM-dd-yyyy")
	
	# Construct context for log entry
	$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	
	# Construct final log entry
	$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($LogFileName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	
	# Add value to log file
	try {
		Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		if ($Severity -eq 1) {
			Write-Verbose -Message $Value
		} elseif ($Severity -eq 3) {
			Write-Warning -Message $Value
		}
	} catch [System.Exception] {
		Write-Warning -Message "Unable to append log entry to $LogFileName.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
	}
}
function Start-DownloadFile {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    Begin {
        # Construct WebClient object
        $WebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not(Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Start download of file
        $WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
    }
    End {
        # Dispose of the WebClient object
        $WebClient.Dispose()
    }
}
function Invoke-XMLUpdate  {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$LanguageID,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Filename,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
		[ValidateSet("Install", "Uninstall")]
        [string]$Action 
    )
    if ($Action -eq "Install"){
        $xmlDoc = [System.Xml.XmlDocument](Get-Content $FileName)
        $xmlDoc.Configuration.Add.Product.Language.ID = $LanguageID
        $xmlDoc.Save($FileName); 
    }
    else {
        $xmlDoc = [System.Xml.XmlDocument](Get-Content $FileName)
        $xmlDoc.Configuration.Remove.Product.Language.ID = $LanguageID
        $xmlDoc.Save($FileName);
    }
}
#Endregion Functions

#Region Initialisations
$LogFileName = "M365AppsSetup.log"
#Endregion Initialisations
switch -Wildcard ($Action) { 
    {($PSItem -match "Install")}{
      $FileName = "install.xml"
    }
    {($PSItem -match "Uninstall")}{
        $FileName = "uninstall.xml"
    }
}

#Initate Install
Write-LogEntry -Value "Initiating Proofing tools $($LanguageID) $($Action) process" -Severity 1
#Attempt Cleanup of SetupFolder
if (Test-Path "$($env:SystemRoot)\Temp\OfficeSetup"){
    Remove-Item -Path "$($env:SystemRoot)\Temp\OfficeSetup" -Recurse -Force -ErrorAction SilentlyContinue
}

$SetupFolder = (New-Item -ItemType "directory" -Path "$($env:SystemRoot)\Temp" -Name OfficeSetup -Force).FullName

try{
    #Download latest Office Deployment Toolkit
    $ODTDownloadURL = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117"
    $WebResponseURL = ((Invoke-WebRequest -Uri $ODTDownloadURL -UseBasicParsing -ErrorAction Stop -Verbose:$false).links | Where-Object { $_.outerHTML -like "*click here to download manually*" }).href
    $ODTFileName = Split-Path -Path $WebResponseURL -Leaf
    $ODTFilePath = $SetupFolder
    Write-LogEntry -Value "Attempting to download latest Office Deployment Toolkit executable" -Severity 1
    Start-DownloadFile -URL $WebResponseURL -Path $ODTFilePath -Name $ODTFileName
    
    try{
        #Extract setup.exe from ODT Package
        $ODTExecutable = (Join-Path -Path $ODTFilePath -ChildPath $ODTFileName)
        $ODTExtractionPath = (Join-Path -Path $ODTFilePath -ChildPath (Get-ChildItem -Path $ODTExecutable).VersionInfo.ProductVersion)
        $ODTExtractionArguments = "/quiet /extract:$($ODTExtractionPath)"
        Write-LogEntry -Value "Attempting to extract the setup.exe executable from Office Deployment Toolkit" -Severity 1
        Start-Process -FilePath $ODTExecutable -ArgumentList $ODTExtractionArguments -NoNewWindow -Wait -ErrorAction Stop
        $SetupFilePath = ($ODTExtractionPath | Get-ChildItem | Where-Object {$_.Name -eq "setup.exe"}).FullName
        Write-LogEntry -Value "Setup file ready at $($SetupFilePath)" -Severity 1
        try{
            #Prepare Proofing tools installation or removal
            Copy-Item -Path $SetupFilePath -Destination $SetupFolder -Force -ErrorAction Stop
            $OfficeCR2Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$($SetupFolder)\setup.exe").FileVersion 
            Write-LogEntry -Value "Office C2R Setup is running version $OfficeCR2Version" -Severity 1
            Invoke-XMLUpdate -LanguageID $LanguageID -Filename "$($PSScriptRoot)\$($Filename)" -Action $Action
            Copy-Item "$($PSScriptRoot)\$($Filename)" $SetupFolder -Force -ErrorAction Stop
            Write-LogEntry -Value "Proofing tools $($LanguageID) configuration file copied" -Severity 1           
            Try{
                #Running office installer
                Write-LogEntry -Value "Starting Proofing tools $($LanguageID) $($Action) with Win32App method" -Severity 1
                $OfficeInstall = Start-Process "$($SetupFolder)\setup.exe" -ArgumentList "/configure $($SetupFolder)\$($Filename)" -NoNewWindow -Wait -PassThru -ErrorAction Stop
              }
            catch [System.Exception]{
                Write-LogEntry -Value  "Error running the Proofing tools $($LanguageID) $($Action). Errormessage: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception]{
            Write-LogEntry -Value  "Error preparing Proofing tools $($LanguageID) $($Action). Errormessage: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception]{
        Write-LogEntry -Value  "Error extraction setup.exe from ODT Package. Errormessage: $($_.Exception.Message)" -Severity 3
    }
    
}
catch [System.Exception]{
    Write-LogEntry -Value  "Error downloading Office Deployment Toolkit. Errormessage: $($_.Exception.Message)" -Severity 3
}
Write-LogEntry -Value "Proofing Tools $($LanguageID) $($Action) completed" -Severity 1
