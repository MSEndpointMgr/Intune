<#
.SYNOPSIS
  Script to install Office as a Win32 App during Autopilot

.DESCRIPTION
    Script to install Office as a Win32 App during Autopilot by downloading the latest Office Deployment Toolkit
    Running Setup.exe from downloaded files with provided config.xml file. 

.NOTES
  Version:        1.0
  Author:         Jan Ketil Skanke
  Creation Date:  01.07.2021
  Purpose/Change: Initial script development
        Author:      Jan Ketil Skanke
        Contact:     @JankeSkanke
        Updated:     2021-09-08
        Version history:
        1.0.0 - (2020-10-11) Script created
#>

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
#Endregion Functions

#Region Initialisations
$LogFileName = "M365AppsSetup.log"
#Endregion Initialisations

#Initate Install
Write-LogEntry -Value "Initiating Office setup process" -Severity 1
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
            #Prepare Office Installation
            Copy-Item -Path $SetupFilePath -Destination $SetupFolder -Force -ErrorAction Stop
            $OfficeCR2Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$($SetupFolder)\setup.exe").FileVersion 
            Write-LogEntry -Value "Office C2R Setup is running version $OfficeCR2Version" -Severity 1
            Copy-Item "$($PSScriptRoot)\configuration.xml" $SetupFolder -Force -ErrorAction Stop
            Write-LogEntry -Value "Office Setup configuration filed copied" -Severity 1           
            Try{
                #Running office installer
                Write-LogEntry -Value "Starting M365 Apps Install with Win32App method" -Severity 1
                $OfficeInstall = Start-Process "$($SetupFolder)\setup.exe" -ArgumentList "/configure $($SetupFolder)\configuration.xml" -Wait -PassThru -ErrorAction Stop
              }
            catch [System.Exception]{
                Write-LogEntry -Value  "Error running the M365 Apps install. Errormessage: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception]{
            Write-LogEntry -Value  "Error preparing office installation. Errormessage: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception]{
        Write-LogEntry -Value  "Error extraction setup.exe from ODT Package. Errormessage: $($_.Exception.Message)" -Severity 3
    }
    
}
catch [System.Exception]{
    Write-LogEntry -Value  "Error downloading Office Deployment Toolkit. Errormessage: $($_.Exception.Message)" -Severity 3
}
Write-LogEntry -Value "M365 Apps setup completed" -Severity 1
