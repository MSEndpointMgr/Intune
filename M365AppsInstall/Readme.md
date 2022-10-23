# M365 Apps Intune scripted dynamic install using Office Deployment Toolkit 
## This solution covers installation of the following products 
* [M365 Apps(Office)](#Main-Office-Package)
* [Project](#Project-and-Visio)
* [Visio](#Project-and-Visio)
* [Proofing tools](#Proofing-tools)

Each product is made of the following components 
* Install script (PowerShell)
* Configuration.xml (config.office.com)
* Detection (script or documented)
    
### Main Office Package

1. Define your config XML (Example below, can be generated at office.com)
```xml
<Configuration ID="9aa11e20-2e29-451a-b0ba-f1ae3e89d18d">
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise" MigrateArch="TRUE">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="Bing" />
    </Product>
  </Add>
  <Property Name="SharedComputerLicensing" Value="0" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
  <Property Name="DeviceBasedLicensing" Value="0" />
  <Property Name="SCLCacheOverride" Value="0" />
  <Updates Enabled="TRUE" />
  <AppSettings>
    <Setup Name="Company" Value="Company Name" />
  </AppSettings>
  <Display Level="None" AcceptEULA="FALSE" />
</Configuration>
```
2. Create a .Intunewim using the Win32 Content Prep tool [Prepare Win32 app content for upload](https://learn.microsoft.com/en-us/mem/intune/apps/apps-win32-prepare?WT.mc_id=EM-MVP-5002085) containing the configuration.xml and the InstallM365Apps.ps1 
3. Upload .Intunewim and define the following parameters during install 
    1. Install Command : powershell.exe -executionpolicy bypass -file InstallM365Apps.ps1
    2. Uninstall Command : powershell.exe -executionpolicy bypass -file InstallM365Apps.ps1 (Not working yet)
    3. Install behaviour: System 
    4. Requirements (probable 64 bit Windows something)
    5. Detection: Use PowerShell detection Script M365AppsWin32DetectionScript.ps1 
 4. Assign 

### Project and Visio

1. Define your config XML (Example below, can be generated at office.com)
```xml
<Configuration ID="fc6a02c8-622f-4cf4-bf7f-6c57847b0580">
  <Add OfficeClientEdition="64" Version="MatchInstalled">
    <Product ID="ProjectProRetail">
      <Language ID="MatchInstalled" Fallback="en-us" TargetProduct="O365ProPlusRetail"/>
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="OneDrive" />
    </Product>
  </Add>
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
  <Updates Enabled="TRUE" />
  <AppSettings>
    <Setup Name="Company" Value="Company Name" />
  </AppSettings>
  <Display Level="None" AcceptEULA="TRUE" />
</Configuration>
```
This configuration file example will match the language installed (M365 Apps). TargetProduct is required for that to work. Also this example will shutdown running Office Apps for end users during install. The follow step 2-4 from the main office package. 

### Proofing tools

We recommend installing only 1 language on the computers unless your requirements are specific. But there might still be need for proofing tools for multiple languages. The main thinking here is to have all possible proofing tools in your environment as available to end user to install by their own choosing. 

For proofing tool the included configuration.xml files are just "templates" as the script it self will rewrite the XML dynamically based on the parameters you send to the script. 

EXAMPLES
```
InstallProofingTools.ps1 -LanguageID "nb-no" -Action Install
InstallProofingTools.ps1 -LanguageID "nb-no" -Action Uninstall
```
It is also recommended that you have a requirement to check if Main Office is installed on the device as the install will fail if you try to install the proofing tools without Office installed. 
This can be done using a registry key check or using the provided requirement script. 

Detection of the proofing tools can be done either with the provided detection script, customized for each LanguageID or by having a registry key check. 

For more details and instructions go to [MSEndpointMgr Blog](https://msendpointmgr.com)



