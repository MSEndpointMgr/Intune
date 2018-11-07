# Check if we're running as a 64-bit process or not
if (-not[System.Environment]::Is64BitProcess) {
    # Get the sysnative path for powershell.exe
   $SysNativePowerShell = Join-Path -Path ($PSHOME.ToLower().Replace("syswow64", "sysnative")) -ChildPath "powershell.exe"

   # Construct new ProcessStartInfo object to restart powershell.exe as a 64-bit process and re-run scipt
   $ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
   $ProcessStartInfo.FileName = $SysNativePowerShell
   $ProcessStartInfo.Arguments = "-ExecutionPolicy Bypass -File ""$($PSCommandPath)"""
   $ProcessStartInfo.RedirectStandardOutput = $true
   $ProcessStartInfo.RedirectStandardError = $true
   $ProcessStartInfo.UseShellExecute = $false
   $ProcessStartInfo.WindowStyle = "Hidden"
   $ProcessStartInfo.CreateNoWindow = $true

   # Instatiate the new 64-bit process
   $Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)

   # Read standard error output to determine if the 64-bit script process somehow failed
   $ErrorOutput = $Process.StandardError.ReadToEnd()
   if ($ErrorOutput) {
       Write-Error -Message $ErrorOutput
   }
}
else {
    # Construct a list of custom objects to configure OneDrive
    $RegistryList = New-Object -TypeName System.Collections.ArrayList

    # Construct custom object for enabling silent account configuration
    $RegistryItem = [PSCustomObject]@{
        "Path" = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        "Name" = "SilentAccountConfig"
        "Value" = "1"
    }
    $RegistryList.Add($RegistryItem) | Out-Null

    # Construct custom object for enabling Files on Demand
    $RegistryItem = [PSCustomObject]@{
        "Path" = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        "Name" = "FilesOnDemandEnabled"
        "Value" = "1"
    }
    $RegistryList.Add($RegistryItem) | Out-Null

    # Process each item in the array list
    foreach ($Item in $RegistryList) {
        # Verify if registry path exists, if not create key including value
        if (-not(Test-Path -Path $Item.Path)) {
            New-Item -Path $Item.Path -Force | Out-Null
            New-ItemProperty -Path $Item.Path -Name $Item.Name -Value $Item.Value -PropertyType DWORD -Force | Out-Null
        }
        else {
            New-ItemProperty -Path $Item.Path -Name $Item.Name -Value $Item.Value -PropertyType DWORD -Force | Out-Null
        }
    }
}