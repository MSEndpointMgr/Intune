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
    # Code to be executed as 64-bit
}