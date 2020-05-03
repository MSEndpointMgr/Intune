function Invoke-Executable {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable.")]
        [ValidateNotNull()]
        [string]$Arguments
    )

    # Construct a hash-table for default parameter splatting
    $SplatArgs = @{
        FilePath = $FilePath
        NoNewWindow = $true
        Passthru = $true
        ErrorAction = "Stop"
    }

    # Add ArgumentList param if present
    if (-not([System.String]::IsNullOrEmpty($Arguments))) {
        $SplatArgs.Add("ArgumentList", $Arguments)
    }

    # Invoke executable and wait for process to exit
    try {
        $Invocation = Start-Process @SplatArgs
        $Handle = $Invocation.Handle
        $Invocation.WaitForExit()
    }
    catch [System.Exception] {
        Write-Warning -Message $_.Exception.Message; break
    }

    return $Invocation.ExitCode
}