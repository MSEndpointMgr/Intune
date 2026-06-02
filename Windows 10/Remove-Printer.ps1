<#
.Synopsis
Created on:   31/12/2021
Created by:   Ben Whitmore
Filename:     Remove-Printer.ps1

powershell.exe -executionpolicy bypass -file .\Remove-Printer.ps1 -PrinterName "Canon Printer Upstairs"

.Example
.\Remove-Printer.ps1 -PrinterName "Canon Printer Upstairs"
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $True)]
    [String]$PrinterName
)

Try {
    #Remove Printer
    $PrinterExist = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
    if ($PrinterExist) {
        $PrinterPort = (Get-Printer -Name $PrinterName).PortName
        Remove-Printer -Name $PrinterName -Confirm:$false
        Remove-PrinterPort -Name $PrinterPort -Confirm:$false
    }
}
Catch {
    Write-Warning "Error removing Printer"
    Write-Warning "$($_.Exception.Message)"
}
