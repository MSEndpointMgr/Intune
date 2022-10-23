$RegistryKeys = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$M365Apps = "Microsoft 365 Apps"
$M365AppsCheck = $RegistryKeys | Get-ItemProperty | Where-Object { $_.DisplayName -match $M365Apps }
if ($M365AppsCheck) {
    Write-Output "OK"
	Exit 0
   }