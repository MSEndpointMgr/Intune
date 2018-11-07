# Define registry path, key and value
$Path = "HKCU:\SOFTWARE\Microsoft\OneDrive"
$Name = "EnableADAL"
$Value = 1

# Verify if registry path exists, if not create key including value
if (-not(Test-Path -Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
}
else {
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
}