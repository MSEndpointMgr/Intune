$DomainName = "byteben.com"
$Name = "gMSA_ndes"
$DNSHostName = "$($Name).$($DomainName)"
$PasswordInterval = 30
$AllowedPrincipals = "NDES-Servers"
New-ADServiceAccount -Name $Name -DNSHostName $DNSHostName -ManagedPasswordIntervalInDays $PasswordInterval -PrincipalsAllowedToRetrieveManagedPassword $AllowedPrincipals -Enabled $true