$TemplateName = "NDES Intune"
$SubjectNames = @("CN=CL", "CN=CORP")
$Certificates = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -match ($SubjectNames -join "|") }
foreach ($Certificate in $Certificates) {
    $CertificateTemplateInformation = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -match "Certificate Template Information"}
    if ($CertificateTemplateInformation -ne $null) {
        $CertificateTemplateName = ($CertificateTemplateInformation).Format(0) -replace "(.+)?=(.+)\((.+)?", '$2'
        if ($CertificateTemplateName -ne $null) {
            if ($CertificateTemplateName -like $TemplateName) {
                return 0
            }
        }
    }
}