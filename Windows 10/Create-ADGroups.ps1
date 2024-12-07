$Groups = @("AOVPN-Servers", "AOVPN-Users", "NDES-Servers", "NPS-Servers")
Foreach ($Group in $Groups) {
    New-ADGroup -GroupScope "Global" -Name $Group
}