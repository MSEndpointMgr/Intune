$BitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot
if (($BitLockerOSVolume.VolumeStatus -like "FullyEncrypted") -and ($BitLockerOSVolume.KeyProtector.Count -eq 2)) {
    return 0
}