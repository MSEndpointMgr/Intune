# Release notes for IntuneWin32App module

## 1.1.1
- Improved output for attempting to update the PSIntuneAuth module in the internal Get-AuthToken function.

## 1.1.0
- Added a new function called Get-MSIMetaData to retrieve MSI file properties like ProductCode and more.
- Added a new function called New-IntuneWin32AppRequirementRule to create a customized requirement rule for the Win32 app. This function does not support 'Additional requirement rules' as of yet, but will be implemented in a future version.
- Function Add-IntuneWin32App now supports an optional RequirementRule parameter. Use New-IntuneWin32AppRequirementRule function to create a suitable object for this parameter. If the RequirementRule parameter is not specified for Add-IntuneWin32App, default values of 'applicableArchitectures' with a value of 'x64,x86' and 'minimumSupportedOperatingSystem' with a value of 'v10_1607' will be used when adding the Win32 app.

## 1.0.1
- Updated Get-IntuneWin32App function to load all properties for objects return and support multiple objects returned for wildcard search when specifying display name

## 1.0.0
- Initial release, se README.md for documentation.