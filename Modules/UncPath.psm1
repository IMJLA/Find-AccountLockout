function New-UncPath{
<#
    .SYNOPSIS
        Converts a local file path into a UNC path
    .DESCRIPTION
        Scenario 1 - The specified path refers to a local drive that is not a mapped network drive.
            The function generates a UNC path to the administrative share for that drive (e.g. '\\hostname\C$')
        Scenario 2 - The specified path refers to a mapped network drive.
            The function looks up the UNC path of the mapped drive, and uses it to replace the mapped drive letter.
    .OUTPUTS
        The new UNC path is returned to the pipeline as a string.
    .EXAMPLE
        New-UncPath -Path 'C:\test'
    .EXAMPLE
        'J:\test' | New-UncPath
#>
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$Path
    )

    if ($Path -like "\\*"){
      Write-Output $Path
    }
    else{
      $Drive = Split-Path -Path $Path -Qualifier
      $Win32logicalDisk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 4 AND DeviceID = '$Drive'"
      if($null -ne $Win32logicalDisk){

        [String]$uncPath = $Path.Replace($Drive, $Win32logicalDisk.ProviderName)
        Write-Output $uncPath

      }else{

        $Sys = Get-WmiObject -Class Win32_ComputerSystem
        $FQDN = "$($Sys.DNSHostName).$($Sys.Domain)"
        [String]$uncPath = $Path.Replace($Drive,"\\$FQDN\$($Drive.Replace(':',''))`$")
        Write-Output $uncPath

      }

    }
}
