Function ConvertTo-ExchangeRole{
    <#
        .SYNOPSIS
            Convert the msExchCurrentServerRoles AD attribute into the Exchange Roles it represents
        .DESCRIPTION
            Performs a bitwise And comparison against a provided integer and the keys from a hard-coded dictionary
            Dictionary based on a table from a TechNet article
            https://technet.microsoft.com/en-us/library/bb123496(EXCHG.80).aspx
        .PARAMETER Roles
            Integer representing the Exchange roles held by the server. Matches the msExchCurrentServerRoles AD attribute.
        .OUTPUTS
            Returns a collection of strings representing the Exchange roles found
            Valid Outputs:
                "CAS"
                "ET"
                "HT"
                "MB"
                "UM"
        .EXAMPLE
            ConvertTo-ExchangeRole 38
        .EXAMPLE
            38 | ConvertTo-ExchangeRole
        .NOTES
    #>
    param(
        [parameter(
            Mandatory=$true,
            ValueFromPipeLine=$true)
        ]
        [int32]$Roles
    )
    begin{
        $roleDictionary = @{
            2  = "MB"
            4  = "CAS"
            16 = "UM"
            32 = "HT"
            64 = "ET"
        }
    }
    process{
        $roleDictionary.Keys | ?{$_ -bAnd $Roles} | %{$roleDictionary.Get_Item($_)}
    }
    end{
        Remove-Variable roleDictionary
    }
}

Function ConvertTo-ExchangeVersion{
    <#
        .SYNOPSIS
            Converts the versionNumber AD attribute into the Exchange versions it represents
        .DESCRIPTION
            Converts a provided 32-bit Base 10 integer to binary, then splits the binary bits according to Microsoft's structure
            http://blogs.msdn.com/b/pcreehan/archive/2009/09/21/parsing-serverversion-when-an-int-is-really-5-ints.aspx
        .PARAMETER Version
            Integer representing the Exchange Version of the server. Matches the versionNumber AD attribute.
        .OUTPUTS
            Returns an object with 5 properties containing 16-bit Base 10 integers which represent:
                Major Version #
                Minor Version #
                Build #
                Unknown Flag
                Unknown Legacy Version #
        .EXAMPLE
            ConvertTo-ExchangeVersion 1912832083
        .EXAMPLE
            1912832083 | ToExchangeVersion
    #>
    [CmdletBinding(
        SupportsShouldProcess=$false,
        ConfirmImpact="Low"
    )]
    param(
        [parameter(
            Mandatory=$true,
            ValueFromPipeLine=$true)
        ]
        [int32]$Version
    )
    begin{
        #Write-Log -Type 'Debug' -Text "$(Get-Date -Format s)`t$(hostname)`tConvertTo-ExchangeVersion: Input Base 10:`t$Version"
        $VersionSizeInBits = 32
    }
    process{
        $BinaryVersion = [convert]::ToString([int32]$Version,2)

        #If LegacyVersionStructure < 4 bits, [convert] does not include the preceding 0's that complete the 32-bit integer
        #We need to add them back
        #Write-Log -Type 'Debug' -Text "$(Get-Date -Format s)`t$(hostname)`tConvertTo-ExchangeVersion: Input Bits:`t$($BinaryVersion.Length)`t$BinaryVersion"
        for ($i=$($BinaryVersion.Length);$i -lt $VersionSizeInBits;$i++){
            $BinaryVersion = '0' + $BinaryVersion
        }
        #Write-Log -Type 'Debug' -Text "$(Get-Date -Format s)`t$(hostname)`tConvertTo-ExchangeVersion: Output Bits:`t$($BinaryVersion.Length)`t$BinaryVersion"
        New-Object PSObject -Property @{
            LegacyVersionStructure = [convert]::ToInt16($BinaryVersion.Substring(0,4),2) #The first 4 bits represent a number used for comparison against older version number structures.
            MajorVersion = [convert]::ToInt16($BinaryVersion.Substring(4,6),2) #The next 6 bits represent the major version number.
            MinorVersion = [convert]::ToInt16($BinaryVersion.Substring(10,6),2) #The next 6 bits represent the minor version number.
            Flag = [convert]::ToInt16($BinaryVersion.Substring(16,1),2) #The next 1 bit is just a flag that you can ignore.
            Build = [convert]::ToInt16($BinaryVersion.Substring(17,15),2) #The last 15 bits is the build number.
        }
    }
    end{
        Remove-Variable BinaryVersion
        Remove-Variable VersionSizeInBits
    }
}

Function Get-ADExchangeServer{
    <#
        .SYNOPSIS
            Discover all Exchange servers in the current AD domain
        .DESCRIPTION
            Searches the default root configuration naming context for Exchange servers and returns them in a friendly form.
        .OUTPUTS
            Returns an object with 4 properties for each Exchange server:
                FQDN - The Fully Qualified Domain Name of the server
                Roles (Exchange Roles) - Collection of strings returned from ConvertTo-ExchangeRole
                Class - String matching the objectClass AD attribute
                Version - PSCustomObject returned from ConvertTo-ExchangeVersion
        .EXAMPLE
            Get-ADExchangeServer
    #>
    Import-Module ActiveDirectory -Cmdlet Get-ADObject -Verbose:$false
    [String]$context = ([ADSI]"LDAP://RootDse").configurationNamingContext
    $Splat = @{
        LDAPFilter = "(|(objectClass=msExchExchangeServer)(objectClass=msExchClientAccessArray))"
        SearchBase = $context
        Properties = 'objectClass','msExchCurrentServerRoles','networkAddress','versionNumber'
    }
    $Results = Get-ADObject @Splat
    ForEach ($ExchServer in $Results) {
        $FQDN = ($ExchServer.networkAddress | Where-Object -FilterScript {$_ -like "ncacn_ip_tcp*"}).Split(":")[1]
        $Roles = ConvertTo-ExchangeRole $ExchServer.msExchCurrentServerRoles
        $Class = $ExchServer.objectClass
        $ExchVersion = ConvertTo-ExchangeVersion -Version $ExchServer.versionNumber

        $Object = New-Object PSObject -Property @{
            FQDN = $FQDN
            Roles = $Roles
            Class = $Class
            MajorVersion = $ExchVersion.MajorVersion
            MinorVersion = $ExchVersion.MinorVersion
            Flag = $ExchVersion.Flag
            Build = $ExchVersion.Build
            LegacyVersionStructure = $ExchVersion.LegacyVersionStructure
        }
        $Object
    }
}

Function GoGo-GadgetExchange{
  <#
    .SYNOPSIS
        Make Exchange Cmdlets available in the current PowerShell session.
    .DESCRIPTION
        Automatically detects the Exchange servers using LDAP, tries to connect to each one until it succeeds.
        Exchange Server 2007 requires the Exchange Management Tools
        Exchange 2010 connects via PowerShell Remoting
        Tested with Exchange Server 2007 & 2010 Coexistence (currently does not allow you to specify which one it chooses)
    .PARAMETER CommandNamesToImport
        Optional but highly recommended for performance. Limits the commands imported to the list you specify.
        Should match the accceptable input for the -CommandName parameter of the Import-PSSession CMDlet
    .OUTPUTS
        Results are written to the console.
    .EXAMPLE
        GoGo-GadgetExchange
    .EXAMPLE
        GoGo-GadgetExchange -CommandNamesToImport 'Get-Mailbox'
    .NOTES
        Version:
            1.0.2016.10.14
        Prerequisites:
            OS:
                Tested running on Windows 8.1 and Server 2008 R2
            Software:
                Requires PS 2.0 for the try catch statements
                PowerShell Active Directory Cmdlets
            Domain:
                2003 Functional Level or Above
            Permissions:
                Only tested with Domain Admins membership

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
  #>

  [CmdletBinding(
    SupportsShouldProcess=$false,
    ConfirmImpact="Low"
  )]
  param(
    [parameter(Mandatory=$false,ValueFromPipeLine=$false)]
    [String[]]
    $CommandNamesToImport,

    #The FQDN(s) of the Exchange Server(s) to try to connect to using PS Remoting. If not specified the script will attempt to discover them through LDAP
    [parameter(Mandatory=$false,ValueFromPipeLine=$false)]
    [PSObject[]]$ExchangeServer = (Get-ADExchangeServer),

    #If true, this will return the Exchange session as an object instead of importing it into the current session.
    [Switch]$ReturnSessionObject = $false

  )
  begin{
    #Remove any existing Exchange PSSessions to avoid creating duplicates
    Get-PSSession | Where-Object -FilterScript {$_.ConfigurationName -eq 'Microsoft.Exchange'} | Remove-PSSession #I wanted to use the -ConfurationName filtering parameter for Get-PSSession, but it would raise the requirements to PS 4.0

    #This variable will track our progress as we try to connect to servers until we succeed
    [Boolean]$ConnectedToExchange = $false

    if($CommandNamesToImport){
      $CommandNamesToImport += 'Get-Mailbox'
    }

  }
  process{
    ForEach ($Server in $ExchangeServer) {
      if($ConnectedToExchange -eq $false){
        Switch ($Server.MajorVersion){
          {$_ -ge 14} {
            #In Exchange 2010 or newer, loading the snapin is deprecated. Best practice is to create a remote PSSession to the Exchange server.
            
            #Write-Log -Type 'Debug' -Text "GoGo-GadgetExchange`tExchange 2010 or newer Detected on $($Server.FQDN)"
            
            try{
              $Uri = "http://$($Server.FQDN)/PowerShell"
              Write-Log -Type 'Verbose' -Text `
                "GoGo-GadgetExchange`tNew-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $Uri -ErrorAction Stop"
              $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $Uri -ErrorAction Stop

              #Import specific commands (preferred) or import all available commands? (slow)
              if($CommandNamesToImport){
                #Write-Log -Type 'Verbose' -Text "GoGo-GadgetExchange`tImport-Module (Import-PSSession `$Session -CommandName @('$($CommandNamesToImport -join "','")') -ErrorAction Stop -Verbose:$false) -Global -Verbose:$false"
                #Import-Module (Import-PSSession $Session -CommandName $CommandNamesToImport -AllowClobber -ErrorAction Stop -Verbose:$false) -Global -Verbose:$false -WarningAction SilentlyContinue
                
                ##$null = Import-PSSession $Session -CommandName $CommandNamesToImport -AllowClobber -ErrorAction Stop -Verbose:$false
              }else{
                Write-Log -Type 'Verbose' -Text `
                  "GoGo-GadgetExchange`tImport-Module (Import-PSSession `$Session -ErrorAction Stop -Verbose:$false) -Global -Verbose:$false"
                #Import-Module (Import-PSSession $Session -AllowClobber -ErrorAction Stop -Verbose:$false) -Global -Verbose:$false -WarningAction SilentlyContinue
                #$null = Import-PSSession $Session -AllowClobber -ErrorAction Stop -Verbose:$false
              }

              #Return the PSSession object if requested
              if($ReturnSessionObject -eq $true){
                #Write-Log -Type 'Debug' -Text "GoGo-GadgetExchange`t$($Session.GetType().FullName)"
                Write-Output $Session
                #Write-Log -Type 'Debug' -Text "GoGo-GadgetExchange`tSession has been returned"
              }
              $WarningPreference = "Continue"
              $ConnectedToExchange = $true
            }
            catch{
              Write-Log -Type 'Verbose' -Text ("$($_.Exception.Message)")
            }
          }
          8 {
            #Add the Exchange PowerShell snap-in for Exchange 2007 or older
            #Write-Log -Type 'Debug' -Text "GoGo-GadgetExchange`tExchange 2007 Detected on $($Server.FQDN)"
            Try{
              Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction Stop
              $ConnectedToExchange = $true
            }Catch [System.Management.Automation.ActionPreferenceStopException]{
              Switch -Wildcard ($_.Exception.Message){
                "*it is already added.*"{
                  Write-Log -Type 'Debug' -Text `
                    "GoGo-GadgetExchange`tThe script was already run in the Exchange Management Shell, or the snap-in has already been loaded manually.  Either way we don't care' let's remove the harmless error so it doesn't get logged."
                  $Error.RemoveAt(0)
                }
                "*The system cannot find the file specified.*"{
                  Write-Log -Type 'Debug' -Text `
                    "GoGo-GadgetExchange`tA file is missing. The installed Exchange Management Tools version probably does not match the server."
                }
                default {
                  Write-Log -Type 'Debug' -Text `
                    "GoGo-GadgetExchange`t$($Server.FQDN)`t$_"
                }
              }
            }Catch {
              Write-Error "Unhandled exception. Could not connect to Exchange."
            }
          }
          0 {
            Write-Log -Type 'Verbose' -Text "GoGo-GadgetExchange`tNo version found on $($Server.FQDN). Not attempting to connect. Possible CAS Array."
          }
          default {
            Write-Log -Type 'Verbose' -Text "GoGo-GadgetExchange`tUnsupported version $_ found on $($Server.FQDN). Not attempting to connect."
          }
        }
      }
    }
  }
  end{
    $TestCommand = "Get-Mailbox -ResultSize 1 -WarningAction SilentlyContinue"
    if($ReturnSessionObject -eq $false){
      try {
        Invoke-Expression $TestCommand | Out-Null
        Write-Log -Type 'Debug' "GoGo-GadgetExchange`tSuccessfully tested connection to Exchange by running the Get-Mailbox Cmdlet in an imported PSSession"
      }catch{
        try{
          Invoke-Expression $CommandNamesToImport[0] | Out-Null
          Write-Log -Type 'Verbose' -Text "GoGo-GadgetExchange`tSuccessfully tested connection to Exchange by running the $($CommandNamesToImport[0]) Cmdlet"
        }catch{
          Write-Error "Testing failed. The Exchange Cmdlets are still not available in the current PowerShell session. Session failed to import."
        }
      }
    }
    else{

      try{

        $TestCommand = [scriptblock]::Create($TestCommand)
        Invoke-Command -ScriptBlock $TestCommand -Session $Session | Out-Null
        Write-Log -Type 'Verbose' -Text "GoGo-GadgetExchange`tSuccessfully tested connection to Exchange by running the Get-Mailbox Cmdlet in a remote PSSession"

      }catch{

        try{

          $TestCommand = [scriptblock]::Create($CommandNamesToImport[0])
          Invoke-Command -ScriptBlock $TestCommand -Session $Session | Out-Null
          Write-Log -Type 'Verbose' -Text "GoGo-GadgetExchange`tSuccessfully tested connection to Exchange by running the $($CommandNamesToImport[0]) Cmdlet"
        
        }catch{

          Write-Error $_

        }

      }

    }

  }

}
