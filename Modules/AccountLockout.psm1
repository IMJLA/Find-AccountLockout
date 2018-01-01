if (!(Get-Module ActiveDirectory)) {
  Import-Module -Name ActiveDirectory -Cmdlet Get-AdDomain,Get-ADGroupMember -Verbose:$false -ErrorAction Stop
}

function Expand-Lockout {
  [CmdletBinding()]
  param(
      <#
      The account lockout events to expand
      These should be objects returned by Get-WinEvent
      #>
      [Parameter(
          Mandatory = $true,
          Position = 0,
          ValueFromPipeline
      )]
      $Event,

      #The LockoutDomain object that was created by Get-Lockout
      [LockoutDomain]$LockoutDomain
  )
  begin{
    #Import-Module -Name ActiveDirectory -Cmdlet 'Get-ADUser' -ErrorAction SilentlyContinue -Verbose:$false
  }
  process{
    ForEach ($CurrentEvent in $Event){

      #$Object = [xml]$CurrentEvent.ToXml()

      #Assign names to the properties of the current event
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'LockedAccountName' -Value $CurrentEvent.Properties[0].Value -Force
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'CallerComputerName' -Value $CurrentEvent.Properties[1].Value -Force
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'LockedAccountSID' -Value $CurrentEvent.Properties[2].Value -Force
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'SubjectSID' -Value $CurrentEvent.Properties[3].Value -Force
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'SubjectAccountName' -Value $CurrentEvent.Properties[4].Value -Force
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'SubjectAccountDomain' -Value $CurrentEvent.Properties[5].Value -Force
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'SubjectLogonID' -Value $CurrentEvent.Properties[6].Value -Force

      #Find the locked account's e-mail address so it can be used to notify them
      $LockedAccountEmail = (Get-ADUser -Identity $($CurrentEvent.LockedAccountName) -Properties Mail).Mail
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name 'LockedAccountEmail' -Value $LockedAccountEmail -Force

      #Investigate the CallerComputerName
      $CallerComputerInvestigation = New-Object -TypeName System.Collections.Generic.List[System.Object]
      Switch -Wildcard ($CurrentEvent.CallerComputerName){
        ''{
          <#
          If the CallerComputerName is blank, it's probably an IAS/NPS/LDAP server (they do not log this information for some reason).
          If known IAS/NPS/LDAP servers were provided, we can check their logs for more info.
          #>
          ForEach ($Server in $LockoutDomain.RASandIASServers.Name){
            Write-Log -Type 'Verbose' -Text "Expand-Lockout`tSearch-LockoutComputer -User `"$($CurrentEvent.LockedAccountName)`" -ComputerName `"$Server`" -Start `"$($CurrentEvent.TimeCreated.AddDays(-3))`" -End `"$($CurrentEvent.TimeCreated)`""
            
            $LockoutComputerSearchResult = Search-LockoutComputer -User "$($CurrentEvent.LockedAccountName)" -ComputerName "$Server" -Start $CurrentEvent.TimeCreated.AddDays(-3) -End $CurrentEvent.TimeCreated

            Write-Log -Type 'Verbose' -Text "Expand-Lockout`t$Server found to have $($LockoutComputerSearchResult.UnauthorizedDevices_IAS.Count) unauthorized IAS devices"

            $null = $CallerComputerInvestigation.Add($LockoutComputerSearchResult)
            
          }
          
          Write-Log -Type 'Verbose' -Text "Expand-Lockout`tCurrent event contains $($($CallerComputerInvestigation.UnauthorizedDevices_IAS | ?{$null -ne $_}).Count) non-null unauthorized IAS devices"
          Write-Log -Type 'Debug' -Text "Expand-Lockout`t`t$($CallerComputerInvestigation.UnauthorizedDevices_IAS | Format-List -Property * | Out-String)"
          
        }
        default{
          #If the CallerComputerName was not blank, investigate the CallerComputerName
          Write-Log -Type 'Verbose' -Text "Expand-Lockout`tSearch-LockoutComputer -User `"$($CurrentEvent.LockedAccountName)`" -ComputerName `"$($CurrentEvent.CallerComputerName)`" -Start `"$($CurrentEvent.TimeCreated.AddDays(-3))`" -End `"$($CurrentEvent.TimeCreated)`""
          
          $LockoutComputerSearchResult = Search-LockoutComputer -User "$($CurrentEvent.LockedAccountName)" -ComputerName "$($CurrentEvent.CallerComputerName)" -Start $CurrentEvent.TimeCreated.AddDays(-3) -End $CurrentEvent.TimeCreated
          $null = $CallerComputerInvestigation.Add($LockoutComputerSearchResult)
        }
      }

      #Add the results of the investigation to the current event object, then return the object
      $CurrentEvent | Add-Member -MemberType NoteProperty -Name CallerComputerInvestigation -Value $CallerComputerInvestigation -Force
      Write-Output $CurrentEvent
    }
  }
  end{}
}

function Get-Lockout {
  [CmdletBinding()]
  param(
    <#
    Name of the domain to search
    This will be passed to the Identity parameter of Get-AdDomain
    Default is the DNS Root of the current AD domain
    #>
    [String]$DomainName,

    #User whose lockouts to retrieve. ?What values to accept?
    [String[]]$User,

    <#
    User accounts that do not belong to an individual user.
    Lockouts of these accounts may represent an attempted security breach or a misconfiguration.
    Therefore we will notify the admininstrators but do not notify the user.
    #>
    [String[]]$SpecialUser = @("Administrator","admin","root"),
    
    <#
    Beginning of the date range to search in the text logs
    Defaults to 3 days prior to the $End parameter
    #>
    $Start,

    <#
    End of the date range to search in the text logs
    Defaults to the current date
    #>
    $End,

    #Number of account lockouts to retrieve. 0 means unlimited.
    [Int32]$Lockouts = 1
  )
  begin{
  
     
    Write-Progress -Activity "Finding Account Lockouts" -CurrentOperation "Collecting information about the Active Directory Domain" -Id 1 -ParentId 0 -PercentComplete 0
    Write-Log -Type 'Verbose' -Text "Get-Lockout`t[LockoutDomain]::New($DomainName)"
    $LockoutDomain = [LockoutDomain]::New($DomainName)

    #Collect the time zone of the PDC Emulator
    Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WMIObject -Class Win32_TimeZone -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`""
    $TimeZone = Get-WMIObject -Class Win32_TimeZone -ComputerName $LockoutDomain.ADDomain.PDCEmulator
    $TimeZoneName = ($TimeZone.__RELPATH -split '"')[1]
    Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WMIObject returned $TimeZoneName as the time zone on the PDC Emulator."

  }
  process{
    #Search for matching events with ID 4740 in the Security log on the PDC Emulator
    #Investigate the account lockout events in more detail
    if ([String]::IsNullOrEmpty($User) -or [String]::IsNullOrWhiteSpace($User)){
      if ($null -eq $Start){
        if ($null -eq $End){
          Write-Log -Type 'Debug' -Text "Get-Lockout`tNo user or date range was provided. Returning the single most recent acccount lockout event."
          Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WinEvent -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`" -FilterHashtable @{Logname='Security';Id=4740} -MaxEvents 1"
          $Events = Get-WinEvent -ComputerName $LockoutDomain.ADDomain.PDCEmulator -FilterHashtable @{Logname='Security';Id=4740} -MaxEvents 1 -Verbose:$false
          Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WinEvent returned $($Events.Count) results."
        }
        else{
          Write-Log -Type 'Debug' -Text "Get-Lockout`tOnly an end date was provided (no user or start date). Returning account lockout events that occurred prior to that time."
          $EndDate = Get-Date (Get-Date $End).ToUniversalTime() -Format s
          $XPath = "*[System[EventID=4740 and TimeCreated[@SystemTime <= '$EndDate']]]"
          Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WinEvent -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`" -LogName Security -FilterXPath $XPath"
          $Events = Get-WinEvent -ComputerName $LockoutDomain.ADDomain.PDCEmulator -LogName Security -FilterXPath $XPath -ErrorAction SilentlyContinue
          Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WinEvent returned $($Events.Count) results."
        }
      }
      else{
        $StartDate = Get-Date (Get-Date $Start).ToUniversalTime() -Format s
        if ($null -eq $End){
          Write-Log -Type 'Debug' -Text "Get-Lockout`tOnly a start date was provided (no user or end date). Returning account lockout events that occurred after that time."
          $XPath = "*[System[EventID=4740 and TimeCreated[@SystemTime >= '$StartDate']]]"
          Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WinEvent -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`" -LogName Security -FilterXPath `"$XPath`""
          $Events = Get-WinEvent -ComputerName $LockoutDomain.ADDomain.PDCEmulator -LogName Security -FilterXPath $XPath -ErrorAction SilentlyContinue
          Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WinEvent returned $($Events.Count) results."
        }
        else{
          Write-Log -Type 'Debug' -Text "Get-Lockout`tA date range was provided, but no user was. Returning account lockout events from that period."
          $EndDate = Get-Date (Get-Date $End).ToUniversalTime() -Format s
          $XPath = "*[System[EventID=4740 and TimeCreated[@SystemTime <= '$EndDate' and @SystemTime >= '$StartDate']]]"
          Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WinEvent -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`" -LogName Security -FilterXPath `"$XPath`""
          $Events = Get-WinEvent -ComputerName $LockoutDomain.ADDomain.PDCEmulator -LogName Security -FilterXPath $XPath -ErrorAction SilentlyContinue
          Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WinEvent returned $($Events.Count) results."
        }
      }
    }
    else{
      Write-Log -Type 'Debug' -Text "Get-Lockout`t$($User.Count) users provided. Retrieving all account lockout events so they can be filtered by user."
      $XPath = "*[System[EventID=4740] and EventData[Data[@Name = 'TargetUserName'] and Data = '$User']]"
      Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WinEvent -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`" -LogName Security -FilterXPath `"$XPath`""
      $Events = Get-WinEvent -ComputerName $LockoutDomain.ADDomain.PDCEmulator -LogName Security -FilterXPath $XPath -ErrorAction SilentlyContinue
      Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WinEvent returned $($Events.Count) results."
    }

    If($Events.Count -gt 0){
      $Events | Add-Member -MemberType NoteProperty -Name LockoutDomain -Value $LockoutDomain -Force
      $Events | Add-Member -MemberType NoteProperty -Name TimeZone -Value $TimeZoneName -Force
      $Events = $Events | Expand-Lockout -LockoutDomain $LockoutDomain
      $Users = $Events.LockedAccountName | Sort-Object -Unique
    }
    Else{

      #Find the oldest event in the Security log on the PDC Emulator
      #Any lockouts prior to this event are no longer in the log
      Write-Log -Type 'Verbose' -Text "Get-Lockout`tGet-WinEvent -ComputerName `"$($LockoutDomain.ADDomain.PDCEmulator)`" -LogName `"Security`" -MaxEvents 1 -Oldest"
      $oldest = Get-WinEvent -ComputerName $LockoutDomain.ADDomain.PDCEmulator -LogName "Security" -MaxEvents 1 -Oldest
      Write-Log -Type 'Debug' -Text "Get-Lockout`tGet-WinEvent returned $($oldest.TimeCreated) as the oldest event in the Security log on the PDC emulator."

      Write-Log -Type 'Verbose' -Text "Get-Lockout`tNo matching account lockout event was found. This could indicate that the lockouts occured prior to $($oldest.TimeCreated) (the oldest event in the Security log on the PDC emulator)."

    }

  }
  end{

    Write-Output $Events

  }
}

function Save-Lockout {
  [CmdletBinding()]
  param(
    #The account lockout event, generated by Get-Lockout
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ValueFromPipeline
    )]
    [AllowNull()]
    $Event,

    #SMTP server to use to send the notification e-mails
    [String]$MailServer,

    #SMTP address to use as the Sender of the notification e-mails. Default is DoNotReply@DoNotReply.com
    [String]$MailSender = 'DoNotReply@DoNotReply.com',

    #SMTP addresses to send the notification e-mails to
    [String[]]$MailRecipient,

    #Whether or not to send the report to the user who was locked out
    [Boolean]$NotifyUser = $false,

    <#
    User accounts that do not belong to an individual user.
    These lockouts may represent an attempted security breach or a misconfiguration.
    Notify the admininstrators but do not notify the user.
    #>
    [String[]]$SpecialUser = @("Administrator","admin","root"),

    #The root folder to output the reports into
    [String]$ReportOutputPath = $PSScriptRoot
  )
  begin{
    Import-Module "$PSScriptRoot\UncPath.psm1" -Verbose:$false

    #Convert the report output path to a UNC path
    $OutputPath = New-UncPath -Path $ReportOutputPath


    <# While creating directories, New-Item is subject to a limit on the length of characters in a UNC path.
    In order to work with a shorter path, we will create a new PSDrive to use #>
    $ReportOutputDrive = New-PSDrive -Name 'ReportOutputDrive' -PSProvider 'FileSystem' -Root $OutputPath -Scope Global
  }
  process{

    ForEach ($CurrentEvent in $Event){

      #Create one folder per user
      [String]$UserFolder = $CurrentEvent.LockedAccountName.Replace('.','-')
      [String]$UserFolderPath = "ReportOutputDrive:\$UserFolder"
      $null = New-Item -Path $UserFolderPath -Type Directory -ErrorAction SilentlyContinue

      #Create one folder per account lockout
      [String]$CurrentEventFolder = ($CurrentEvent.TimeCreated | Get-Date -Format s).Replace(':','-')
      [String]$CurrentEventFolderPath = "$UserFolderPath\$CurrentEventFolder"
      Write-Log -Type 'Debug' -Text "Save-Lockout`tRemove-Item -Path $CurrentEventFolderPath -Force -Confirm:$false -Recurse -ErrorAction SilentlyContinue"
      $null = Remove-Item -Path $CurrentEventFolderPath -Force -Confirm:$false -Recurse -ErrorAction SilentlyContinue
      Write-Log -Type 'Debug' -Text "Save-Lockout`tNew-Item -Path $CurrentEventFolderPath -Type Directory -ErrorAction SilentlyContinue"
      $null = New-Item -Path $CurrentEventFolderPath -Type Directory -ErrorAction SilentlyContinue

      #Create a folder for logs
      [String]$LogPath = "$CurrentEventFolderPath\Logs"
      Write-Log -Type 'Debug' -Text "Save-Lockout`tNew-Item -Path $LogPath -Type Directory -ErrorAction SilentlyContinue"
      $null = New-Item -Path $LogPath -Type Directory -ErrorAction SilentlyContinue

      #Create a folder for Windows logs
      [String]$WindowsLogPath = "$LogPath\Windows"
      Write-Log -Type 'Debug' -Text "Save-Lockout`tNew-Item -Path $WindowsLogPath -Type Directory -ErrorAction SilentlyContinue"
      $null = New-Item -Path $WindowsLogPath -Type Directory -ErrorAction SilentlyContinue

      #Create a folder for the Windows logs from the PDC Emulator
      Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($CurrentEvent.LockoutDomain.ADDomain.PDCEmulator)`" -InvalidChars 46 -Replacement '-' -ReturnAsFileName $true"
      [String]$PDCFolderName = Remove-InvalidFileNameChars -Name $CurrentEvent.LockoutDomain.ADDomain.PDCEmulator -InvalidChars 46 -Replacement '-' -ReturnAsFileName $true
      Write-Log -Type 'Debug' -Text "Save-Lockout`tNew-Item -Path `"$WindowsLogPath`" -Name $PDCFolderName -Type Directory -ErrorAction SilentlyContinue"
      $null = New-Item -Path "$WindowsLogPath" -Name $PDCFolderName -Type Directory -ErrorAction SilentlyContinue

      #Title the report
      [String]$Title = 'Active Directory Account Lockout Report'

      #Construct the body of the HTML report
      [String[]]$ReportBody = @()

      #Build the HTML table for the Windows account lockout event
      $Props = @{Label="Locked Account Name";Expression={$_.LockedAccountName}},
        @{Label="Caller Computer Name";Expression={$_.CallerComputerName}},
        @{Label="Time Created";Expression={$_.TimeCreated}},
        @{Label="Time Zone";Expression={$_.TimeZone}},
        @{Label="Subject Account";Expression={"$($_.SubjectAccountDomain)\$($_.SubjectAccountName)"}},
        @{Label="Subject Logon ID";Expression={$_.SubjectLogonID}}
      $ReportBody += New-HtmlHeading -Level 3 -Text 'AD Account Lockout Events'
      $ReportBody += New-HtmlHeading -Level 5 -Text "Each account lockout generates an Event with ID 4740 in the Security log on the PDC Emulator ($($CurrentEvent.LockoutDomain.ADDomain.PDCEmulator)):"
      $ReportBody += $CurrentEvent | ConvertTo-Html -Property $Props -Fragment | New-BootstrapTable

      if ($CurrentEvent.CallerComputerName -eq ''){

        $ReportBody += New-HtmlHeading -Level 5 -Text 'The Caller Computer Name in the account lockout event was blank.'
        $ReportBody += New-HtmlHeading -Level 5 -Text 'The lockout was probably caused by an incorrect password via RADIUS (such as WiFi) or LDAP (such as a scanner).'
        $ReportBody += New-HtmlHeading -Level 5 -Text "The logs on known IAS/NPS/LDAP servers ($($CurrentEvent.CallerComputerInvestigation.ComputerName)) will be searched for the Locked Account Name ($($CurrentEvent.LockedAccountName))."

      }

      ForEach ($InvestigatedComputer in $CurrentEvent.CallerComputerInvestigation){
        if ($InvestigatedComputer.PSSessionFailure){
            $ReportBody += New-HtmlHeading -Level 5 -Text "A remote PSSession could not be established to $($InvestigatedComputer.ComputerName) so its logs could not be searched.."
        }
    }

      #Build the RADIUS section of the report
      $ReportBody += New-HtmlHeading -Level 3 -Text 'RADIUS Devices With Failed Authentication Attempts'

      if (($null -ne $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS) -or ($null -ne $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NPS)){

        Write-Log -Type 'Verbose' -Text "Save-Lockout`tCurrent Event contains $($($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS | Measure-Object).Count) unauthorized IAS devices"
        Write-Log -Type 'Verbose' -Text "Save-Lockout`tCurrent Event contains $($($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NPS | Measure-Object).Count) unauthorized NPS devices"

        $Devices = @()

        #Format the NPS log devices
        $Props = @{Label="RADIUS Computer Name";Expression={$($_.MatchingLogs.'npsComputerName' | Sort-Object -Unique)}},
          @{Label="Client Friendly Name";Expression={$($_.MatchingLogs.'npsClientFriendlyName' | Sort-Object -Unique)}},
          @{Label="Client IP Address";Expression={$($_.MatchingLogs.'npsClientIPAddress' | Sort-Object -Unique)}},
          @{Label="Server IP Address";Expression={$($_.MatchingLogs.'npsNASIPAddress' | Sort-Object -Unique)}},
          @{Label="Reason Code";Expression={$($_.MatchingLogs.'iasRadiusReason-Code_Name' | Sort-Object -Unique)}},
          @{Label="Occurences";Expression={$(($_.MatchingLogs | Measure-Object).Count | Sort-Object -Unique)}}

        $Devices += $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NPS | Select-Object -Property $Props

        #Format the IAS log devices
        $Props = @{Label="RADIUS Computer Name";Expression={$($_.MatchingLogs.'iasComputer-Name' | Sort-Object -Unique)}},
          @{Label="Client Friendly Name";Expression={$($_.MatchingLogs.'iasRadiusClient-Friendly-Name' | Sort-Object -Unique)}},
          @{Label="Client IP Address";Expression={$($_.MatchingLogs.'iasRadiusClient-IP-Address' | Sort-Object -Unique)}},
          @{Label="Server IP Address";Expression={$($_.MatchingLogs.'iasNAS-IP-Address' | Sort-Object -Unique)}},
          @{Label="Reason Code";Expression={$($_.MatchingLogs.'iasRadiusReason-Code_Name' | Sort-Object -Unique)}},
          @{Label="Occurences";Expression={$(($_.MatchingLogs | Measure-Object).Count | Sort-Object -Unique)}}

        $Devices += $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS | Select-Object -Property $Props

        $ReportBody += New-HtmlHeading -Level 5 -Text "$($Devices.Count) devices with failed RADIUS authentication were found (the Reason-Code was 16 [IAS_AUTH_FAILURE])."

        #Build the HTML table for the RADIUS log devices
        $ReportBody += $Devices | ConvertTo-Html -Fragment | New-BootstrapTable

        #Create a folder for the RADIUS logs
        [String]$RADIUSFolderPath = "$LogPath\RADIUS"
        Write-Log -Type 'Debug' -Text "Save-Lockout`tNew-Item -Path $RADIUSFolderPath -Type Directory -ErrorAction SilentlyContinue"
        $null = New-Item -Path $RADIUSFolderPath -Type Directory -ErrorAction SilentlyContinue

        #Save the original IAS log lines to file
        ForEach ($LogItem in $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS.MatchingLogs) {
          if ($null -ne $LogItem){

            #Write-Log -Type 'Debug' -Text "Save-Lockout`t$($LogItem | Format-List  * | Out-String)"

            #Create one folder per computer with IAS log events for unauthorized connections
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogComputer)`" -InvalidChars 46 -Replacement '-'"
            [String]$IasComputerFolderName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogComputer)" -InvalidChars 46 -Replacement '-'

            Write-Log -Type 'Verbose' -Text "Save-Lockout`tNew-Item -Path `"$RADIUSFolderPath`" -Name `"$IasComputerFolderName`" -Type Directory -ErrorAction SilentlyContinue"
            $null = New-Item -Path "$RADIUSFolderPath" -Name "$IasComputerFolderName" -Type Directory -ErrorAction SilentlyContinue

            #Save the log lines to file
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogFile)`" -Replacement '_' -ReturnAsFileName $true"
            $FileName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogFile)" -Replacement '_' -ReturnAsFileName $true
            
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tOut-File -Append -LiteralPath `"$RADIUSFolderPath\$IasComputerFolderName\$FileName`""
            $LogItem.SourceLogLine.Line | Out-File -Append -LiteralPath "$RADIUSFolderPath\$IasComputerFolderName\$FileName"

          }

        }
        
        #Export the IAS log events to CSV
        try{

          #Write-Log -Type 'Debug' -Text "Save-Lockout`tDrives inside try-catch: $((Get-PSDrive).Name -join ' ')"
          Write-Log -Type 'Verbose' -Text "Save-Lockout`tExporting IAS logs for $($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS.Count) unauthorized devices to CSV"
          Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject -Object `$CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS.MatchingLogs -LiteralPath `"$RADIUSFolderPath\IAS-Logs_Unauthorized.csv`""
          Export-UnlikeObject -Object $($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IAS.MatchingLogs) -LiteralPath "$RADIUSFolderPath\IAS-Logs_Unauthorized.csv"

        }
        catch [System.Management.Automation.RuntimeException]{
          Switch ($_.Exception.Message){
            "Cannot bind argument to parameter 'LiteralPath' because it is an empty string."{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tError: No file path provided. CSV file not created"
            }
            "Cannot bind argument to parameter 'Object' because it is null."{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tNo unauthorized IAS devices were found."
            }
            default{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tERROR! Unhandled Exception: $_"
            }

          }

        }
        
        #Save the original NPS log lines to file
        ForEach ($LogItem in $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NPS.MatchingLogs) {
          if ($null -ne $LogItem){
          
            #Create one folder per computer with log events for unauthorized connections
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogComputer)`" -InvalidChars 46 -Replacement '-'"
            [String]$ComputerFolderName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogComputer)" -InvalidChars 46 -Replacement '-'
                        Write-Log -Type 'Verbose' -Text "Save-Lockout`tNew-Item -Path `"$RADIUSFolderPath`" -Name `"$ComputerFolderName`" -Type Directory -ErrorAction SilentlyContinue"
            $null = New-Item -Path "$RADIUSFolderPath" -Name "$ComputerFolderName" -Type Directory -ErrorAction SilentlyContinue
            
            #Save the log lines to file
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogFile)`" -Replacement '_' -ReturnAsFileName $true"
            $FileName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogFile)" -Replacement '_' -ReturnAsFileName $true
            
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tOut-File -Append -LiteralPath `"$RADIUSFolderPath\$ComputerFolderName\$FileName`""
            $LogItem.SourceLogLine.Line | Out-File -Append -LiteralPath "$RADIUSFolderPath\$ComputerFolderName\$FileName"

          }

        }
        
        #Export the NPS log events to CSV
        try{
         
         $CsvPath = "$RADIUSFolderPath\NPS-Logs_Unauthorized.csv"
          Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject -Object `$CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NPS.MatchingLogs -LiteralPath `"$CsvPath`""
          Export-UnlikeObject -Object $($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NPS.MatchingLogs) -LiteralPath $CsvPath

        }
        catch [System.Management.Automation.RuntimeException]{

          Switch ($_.Exception.Message){

            "Cannot bind argument to parameter 'LiteralPath' because it is an empty string."{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tError: No file path provided. CSV file not created"
            }

            "Cannot bind argument to parameter 'Object' because it is null."{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tNo unauthorized NPS devices were found."
            }

            default{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tERROR! Unhandled Exception: $_"
            }

          }

        }

      }
      else{
        $ReportBody += New-HtmlHeading -Level 5 -Text "No failed RADIUS authentication events for $($CurrentEvent.LockedAccountName) were found in the logs on $($CurrentEvent.CallerComputerInvestigation.ComputerName)."
      }

      #Build the IIS section of the report
      $ReportBody += New-HtmlHeading -Level 3 -Text 'IIS Devices With Failed Authentication Attempts'

      if ($null -ne $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS){
      
          if ($CurrentEvent.CallerComputerInvestigation.IsExchangeCAS -eq $true){

              $ReportBody += New-HtmlHeading -Level 5 -Text "$($CurrentEvent.CallerComputerName) is an Exchange Client Access Server."
              $ReportBody += New-HtmlHeading -Level 5 -Text  "The lockout was probably caused by an incorrect password in Outlook, Outlook Web App, or an ActiveSync device such as a cell phone/tablet."

          }

          #Build the HTML table for the IIS W3C log devices
          $Props = @{Label="Type";Expression={$_.DeviceType}},
              @{Label="Model";Expression={$_.DeviceModel}},
              @{Label="Friendly Name";Expression={$_.DeviceFriendlyName}},
              @{Label="Operating System";Expression={$_.DeviceOS}},
              @{Label="User Agent";Expression={$_.DeviceUserAgent}},
              @{Label="Last Successful Sync";Expression={$_.LastSuccessSync}}
          $Count = ($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS | Measure-Object).Count
          $Text = "$Count devices with failed authentication attempts (HTTP 401/unauthorized) were found in the IIS logs on $($CurrentEvent.CallerComputerInvestigation.ComputerName)."
          $ReportBody += New-HtmlHeading -Level 5 -Text $Text

              $CombinedDevices = @()
              $CombinedDevices += $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS.MatchingActiveSyncDevices
              $CombinedDevices += $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS
              $CombinedDevices = $CombinedDevices | Sort-Object -Property DeviceUserAgent -Unique
              $DeviceTable = $CombinedDevices | ConvertTo-Html -Property $Props -Fragment
              $DeviceTable = $DeviceTable | New-BootstrapTable
              $ReportBody += $DeviceTable
                
          #Create a folder for the IIS W3C logs
          [String]$IISFolderPath = "$LogPath\IIS"
          $null = New-Item -Path $IISFolderPath -Type Directory -ErrorAction SilentlyContinue

          ForEach ($LogItem in $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS.MatchingLogs) {
              if ($null -ne $LogItem){

                  #Create one folder per computer with IIS W3C log events for unauthorized connections
                  Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogComputer)`" -InvalidChars 46 -Replacement '-'"
                  [String]$IISComputerFolderName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogComputer)" -InvalidChars 46 -Replacement '-'
                  Write-Log -Type 'Verbose' -Text "Save-Lockout`tNew-Item -Path `"$IISFolderPath`" -Name `"$IISComputerFolderName`" -Type Directory -ErrorAction SilentlyContinue"
                  $null = New-Item -Path "$IISFolderPath" -Name "$IISComputerFolderName" -Type Directory -ErrorAction SilentlyContinue

                  #Save the original IIS W3C log lines to file
                  Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogFile)`" -Replacement '_' -ReturnAsFileName $true"
                  $FileName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogFile)" -Replacement '_' -ReturnAsFileName $true
                  
                  Write-Log -Type 'Verbose' -Text "Save-Lockout`tOut-File -Append -LiteralPath `"$IISFolderPath\$IISComputerFolderName\$FileName`""
                  $LogItem.SourceLogLine.Line | Out-File -Append -LiteralPath "$IISFolderPath\$IISComputerFolderName\$FileName"
              }
          }

          #Export the IIS W3C log events to CSV
          try{

              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject -Objects `$CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS.UnauthorizedIisW3CLogs -LiteralPath `"$IISFolderPath\IIS-W3C-Logs_Unauthorized.csv`""

              Export-UnlikeObject -Object $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_IIS.MatchingLogs -LiteralPath "$IISFolderPath\IIS-W3C-Logs_Unauthorized.csv"

          }
          catch [System.Management.Automation.RuntimeException]{
              Switch ($_.Exception.Message){
                  "Cannot bind argument to parameter 'LiteralPath' because it is an empty string."{
                    Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tError: No file path provided. CSV file not created"
                  }
                  "Cannot bind argument to parameter 'Object' because it is null."{
                    Write-Log -Type 'Verbose' -Text "Save-Lockout`tNo matching IIS W3C log events were found."
                  }
                  default{
                    Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tERROR! Unhandled Exception: $_"
                  }
              }
          }

      }
      else{
        $ReportBody += New-HtmlHeading -Level 5 -Text "No failed IIS authentication events for $($CurrentEvent.LockedAccountName) were found in the logs on $($CurrentEvent.CallerComputerInvestigation.ComputerName)."
      }

      #Build the NetLogon section of the report
      $ReportBody += New-HtmlHeading -Level 3 -Text 'NetLogon Devices With Failed Authentication Attempts'
      if ($null -ne $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon){

        #Write-Log -Type 'Debug' -Text "Save-Lockout`t$($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon | fl * | Out-String)"))

        <#
        TO DO: Determine if it is a DC
        if ($CurrentEvent.CallerComputerInvestigation.IsDomainController -eq $true){
            $ReportBody += New-HtmlHeading -Level 5 -Text `
              "$($CurrentEvent.CallerComputerName) is a Domain Controller."
        }
        #>

        #Build the HTML table for the NetLogon log devices  
        $Props = @{Label="Logs From";Expression={($_.MatchingLogs.SourceLogComputer | Sort-Object -Unique) -Join ','}},
          @{Label="Computer";Expression={($_.MatchingLogs.NetLogonSourceComputer | Sort-Object -Unique) -Join ','}},
          @{Label="Type";Expression={($_.MatchingLogs.NetLogonType | Sort-Object -Unique) -Join ','}},
          @{Label="Component";Expression={($_.MatchingLogs.NetLogonComponent | Sort-Object -Unique) -Join ','}},
          @{Label="Description";Expression={($_.MatchingLogs.NetLogonDescription | Sort-Object -Unique) -Join ','}},
          @{Label="Relay Computer";Expression={($_.MatchingLogs.NetLogonRelayComputer | Sort-Object -Unique) -Join ','}},
          @{Label="Result";Expression={($_.MatchingLogs.NetLogonResult | Sort-Object -Unique) -Join ','}},
          @{Label="Status";Expression={($_.MatchingLogs.NetLogonResultStatus | Sort-Object -Unique) -Join ','}},
          @{Label="Occurences";Expression={$((($_.MatchingLogs | Measure-Object).Count | Sort-Object -Unique) -Join ',')}}
          $Count = ($CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon | Measure-Object).Count
          $Text = "$Count devices with failed NetLogon authentication attempts were found in the logs on $($CurrentEvent.CallerComputerInvestigation.ComputerName)."
        $ReportBody += New-HtmlHeading -Level 5 -Text $Text
        $Html = $null
        $Html = $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon | ConvertTo-Html -Property $Props -Fragment
        $Table = $Html | New-BootstrapTable
        $ReportBody += $Table

        #Create a folder for the NetLogon logs
        [String]$NetLogonFolderPath = "$LogPath\NetLogon"
        $null = New-Item -Path $NetLogonFolderPath -Type Directory -ErrorAction SilentlyContinue

        ForEach ($LogItem in $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon.MatchingLogs) {

          if ($null -ne $LogItem){
          
            #Create one folder per computer with NetLogon log events for unauthorized connections
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogComputer)`" -InvalidChars 46 -Replacement '-'"
            [String]$NetLogonComputerFolderName = Remove-InvalidFileNameChars -Name `
              "$($LogItem.SourceLogComputer)" -InvalidChars 46 -Replacement '-'
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tNew-Item -Path `"$IISFolderPath`" -Name `"$NetLogonComputerFolderName`" -Type Directory -ErrorAction SilentlyContinue"

            $Params = $null
            $Params = @{
              Path = "$NetLogonFolderPath"
              Name = "$NetLogonComputerFolderName"
              Type = 'Directory'
              ErrorAction = 'SilentlyContinue'
            }
            $null = New-Item @Params
              

            #Save the original NetLogon log lines to file
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tRemove-InvalidFileNameChars -Name `"$($LogItem.SourceLogFile)`" -Replacement '_' -ReturnAsFileName $true"
            $FileName = Remove-InvalidFileNameChars -Name "$($LogItem.SourceLogFile)" -Replacement '_' -ReturnAsFileName $true
            Write-Log -Type 'Verbose' -Text "Save-Lockout`tOut-File -Append -LiteralPath `"$NetLogonFolderPath\$NetLogonComputerFolderName\$FileName`""
            $LogItem.SourceLogLine.Line | Out-File -Append -LiteralPath "$NetLogonFolderPath\$NetLogonComputerFolderName\$FileName"

          }
        }

        #Export the NetLogon log events to CSV
        try{
          
          $Params = $null
          $Params = @{
            Object = $CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon.MatchingLogs
            LiteralPath = "$NetLogonFolderPath\NetLogon-Logs_Unauthorized.csv"
          }
          Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject -Objects `$CurrentEvent.CallerComputerInvestigation.UnauthorizedDevices_NetLogon.MatchingLogs -LiteralPath `"$NetLogonFolderPath\NetLogon-Logs_Unauthorized.csv`""
          Export-UnlikeObject @Params

        }
        catch [System.Management.Automation.RuntimeException]{

          Switch ($_.Exception.Message){
            "Cannot bind argument to parameter 'LiteralPath' because it is an empty string."{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tError: No file path provided. CSV file not created"
            }
            "Cannot bind argument to parameter 'Object' because it is null."{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tNo matching NetLogon log events were found."
            }
            default{
              Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-UnlikeObject`tERROR! Unhandled Exception: $_"
            }

          }

        }

      }
      else {
        $ReportBody += New-HtmlHeading -Level 5 -Text "No events for failed authentication for $($CurrentEvent.LockedAccountName) were found in the NetLogon logs on $($CurrentEvent.CallerComputerInvestigation.ComputerName)."
      }

      #Assemble the complete HTML report
      $Params = $null
      $Params = @{
        Title = $Title
        Description = 'The accounts below were locked due to an excessive number of logon attempts with incorrect passwords.'
        Body = $ReportBody
      }
      $Report = New-BootstrapReport @Params

      #If the NotifyUser option was used, and the user is not a special account such as a service account, add the user to the list of mail recipients.
      if ($SpecialUser -notcontains "*$($Event.LockedAccountName)*"){

        Write-Log -Type 'Debug' -Text "Save-Lockout`tThe user is not an administrative/service/non-interactive account, so they are eligible for notification."
        if ($NotifyUser -eq $True){
          Write-Log -Type 'Debug' -Text "Save-Lockout`tThe -NotifyUser switch was used, so the user ($($CurrentEvent.Mail)) will be notified that their account was locked."
          $MailRecipients += $CurrentEvent.LockedAccountEmail
        }else{
          Write-Log -Type 'Debug' -Text "Save-Lockout`tThe -NotifyUser switch was not used, so the user won't be notified that their account was locked."
        }

      }
      else{

        Write-Log -Type 'Debug' -Text "Save-Lockout`tThe user is an administrative/service/non-interactive account, so it is ineligible for notification. Only the e-mail addresses provided to the -MailRecipients parameter will be notified."

      }

      #Email the report
      try{

        Write-Log -Type 'Verbose' -Text "Save-Lockout`tSend-MailMessage -SmtpServer `"$MailServer`" -To @('$($MailRecipient -join "','")') -From `"$MailSender`" -Subject `"$Title`" -Body `"`$(`$Report | Out-String)`" -BodyAsHtml -Priority high"
        Send-MailMessage -SmtpServer "$MailServer" -To $MailRecipient -From "$MailSender" -Subject "$Title" -Body "$($Report | Out-String)" -BodyAsHtml -Priority high

      }catch{

        Write-Log -Type 'Debug' -Text "Save-Lockout`tSend-MailMessage error: $($_.Exception.Message)"

      }

      #Save the report to a file
      Write-Log -Type 'Verbose' -Text "Save-Lockout`tOut-File -LiteralPath `"$CurrentEventFolderPath\LockoutSummary.htm`""

      $Report | Out-File -LiteralPath "$CurrentEventFolderPath\LockoutSummary.htm"

      #Export the actual account lockout event to a .EVTX file
      [String]$PDCWindowsLogPath = "$WindowsLogPath\$PDCFolderName"
      $UtcTime = $CurrentEvent.TimeCreated.ToUniversalTime()
      $StartTime = $UtcTime.AddSeconds(-1)
      $EndTime = $UtcTime.AddSeconds(1)
      $NonPsDrivePath = $PDCWindowsLogPath -replace 'ReportOutputDrive:',"$OutputPath"

      Write-Log -Type 'Verbose' -Text "Save-Lockout`tExport-EventLog -Path 'Security' -Computer `"$($CurrentEvent.LockoutDomain.ADDomain.PDCEmulator)`" -Start `"$StartTime`" -End `"$EndTime`" -EventDataData `"$($CurrentEvent.LockedAccountName)`" -EventId 4740 -targetFilePath `"$NonPsDrivePath\Security.evtx`""

      $Params = $null
      $Params = @{
          Path = 'Security'
          Computer = "$($CurrentEvent.LockoutDomain.ADDomain.PDCEmulator)"
          Start = $StartTime
          End = $EndTime
          EventDataData = "$($CurrentEvent.LockedAccountName)"
          EventId = 4740,4625
          targetFilePath = "$NonPsDrivePath\Security.evtx"
      }
      $ExportResult = Export-EventLog @Params

      ForEach ($Result in $ExportResult){
          Write-Log -Type 'Verbose' -Text $Result
      }

    }
  }
  end{
    Remove-PSDrive -Name 'ReportOutputDrive'
  }
}

function Search-LockoutComputer {
  param(

    #The user who was locked out by this computer
    [String]$User,

    #The name of the computer to search for causes of the account lockout
    [String[]]$ComputerName = @('localhost'),

    <#
    Beginning of the date range to search in the text logs
    Defaults to 3 days prior to the $End parameter
    #>
    $Start,

    <#
    End of the date range to search in the text logs
    Defaults to the current date
    #>
    $End,

    <#
    The log formats to search
    Valid values are 'IAS-or-NPS' or 'IIS-W3C' or 'NetLogon'
    #>
    [String[]]$TextLogFormat = @('IAS-or-NPS','IIS-W3C','NetLogon')

  )
  begin{

    if ($null -eq $End){

      $End = Get-Date

    }

    if ($null -eq $Start){

      $Start = $End.AddDays(-3)

    }

    Import-Module "$PSScriptRoot\GadgetExchange.psm1" -WarningAction SilentlyContinue -Verbose:$false
    [PSObject[]]$ExchangeClientAccessServers = Get-ADExchangeServer | Where-Object -FilterScript {$_.Roles -contains 'CAS'}

  }
  process{

    ForEach ($Computer in $ComputerName){

        try{
            Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tNew-PSSession -ComputerName `"$Computer`""
            $PSSession = New-PSSession -ComputerName $Computer -ErrorAction Stop
        }
        catch{
            $ErrorMessage = $_.Exception.Message
            Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tCould not establish a remote PSSession to $Computer. $ErrorMessage"
        }

        if ($PSSession) {
        
          #Enumerate the log files to search
          $params = @{
            ComputerName = $Computer
            LogFormat = $TextLogFormat
            Start = $Start
            End = $End
            PSSession = $PSSession
          }
          Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tGet-TextLog -ComputerName `"$Computer`" -LogFormat @('$($TextLogFormat -join "','")') -Start `"$Start`" -End `"$End`" -PSSession `$PSSession"
          $LogsAfterStartDate = Get-TextLog @params
          Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLog returned $($LogsAfterStartDate.Count) log files"
          Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLog returned $($LogsAfterStartDate | fl * | Out-String) log files"

          #Search the enumerated log files files
          $params = @{
            ComputerName = $Computer
            LogFile = $LogsAfterStartDate
            StringToFind = $User
            PSSession = $PSSession
          }
          Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tSearch-TextLog -ComputerName `"$ComputerName`" -LogFile `$LogsAfterStartDate -StringToFind `"$User`" -PSSession `$PSSession"
          $LogSearchResults = Search-TextLog @params
          Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tSearch-TextLog returned $($LogSearchResults.Count) log lines from $Computer"

          #Convert the search results into usable objects
          Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tConvertFrom-TextLog -LogLines `$LogSearchResults"
          $ProcessedLogObjects = ConvertFrom-TextLog -LogLines $LogSearchResults
          Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tConvertFrom-TextLog returned $($ProcessedLogObjects.Count) objects from $Computer"
          
          #Try to identify the actual devices causing the account lockouts
          $params = @{
            InputObject = $ProcessedLogObjects
            Filter = 'Unauthorized'
            User = $User
          }
          Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tGet-TextLogDevice -InputObject `$ProcessedLogObjects -Filter 'Unauthorized' -User '$User'"
          $TextLogDevices = Get-TextLogDevice @params
          Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLogDevice returned $(($TextLogDevices | Measure-Object).Count) devices from $Computer"

        }

      #If the computer is an IIS server, note that.  Also check to see if it is an Exchange Client Access server, and note that.
      Write-Log -Type 'Verbose' -Text "Search-LockoutComputer`tGet-WindowsFeature -ComputerName '$Computer' -Name 'Web-Server'"
      $WindowsFeatures = Get-WindowsFeature -ComputerName "$Computer" -Name 'Web-Server' -ErrorAction SilentlyContinue -Verbose:$false -Debug:$false
      if ($WindowsFeatures.Installed -eq $True) {
          [Boolean]$WebServer = $true
          if ($ExchangeClientAccessServers | Where-Object -FilterScript {$_.FQDN -like "*$Computer*"}){
              [Boolean]$ExchangeCAS = $true
          }
          else{
              [Boolean]$ExchangeCAS = $false
          }
      }
      else{
          [Boolean]$WebServer = $false
      }

      Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLogDevice returned $($TextLogDevices.IISW3CObjects.Count) unauthorized IIS devices"
      Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLogDevice returned $($TextLogDevices.IASObjects.Count) unauthorized IAS devices"
      Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLogDevice returned $($TextLogDevices.NetLogonObjects.Count) unauthorized NetLogon devices"
      Write-Log -Type 'Debug' -Text "Search-LockoutComputer`tGet-TextLogDevice returned $($TextLogDevices.NPSObjects.Count) unauthorized NPS devices"

      #What events to find in event log?
      #LDAP logs?
      #Scheduled tasks
      #Services
      #Credential Manager (if possible)

      $CallerComputerInvestigation = New-Object -TypeName PSObject -Prop @{
          'ComputerName' = $ComputerName
          'IsWebServer' = $WebServer
          'IsIAS' = $IAS
          'IsExchangeCAS' = $ExchangeCAS
          'UnauthorizedDevices_IIS' = $TextLogDevices.IISW3CObjects | Where-Object {$null -ne $_}
          'UnauthorizedDevices_IAS' = $TextLogDevices.IASObjects | Where-Object {$null -ne $_}
          'UnauthorizedDevices_NetLogon' = $TextLogDevices.NetLogonObjects | Where-Object {$null -ne $_}
          'UnauthorizedDevices_NPS' = $TextLogDevices.NPSObjects | Where-Object {$null -ne $_}
          'PSSessionFailure' = !([Boolean]$PSSession)
      }
      Write-Output $CallerComputerInvestigation

      $PSSession | Remove-PSSession -ErrorAction SilentlyContinue
    }
  }
  end{}
}

Class LockoutDomain {
  $ADDomain
  $ADDomainControllers
  $RASandIASServers

  LockoutDomain([String]$DomainName){

    #Load the ActiveDirectory PowerShell module for the AD DS Cmdlets that are used in this script.
    #Import-Module ActiveDirectory -Cmdlet Get-AdDomain -Verbose:$false

    #Collect information on the specified domain, or on the current domain if none was specified.
    try{
      if(($null -eq $DomainName) -or ("" -eq $DomainName)){
        Write-Log -Type 'Verbose' -Text "[LockoutDomain]::New($DomainName)`tGet-ADDomain"
        $this.ADDomain = Get-ADDomain -ErrorAction Stop
      }else{
        Write-Log -Type 'Verbose' -Text "[LockoutDomain]::New($DomainName)`tGet-ADDomain -Identity `"$DomainName`" -Server `"$DomainName`" -ErrorAction Stop"
        $this.ADDomain = Get-ADDomain -Identity $DomainName -Server $DomainName -ErrorAction Stop
      }
    }
    catch{
      Write-Log -Type 'Verbose' -Text "[LockoutDomain]::New($DomainName)`tGet-ADDomain error: $($_.Exception.Message )"
      Break
    }

    #Collect information on the domain controllers in the domain
    Write-Log -Type 'Verbose' -Text "[LockoutDomain]::New($DomainName)`tGet-ADDomainController -Filter * -Server `"$($this.ADDomain.PDCEmulator)`""
    $this.ADDomainControllers = Get-ADDomainController -Filter * -Server $($this.ADDomain.PDCEmulator)

    #Collect information on the RAS and IAS servers in the domain
    # https://technet.microsoft.com/en-us/library/dn579255(v=ws.11).aspx#BKMK_RASandIAS
    Write-Log -Type 'Verbose' -Text "[LockoutDomain]::New($DomainName)`tGet-ADGroupMember -Identity 'RAS and IAS Servers' -Server `"$($this.ADDomain.PDCEmulator)`""
    $this.RASandIASServers = Get-ADGroupMember -Identity 'RAS and IAS Servers' -Server $($this.ADDomain.PDCEmulator)

  }

}

Class Lockout {

  [String]$DomainName
  [String]$User
  [System.Diagnostics.Eventing.Reader.EventLogRecord]$EventLogRecord
  [String]$LockedAccountName
  [String]$CallerComputerName
  [String]$LockedAccountSID
  [String]$SubjectSID
  [String]$SubjectAccountName
  [String]$SubjectAccountDomain
  [String]$SubjectLogonID



}

Class LockoutUser {
  $ADUser
  [LockoutDomain]$LockoutDomain
  [Lockout[]]$Lockouts
  $WindowsEvents
  $FailedAuthDevices

  LockoutUser (){

  }
}


    <#
    #Originally I was going to use this to discover the DCs in remote domains
    #The problem is that it throws an error and returns nothing if there are artifacts in AD from old DCs that no longer have valid DNS A Records
    $Context = new-object 'System.DirectoryServices.ActiveDirectory.DirectoryContext'("domain", $this.ADDomain.DNSRoot )
    [System.DirectoryServices.ActiveDirectory.DomainController]::FindAll($Context)
    #>
