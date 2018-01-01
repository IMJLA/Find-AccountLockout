<#
  .SYNOPSIS
    Collects information about Active Directory account lockouts and their causes.
  .DESCRIPTION
    Use 1 - Run this script manually to search for lockouts by user
    Use 2 - Set this script as a scheduled task on the PDC Emulator to run when an account lockout event (EventID 4740) is logged in the Security log.

    The script can notify the user and IT of the lockout and the source. This is for security as well as fixing the cause of unintentional lockouts.
  .OUTPUTS
    No output is returned to the shell. Instead the HTML report is e-mailed and saved to file. A CSV of the matching events from IIS logs is also saved to file.
  .EXAMPLE
    .\Find-AccountLockout.ps1
    This example saves an HTML report for the single most recent account lockout.
    The report is saved in the same folder where the script is saved.

  .EXAMPLE
    .\Find-AccountLockout.ps1 -User 'john.doe'
    This example saves an HTML report for each account lockout found for the user john.doe.
    The report is saved in the same folder where the script is saved.

  .EXAMPLE
    .\Find-AccountLockout.ps1 -Start ((Get-Date).AddDays(-1)) -End (Get-Date)
    This example saves an HTML report for each lockout that occurred in the past 24 hours.
    The report is saved in the same folder where the script is saved.

  .EXAMPLE
    .\Find-AccountLockout.ps1 -MailServer 'smtp.contoso.com' -MailRecipient 'IT@contoso.com' -ReportOutputPath 'C:\Account Lockouts'

    This example saves an HTML report for the single most recent account lockout.
    The report is saved in the same folder where the script is saved.
    The report is e-mailed to IT@contoso.com via the SMTP server smtp.contoso.com
  .NOTES
    Tested running on Windows 10 searching the Event Logs logs from a Server 2008 R2 PDC Emulator
    Prerequisites:
      PowerShell 5+
      Active Directory Module for Windows PowerShell
      Network connectivity to the PDC Emulator
      
      The PDC Emulator must be running Windows Server 2008 or newer for Get-WinEvent and Event Id 4740

      The Default Domain Controllers Policy must have the following setting enabled:
        Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Audit Policy\Audit account management > Success

      The user running a script must be a member of 'Domain Admins' to access the PDC Emulator's Security log and C$ administrative file share.
    
    ToDo: Make saving the report and logs optional (should be default to only return the object)
    ToDo: Option to always search IIS logs on Exchange CAS servers
    ToDo: Option to always search RADIUS logs
    ToDo: Option to search all DCs
    ToDo: Export all desired events, then use the exports to convert to objects.  This reduces the number of times the huge security log has to be searched.
    ToDo: Look for Event 4625 (failed logon event) and correlate using Logon ID
    ToDo: Look for Event 4771 on lockout origin DC (when I saw one it was caused by disconnected Windows session on a Server2012 server) (529 on 2003)
      #Client Address gives a computer to check, look on that PC for 4771/529 events as well
      #Discover DHCP servers, retrieve their subnets, check DHCP for that IP, then lookup MAC addr vendor?
    ToDo: Look for Event 644 on Server 2003 lockout origin DC (when I saw one it was caused by a RADIUS lockout)
    ToDo: Look for Event 1 on the IAS server (?Corresponding event on NPS server?)
    ToDo: Expand the RADIUS Class attribute https://technet.microsoft.com/en-us/library/dd197432(v=ws.10).aspx
    ToDo: Create and implement LogFile and LogLine classes in TextLog.psm1
    ToDo: Create and implement classes in AccountLockout.psm1
#>
[CmdletBinding()]
param(
  
  <#
  Account names to search for account lockouts
  These will be compared to the Account Name property of the Account That Was Locked Out in Event ID 4740.
  #>
  [String[]]$User,

  <#
  Name of the domain to search
  This will be passed to the Identity parameter of Get-AdDomain.
  Default is the DNS Root of the current Active Directory domain
  #>
  [String]$DomainName,

  <#
  User accounts that do not belong to an individual user, such as service accounts.
  Lockouts of these accounts may represent an attempted security breach or a misconfiguration.
  If these accounts are locked out, notify the admininstrators but not the user.
  #>
  [String[]]$SpecialUser = @('Administrator','admin','root'),

  #Beginning of the date range to search for account lockouts
  $Start,

  #End of the date range to search for account lockouts
  $End,

  #Root folder to output the reports into. Default: "$PSScriptRoot\Results"
  [String]$ReportOutputPath,

  #If enabled, send the report to the user who was locked out
  [Switch]$NotifyUser,

  #SMTP server to use to send the notification e-mails
  [String]$MailServer,

  #SMTP address to use as the Sender of the notification e-mails. Default: DoNotReply@DoNotReply.com
  [String]$MailSender = 'DoNotReply@AccountLockout.com',

  #SMTP addresses to send the notification e-mails to
  [String[]]$MailRecipient

)
begin{

    $Global:NewLog = New-Object -TypeName System.Collections.Generic.List[String]

  #Load required modules
  Remove-Module AccountLockout -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\AccountLockout.psm1" -Verbose:$false

  Remove-Module BootstrapReport -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\BootstrapReport\BootstrapReport.psm1" -Verbose:$false

  Remove-Module EventLog -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\EventLog.psm1" -Verbose:$false

  Remove-Module GadgetExchange -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\GadgetExchange.psm1" -WarningAction SilentlyContinue -Verbose:$false

  Remove-Module InvalidFileNameChars -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\InvalidFileNameChars.psm1" -Verbose:$false

  Remove-Module LogMessage -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\LogMessage.psm1" -Verbose:$false

  Remove-Module TextLog -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\TextLog\TextLog.psm1" -Verbose:$false

  Remove-Module UncPath -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\UncPath.psm1" -Verbose:$false

  Remove-Module UnlikeObject -Force -ErrorAction SilentlyContinue -Verbose:$false
  Import-Module "$PSScriptRoot\Modules\UnlikeObject.psm1" -Verbose:$false

  #Set the output path to a default value if it was not already specified
  if ([String]::IsNullOrEmpty($ReportOutputPath)){
    $ReportOutputPath = "$PSScriptRoot\Results"
  }

}
process{

  #Search for account lockouts
  Write-Log -Type 'Verbose' -Text "Find-AccountLockout.ps1`tGet-Lockout -User @('$($User -join "','")') -DomainName `"$DomainName`" -Start `"$Start`" -End `"$End`" -SpecialUser @('$($SpecialUser -join "','")') -ErrorAction Continue"
  $AccountLockouts = Get-Lockout -User $User -DomainName $DomainName -Start $Start -End $End -SpecialUser $SpecialUser -ErrorAction Continue

  #Save the account lockouts that were found
  Write-Log -Type 'Verbose' -Text "Find-AccountLockout.ps1`tSave-Lockout -ReportOutputPath `"$ReportOutputPath`" -MailServer `"$MailServer`" -MailRecipients @('$($MailRecipient -split "`',`'")') -NotifyUser $NotifyUser -ErrorAction Continue"
  $AccountLockouts | Save-Lockout -ReportOutputPath "$ReportOutputPath" -MailServer "$MailServer" -MailRecipient $MailRecipient -NotifyUser $NotifyUser -ErrorAction Continue

}
end{

  $NewLog | Out-File "$PSScriptRoot\Logs\$((Get-Date -Format s) -replace ':','-').log"
  Write-Output $AccountLockouts

  #Unload modules that were used by the script
  Remove-Module AccountLockout -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module BootstrapReport -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module EventLog -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module GadgetExchange -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module InvalidFileNameChars -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module LogMessage -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module TextLog -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module UncPath -Force -ErrorAction SilentlyContinue -Verbose:$false
  Remove-Module UnlikeObject -Force -ErrorAction SilentlyContinue -Verbose:$false

}
