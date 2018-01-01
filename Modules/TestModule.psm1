function ExchangeFunction {
    $uri = 'http://lvhq-xca10.tutorperini.com/PowerShell'
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $Uri
    Import-Module (Import-PSSession $Session) -Global
    #Import-Module (Import-PSSession $Session -CommandName 'Get-ActiveSyncDeviceStatistics') -Global
}

<#
r:
cd '.\IT Support Team\Scripts\PowerShell\AccountLockoutSource\Modules'
import-module .\TestModule.psm1
ExchangeFunction
Get-ActiveSyncDeviceStatistics

Get-Mailbox -ResultSize 1
Import-PSSession -Session (Get-PSSession)
Get-Mailbox -ResultSize 1

#>