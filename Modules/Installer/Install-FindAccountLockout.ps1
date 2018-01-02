#Requires -Version 5.0
param(
    #The samAccountName of the service account that will run the Find-AccountLockout scheduled task
    [Parameter(Mandatory=$true)]
    [String]$SamAccountName
)

function Install-ScheduledTask{
    param(
	    [String]$SamAccountName,
	    [String]$FullName = 'Find-AccountLockout AD Account Lockout Reporter',
	    [String]$Description = 'Account used for running the Find-AccountLockout scheduled task on the PDC Emulator',
	    [String]$TaskName = 'Test',
        [String]$TaskRun = 'ping google.com',
	    [String]$Schedule = 'ONEVENT',
	    [String]$EventChannel = 'Security',
	    [String]$Modifier = '*[System[EventID=4740]]',
        [String]$RunLevel = 'HIGHEST',
        [String]$TaskDescription = 'Report Active Directory account lockouts',
        [String]$MultipleInstancesPolicy = 'Parallel',
        [String[]]$TaskElementsToRemove = @('StartBoundary','Duration','WaitTimeout')
    )

    #Identify the domain
    Write-Verbose "Install-ScheduledTask.ps1`tGet-ADDomain"
    $Domain = (Get-ADDomain).NetBIOSName

    #Create the service account
    Write-Verbose "Install-ScheduledTask.ps1`tGet-ADUser -Identity $SamAccountName"
    if(Get-ADUser -Identity $SamAccountName -ErrorAction SilentlyContinue){
        Write-Debug "Install-ScheduledTask.ps1`t$SamAccountName is an existing account"
        $User = "$Domain\$SamAccountName"
        $Cred = Get-Credential -Message "Enter the password for the service account (leave blank for managed service accounts)" -UserName $User
        $Pass = $Cred.GetNetworkCredential().Password
    }
    else{
        #New-ADServiceAccount -SamAccountName $SamAccountName -Name $AccountFullName -Description $Description
        #Add-ADComputerServiceAccount -Identity $(hostname) -ServiceAccount $SamAccountName
        #Install-ADServiceAccount -Identity $SamAccountName
        #Add-ADGroupMember -Identity 'Domain Admins' -Members $SamAccountName
        $User = "$Domain\$SamAccountName$"
        $Pass = $null
    }
    
    #Create the scheduled task
    $Result = $null
    Write-Verbose "Install-ScheduledTask.ps1`tSchTasks.exe /Create /TN `"$TaskName`" /RU `"$User`" -RP ****** /SC $Schedule /EC $EventChannel /MO $Modifier /TR `"`$TaskRun`" /RL $RunLevel /F"
    $Result = SchTasks.exe /Create /TN "$TaskName" /RU $User -RP "$Pass" /SC $Schedule /EC $EventChannel /MO $Modifier /TR $TaskRun /RL $RunLevel /F
    Write-Debug "  Install-ScheduledTask.ps1`tSchTasks.exe: $Result"

    #Create a working directory and build a filename for our XML file
    $XmlDir = "$Env:ProgramData\Find-AccountLockout"
    $null = New-Item -Type Directory -Path $XmlDir -ErrorAction SilentlyContinue
    $XmlFile = "$XmlDir\$TaskName.xml"

    #Export the scheduled task so it can be optimized
    $Result = $null
    Write-Verbose "Install-ScheduledTask.ps1`tSchTasks.exe /Query /TN `"$TaskName`" /XML > `"$XmlFile`""
    $Result = SchTasks.exe /Query /TN "$TaskName" /XML > "$XmlFile"
    Write-Debug "  Install-ScheduledTask.ps1`tSchTasks.exe: $Result"

    #Delete the scheduled task so it can be recreated with optimized settings
    $Result = $null
    Write-Verbose "Install-ScheduledTask.ps1`tSchTasks.exe /Delete /TN `"$TaskName`" /F"
    $Result = SchTasks.exe /Delete /TN "$TaskName" /F
    Write-Debug "  Install-ScheduledTask.ps1`tSchTasks.exe: $Result" #This should not return anything so I have commented out this line

    #Add missing attributes and correct incorrect attributes
    [XML]$Task = Get-Content -LiteralPath $XmlFile

    #Add a description to the task
    $NewItem = $Task.CreateElement('Description')
    $NewItem.PsBase.InnerText = $TaskDescription
    $null = $Task.Task.RegistrationInfo.AppendChild($NewItem)

    #Remove the BS added by the AppendChild method
    $Task = [xml]$Task.OuterXml.Replace(" xmlns=`"`"", "")

    #Set the MultipleInstancesPolicy node
    $Task = [xml]$Task.OuterXml.Replace('<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',"<MultipleInstancesPolicy>$MultipleInstancesPolicy</MultipleInstancesPolicy>")

    #Save the XML file
    $Task.Save($XmlFile)

    #Remove unnecessary attributes
    $XML = Get-Content -LiteralPath $XmlFile
    ForEach ($Prop in $TaskElementsToRemove){
        $XML = $XML | Where-Object -FilterScript {$_ -notlike "*<$Prop>*"}
    }

    #Save the XML File
    $XML | Out-File -LiteralPath $XmlFile

    #Create the scheduled task
    $Result = $null
    Write-Verbose "Install-ScheduledTask.ps1`tSchTasks.exe /Create /TN `"$TaskName`" /RU `"$User`" -RP ****** XML `"$XmlFile`""
    $Result = SchTasks.exe /Create /TN "$TaskName" /RU $User -RP "$Pass" -XML "$XmlFile"
    Write-Debug "  Install-ScheduledTask.ps1`tSchTasks.exe: $Result"
    Write-Output $Result

}

#Build the command
$TaskRun = "powershell -ExecutionPolicy Bypass -NoProfile -NonInteractive -Command '& '$PSScriptRoot\..\..\Find-AccountLockout.ps1''"
Write-Debug "  Install-ScheduledTask.ps1`t`$TaskRun = `"$TaskRun`""


$Params = @{
    SamAccountName = $SamAccountName
    TaskRun = $TaskRun
}
Install-ScheduledTask @Params