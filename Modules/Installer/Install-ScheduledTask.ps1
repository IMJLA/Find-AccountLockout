#Requires -Version 5.0

$Params = @{
	#$SamAccountName = 'services.adlck'
	SamAccountName = 'Services.EgnyteELC'
	FullName = 'Services AD Account Lockout Reporter'
	Description = 'Account used for running the Find-AccountLockout scheduled task on the PDC Emulator'
	TaskName = 'Test'
    TaskRun = 'ping google.com'
	Schedule = 'ONEVENT'
	EventChannel = 'Security'
	Modifier = '*[System[EventID=4740]]'
    RunLevel = 'HIGHEST'
    TaskDescription = 'Report Active Directory account lockouts'
    MultipleInstancesPolicy = 'Parallel'
    TaskPropertiesToRemove = @('StartBoundary','Duration','WaitTimeout')
}

function Install-ScheduledTask{
    param(
	    [String]$SamAccountName,
	    [String]$FullName,
	    [String]$Description,
	    [String]$TaskName,
        [String]$TaskRun,
	    [String]$Schedule,
	    [String]$EventChannel,
	    [String]$Modifier,
        [String]$RunLevel,
        [String]$TaskDescription,
        [String]$MultipleInstancesPolicy,
        [String[]]$TaskPropertiesToRemove
    )

    #Identify the domain
    Write-Verbose "Install-ScheduledTask.ps1`tGet-ADDomain"
    $Domain = (Get-ADDomain).NetBIOSName

    #Create the service account
    Write-Verbose "Install-ScheduledTask.ps1`tGet-ADUser -Identity $SamAccountName"
    if(Get-ADUser -Identity $SamAccountName -ErrorAction SilentlyContinue){
        Write-Debug "Install-ScheduledTask.ps1`t$SamAccountName is an existing service account"
    }
    else{
        #New-ADServiceAccount -SamAccountName $SamAccountName -Name $AccountFullName -Description $Description
        #Add-ADComputerServiceAccount -Identity $(hostname) -ServiceAccount $SamAccountName
        #Install-ADServiceAccount -Identity $SamAccountName
        #Add-ADGroupMember -Identity 'Domain Admins' -Members $SamAccountName
    }
    
    #Create the scheduled task
    $Result = $null
    Write-Verbose "Install-ScheduledTask.ps1`tSchTasks.exe /Create /TN `"$TaskName`" /RU `"$Domain\$SamAccountName`" -RP `"16Xpr21tl98^`" /SC $Schedule /EC $EventChannel /MO $Modifier /TR `"`$TaskRun`" /RL $RunLevel /F"
    $Result = SchTasks.exe /Create /TN "$TaskName" /RU "$Domain\$SamAccountName" -RP "16Xpr21tl98^" /SC $Schedule /EC $EventChannel /MO $Modifier /TR $TaskRun /RL $RunLevel /F
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
    Write-Debug "  Install-ScheduledTask.ps1`tSchTasks.exe`t$Result" #This should not return anything so I have commented out this line

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
    ForEach ($Prop in $TaskPropertiesToRemove){
        $XML = $XML | Where-Object -FilterScript {$_ -notlike "*<$Prop>*"}
    }

    #Save the XML File
    $XML | Out-File -LiteralPath $XmlFile

    #Create the scheduled task
    $Result = $null
    Write-Verbose "Install-ScheduledTask.ps1`tSchTasks.exe /Create /TN `"$TaskName`" /RU `"$Domain\$SamAccountName`" -RP `"16Xpr21tl98^`" XML `"$XmlFile`""
    $Result = SchTasks.exe /Create /TN "$TaskName" /RU "$Domain\$SamAccountName" -RP "16Xpr21tl98^" -XML "$XmlFile"
    Write-Debug "  Install-ScheduledTask.ps1`tSchTasks.exe`t$Result"
    Write-Output $Result

}

#Build the command
$TaskRun = "powershell -ExecutionPolicy Bypass -Command '& '$PSScriptRoot\..\..\Find-AccountLockout.ps1''"
Write-Debug "  Install-ScheduledTask.ps1`t`$TaskRun = `"$TaskRun`""
$Params['TaskRun'] = $TaskRun

Install-ScheduledTask @Params
pause