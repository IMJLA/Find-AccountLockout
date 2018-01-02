function Export-EventLog{
    param (

      #The name of the event log to export events from, or the path to the event log file to export events from
	    [String]$Path = 'System',

      #TO DO: Detect the Path Type depending on whether or not it contains a slash
	    [System.Diagnostics.Eventing.Reader.PathType]$PathType = 'LogName',

      #The computer whose event logs are to be exported
      [String[]]$Computer = 'localhost',

      #The beginning of the date range to include in the export
      [DateTime]$Start = (Get-Date).AddDays(-1).ToUniversalTime(),

      #The end of the date range to include in the export
      [DateTime]$End = (Get-Date).ToUniversalTime(),

      #The value to search for in the Data elements within the EventData section.
      [String]$EventDataData,

      #The EventID to include in the export
      [String[]]$EventId,

      #The path to the new event log file to create
	    [String]$targetFilePath = "$PSScriptRoot\EventLog.evtx",

      <#
      When true, continue exporting events even if the specified query fails for some logs
      When false, do not continue to export events when the specified query fails
      #>
	    [bool]$tolerateQueryErrors = $true,

      #The culture that specifies which language that the exported event messages will be in.
	    [CultureInfo]$targetCultureInfo = (New-Object System.Globalization.CultureInfo($PSCulture))
    )
    begin{
        [String]$StartDateTime = Get-Date $Start -Format s
        [String]$EndDateTime = Get-Date $End -Format s
        [String]$Query = @"
<QueryList>
    <Query Id="0" Path="$Path">
        <Select Path="$Path">
            *[System[(EventID=$($EventId -join ' or EventId=')) and TimeCreated[@SystemTime &gt;= '$StartDateTime' and @SystemTime &lt;= '$EndDateTime']] and EventData[Data="$EventDataData"]]
        </Select>
    </Query>
</QueryList>
"@
    }
    process{
        ForEach ($ComputerName in $Computer){
            <#
            Currently the EventLogSession.ExportLogAndMessages method does not support UNC paths for the target output destination.
            Use a local path for that method, and then move the resulting files to the final destination.
            #>

            #Create a folder on the remote computer for the output from Export-EventLog
            if ([String]::IsNullOrEmpty($Env:ProgramData) -or [String]::IsNullOrWhiteSpace($Env:ProgramData)){
                $LocalTempScriptDir = "C:\ProgramData\Export-EventLog"
            }
            else {
                $LocalTempScriptDir = "$Env:ProgramData\Export-EventLog"
            }
            Write-Output "Export-EventLog`t`tLocalTempScriptDir:$LocalTempScriptDir"
            $RemoteTempScriptDir = "\\$ComputerName\$($LocalTempScriptDir -replace ':','$')"
            $null = md $RemoteTempScriptDir -ErrorAction SilentlyContinue

            #Create a folder for the current instance of the script, to prevent conflicts with files from previous or concurrent instances
            $CurrentExportDir = "$((Get-Date -Format s) -replace ':','-')"
            $LocalTempCurrentExportDir = "$LocalTempScriptDir\$CurrentExportDir"
            $RemoteTempCurrentExportDir = "$RemoteTempScriptDir\$CurrentExportDir"
            $null = md $RemoteTempCurrentExportDir -ErrorAction SilentlyContinue

            #Construct the local file path for the targetFilePath parameter of the EventLogSession.ExportLogAndMessages method
            $DestinationDir = $targetFilePath | Split-Path
            $DestinationFile = $targetFilePath | Split-Path -Leaf
            $LocalPath = "$LocalTempCurrentExportDir\$DestinationFile"
            Write-Output "Export-EventLog`t`tLocalPath:$LocalPath"

            #Export the event logs to .EVTX
            try{
                Write-Output "Export-EventLog`t`tNew-Object System.Diagnostics.Eventing.Reader.EventLogSession(`"$ComputerName`")"
                $EventLogSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession($ComputerName)
                Write-Output "Export-EventLog`t`t`$EventLogSession.ExportLogAndMessages(`"$Path`",`"$PathType`",@`"`r`n$Query`r`n`"@,`"$LocalPath`",`$$tolerateQueryErrors,`"$targetCultureInfo`")"
                $EventLogSession.ExportLogAndMessages("$Path","$PathType",$Query,"$LocalPath",$tolerateQueryErrors,$targetCultureInfo)

                #Write-Output "Export-EventLog`t`tGet-ChildItem -Path `"$RemoteTempCurrentExportDir`" -Recurse | Move-Item -Destination `"$DestinationDir`""
                #Get-ChildItem -Path "$RemoteTempCurrentExportDir" -Recurse | Move-Item -Destination "$DestinationDir" -Force #This fails if copying from \\comp1\c$ to \\comp1\c$ with the error "Source and destination path must have identical roots. Move will not work across volumes"
                
                Write-Output "Export-EventLog`t`trobocopy `"$RemoteTempCurrentExportDir`" `"$DestinationDir`" *.* /S /E /MOV /R:1 /W:1"
                $null = & robocopy "$RemoteTempCurrentExportDir" "$DestinationDir" *.* /S /E /MOV /R:1 /W:1
            }
            catch{
                $CurrentError = $_
                switch -Wildcard ($CurrentError.Message){
                    "*The file exists*"{Write-Host "$targetFilePath already exists."}
                    default{
                        Write-Output "Export-EventLog`tError: $($CurrentError.Message)"
                        Write-Output "Export-EventLog`tError: $($CurrentError.Exception.Message)"
                    }
                }
            }
        }
    }
    end{}
}
