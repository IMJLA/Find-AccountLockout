function Write-Log{
    #Display a message on-screen and then return it to the pipeline
    param(
        #The message to display and return
        [String]$Text,

        #The display method to use to display the message
        [String]$Type = 'Host'
    )
    [String]$MessageToLog = "$(Get-Date -Format s)`t$(hostname)`t$Text"
    Switch ($Type) {
        'Verbose'{Write-Verbose $MessageToLog}
        'Debug'{Write-Debug "  $MessageToLog"}
        default{Write-Host $MessageToLog}
    }
    $null = $Global:NewLog.Add($MessageToLog)
    #Write-Output $MessageToLog
}
