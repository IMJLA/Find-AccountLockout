function ConvertFrom-TextLog {
  #Convert lines from text-based log files into PSObjects

  param(

    #The log lines to convert into PowerShell objects
    [Parameter(
        ValueFromPipeline=$true,
        Position=0
    )]
    [PSObject[]]$LogLines,

    <#
    Type of log to search.
    Valid values are: IIS-W3C, IAS, odbc (for NPS logs), NetLogon
    #>
    [String]$LogFormat,

    #The optional fields obtained from the field row in the log file
    [String[]]$Fields

  )
  begin{

    Import-Module "$PSScriptRoot\..\UncPath.psm1" -Verbose:$false
    [String]$DictionaryDir = "$(New-UncPath $PSScriptRoot)\Dictionaries"
    
    #Interpret IAS Database Format Log Files.pdf
    #https://technet.microsoft.com/en-us/library/dd197432(v=ws.10).aspx
    $IAS_RADIUS_Attributes = Get-DictionaryFromCsv -Path "$DictionaryDir\IAS_RADIUS_Attributes.csv" -ErrorAction Stop

    #Interpret NPS Database Format Log Files.pdf
    #https://technet.microsoft.com/en-us/library/cc771748(v=ws.10).aspx
    $IAS_AuthTypes = Get-DictionaryFromCsv -Path "$DictionaryDir\IAS_Authentication_Types.csv" -ErrorAction Stop
    $IAS_ReasonCodes = Get-DictionaryFromCsv -Path "$DictionaryDir\IAS_Reason_Codes.csv" -ErrorAction Stop
    $IAS_PacketTypes = Get-DictionaryFromCsv -Path "$DictionaryDir\IAS_Packet_Types.csv" -ErrorAction Stop

    #Define the NetLogon return codes
    $NetLogon_ReturnCodes = Get-DictionaryFromCsv -Path "$DictionaryDir\NetLogon_Return_Codes.csv" -ErrorAction Stop

  }
  process{

    ForEach ($Line in $LogLines){
    
      if ($Line.SourceLogFile.LogFormat){
        $Format = $Line.SourceLogFile.LogFormat
      }
      else{
        $Format = $LogFormat
      }

      $Object = New-Object -TypeName PSObject -Property (@{
        'SourceLogComputer' = $Line.SourceLogComputer
        'SourceLogLineNumber' = $Line.LineNumber
        'SourceLogLine' = $Line
        'SourceLogFile' = $Line.SourceLogFile
      })

      Switch ($Format){

        'IAS'{

          #IAS logs are comma-delimited
          if ($Line.Line){
            $EventDetails = $Line.Line.Split(',')
          }
          else{
            $EventDetails = $Line.Split(',')
          }

          #Beyond the header, RADIUS attributes and values are listed in pairs
          for ($n = 6; $n -lt $EventDetails.Count; $n = $n+2){
            #Write-Log -Type 'Debug' -Text "ConvertFrom-TextLog`tAttribute $(7 + (($n-6)/2)) out of $((($EventDetails.Count - 6) / 2) + 6)"

            $attName = $IAS_RADIUS_Attributes["$($EventDetails[$n])"]
            if(!($attName)){$attName = "Attribute$($EventDetails[$n])"}

            <# Some IAS attributes have multiple entries,
            so we need to create a collection for each attribute. #>
            $attValue = New-Object -TypeName System.Collections.Generic.List[String]
            $null = $attValue.Add(($EventDetails[$n+1]))

            #Set the value of the attribute.
            try{

              $params = @{
                Name = "iasRadius$attName"
                Value = $attValue
                MemberType = 'NoteProperty'
                ErrorAction = 'Stop'
              }
              $Object | Add-Member @params

            }
            catch [System.Management.Automation.RuntimeException]{

              #If there is already a value for that attribute, just add the new value to the existing array.
              $null = $Object.("iasRadius$attName").Add(($attValue))

            }

          }

          #Write-Log -Type 'Debug' -Text "ConvertFrom-TextLog`tObject:$($Object | fl * | Out-String)"

          $Props = @{
            <# The first six record fields make up the header
            https://technet.microsoft.com/en-us/library/dd197432(v=ws.10).aspx #>
            'iasNAS-IP-Address' = $EventDetails[0] # The IP address of the Network Access Server that is sending the request
            'iasUser-Name' = $EventDetails[1] # The user name that is requesting access
            'iasRecord-Date' = $EventDetails[2] # The date that the log is written
            'iasRecord-Time' = $EventDetails[3] # The time that the log is written
            'iasService-Name' = $EventDetails[4] # The name of the service that is running on the RADIUS server
            'iasComputer-Name' = $EventDetails[5] # The name of the RADIUS server

            #Expand the attributes that are coded rather than plain-text
            'iasRadiusAuthentication-Type_SchemeName' = $IAS_AuthTypes[$Object.'iasRadiusAuthentication-Type']
            'iasRadiusReason-Code_Name' = $IAS_ReasonCodes[$Object.'iasRadiusReason-Code']
            'iasRadiusPacket-Type_Name' = $IAS_PacketTypes[$Object.'iasRadiusPacket-Type']

          }

          $Object | Add-Member -NotePropertyMembers $Props

          Write-Output $Object

        }
        'IIS-W3C'{

          #IIS W3C logs are space-delimited
          if ($Line.Line){
            $EventDetails = $Line.Line -split ' '
          }
          else{
            $EventDetails = $Line -split ' '
          }
          
          #If field headers were not provided, we need them from the source log file
          if ($null -eq $Fields){
            $Fields = $Line.SourceLogFile.Fields
          }

          #Use the field headers to assign the log fields to attributes on the object
          For ($CurrentFieldIndex = 0;$CurrentFieldIndex -lt $Fields.Count;$CurrentFieldIndex++){
            $FieldName = "W3C$($Fields[$CurrentFieldIndex] -replace '[\-\(\)]','')"
            $Object | Add-Member -MemberType NoteProperty -Name $FieldName -Value $EventDetails[$CurrentFieldIndex] -Force
          }

          #Process the Client-Server URI Query
          #For initial AutoDiscover requests the query is just a hyphen. No need to parse that.
          if($Object.W3CcsUriQuery -ne '-'){
            $QueryParts = ConvertFrom-CSV $Object.W3CcsUriQuery.Split('&') -Delimiter '=' -Header "Name","Value" -ErrorAction SilentlyContinue
            $QueryParts | ForEach-Object{
                $AddMemberParams = @{
                  Name = "W3CcsUriQuery$($_.Name)"
                  Value = $_.Value
                  MemberType = 'NoteProperty'
                  Force = $true
                  ErrorAction = 'SilentlyContinue'
                }
                $Object | Add-Member @AddMemberParams
            }
          }

          <#
          Process the Log item from the Client-Server URI Query.
          This contains IIS's Exchange ActiveSync protocol logs
          http://technet.microsoft.com/en-us/library/bb201675.aspx
          #>
          try{

            #ZOMG RegEx from Hell...WTF was I thinking. Probably never touch this line again out of fear because it seems to be working
            $regex = [regex]::matches(
              $Object.W3CcsUriQueryLog,
              '([A-Za-z]*)[:]*([\w\(\[][A-Za-z0-9\%\.\-\(\)]*)(_)'
            ) | Select Groups

            <#
            Some ActiveSync Query log items have multiple entries,
            so we need to create an array for each Query log Item.
            #>
            $regex | ForEach-Object{
              $name = $_.Groups[1].Value
              $value = @()
              $value += $_.Groups[2].Value
              try{
                $Parameters = @{
                   Name = "W3CcsUriQueryLog$name"
                   Value = $value
                   MemberType = 'NoteProperty'
                   ErrorAction = 'Stop'
                }
                $Object | Add-Member @Parameters
                  
              }
              catch [System.Management.Automation.RuntimeException]{
                <#
                If there is already a value for that item,
                just add the new value to the existing array.
                #>
                $Object.("W3CcsUriQueryLog$name") += $value
              }
            }
          }catch{}
          
          Write-Output $Object

        }
        'odbc'{

          #NPS logs are comma-delimited
          if ($Line.Line){
            $EventDetails = $Line.Line -Split ','
          }
          else{
            $EventDetails = $Line -Split ','
          }

          <# There should be 66 ordered fields
          https://technet.microsoft.com/en-us/library/cc771748(v=ws.10).aspx #>

          $Props = @{
            'npsComputerName' = $EventDetails[0] # The name of the server where the packet was received
            'npsServiceName' = $EventDetails[1] # The name of the service that generated the record—IAS or the Routing and Remote Access service
            'npsRecordDate' = $EventDetails[2] # The date at the NPS or Routing and Remote Access server
            'npsRecordTime' = $EventDetails[3] # The time at the NPS or Routing and Remote Access server
            'npsPacketType' = $EventDetails[4] # The type of packet
            'npsUserName' = $EventDetails[5] # The user identity, as specified by the user.
            'npsFullyQualifiedDistinguishedName' = $EventDetails[6] # The user name in canonical format (this is an IAS-internal attribute).
            'npsCalledStationID' = $EventDetails[7] # The phone number dialed by the user.
            'npsCallingStationID' = $EventDetails[8] # The phone number from which the call originated.
            'npsCallbackNumber' = $EventDetails[9] # The callback phone number.
            'npsFramedIPAddress' = $EventDetails[10] # The framed address to be configured for the user.
            'npsNASIdentifier' = $EventDetails[11] # The text that identifies the network access server originating the request.
            'npsNASIPAddress' = $EventDetails[12] # The IP address of the network access server originating the request.
            'npsNASPort' = $EventDetails[13] # The physical port number of the network access server originating the request.
            'npsClientVendor' = $EventDetails[14] # The manufacturer of the network access server (this is an IAS-internal attribute).
            'npsClientIPAddress' = $EventDetails[15] # The IP address of the RADIUS client (this is an IAS-internal attribute).
            'npsClientFriendlyName' = $EventDetails[16] # The friendly name for the RADIUS client (this is an IAS-internal attribute).
            'npsEventTimestamp' = $EventDetails[17] # The date and time that this event occurred on the network access server.
            'npsPortLimit' = $EventDetails[18] # The maximum number of ports that the network access server provides to the user.
            'npsNASPortType' = $EventDetails[19] # The type of physical port that is used by the network access server originating the request.
            'npsConnectInfo' = $EventDetails[20] # Information that is used by the network access server to specify the type of connection made. Typical information includes connection speed and data encoding protocols.
            'npsFramedProtocol' = $EventDetails[21] # The protocol to be used.
            'npsServiceType' = $EventDetails[22] # The type of service that the user has requested.
            'npsAuthenticationType' = $EventDetails[23] # The authentication scheme, which is used to verify the user and can be:
            'npsPolicyName' = $EventDetails[24] # The friendly name of the network policy that either granted or denied access. This attribute is logged in Access-Accept and Access-Reject messages. If a user is rejected because none of the network policies matched, then this attribute is blank.
            'npsReasonCode' = $EventDetails[25] # The reason for rejecting a user, which can be:
            'npsClass' = $EventDetails[26] # The attribute that is sent to the client in an Access-Accept packet.
            'npsSessionTimeout' = $EventDetails[27] # The length of time (in seconds) before the session is terminated.
            'npsIdleTimeout' = $EventDetails[28] # The length of idle time (in seconds) before the session is terminated.
            'npsTerminationAction' = $EventDetails[29] # The action that the network access server takes when service is completed.
            'npsEAPFriendlyName' = $EventDetails[30] # The friendly name of the EAP-based authentication method that was used by the access client and NPS server during the authentication process. For example, if the client and server use Extensible Authentication Protocol (EAP) and the EAP type MS-CHAP v2, the value of EAP-Friendly-Name is “Microsoft Secured Password (EAP-MSCHAPv2)."
            'npsAcctStatusType' = $EventDetails[31] # The number that specifies whether an accounting packet starts or stops a bridging, routing, or Terminal Server session.
            'npsAcctDelayTime' = $EventDetails[32] # The length of time (in seconds) for which the network access server has been sending the same accounting packet.
            'npsAcctInputOctets' = $EventDetails[33] # The number of octets received during the session.
            'npsAcctOutputOctets' = $EventDetails[34] # The number of octets sent during the session.
            'npsAcctSessionId' = $EventDetails[35] # The unique numeric string that identifies the server session.
            'npsAcctAuthentic' = $EventDetails[36] # The number that specifies which server authenticated an incoming call.
            'npsAcctSessionTime' = $EventDetails[37] # The length of time (in seconds) for which the session has been active.
            'npsAcctInputPackets' = $EventDetails[38] # The number of packets received during the session.
            'npsAcctOutputPackets' = $EventDetails[39] # The number of packets sent during the session.
            'npsAcctTerminateCause' = $EventDetails[40] # The reason that a connection was terminated.
            'npsAcctMultiSsnID' = $EventDetails[41] # The unique numeric string that identifies the multilink session.
            'npsAcctLinkCount' = $EventDetails[42] # The number of links in a multilink session.
            'npsAcctInterimInterval' = $EventDetails[43] # The length of interval (in seconds) between each interim update that the network access server sends.
            'npsTunnelType' = $EventDetails[44] # The tunneling protocol to be used.
            'npsTunnelMediumType' = $EventDetails[45] # The medium to use when creating a tunnel for protocols. For example, L2TP packets can be sent over multiple link layers.
            'npsTunnelClientEndpt' = $EventDetails[46] # The IP address of the tunnel client.
            'npsTunnelServerEndpt' = $EventDetails[47] # The IP address of the tunnel server.
            'npsAcctTunnelConn' = $EventDetails[48] # An identifier assigned to the tunnel.
            'npsTunnelPvtGroupID' = $EventDetails[49] # The group ID for a specific tunneled session.
            'npsTunnelAssignmentID' = $EventDetails[50] # The tunnel to which a session is assigned.
            'npsTunnelPreference' = $EventDetails[51] # The preference of the tunnel type, as indicated with the Tunnel-Type attribute when multiple tunnel types are supported by the access server.
            'npsMSAcctAuthType' = $EventDetails[52] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSAcctEAPType' = $EventDetails[53] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSRASVersion' = $EventDetails[54] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSRASVendor' = $EventDetails[55] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSCHAPError' = $EventDetails[56] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSCHAPDomain' = $EventDetails[57] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSMPPEEncryptionTypes' = $EventDetails[58] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsMSMPPEEncryptionPolicy' = $EventDetails[59] # A Routing and Remote Access service attribute. For more information, see RFC 2548.
            'npsProxyPolicyName' = $EventDetails[60] # The name of the connection request policy that matched the connection request.
            'npsProviderType' = $EventDetails[61] # Specifies the location where authentication occurs. Possible values are 0, 1, and 2. A value of 0 indicates that no authentication occurred. A value of 1 indicates that authentication occurs on the local NPS server. A value of 2 indicates that the connection request is forwarded to a remote RADIUS server for authentication.
            'npsProviderName' = $EventDetails[62] # A string value that corresponds to Provider-Type. Possible values are "None" for a Provider-Type value of 0, "Windows" for a Provider-Type value of 1, and "Radius Proxy" for Provider-Type value of 2.
            'npsRemoteServerAddress' = $EventDetails[63] # The IP address of the remote RADIUS server to which the connection request was forwarded for authentication.
            'npsMSRASClientName' = $EventDetails[64] # The name of the remote access client. The Vendor-Length of the Value field, including the vendor ID, vendor-type, vendor-length, and value, must be at least 7 and less than 40.
            'npsMSRASClientVersion' = $EventDetails[65] # The operating system version that is installed on the remote access client. The Vendor-Length of the Value field, including the vendor ID, vendor-type, vendor-length, and value, must be at least 7.

          }
          $Object | Add-Member -NotePropertyMembers $Props
          $Props = @{
            #Expand the attributes that are coded rather than plain-text
            'iasRadiusAuthentication-Type_SchemeName' = $IAS_AuthTypes[$Object.'npsAuthenticationType']
            'iasRadiusReason-Code_Name' = $IAS_ReasonCodes[$Object.'npsReasonCode']
            'iasRadiusPacket-Type_Name' = $IAS_PacketTypes[$Object.'npsPacketType']
          }
          $Object | Add-Member -NotePropertyMembers $Props
          Write-Output $Object

        }

        'NetLogon'{
        
          #RegEx the heck out of it.  Still haven't found the perfect RegEx because the NetLogon logs follow no standards. I keep finding outlying examples that don't fit in with the regex.
          $RegEx = "(?<Date>\d{2}\/\d{2}) (?<Time>\d{2}:\d{2}:\d{2}) \[(?<Type>\w*)\] (\[(?<ID>\w*)\] )?((?<Domain>\w*): )?((?<Component>\w*): )?((?<Description>.*) of (?<TargetDomain>[^\\]*)\\(?<TargetUser>\S*) from (?<SourceComputer>\S*)? (\(via (?<RelayComputer>[^)]*)\) )?(?<Action>\w*)( (?<ResultCode>.*))?)?((?<Description2>.*) \'(?<Event>.*)\' \((?<EventDetail>.*)\) to \\\\(?<SamLogonClient>\S*) Site: (?<Site>\S*) on (?<CommProtocol>\S*) (?<AuthProtocol>\S*))?(?<Description3>.*)"
            #$RegEx = '(?<Date>\d{2}\/\d{2}) (?<Time>\d{2}:\d{2}:\d{2}) \[(?<Type>\w*)\] (\[(?<ID>\w*)\] )?((?<Domain>\w*): ((?<Component>\w*):)? (?<Description>.*) of (?<TargetDomain>\w*)\\(?<TargetUser>\S*) from (?<SourceComputer>\S*)? (\(via (?<RelayComputer>[^)]*)\) )?(?<Action>\w*)( (?<ResultCode>.*))?)?(?<Description2>.*)'

            if ($Line.Line){
              $RegExResult = $Line.Line -match $RegEx
            }
            else{
              $RegExResult = $Line -match $RegEx
            }

          $Description = -join ($Matches.Description,$Matches.Description2,$Matches.Description3)

          try{
            $NetLogonResultStatus = $NetLogon_ReturnCodes[$Matches.ResultCode]
          }
          catch{}

          $Props = @{
            NetLogonTimeCreated = $Matches.Time
            NetLogonDate = $Matches.Date
            NetLogonType = $Matches.Type
            NetLogonDomain = $Matches.Domain
            NetLogonComponent = $Matches.Component
            NetLogonDescription = $Description
            NetLogonAttemptedAuthDomain = $Matches.TargetDomain
            NetLogonAttemptedAuthUser = $Matches.TargetUser
            NetLogonSourceComputer = $Matches.SourceComputer
            NetLogonRelayComputer = $Matches.RelayComputer
            NetLogonResult = $Matches.Action
            NetLogonResultStatusCode = $Matches.ResultCode
            NetLogonResultStatus = $NetLogonResultStatus
          }
          $Object | Add-Member -NotePropertyMembers $Props

          #Write-Log -Type 'Debug' -Text "ConvertFrom-TextLog`tCurrent Object: $($Object | fl * | out-string)"

          Write-Output $Object

        }
        default{

          Write-Log -Type 'Verbose' -Text "ConvertFrom-TextLog`tNo matching LogFormat found for $Format so a CSV conversion will be attempted"
          $Object = ConvertFrom-Csv $Line

        }


      }

    }

  }
  end{

  }

}

function Get-DictionaryFromCsv {

  #Converts a CSV with two columns and no header into a dictionary that can be used to look up the meaning of an error code, for example.

  [CmdletBinding()]
  param(
    #The path to the CSV file. This will be passed to the Path parameter of Get-Content
    [String]$Path
  )

  $Text = Get-Content -Path $Path -ErrorAction Stop
  $Delimited = $Text -replace ",","="
  $Separated = $Delimited -join "`n"
  $Dictionary = $Separated | ConvertFrom-StringData
  Write-Output $Dictionary

}

function Get-NPSAttribute {

  #Uses netsh.exe to enumerate the available attributes on a Network Policy Server

  param(

    #The category of attributes to request from netsh.exe
    [String[]]$Category = @('crpconditionattributes','crpprofileattributes','npconditionattributes','npprofileattributes')

  )

  begin{

    #Use the help for netsh.exe to get the full names of the attribute categories
    $NetShHelpInfo = netsh nps show ?

  }

  process{

    ForEach ($CurrentCategory in $Category){

      #Retrieve the full line for the current category from the netsh.exe help file
      $CategoryMatchInfo = $NetShHelpInfo | Select-String -Pattern $CurrentCategory

      #Extract the attribute category names out of the full lines returned from the help file
      $CategorySplit = ($CategoryMatchInfo -split 'available ')[1]

      #Remove the period from the end
      $LowercaseCategory = $CategorySplit.SubString(0,$CategorySplit.Length-1)

      #Convert the name of the attribute category to Title Case
      $CategoryTitle = (Get-Culture).TextInfo.ToTitleCase($LowercaseCategory)

      #Use netsh.exe to enumerate the attributes in this category
      $NetShResult = netsh nps show $CurrentCategory

      #Remove the header and footer from the netsh.exe results
      $AttributeLines = $NetShResult[5..$($Attribs.Count-4)]

      #Parse the lines that contain attributes
      ForEach ($AttributeLine in $AttributeLines){

        #Use a regular expression with named groups to retrieve specific properties of the current attribute
        $null = $AttributeLine -match '(?<Name>\S+)(?:\s+)(?<ID>\S+)(?:\s+)(?<Type>.+)'

        New-Object -TypeName PSObject -Property (@{
          Name = $Matches.Name
          ID = $Matches.ID
          Type = $Matches.Type
          CategoryFriendlyName = $CategoryTitle
          CategoryNetshName = $CurrentCategory
        })

      }
    }
  }
  end{}
}

function Get-TextLog {
  param(

    #Name of the computer(s) to get text log files from
    [String[]]$ComputerName = 'localhost',

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
    Which types of text logs to search
    Valid values are 'IAS-or-NPS' or 'IIS-W3C' or 'NetLogon'
    Gets all log types by defeault.
    #>
    [String[]]$LogFormat = @('IAS-or-NPS','IIS-W3C','NetLogon'),

    <#
    The paths to the folders to search for logs
    Defaults to Microsoft's default log path for each $LogFormat
    Will be passed to the Path parameter of Get-ChildItem
    #>
    [String[]]$Path,

    <#
    The pattern to match against the log file names
    Defaults to Microsoft's default log name pattern for each $LogFormat
    Will be passed to the Include parameter of Get-ChildItem
    #>
    [String[]]$Include,

    #An existing PSSession to the remote computer.  Only works with 1 computer specified.
    [System.Management.Automation.Runspaces.PSSession]$PSSession

  )
  begin{

    if ($null -eq $End){

      $End = Get-Date

    }

    if ($null -eq $Start){

      $Start = $End.AddDays(-3)

    }

  }

  process{

    ForEach ($Computer in $ComputerName){
      
      if (!$PSSession){

        $RemovePSSession = $true
          #Start a new PSSession on the remote computer
          try{

            $PSSession = New-PSSession -ComputerName $Computer -ErrorAction Stop

          }
          catch{

            Write-Log -Type 'Verbose' -Text "Get-TextLog`tCould not establish remote PSSession on $Computer."
            Continue

          }

      }


      $LogFiles = Invoke-Command -Session $PSSession -ScriptBlock{

        param(

          <#
          Which types of logs to search
          Valid values are 'IAS-or-NPS' or 'IIS-W3C' or 'NetLogon'
          #>
          [String[]]$LogFormat = @('IAS-or-NPS','IIS-W3C','NetLogon'),

          <#
          The path to the folder to search for logs
          Defaults to Microsoft's default log path for each $LogFormat
          #>
          [String]$Path,

          #Beginning of the date range to search
          $Start,

          #The Debug action preference to use in the remote PSSession
          [System.Management.Automation.ActionPreference]$DebugPref,

          #The Verbose action preference to use in the remote PSSession
          [System.Management.Automation.ActionPreference]$VerbosePref
        )

        begin{

          $DebugPreference = $DebugPref
          $VerbosePreference = $VerbosePref

        }

        process{

          #Search each type of log that we need to search on this computer
          ForEach($Type in $LogFormat){

            #Re-initialize the variables
            $Folder = $Path
            $FileName = $Include
            $LogFiles = $null
            $Format = $Type

            Switch ($Type){

              'IAS-or-NPS'{

                if([String]::IsNullOrEmpty($FileName)){
                  [String]$FileName = "*.log"
                }

                [int]$FirstEventLine = 1

                  #Retrieve the NPS log settings
                  $NpsLogConfig = netsh nps dump exportPSK=YES | Select-String 'set filelog accounting'
                  $RegEx = '(?:.*directory = ")(?<LogDirectory>[^"]*)(?:.*format = ")(?<LogFormat>[^"]*)(?:".*)'
                  $Result = $NpsLogConfig -match $RegEx
                  if ([String]::IsNullOrEmpty($Folder)){
                    $Folder = $Matches.LogDirectory
                  }
                  $Format = $null
                  $Format = $Matches.LogFormat

                  #If NPS is not installed (or we otherwise did not get a log directory returned), and none was specified, use the default IAS log path
                  if ([String]::IsNullOrEmpty($Folder)){
                    Write-Debug "  $(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tIAS log folder was not specified.  Using default value $Env:windir\system32\LogFiles"
                    $Folder = "$Env:windir\system32\LogFiles"
                  }

              }

              'IIS-W3C'{
                if ([String]::IsNullOrEmpty($Folder)){
                  $Folder = 'C:\inetpub\logs\LogFiles\W3SVC1'
                }
                if([String]::IsNullOrEmpty($FileName)){
                  [String]$FileName = "*.log"
                }
                #These next 3 variables can be used in a log file format that has an equal number of columns in each row, and has properly-delimited field headers in the log file
                [String]$FieldHeaderOpeningDelimiter = ':' #For example, we only care what comes after the colon if the header line is     #Fields: Date Time User Computer
                [String]$FieldDelimiter = ' '
                [int]$FieldHeaderLine = 4
                [int]$FirstEventLine = 5
              }

              'NetLogon'{
                if ([String]::IsNullOrEmpty($Folder)){
                  $Folder = "$Env:windir\debug"
                }
                if([String]::IsNullOrEmpty($FileName)){
                  [String]$FileName = "NetLogon.*"
                }
                [int]$FirstEventLine = 1
              }

            }

            if (!([String]::IsNullOrEmpty($Folder))){

                Write-Verbose "$(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tGet-ChildItem -Path `"$Folder\*`" -Include `"$FileName`""
                $LogFiles = Get-ChildItem -Path "$Folder\*" -Include $FileName -ErrorAction SilentlyContinue
                Write-Debug "  $(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tGet-ChildItem returned $(($LogFiles | Measure-Object).Count) log files."

                Write-Verbose "$(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tWhere-Object -FilterScript {`$_.LastWriteTimeUtc -ge `"$Start`"}"
                $LogFiles = $LogFiles | Where-Object -FilterScript {$_.LastWriteTimeUtc -ge $Start}
                Write-Debug "  $(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tWhere-Object returned $(($LogFiles | Measure-Object).Count) log files modified after $Start."
                  
            }
            if ($null -ne $LogFiles){

              ForEach ($LogFile in $LogFiles){

                Write-Verbose "$(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tGet-Content -Path '$LogFile' -TotalCount $FirstEventLine"
                $FirstLines = Get-Content -Path $LogFile -TotalCount $FirstEventLine -ErrorAction SilentlyContinue
                  
                if ($FirstEventLine -eq 1){
                  $FirstLine = $FirstLines
                }
                else{
                  $FirstLine = $FirstLines[$($FirstEventLine-1)]
                }

                #If it has 66 columns, it's probably an odbc-formatted IAS/NPS log
                if (([String]::IsNullOrEmpty($Format)) -and (($FirstLine -split ',').Count -eq 66)){
                
                    $Format = 'odbc'
                
                }
                Write-Debug "  $(Get-Date -Format s)`t$(hostname)`tGet-TextLog`tLog Format: $Format"
                
                if (($FieldHeaderLine -ne $null) -and ($FieldDelimiter -ne $null)) {

                    $FieldLine = (Get-Content -Path $LogFile -ReadCount $FieldHeaderLine -TotalCount $FieldHeaderLine)[$($FieldHeaderLine-1)]

                    if ($FieldHeaderOpeningDelimiter -ne $null){
                        $Fields = ($FieldLine -split $FieldHeaderOpeningDelimiter)[1]
                    }

                    $Fields = $Fields -split ' ' | Where-Object -FilterScript {$_ -ne ''}
                    $LogFile | Add-Member -MemberType NoteProperty -Name Fields -Value $Fields -Force

                }

                $FirstLine | Add-Member -MemberType NoteProperty -Name SourceLogFile -Value $LogFile
                $FirstLine | Add-Member -MemberType NoteProperty -Name SourceLogComputer -Value $(hostname)

                $LogFile | Add-Member -MemberType NoteProperty -Name LogFormat -Value $Format -Force
                $LogFile | Add-Member -MemberType NoteProperty -Name FirstLine -Value $FirstLine -Force

                Write-Output $LogFile

              }

            }

          }

        }
        end{}

      } -ArgumentList $LogFormat,$Path,$Start,$DebugPreference,$VerbosePreference

      if ($RemovePSSession -eq $true){
        $PSSession | Remove-PSSession -ErrorAction SilentlyContinue
      }
      if ($null -ne $LogFiles){
        ForEach ($LogFile in $LogFiles) {

          Switch ($LogFile.LogFormat){

            'IAS'{
              function Get-LogEventDate{
                param($Event)
                Get-Date "$($Event.'iasRecord-Date') $($Event.'iasRecord-Time')"
              }
            }

            'odbc'{
              function Get-LogEventDate{
                param($Event)
                Get-Date "$($Event.npsRecordDate) $($Event.npsRecordTime)"
                Remove-Variable -Name Event
              }
            }

            'IIS-W3C'{
              function Get-LogEventDate{
                param($Event)
                Get-Date "$($Event.W3Cdate) $($Event.W3Ctime)"
              }
            }

            'NetLogon'{
              function Get-LogEventDate{
                param($Event)
                Get-Date "$($Event.NetLogonTimeCreated)"
              }

            }

          }
          
          $FirstEvent = ConvertFrom-TextLog -LogLines $LogFile.FirstLine -LogFormat $LogFile.LogFormat -Fields $LogFile.FirstLine.SourceLogFile.Fields
          $LogStartDate = Get-LogEventDate -Event $FirstEvent
          Remove-Variable -Name FirstEvent

          if ($LogStartDate -le $End){

            #Convert the local path of the file to a UNC path
            $FilePath = $LogFile.FullName -replace ':','$'
            $FilePath = "\\$($LogFile.PSComputerName)\$FilePath"

            #Get the last line of the log file
              Write-Log -Type 'Verbose' -Text "Get-TextLog`tGet-Content -Path '$FilePath' -Tail 1"
              $LastLine = Get-Content -Path $FilePath -Tail 1 -ErrorAction SilentlyContinue
            
            $LastEvent = ConvertFrom-TextLog -LogLines $LastLine -LogFormat $LogFile.LogFormat -Fields $LogFile.FirstLine.SourceLogFile.Fields
            $LogEndDate = Get-LogEventDate -Event $LastEvent

            Remove-Variable -Name LastEvent

            if ($LogEndDate -ge $Start){

              Write-Output $LogFile

            }
            else{
              Write-Log -Type 'Debug' -Text "Get-TextLog`tThe last event in $($LogFile.FullName) was at $LogEndDate which is before the beginning of our timeframe to search: $Start"
            }
            Remove-Variable -Name LogEndDate
          }
          else{
            Write-Log -Type 'Debug' -Text "Get-TextLog`tThe first event in $($LogFile.FullName) was at $LogStartDate which is after the end of our timeframe to search: $End"
          }
          Remove-Variable -Name LogStartDate
        }
      }

    }

  }

  end{}

}

function Get-TextLogDevice{

  #Gets unique objects from the logs (such as unique devices, unique users, etc.)
  [CmdletBinding(SupportsShouldProcess=$false,ConfirmImpact="Low")]
  param(

    [PSObject[]]$InputObject,

    <#
    An optional filter to apply to the log objects
    Valid values are 'Unauthorized' or 'Unsuccessful'
    (anything else includes all log entries)
    #>
    [String]$Filter,

    #An optional username to verify the logs are for
    [String]$User

  )
  begin{
  
    #Connect a remote PowerShell session to the Exchange server (2010+) so we can use Get-ActiveSyncDeviceStatistics to look for more info about the devices.
    Import-Module "$PSScriptRoot\..\GadgetExchange.psm1" -WarningAction SilentlyContinue -Verbose:$false

    Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tGoGo-GadgetExchange -CommandNamesToImport 'Get-ActiveSyncDeviceStatistics' -ReturnSessionObject"
    $ExchangeSession = GoGo-GadgetExchange -CommandNamesToImport 'Get-ActiveSyncDeviceStatistics' -ReturnSessionObject
              
    #Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t$($ExchangeSession.GetType().FullName)"
    
    #Initialize the object that will store the results
    $TextLogObjects = New-Object -TypeName PSObject

    <#
    Which types of logs to search
    Valid values are 'IAS' or 'IIS-W3C' or 'NetLogon' or 'odbc'
    #>
    Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tSorting $($InputObject.Count) log events by format..."
    [String[]]$LogFormat = $InputObject.SourceLogLine.SourceLogFile.LogFormat | Sort-Object -Unique

  }
  process{

      ForEach ($TypeOfLog in $LogFormat){

        $CurrentLogs = $InputObject | Where-Object -FilterScript {$_.SourceLogLine.SourceLogFile.LogFormat -eq $TypeOfLog}

        Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tFound $($CurrentLogs.Count) $TypeOfLog log events..."

          #Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t`$CurrentLogs[0]: $($CurrentLogs[0] | fl * | Out-String)"

        #Filter the results
        Switch ($Filter) {
          'Unauthorized' {
            Switch ($TypeOfLog) {
              'IIS-W3C'{
                [String]$FilterVar = 'W3CscStatus'
                [ScriptBlock]$FilterScript = {$_.W3CscStatus -eq '401'}
                [ScriptBlock]$UserFilter = {($($_.W3CcsUsername -split '\\')[1] -eq $User) -or ($_.W3CcsUsername -eq $User) -or ($_.W3CcsUsername -like "$User@*")}
              }
              'IAS'{
                #[ScriptBlock]$FilterScript = {($_.'iasRadiusPacket-Type' -eq 3) -or ($_.'iasRadiusReason-Code' -eq 16)}
                [String]$FilterVar = 'iasRadiusPacket-Type'
                [ScriptBlock]$FilterScript = {$_.'iasRadiusPacket-Type' -eq 3}
                [ScriptBlock]$UserFilter = {(($_.'iasRadiusSAM-Account-Name' -split '\\')[1] -eq $User) -or ($_.'iasRadiusSAM-Account-Name' -eq $User) -or ($_.'iasRadiusSAM-Account-Name' -like "$User@*")}
              }
              'NetLogon'{
                [String]$FilterVar = 'NetLogonResultStatusCode'
                [ScriptBlock]$FilterScript = {$_.NetLogonResultStatusCode -eq '0xC000006A'}
                [ScriptBlock]$UserFilter = {($($_.NetLogonAttemptedAuthUser -split '\\')[1] -eq $User) -or ($_.NetLogonAttemptedAuthUser -eq $User) -or ($_.NetLogonAttemptedAuthUser -like "$User@*")}
              }
              'odbc'{
                [String]$FilterVar = 'npsReasonCode'
                [ScriptBlock]$FilterScript = {$_.'npsReasonCode' -eq 16}
                [ScriptBlock]$UserFilter = {(($_.'npsUserName' -split '\\')[1] -eq $User) -or ($_.'npsUserName' -eq $User) -or ($_.'npsUserName' -like "$User@*") -or ((($_.'npsFullyQualifiedDistinguishedName' -replace '"','' -split '\\')[1] -eq $User))}
                }
              default {
               #If we don't know the log format, we don't know how to filter.  So return everything.
               [ScriptBlock]$FilterScript = {$true}
               [ScriptBlock]$UserFilter = {$true}
              }
            }

            Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {$FilterScript}"
            $FilteredLogs = $CurrentLogs | Where-Object -FilterScript $FilterScript
            $Count = ($FilteredLogs | Measure-Object).Count
            Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tWhere-Object returned $Count log lines for unauthorized $TypeOfLog events."

            If ($Count -eq 0) {

                Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t$FilterVar : $($CurrentLogs | Group-Object -Property $FilterVar -NoElement | Out-String)"

            }

            if([String]::IsNullOrEmpty($User)){

            }
            else{

              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {$UserFilter}"
              $FilteredLogs = $FilteredLogs | Where-Object -FilterScript $UserFilter
              Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tWhere-Object returned $(($FilteredLogs | Measure-Object).Count) log lines for the user: $User"

            }

          }
          'Unsuccessful'{
            #TODO
          }
          default {

            $FilteredLogs = $CurrentLogs

          }

        }

        #Perform log processing (unique to each type of log)
        Switch ($TypeOfLog) {

          'IIS-W3C'{

            #Initialize the collection of unique objects we will return
            $IISw3CObjects = New-Object -TypeName System.Collections.Generic.List[PSObject]

            #Get the unique DeviceUserAgents
            $DeviceUserAgents = $FilteredLogs | Select-Object -ExpandProperty W3CcsUserAgent -ErrorAction SilentlyContinue | Sort-Object -Unique
            $Usernames = $FilteredLogs | Select-Object -ExpandProperty W3CcsUsername -ErrorAction SilentlyContinue | Sort-Object -Unique

            Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t$($DeviceUserAgents.Count) unique DeviceUserAgents from all matching log events."

            Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t`t$($DeviceUserAgents -join ' , ')"

            if ([String]::IsNullOrEmpty($Usernames)){

            }
            else{

                $ActiveSyncDeviceStats = @()
                ForEach ($Username in $Usernames){
                    Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tGet-ActiveSyncDeviceStatistics -Mailbox '$Username'"
                    $ScriptBlock = [ScriptBlock]::Create("Get-ActiveSyncDeviceStatistics -Mailbox '$Username'")
                    $ActiveSyncDeviceStats += Invoke-Command -ScriptBlock $ScriptBlock -Session $ExchangeSession
                }

              Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tGet-ActiveSyncDeviceStatistics returned $($ActiveSyncDeviceStats.Count) ActiveSync devices."

              #Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t`t$($ActiveSyncDeviceStats.DeviceUserAgent -join ' , ')"

            }

            ForEach($Agent in $DeviceUserAgents){

              #Add info for any ActiveSync devices that were found which match this DeviceUserAgent
              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {`$_.DeviceUserAgent -eq $Agent}"

              $MatchingActiveSyncDevices = $ActiveSyncDeviceStats | Where-Object -FilterScript {$_.DeviceUserAgent -eq $Agent}

              Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tWhere-Object returned $($MatchingActiveSyncDevices.Count) ActiveSync devices with the current DeviceUserAgent."

              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {`$_.W3CcsUserAgent -eq $Agent}"

              #Extract the logs for this DeviceUserAgent
              $MatchingLogs = $FilteredLogs | Where-Object -FilterScript {$_.W3CcsUserAgent -eq $Agent}

              Write-Log -Type 'Debug' -Text "Get-TextLogDevice`tWhere-Object returned $($MatchingLogs.Count) log events with the current DeviceUserAgent."

              $obj = New-Object -TypeName PSObject -Property (@{
                  'DeviceUserAgent' = $Agent
                  'MatchingActiveSyncDevices' = $MatchingActiveSyncDevices
                  'MatchingLogs' = $MatchingLogs
                })

              #Output the results
              $null = $IISw3CObjects.Add(($obj))

              $TextLogObjects | Add-Member -MemberType NoteProperty -Name IISW3CObjects -Value $IISw3CObjects -Force

            }
          }
          'IAS'{

            #Initialize the collection of unique devices we will return
            $IASObjects = New-Object -TypeName System.Collections.Generic.List[PSObject]

            #Get the unique devices
            $NASIPAddresses = $FilteredLogs | Select -ExpandProperty 'iasNAS-IP-Address' -ErrorAction SilentlyContinue | Sort-Object -Unique
            Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`t$($NASIPAddresses.Count) unique Network Access Server IP Addresses from all matching log events."
            #Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t`t$($NASIPAddresses -join ' , ')"

            ForEach($IP in $NASIPAddresses){

              #Extract the logs for this NAS-IP-Address
              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {`$_.'iasNAS-IP-Address' -eq $IP}"

              $MatchingLogs = $FilteredLogs | Where-Object -FilterScript {$_.'iasNAS-IP-Address' -eq $IP}

              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object returned $($MatchingLogs.Count) log events with the current NAS IP Address."

              $obj = New-Object -TypeName PSObject -Property (@{
                  'iasNAS-IP-Address' = $IP
                  'MatchingLogs' = $MatchingLogs
                })

              #Output the results
              $null = $IASObjects.Add(($obj))

              $TextLogObjects | Add-Member -MemberType NoteProperty -Name IASObjects -Value $IASObjects -Force

            }
          }
          'NetLogon'{

            #Initialize the collection of unique objects we will return
            $NetLogonObjects = New-Object -TypeName System.Collections.Generic.List[PSObject]

            #Get the unique DeviceUserAgents
            $SourceComputers = $FilteredLogs | Select -ExpandProperty NetLogonSourceComputer -ErrorAction SilentlyContinue | Sort-Object -Unique
            $Usernames = $FilteredLogs | Select -ExpandProperty NetLogonAttemptedAuthUser -ErrorAction SilentlyContinue | Sort-Object -Unique

            Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`t$($SourceComputers.Count) unique Source Computers from all matching log events."

            Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t`t$($SourceComputers -join ' , ')"

            ForEach($Comp in $SourceComputers){

              #Extract the logs for this NAS-IP-Address
              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {`$_.NetLogonSourceComputer -eq $Comp}"

              $MatchingLogs = $FilteredLogs | Where-Object -FilterScript {$_.NetLogonSourceComputer -eq $Comp}

              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object returned $($MatchingLogs.Count) log events with the current Source Computer."

              $obj = New-Object -TypeName PSObject -Property (@{
                  'NetLogonSourceComputer' = $Comp
                  'MatchingLogs' = $MatchingLogs
                })

              #Output the results
              $null = $NetLogonObjects.Add(($obj))

              $TextLogObjects | Add-Member -MemberType NoteProperty -Name NetLogonObjects -Value $NetLogonObjects -Force

            }

          }
          'odbc'{

            #Initialize the collection of unique devices we will return
            $NPSObjects = New-Object -TypeName System.Collections.Generic.List[PSObject]

            #Get the unique devices
            $NASIPAddresses = $FilteredLogs | Select -ExpandProperty 'npsNASIPAddress' -ErrorAction SilentlyContinue | Sort-Object -Unique
            Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`t$($NASIPAddresses.Count) unique Network Access Server IP Addresses from all matching log events."
            Write-Log -Type 'Debug' -Text "Get-TextLogDevice`t`t$($NASIPAddresses -join ' , ')"

            ForEach($IP in $NASIPAddresses){

              #Extract the logs for this NAS-IP-Address
              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object -FilterScript {`$_.'npsNASIPAddress' -eq $IP}"

              $MatchingLogs = $FilteredLogs | Where-Object -FilterScript {$_.'npsNASIPAddress' -eq $IP}

              Write-Log -Type 'Verbose' -Text "Get-TextLogDevice`tWhere-Object returned $($MatchingLogs.Count) log events with the current NAS IP Address."

              $obj = New-Object -TypeName PSObject -Property (@{
                  'npsNASIPAddress' = $IP
                  'MatchingLogs' = $MatchingLogs
                })

              #Output the results
              $null = $NPSObjects.Add(($obj))

              $TextLogObjects | Add-Member -MemberType NoteProperty -Name NPSObjects -Value $NPSObjects -Force

            }
          }

        }

      }

  }
  end{

    #Remove the PSSession with the Exchange server
    try{Remove-PSSession $ExchangeSession -ErrorAction Stop -Verbose:$false}catch{}

    Write-Output $TextLogObjects

  }
}

function Search-TextLog{
  <#
  .SYNOPSIS
    Search text logs and return a collection of objects representing the matching log events
  .DESCRIPTION
    Large log files on remote systems need to be searched on the remote system.
    This function uses PSRemoting to perform the search remotely, and return only the search results.
    This is much faster than trying to copy the entire log over a slow WAN connection and then search it.
  .OUTPUTS
      System.Object[]. Collection of objects representing the events that matched the search criteria
  .EXAMPLE
      Search-TextLog -StringToFind 'john.doe'
  .EXAMPLE
      Search-TextLog -StringToFind 'john.doe' -ComputerName 'Computer1'
  .EXAMPLE
      Search-TextLog -StringToFind 'john.doe' -ComputerName 'Computer1','Computer2' -End '1/2/2000' -Start '1/1/2000' -LogFolder 'C:\CustomIISLogPath' -LogFormat 'Exchange'
  .NOTES
      Prerequisites: WinRM must be enabled on the remote IIS or IAS/NPS server
      Tested running on Windows 8.1 searching the logs from IIS 8 / Exchange 2010 on Server 2012
      ToDo: Currently only optimized for ActiveSync logs. What about Outlook? Slightly different info, need to fix RegEx for the W3CcsUriQueryLog
      ToDo: Figure out to process the W3CcsUriQueryLogBudget.  See .\Testing\BudgetTest.ps1
  #>
  [CmdletBinding(SupportsShouldProcess=$false,ConfirmImpact="Low")]
  param(

    <#
    String to find in the text logs (a user or IP address, for example)
    This will be passed to the -Pattern parameter of Select-String.
    #>
    [parameter(Mandatory=$true,ValueFromPipeLine=$false,Position=0)]
    [String]$StringToFind,

    <#
    Computers whose logs to search
    This will be passed to the -ComputerName parameter of New-PsSession.
    #>
    [parameter(Mandatory=$false,ValueFromPipeLine=$false,Position=1)]
    [String[]]$ComputerName = 'localhost',

    <#
    The log files to search
    #>
    [parameter(Mandatory=$false,ValueFromPipeLine=$false,Position=2)]
    [PSObject[]]$LogFile,

    #An existing PSSession to the remote computer.  Only works with 1 computer specified.
    [System.Management.Automation.Runspaces.PSSession]$PSSession

  )
  begin{

    #Initialize counters used to Write-Progress
    $n=0
    $count = $ComputerName.Count

    $hostname = hostname

    [System.Collections.Generic.List[PSObject]]$Results = New-Object -TypeName System.Collections.Generic.List[PSObject]

  }
  process{

    ForEach ($Computer in $ComputerName){

      #Write-Log -Type 'Verbose' -Text "Search-TextLog`tBegin`tSearch $Computer for $StringToFind"

      #Calculate the completion percentage, and format it to show 0 decimal places
      $n++
      $percentage = "{0:N0}" -f (($n/($count+1))*100)

      #Indicate how many computers have been processed
      #Write-Progress -Activity ("Seaching Logs") -Status ("Status: $percentage% - Querying computer $n of $count`: $Computer") -PercentComplete $percentage
      
      if (!$PSSession){
        $RemovePSSession = $true
          #Start a new PSSession on the remote computer
          try{

            $PSSession = New-PSSession -ComputerName $Computer -ErrorAction Stop

          }
          catch{

            Write-Log -Type 'Verbose' -Text "Get-TextLog`tCould not establish remote PSSession on $Computer."
            Continue

          }

      }

      #Write-Log -Type 'Debug' -Text "Search-TextLog`t`$LogFile = @('$($LogFile -join "','")')"
      #Write-Log -Type 'Debug' -Text "Search-TextLog`t`$String = `"$StringToFind`""
      #Write-Log -Type 'Debug' -Text "Search-TextLog`t`$VerbosePref = `"$VerbosePreference`""
      #Write-Log -Type 'Debug' -Text "Search-TextLog`t`$DebugPref = `"$DebugPreference`""

      #Use the PSSession to perform the search on the remote computer
      [System.Collections.Generic.List[PSObject]]$CurrentComputerSearchResults = Invoke-Command -Session $PSSession -ScriptBlock{
          param(
            $LogFiles,
            $String,
            $VerbosePref,
            $DebugPref
          )

          $VerbosePreference = $VerbosePref
          $DebugPreference = $DebugPref

          #Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`t`$LogFiles = @('$($LogFiles -join "','")')"
          #Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`t`$String = `"$String`""
          #Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`t`$VerbosePref = `"$VerbosePreference`""
          #Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`t`$DebugPref = `"$DebugPreference`""

          [System.Collections.Generic.List[PSObject]]$MatchingLines = New-Object -TypeName System.Collections.Generic.List[PSObject]

          if($LogFiles -ne $null) {
            ForEach ($LogFile in $LogFiles) {

              #Search the log. Use -LiteralPath if possible because it properly handles spaces in the file path
              try{
                Write-Verbose "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`tSelect-String -LiteralPath `"$($LogFile.FullName)`" -pattern `"$String`""
                [PSObject[]]$CurrentMatchingLines = Select-String -LiteralPath "$($LogFile.FullName)" -pattern "$String"
              }
              catch [System.Management.Automation.ParameterBindingException]{
                Write-Verbose "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`tSelect-String -Path `"$($LogFile.FullName)`" -pattern `"$String`""
                [PSObject[]]$CurrentMatchingLines = Select-String -Path "$($LogFile.FullName)" -pattern "$String" -ErrorAction SilentlyContinue
              }
              catch{
                Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`tSelect-String`tError: $($_.Exception.Message)"
              }

              if($CurrentMatchingLines.Count -ge 1){
                Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`tSelect-String returned $($CurrentMatchingLines.Count) matching lines in $($LogFile.FullName) on $($(hostname))"
                ForEach($CurrentMatchingLine in $CurrentMatchingLines){
                  $CurrentMatchingLine | Add-Member -MemberType NoteProperty -Name SourceLogFile -Value $LogFile
                  $CurrentMatchingLine | Add-Member -MemberType NoteProperty -Name SourceLogComputer -Value $(hostname)
                  $null = $MatchingLines.Add($CurrentMatchingLine)
                }
              }
              else {
                Write-Debug "$(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`tSelect-String returned no matching lines in $($LogFile.FullName)"
              }
            }
          }
          Write-Debug "   $(Get-Date -Format s)`t$(hostname)`tSearch-TextLog`tTotal Number of Matching Lines:`t$($MatchingLines.Count)"
          Write-Output $MatchingLines
        } -ArgumentList $LogFile,$StringToFind,$VerbosePreference,$DebugPreference

      #Close the remote session
      
      if ($RemovePSSession -eq $true){
        $PSSession | Remove-PSSession -ErrorAction SilentlyContinue
    }

      Write-Log -Type 'Debug' -Text "Search-TextLog`t$Computer yielded $($CurrentComputerSearchResults.Count) results."
      $CurrentComputerSearchResults | ForEach-Object{$null = $Results.Add($_)}
      Write-Log -Type 'Debug' -Text "Search-TextLog`tCurrently $($Results.Count) results."
    }
  }
  end{
    Write-Progress -Activity 'Seaching Logs' -Completed
    Write-Log -Type 'Debug' -Text "Search-TextLog`tReturning $($Results.Count) results."
    Write-Output $Results
  }
}

<#
Class TextLogg{
  [String]$LogFormat
  [String]$Path
  [String]$FirstLine
  TextLog(){
    $This.LogType = ''
    $This.Path = ''
    $This.FirstLine = ''
  }
}
#>
#$Object = New-Object 'TextLogg'
