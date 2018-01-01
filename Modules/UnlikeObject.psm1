function Export-UnlikeObject{
    <#
    .SYNOPSIS
         Exports a collection of objects to CSV and includes all the properties of every object.
    .DESCRIPTION
        This function is a layer on top of Export-CSV that enumerates the properties of every object in the provided collection.
        It ensures that each object has all of its properties exported, whereas Export-CSV on its own only exports the properties of the first object.
    .OUTPUTS
        The CSV file is created but no output is returned to the pipeline.
    .EXAMPLE
        This example will create Export.CSV in the same folder the script is saved in.
            $SampleObjects | Export-UnlikeObject
    .EXAMPLE
        This example will create Sample.CSV in the C:\Test folder:
            $SampleObjects | Export-UnlikeObject -LiteralPath 'C:\Test\Sample.CSV'
    #>
    [CmdletBinding(SupportsShouldProcess=$false,ConfirmImpact="Low")]
    param(
        #Collection of objects that you want to export to CSV
        [parameter(Mandatory=$true,ValueFromPipeLine=$true)]
        [AllowNull()]
        [System.Object[]]$Object,

        #The complete file path (including the file name) of the new CSV file to create.
        [parameter(Mandatory=$false)]
        [String]$LiteralPath = "$PSScriptRoot\Export.csv"
    )
    begin{
        Write-Log -Type 'Debug' -Text "Export-UnlikeObject`tExporting $($Object.Count) objects to $LiteralPath"
        Write-Log -Type 'Debug' -Text "Export-UnlikeObject`tDrives: $((Get-PSDrive).Name -join ' ')"
    }
    process{
        #Determine all the unique properties that we need to export
        $UniqueProperties = $Object | ForEach-Object { $_.PSObject.Properties | Select -ExpandProperty Name } | Sort-Object -Unique

        #Export all the things
        $Object | Select-Object $UniqueProperties | Export-CSV -LiteralPath $LiteralPath -NoTypeInformation -Force
    }
    end{}
}