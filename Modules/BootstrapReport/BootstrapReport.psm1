Function New-BootstrapTable {
    <#
        .SYNOPSIS
            Upgrade a boring HTML table to a fancy Bootstrap table
        .DESCRIPTION
            Applies the Bootstrap 'table table-striped' class to an HTML table
        .OUTPUTS
            A string wih the code for the Bootstrap table
        .EXAMPLE
            New-BootstrapTable -HtmlTable '<table><tr><th>Name</th><th>Id</th></tr><tr><td>ALMon</td><td>5540</td></tr></table>'

            This example returns the following string:
            '<table class="table table-striped"><tr><th>Name</th><th>Id</th></tr><tr><td>ALMon</td><td>5540</td></tr></table>'
        .NOTES
            Author: Jeremy La Camera
            Last Updated: 11/6/2016
    #>
    [CmdletBinding()]
    param(
        #The HTML table to apply the Bootstrap striped table CSS class to
        [Parameter(
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [System.String[]]$HtmlTable
    )
    begin{}
    process{
        ForEach ($Table in $HtmlTable) {
            [String]$NewTable = $Table -replace '<table>','<table class="table table-striped">'
            Write-Output $NewTable
        }
    }
    end{}
}

function New-BootstrapReport {
    <#
        .SYNOPSIS
            Build a new Bootstrap report based on an HTML template
        .DESCRIPTION
            Inserts the specified title, description, and body into the HTML report template
        .OUTPUTS
            Outputs a complete HTML report as a string
        .EXAMPLE
            New-BootstrapReport -Title 'ReportTitle' -Description 'This is the report description' -Body 'This is the body of the report'
        .NOTES
            Author: Jeremy La Camera
            Last Updated: 11/6/2016
    #>
    [CmdletBinding()]
    param(
        #Title of the report (displayed at the top)
        [String]$Title,

        #Description of the report (displayed below the Title)
        [String]$Description,

        #Body of the report (tables, list groups, etc.)
        [String[]]$Body,

        #The path to the HTML report template that includes the Boostrap CSS
        [String]$TemplatePath = "$PSScriptRoot\Templates\ReportTemplate.html"
    )
    begin{
        [String]$Report = Get-Content $TemplatePath
        if ($null -eq $report){Write-Host "$TemplatePath not loaded.  Failure.  Error.  Shiznit."}
    }
    process{
        $Report = $Report -replace '_ReportTitle_',$Title
        $Report = $Report -replace '_ReportDescription_',$Description
        $Report = $Report -replace '_ReportBody_',$Body
    }
    end{
        Write-Output $Report
    }
}

function New-HtmlHeading{
    <#
        .SYNOPSIS
            Build a new HTML heading
        .DESCRIPTION
            Inserts the specified text into an HTML heading of the specified level
        .OUTPUTS
            Outputs the heading as a string
        .EXAMPLE
            New-HtmlHeading -Text 'Example Heading'
        .NOTES
            Author: Jeremy La Camera
            Last Updated: 11/6/2016
    #>
    [CmdletBinding()]
    param(
        #The heading level to generate (New-HtmlHeading can create h1, h2, h3, h4, h5, or h6 tags)
        [ValidateRange(1,6)]
        [Int16]$Level = 1,

        #The text of the heading
        [String]$Text
    )
    begin{}
    process{
        Write-Output "<h$Level>$Text</h$Level>"
    }
    end{}
}