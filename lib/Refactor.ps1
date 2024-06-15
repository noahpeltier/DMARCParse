#region Master functions
function Invoke-ParseDmarcReport {
    param (
        [string]$xmlFilePath
    )

    # Load the XML file
    [xml]$xmlDoc = Get-Content -Path $xmlFilePath -raw

    # Parse report metadata
    $reportMetadata = @{
        OrgName   = $xmlDoc.feedback.report_metadata.org_name
        Email     = $xmlDoc.feedback.report_metadata.email
        ReportID  = $xmlDoc.feedback.report_metadata.report_id
        DateRange = @{
            Begin = [datetime]::FromFileTimeUtc([long]$xmlDoc.feedback.report_metadata.date_range.begin * 10000000 + 116444736000000000)
            End   = [datetime]::FromFileTimeUtc([long]$xmlDoc.feedback.report_metadata.date_range.end * 10000000 + 116444736000000000)
        }
    }

    # Parse policy published
    $policyPublished = @{
        Domain = $xmlDoc.feedback.policy_published.domain
        Adkim  = $xmlDoc.feedback.policy_published.adkim
        Aspf   = $xmlDoc.feedback.policy_published.aspf
        P      = $xmlDoc.feedback.policy_published.p
        Sp     = $xmlDoc.feedback.policy_published.sp
        Pct    = $xmlDoc.feedback.policy_published.pct
        Fo     = $xmlDoc.feedback.policy_published.fo
    } | Get-ParsedPolicyValues

    # Parse each record in the report
    $records = [System.Collections.Generic.List[Object]]::new()
    foreach ($record in $xmlDoc.feedback.record) {
        if (!(Is-ValidIPv4 $record.row.source_ip)) {
            Write-host "$($record.row.source_ip) is not a valid IPV4 Address"
            $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
            $IPAddress = (Resolve-DnsName $NameHost -Type A).IPaddress
            
        }
        else {
            $IPAddress = $record.row.source_ip
            $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
        }

        $SourceDomain = Get-RootDomain $NameHost
        $ServiceName = Get-ServiceFromRootName -Domain $SourceDomain -CSV $DMARCConfig.DomainServicesCSV
        $GEOData = (Get-IPGeoLocation -IPAddress $IPAddress -Database $DMARCConfig.GEODATADB)

        $recordObj = [PSCustomObject]@{
            SourceDomain    = $SourceDomain
            ServiceName     = $ServiceName
            SourceIP        = $record.row.source_ip
            PTRServer       = $NameHost
            Count           = $record.row.count
            Disposition     = $record.row.policy_evaluated.disposition
            DKIMResult      = $record.row.policy_evaluated.dkim
            SPFResult       = $record.row.policy_evaluated.spf
            EnvelopeTo      = $record.identifiers.envelope_to
            EnvelopeFrom    = $record.identifiers.envelope_from
            HeaderFrom      = $record.identifiers.header_from
            DKIMAuthResults = [System.Collections.Generic.List[Object]]::new()
            SPFResultList   = [System.Collections.Generic.List[Object]]::new()
            DmarcCompliance = ""
            Country         = $GEOData.flag
            Latitude        = $GEOData.Latitude
            Longitude       = $GEOData.Longitude
        }

        foreach ($dkim in $record.auth_results.dkim) {
            $recordObj.DKIMAuthResults.Add(
                [PSCustomObject]@{
                    Domain        = $dkim.domain
                    Selector      = $dkim.selector
                    Result        = $dkim.result
                    DmarcAlligned = Test-DKIMAlligned $record -AlignmentMode 
                    #Test-DomainAlignment -fromDomain $record.identifiers.envelope_from -checkDomain $record.identifiers.header_from -alignmentMode $policyPublished.Adkim
                }
            )
        }

        foreach ($spf in $record.auth_results.spf) {
            $recordObj.SPFResultList.Add(
                [PSCustomObject]@{
                    Domain        = $spf.domain
                    Scope         = $spf.scope
                    Result        = $spf.result
                    DmarcAlligned = Test-DomainAlignment -fromDomain $record.identifiers.envelope_from -checkDomain $record.identifiers.header_from -alignmentMode $policyPublished.aspf
                }
            )
        }

        # Calculate DMARC Compliance
        $recordObj.DmarcCompliance = ($recordObj.DKIMResult -eq "pass" -or $recordObj.SPFResult -eq "pass")

        $records.Add($recordObj)
    }

    # Create a custom object to hold the entire parsed report
    $report = [PSCustomObject]@{
        ReportMetadata  = $reportMetadata
        PolicyPublished = $policyPublished
        Records         = $records
    }

    return $report
}
#endregion

#region Helper functions

function Get-ServiceFromRootName {
    param(
        $Domain,
        $CSV
    )
    ((Import-CSV $CSV) | where { $_.Domain -eq $Domain }).Service
}

function Is-ValidIPv4 {
    param (
        [string]$ipAddress
    )

    $regex = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    if ($ipAddress -match $regex) {
        return $true
    } else {
        return $false
    }
}

function Get-RootDomain {
    param(
        [string]$Address
    )

    if ($Address -match '@') {
        # Extract the domain part if an email address is provided
        $Address = $Address -replace '.*@'
    }

    # Match the root domain part
    if ($Address -match '([^.]+\.[^.]+)$') {
        return $matches[0]
    }

    return $null
}

function Get-IPGeoLocation {
    param(
        $IPAddress,
        $Database,
        $Connection
    )
    $ip = [Net.IPAddress]::Parse($IPAddress)
    $UINT32 = [Uint32](  [IPAddress]::HostToNetworkOrder($ip.Address) -shr 32 -band [UInt32]::MaxValue )
    $Query = "SELECT * FROM ranges WHERE $UINT32 BETWEEN ipstart AND ipend;"
    if ($Database) {
        $ReturnedObject = Invoke-SqliteQuery -DataSource $Database -Query $Query
    }
    else {
        $ReturnedObject = Invoke-SqliteQuery -SQLiteConnection $Connection -Query $Query
    }
    $ReturnedObject | Add-Member -Type NoteProperty -Name Flag -Value "https://flagsapi.com/$($ReturnedObject.countrycode)/flat/32.png"
    $ReturnedObject | Add-Member -Type NoteProperty -Name IPAddress -Value $IPAddress

    return $ReturnedObject
}

function Test-DomainAlignment {
    param (
        [string]$fromDomain,
        [string]$checkDomain,
        [string]$alignmentMode
    )

    # Check strict (s) alignment
    if ($alignmentMode -eq 's') {
        return $fromDomain -eq $checkDomain
    }
    # Check relaxed (r) alignment
    elseif ($alignmentMode -eq 'r') {
        return ($fromDomain -eq $checkDomain) -or ($fromDomain.EndsWith(".$checkDomain"))
    }
    return $false
}

function Test-SPFAlligned {
    param(
        $Record,
        [ValidateSet("Strict","Relaxed")]
        $AlignmentMode
    )
    $Result = switch ($AlignmentMode) {
        "Strict" {
            ($Record.Identifiers.envelope_from) -eq ($Record.Identifiers.header_from)
        }
        "Relaxed" {
            (Get-RootDomain $Record.Identifiers.envelope_from) -eq (Get-RootDomain $Record.Identifiers.header_from)
        }
    }
    $result -as [bool]
}

function Test-DKIMAlligned {
    param(
        $Record,
        [ValidateSet("Strict","Relaxed")]
        $AlignmentMode
    )
    $Result = switch ($AlignmentMode) {
        "Strict" {
            ($Record.auth_results.dkim.domain) -eq ($Record.Identifiers.header_from)
        }
        "Relaxed" {
            (Get-RootDomain $Record.auth_results.dkim.domain) -eq (Get-RootDomain $Record.Identifiers.header_from)
        }
    }
    $result -as [bool]
}

function Get-ParsedPolicyValues {
    param(
        [Parameter(ValueFromPipeline)]
        $policyTable
    )
    $DKIMAlignment = switch ($policyTable.adkim) {
        "r" { "Relaxed" }
        "s" { "Strict" }
    }
    $SPFAlignment = switch ($policyTable.aspf) { 
        "r" { "Relaxed" }
        "s" { "Strict" }
    }

    $Policy = $policyTable.p 
    $SubdomainPolicy = $policyTable.Sp

    $FailureOptions = $policyTable.fo -split ":"
    $FailureOptionsParsed = foreach ($option in $FailureOptions) {
        switch ($option) {
            "0" { "Generate failure report if both SPF and DKIM fail" }
            "1" { "Generate failure report if any of SPF or DKIM fail" }
            "d" { "Generate DKIM failure report" }
            "s" { "Generate SPF failure report" }
        }
    }

    [ordered]@{
        Policy          = $Policy
        SubdomainPolicy = $SubdomainPolicy
        DKIMAlignment   = $DKIMAlignment
        SPFAlignment    = $SPFAlignment
        Percentage      = $policyTable.pct
        FailureOptions  = $FailureOptionsParsed -join ", "
    }
}

function Convert-FileTimeToDateTime {
    param ([long]$fileTime)
    return [datetime]::FromFileTimeUtc($fileTime * 10000000 + 116444736000000000)
}

function Resolve-ValidIPAddress {
    param ([string]$ipAddress)
    if (!(Is-ValidIPv4 $ipAddress)) {
        Write-Host "$ipAddress is not a valid IPV4 Address"
        $NameHost = (Resolve-DnsName $ipAddress -QuickTimeout).NameHost
        return (Resolve-DnsName $NameHost -Type A -QuickTimeout).IPAddress
    }
    return $ipAddress
}

function Import-XML {
    param(
        $xmlFilePath
    )
    [xml](Get-Content -Path $xmlFilePath -raw)
}

function Import-Configuration {
    param(
        $ConfigurationFilePath
    )
    Remove-Variable -Name DMARCConfig -Scope Global
    $Global:DMARCConfig = Import-PowerShellDataFile -Path $ConfigurationFilePath -Verbose
}

function New-List {
    param(
        [type]$Type = "Object"
    )
    New-Object System.Collections.Generic.List[$Type]
}
#endregion

#region DMARC processing functions
function Get-DMARCReportMetadata {
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$xmlDoc
    )
    $reportMetadata = @{
        OrgName   = $xmlDoc.feedback.report_metadata.org_name
        Email     = $xmlDoc.feedback.report_metadata.email
        ReportID  = $xmlDoc.feedback.report_metadata.report_id
        DateRange = @{
            Begin = [datetime]::FromFileTimeUtc([long]$xmlDoc.feedback.report_metadata.date_range.begin * 10000000 + 116444736000000000)
            End   = [datetime]::FromFileTimeUtc([long]$xmlDoc.feedback.report_metadata.date_range.end * 10000000 + 116444736000000000)
        }
    }

    return $reportMetadata
}

function Get-DMARCReportPolicyDetails {
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$xmlDoc
    )
    @{
        Domain = $xmlDoc.feedback.policy_published.domain
        Adkim  = $xmlDoc.feedback.policy_published.adkim
        Aspf   = $xmlDoc.feedback.policy_published.aspf
        P      = $xmlDoc.feedback.policy_published.p
        Sp     = $xmlDoc.feedback.policy_published.sp
        Pct    = $xmlDoc.feedback.policy_published.pct
        Fo     = $xmlDoc.feedback.policy_published.fo

    } | Get-ParsedPolicyValues


}

function Get-DMARCReportRecords {
    param(
        [Parameter(ValueFromPipeline)]
        [xml]$xmlDoc,
        [switch]$NoGeoData
    )
    BEGIN {
        $records = [System.Collections.Generic.List[Object]]::new()

    }

    PROCESS {
        foreach ($record in $xmlDoc.feedback.record) {
            if (!(Is-ValidIPv4 $record.row.source_ip)) {
                Write-host "$($record.row.source_ip) is not a valid IPV4 Address"
                $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
                $IPAddress = (Resolve-DnsName $NameHost -Type A).IPaddress
            
            }
            else {
                $IPAddress = $record.row.source_ip
                $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
            }

            $SourceDomain = Get-RootDomain $NameHost
            $ServiceName = Get-ServiceFromRootName -Domain $SourceDomain -CSV $DMARCConfig.DomainServicesCSV
            if (!$NoGeoData) {
                $GEOData = (Get-IPGeoLocation -IPAddress $IPAddress -Database $DMARCConfig.GEODATADB)
            }

            $recordObj = [PSCustomObject]@{
                SourceDomain    = $SourceDomain
                ServiceName     = $ServiceName
                SourceIP        = $record.row.source_ip
                PTRServer       = $NameHost
                Count           = $record.row.count
                Disposition     = $record.row.policy_evaluated.disposition
                DKIMResult      = $record.row.policy_evaluated.dkim
                SPFResult       = $record.row.policy_evaluated.spf
                EnvelopeTo      = $record.identifiers.envelope_to
                EnvelopeFrom    = $record.identifiers.envelope_from
                HeaderFrom      = $record.identifiers.header_from
                DKIMAuthResults = [System.Collections.Generic.List[Object]]::new()
                SPFResultList   = [System.Collections.Generic.List[Object]]::new()
                DmarcCompliance = ""
                Country         = $GEOData.flag
                Latitude        = $GEOData.Latitude
                Longitude       = $GEOData.Longitude
                DKIMAlligned = Test-DKIMAlligned $record -AlignmentMode ($xmlDoc | Get-DMARCReportPolicyDetails).dkimalignment
                SPFAlligned = Test-SPFAlligned $record -AlignmentMode ($xmlDoc | Get-DMARCReportPolicyDetails).spfalignment
            }

            foreach ($dkim in $record.auth_results.dkim) {
                $recordObj.DKIMAuthResults.Add(
                    [PSCustomObject]@{
                        Domain        = $dkim.domain
                        Selector      = $dkim.selector
                        Result        = $dkim.result
                        DmarcAlligned = Test-DKIMAlligned $record -AlignmentMode ($xmlDoc | Get-DMARCReportPolicyDetails).dkimalignment
                        #Test-DomainAlignment -fromDomain $record.identifiers.envelope_from -checkDomain $record.identifiers.header_from -alignmentMode $policyPublished.Adkim
                    }
                )
            }

            foreach ($spf in $record.auth_results.spf) {
                $recordObj.SPFResultList.Add(
                    [PSCustomObject]@{
                        Domain        = $spf.domain
                        Scope         = $spf.scope
                        Result        = $spf.result
                        DmarcAlligned = Test-SPFAlligned $record -AlignmentMode ($xmlDoc | Get-DMARCReportPolicyDetails).spfalignment
                        #Test-DomainAlignment -fromDomain $record.identifiers.envelope_from -checkDomain $record.identifiers.header_from -alignmentMode $policyPublished.aspf
                    }
                )
            }

            # Calculate DMARC Compliance
            $recordObj.DmarcCompliance = ($recordObj.DKIMResult -eq "pass" -or $recordObj.SPFResult -eq "pass")

            $records.Add($recordObj)
        }
        return $records
    }
}

#endregion

Import-Configuration -ConfigurationFilePath .\config\Config.psd1
$XML = (import-XMl .\docs\dmarc_reports\enterprise.protection.outlook.com!apcisg.com!1717372800!1717459200.xml) 

$Metadata = $XML | Get-DMARCReportMetadata
$Details = $XML | Get-DMARCReportPolicyDetails
$Records = $XML | Get-DMARCReportRecords -NoGeoData
$passCount = ($array | Where-Object { $_ -eq "pass" }).Count
$failCount = ($array | Where-Object { $_ -eq "fail" }).Count
$totalCount = $array.Count

$spfpassrate  = $records | where {$_.SPFAlligned}
$DKIMAlignmentRate = ""