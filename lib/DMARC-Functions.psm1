function Get-ParsedDMARCReport {
    param(
        $XMLData
    )

    # Helper function to check domain alignment
    function Test-DomainAlignment {
        param (
            $fromDomain,
            $checkDomain,
            $alignmentMode
        )
        if ($alignmentMode -eq 's') {
            return $fromDomain -eq $checkDomain
        } elseif ($alignmentMode -eq 'r') {
            return $fromDomain -eq $checkDomain -or $fromDomain.EndsWith(".$checkDomain")
        }
    }

    #$XMLData #= $XMLData.feedback
    $PolicyDetail = $XMLData.policy_published | Get-ParsedPolicyValues
    $IdentifiedSources = @()
    foreach ($record in $XMLData.record) {
        if (!(Is-ValidIPv4 $record.row.source_ip)) {
            Write-host "$($record.row.source_ip) is not a valid IPV4 Address"
            $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
            $IPAddress = (Resolve-DnsName $NameHost -Type A).IPaddress
        }
        else {
            $IPAddress = $record.row.source_ip
            $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
        }
        
        #$PTRServer = if ($HostInfo.Name -isnot [string]) {$HostInfo.Name[0]}else{$HostInfo.Name}
        $GeoData = Get-IpgeoLocation -IPAddress $IPAddress -Database $Global:DMARCConfig.GEODATADB
        $spfDomain = $record.auth_results.spf.domain
        $fromDomain = $record.identifiers.header_from
        $spfAligned = Test-DomainAlignment -fromDomain $fromDomain -checkDomain $spfDomain -alignmentMode $PolicyDetail.SPFAlignment[0]

        foreach ($dkim in $record.auth_results.dkim) {
            $dkimDomain = $dkim.domain
            $dkimAligned = Test-DomainAlignment -fromDomain $fromDomain -checkDomain $dkimDomain -alignmentMode $PolicyDetail.DKIMAlignment[0]

            $IdentifiedSources += [pscustomobject]@{
                Source      = $GeoData.organization
                From        = $record.identifiers.header_from
                IP          = $IPAddress
                PTRServer   = $NameHost
                Country     = $GeoData.countrycode
                Latitude    = $GeoData.latitude
                Longitude   = $GeoData.longitude
                CountryFlag = $GeoData.flag
                Volume      = $record.row.count
                ActionTaken = ""
                SPF         = [pscustomobject]@{
                    MailFromDomain = $spfDomain
                    DMARCResult    = if ($spfAligned) { "aligned" } else { "not aligned" }
                    SPFResult      = $record.auth_results.spf.result
                }
                DKIM        = [pscustomobject]@{
                    Domain      = $dkim.domain
                    Selector    = $dkim.selector
                    DMARCResult = if ($dkimAligned) { "aligned" } else { "not aligned" }
                    DKIMResult  = $dkim.result
                }
            }
        }
    }

    $Report = [pscustomobject]@{
        ReportDetails     = [pscustomobject]@{
            ReportID     = $XMLData.report_metadata.report_id
            Provider     = $XMLData.report_metadata.org_name
            EmailContact = $XMLData.report_metadata.email
            Coverage     = [pscustomobject]@{
                Begin = [System.DateTime]::UnixEpoch.AddSeconds($XMLData.report_metadata.date_range.begin).ToLocalTime()
                End   = [System.DateTime]::UnixEpoch.AddSeconds($XMLData.report_metadata.date_range.end).ToLocalTime()
            }
        }
        PolicyDetail      = $PolicyDetail
        IdentifiedSources = $IdentifiedSources
    }
    return $Report
}

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
                    DmarcAlligned = Test-DomainAlignment -fromDomain $record.identifiers.envelope_from -checkDomain $record.identifiers.header_from -alignmentMode $policyPublished.Adkim
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
    $Policy = switch ($policyTable.p) {
        "none" { "Unspecified (defaults to Policy)" }
    }
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
        DKIMAlignment  = $DKIMAlignment
        SPFAlignment   = $SPFAlignment
        Policy         = $Policy
        Percentage     = $policyTable.pct
        FailureOptions = $FailureOptionsParsed -join ", "
    }
}

function Get-ServiceFromRootName  {
    param(
        $Domain,
        $CSV
    )
    ((Import-CSV $CSV) | where {$_.Domain -eq $Domain}).Service
}

function Get-RootDomain {
    param(
        $Address
    )
    $Address -replace '.*\.(.*\..*)', '*.$1'
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

function Get-XmlFromBase64Gzip {
    param (
        [string]$Base64Data
    )

    # Convert the base64 string to a byte array
    $byteArray = [System.Convert]::FromBase64String($Base64Data)
    
    # Create a memory stream from the byte array
    $memoryStream = New-Object System.IO.MemoryStream
    $memoryStream.Write($byteArray, 0, $byteArray.Length)
    $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

    # Create a GZipStream to decompress the data
    $gzipStream = New-Object System.IO.Compression.GZipStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
    
    # Create a stream reader to read the decompressed data
    $streamReader = New-Object System.IO.StreamReader($gzipStream)
    $xmlContent = $streamReader.ReadToEnd()

    # Close the streams
    $streamReader.Close()
    $gzipStream.Close()
    $memoryStream.Close()

    # Return the XML content
    return $xmlContent
}

function Get-XmlFromBase64Zip {
    param (
        [string]$Base64Data
    )

    # Convert the base64 string to a byte array
    $byteArray = [System.Convert]::FromBase64String($Base64Data)
    
    # Create a memory stream from the byte array
    $memoryStream = New-Object System.IO.MemoryStream
    $memoryStream.Write($byteArray, 0, $byteArray.Length)
    $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

    # Create a ZipArchive to access the zip file
    $zipArchive = New-Object System.IO.Compression.ZipArchive($memoryStream, [System.IO.Compression.ZipArchiveMode]::Read)
    
    # Assuming the XML file is the first entry in the zip archive
    $zipEntry = $zipArchive.Entries[0]

    # Create a stream reader to read the entry
    $streamReader = New-Object System.IO.StreamReader($zipEntry.Open())
    $xmlContent = $streamReader.ReadToEnd()

    # Close the streams
    $streamReader.Close()
    $zipArchive.Dispose()
    $memoryStream.Close()

    # Return the XML content
    return $xmlContent
}

function Import-Configuration {
    param(
        $ConfigurationFilePath
    )
    Remove-Variable -Name DMARCConfig -Scope Global
    $Global:DMARCConfig = Import-PowerShellDataFile -Path $ConfigurationFilePath -Verbose
}

function Import-DMARCReport {
    param(
        [Parameter(ValueFromPipeline)]
        $XMLFile
    )
    PROCESS {
        ([xml](Get-Content $XMLFile -raw)).feedback
    }
}

Export-ModuleMember -Function *