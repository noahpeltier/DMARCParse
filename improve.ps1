
$TestXML = [xml](Get-Content '.\yahoo.com!apcisg.com!1718064000!1718150399.xml (002)' -raw)

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

function Export-DmarcReportToHtml {
    param (
        [PSCustomObject]$DmarcReport,
        [string]$OutputFilePath
    )

    # Ensure Bootstrap CDN is available
    $bootstrapCdn = @"
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
"@

    # Group records by ServiceName
    $groupedRecords = $DmarcReport.Records | Group-Object -Property ServiceName

    # Create HTML content
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>DMARC Report</title>
    $bootstrapCdn
</head>
<body>
    <div class="container mt-5" style="max-width: 1700px; font-size: 13px;">
        <h1 class="mb-4">DMARC Report</h1>
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Report Metadata</h5>
                <p class="card-text"><strong>Org Name:</strong> $($DmarcReport.ReportMetadata.OrgName)</p>
                <p class="card-text"><strong>Email:</strong> $($DmarcReport.ReportMetadata.Email)</p>
                <p class="card-text"><strong>Report ID:</strong> $($DmarcReport.ReportMetadata.ReportID)</p>
                <p class="card-text"><strong>Date Range:</strong> $($DmarcReport.ReportMetadata.DateRange.Begin) - $($DmarcReport.ReportMetadata.DateRange.End)</p>
            </div>
        </div>
        <div class="accordion mt-4" id="accordionExample">
"@

    # Add records grouped by ServiceName
    $index = 0
    foreach ($group in $groupedRecords) {
        $index++
        $htmlContent += @"
            <div class="accordion-item">
                <h2 class="accordion-header" id="heading$index">
                    <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse$index" aria-expanded="true" aria-controls="collapse$index">
                        $($group.Name) ($($group.Count) records)
                    </button>
                </h2>
                <div id="collapse$index" class="accordion-collapse collapse" aria-labelledby="heading$index" data-bs-parent="#accordionExample">
                    <div class="accordion-body">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th scope="col">Source Domain</th>
                                    <th scope="col">Source IP</th>
                                    <th scope="col">PTR Server</th>
                                    <th scope="col">Count</th>
                                    <th scope="col">Disposition</th>
                                    <th scope="col">DKIM Result</th>
                                    <th scope="col">SPF Result</th>
                                    <th scope="col">Envelope To</th>
                                    <th scope="col">Envelope From</th>
                                    <th scope="col">Header From</th>
                                    <th scope="col">DMARC Compliance</th>
                                    <th scope="col">Country</th>
                                </tr>
                            </thead>
                            <tbody>
"@
        foreach ($record in $group.Group) {
            if ($record.SPFResult -eq "fail") {
                $SPFResult = "<span class='badge text-bg-danger'>$($record.SPFResult)</span>"
            }
            else {
                $SPFResult = "<span class='badge text-bg-success'>$($record.SPFResult)</span>"
            }
            if ($record.DKIMresult -eq "fail") {
                $DKIMResult = "<span class='badge text-bg-danger'>$($record.DKIMresult)</span>"
            }
            else {
                $DKIMResult = "<span class='badge text-bg-success'>$($record.DKIMresult)</span>"
            }
            $htmlContent += @"
                                <tr>
                                    <td>$($record.SourceDomain)</td>
                                    <td>$($record.SourceIP)</td>
                                    <td>$($record.PTRServer)</td>
                                    <td>$($record.Count)</td>
                                    <td>$($record.Disposition)</td>
                                    <td>$DKIMResult</td>
                                    <td>$SPFResult</td>
                                    <td>$($record.EnvelopeTo)</td>
                                    <td>$($record.EnvelopeFrom)</td>
                                    <td>$($record.HeaderFrom)</td>
                                    <td>$($record.DmarcCompliance)</td>
                                    <td><img src='$($record.Country)'></td>
                                </tr>
"@
        }
        $htmlContent += @"
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"@
    }

    # Closing HTML tags
    $htmlContent += @"
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js" integrity="sha384-oBqDVmMz9ATKxIep9tiCxS/Z9fNfEXiDAYTujMAeBAsjFuCZSmKbSSUnQlmh/jp3" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.min.js" integrity="sha384-cuYeSxntonz0PPNlHhBs68uyIAVpIIOZZ5JqeqvYYIcEL727kskC66kF92t6Xl2V" crossorigin="anonymous"></script>
</body>
</html>
"@

    # Save HTML content to file
    $htmlContent | Out-File -FilePath $OutputFilePath -Encoding UTF8
}

$result = Parse-DmarcReport -xmlFilePath '.\yahoo.com!apcisg.com!1718064000!1718150399.xml (002)'

Export-DmarcReportToHtml -DmarcReport $result -OutputFilePath ".\$($result.ReportMetadata.ReportID).html"
<#
$IdentifiedSources = [System.Collections.Generic.List[Object]]::new()
foreach ($record in $TestXML.feedback.record) {
    if (!(Is-ValidIPv4 $record.row.source_ip)) {
        Write-host "$($record.row.source_ip) is not a valid IPV4 Address"
        $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
        $IPAddress = (Resolve-DnsName $NameHost -Type A).IPaddress
        $SourceDomain = Get-RootDomain
    }
    else {
        $IPAddress = $record.row.source_ip
        $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
    }

    $Source = @{
        Source              = ""
        SourceConfiguration = ""
        Volume              = ""
        DMARCComplianceRate = ""
        SPFAllignmentRate   = ""
        DKIMAllignmetnRate  = ""
        Server              = @{
            Servername          = ""
            FromDomainCount     = ""
            Volume              = ""
            UniqueIPCount       = ""
            DMARCComplianceRate = @{
                TotalPercent = ""
                SPF          = ""
                DKIM         = ""
            }
            Records             = ""
        }
    }
}

foreach ($record in $TestXML.feedback.record) {
    # Fix the IP address to be an IPV4 to get the nslookup to work
    if (!(Is-ValidIPv4 $record.row.source_ip)) {
        Write-host "$($record.row.source_ip) is not a valid IPV4 Address"
        $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
        $IPAddress = (Resolve-DnsName $NameHost -Type A).IPaddress
        $SourceDomain = Get-RootDomain $NameHost
    }
    else {
        $IPAddress = $record.row.source_ip
        $NameHost = (Resolve-DnsName $record.row.source_ip).NameHost
        $SourceDomain = Get-RootDomain $NameHost
        $ServiceName = Get-ServiceFromRootName -Domain $SourceDomain -CSV .\domain-to-service.csv
    }
    $SourceDomain
    # Enumerate sources
    

}
$IPAddress
$NameHost
$SourceDomain
$ServiceName
@{
    Source              = Get-ServiceFromRootName -Domain $SourceName -CSV .\domain-to-service.csv
    SourceConfiguration = ""
    Volume              = ""
    DMARCComplianceRate = ""
    SPFAllignmentRate   = ""
    DKIMAllignmetnRate  = ""
}


@{
    IdentifiedSources = @(
        @{
            Name                = $ServiceName
            SourceConfiguration = ""
            Volume              = ""
            DMARCComplianceRate = ""
            SPFAllignmentRate   = ""
            DKIMAllignmetnRate  = ""
            Servers             = @()
        }
    )
}
$GEOData = (Get-IPGeoLocation -IPAddress $IPAddress -Connection $SQLITEConnection)
$recordObj = [PSCustomObject]@{
    SourceIP        = $record.row.source_ip
    PTRServer       = $NameHost
    Count           = $record.row.count
    Disposition     = $record.row.policy_evaluated.disposition
    DKIMResult      = $record.row.policy_evaluated.dkim
    SPFResult       = $record.row.policy_evaluated.spf
    EnvelopeTo      = $record.identifiers.envelope_to
    EnvelopeFrom    = $record.identifiers.envelope_from
    HeaderFrom      = $record.identifiers.header_from
    DKIMAuthResults = @()
    SPFResultList   = @()
    DmarcCompliance = ""
    Country         = $GEOData.flag
}

foreach ($dkim in $record.auth_results.dkim) {
    $recordObj.DKIMAuthResults += [PSCustomObject]@{
        Domain   = $dkim.domain
        Selector = $dkim.selector
        Result   = $dkim.result
                
    }
}

foreach ($spf in $record.auth_results.spf) {
    $recordObj.SPFResultList += [PSCustomObject]@{
        Domain        = $spf.domain
        Scope         = $spf.scope
        Result        = $spf.result
        DmarcAlligned = Test-DomainAlignment -fromDomain $record.identifiers.envelope_from -checkDomain $record.identifiers.header_from -alignmentMode 
    }
}

# Calculate DMARC Compliance
$recordObj.DmarcCompliance = ($recordObj.DKIMResult -eq "pass" -or $recordObj.SPFResult -eq "pass")

$records += $recordObj
}
#>

function Get-ParseDMARCMetaData {

}

function Get-ParseDMARCRecord {
    param(
        $Record
    )

}


function Get-DMARCRerportRecords {
    param(
        $Report
    )

}

function Import-DMARC {
    param(
        $Report
    )
    $Item = Get-Item $report 
    if ($Item.Extension -eq ".gz"){
        Get-XmlFromBase64Gzip
    }
}

function Get-XmlFromStream {
    param (
        $InputObject
    )
    $InputObject = ".\google.com!apcisg.com!1718064000!1718150399.zip"
    switch ((Get-Item $InputObject).Extension) {
        ".gz" {
            $Streamtype = "GZipStream"
            $CompressionMode = [System.IO.Compression.CompressionMode]::Decompress
        }
        ".zip" {
            $Streamtype = "ZipArchive"
            $CompressionMode = [System.IO.Compression.ZipArchiveMode]::Read
        }
    }
    $byteArray = [IO.File]::ReadAllBytes($InputObject)
    # Create a memory stream from the byte array
    $memoryStream = New-Object System.IO.MemoryStream
    $memoryStream.Write($byteArray, 0, $byteArray.Length)
    $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

    # Create a GZipStream to decompress the data
    $Stream = New-Object System.IO.Compression.$Streamtype($memoryStream, $CompressionMode)
    
    $zipEntry = $zipArchive.Entries[0]
    # Create a stream reader to read the decompressed data
    $zipEntry.Open()
    $streamReader = New-Object System.IO.StreamReader($Stream)
    $xmlContent = $streamReader.ReadToEnd()

    # Close the streams
    $streamReader.Close()
    $Stream.Close()
    $memoryStream.Close()

    # Return the XML content
    return $xmlContent
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

function Get-DataType {
    param(
        $InputObject
    )
    if (Test-Path $InputObject) {
        
    }
}

Get-XmlFromStream -InputObject ".\google.com!apcisg.com!1718064000!1718150399.zip"