Import-Module .\lib\DMARC-Functions.psm1 -Force
Import-Module .\lib\EMail-Functions.psm1 -Force
Import-Configuration .\config\Config.psd1 -force

Connect-MgGraph -Scopes Mail.ReadWrite, Mail.ReadWrite.Shared, Mail.Send, Mail.Send.Shared

if (Test-Path ".\$($DMARCConfig.MailboxPath).txt") {
    $DMARCEmails = (get-deltaMailMessages -DeltaLinkFile ".\$($DMARCConfig.MailboxPath).txt" | ConvertFrom-MGMailMessage)
}
else {
    $DMARCEmails = (get-initialMailMessages -Path $DMARCConfig.MailboxPath | ConvertFrom-MGMailMessage)
}

foreach ($email in ($DMARCEmails | Where-Object {$_.attachments.name})) {
    Write-host "Processing $($Email.subject)"
    if ($email.attachments.name) {
        if ($email.attachments.name -match "zip") {
            $XML = (Get-XmlFromBase64Zip -Base64Data $email.attachments.contentBytes) 
        }
        else {
            $XML = (Get-XmlFromBase64Gzip -Base64Data $email.attachments.contentBytes)
        }
    }
    
    $XML | Out-File (Join-Path $Global:DMARCConfig.ReportsPath -ChildPath ($email.attachments.name -replace '.xml.*|.zip.*', ".xml"))
}


$DMARCReports = Get-ChildItem $DMARCConfig.ReportsPath | Import-DMARCReport
$totalReports = $DMARCReports.Count
$counter = 0
$ParsedReports = [System.Collections.Generic.List[Object]]::new()
foreach ($report in $DMARCReports) {
    $counter++
    $percentComplete = ($counter / $totalReports) * 100
    Write-Progress -Activity "Current File $($report.name)" -Status "Processing $counter of $totalReports" -PercentComplete $percentComplete

    #$Object = Get-ParsedDMARCReport -XMLData $report
    $Object = Invoke-ParseDmarcReport -xmlFilePath $report
    $Json = $Object | ConvertTo-Json -Depth 10
    $ParsedReports.Add($Object)
}

#Invoke-SqliteQuery -DataSource .\reports\reports.sqlite -Query "INSERT INTO reports (json) VALUES ('$Json');"

$totalReports = $DMARCReports.Count
$counter = 0
$ParsedReports = [System.Collections.Generic.List[Object]]::new()
foreach ($report in $DMARCReports) {
    Start-Job -ScriptBlock
    $Object = Invoke-ParseDmarcReport -xmlFilePath $report
}