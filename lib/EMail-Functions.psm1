function Get-MgUserMailFolderFromPath {
    [CmdletBinding(DefaultParameterSetName = 'Folders')]
    param (
        [Parameter(ParameterSetName = "Folders", Position = 0)]
        [Parameter(ParameterSetName = "Messages", Position = 0)]
        [string]$Path,
        [Parameter(ParameterSetName = "Folders")]
        [switch]$ListChildren,
        [Parameter(ParameterSetName = "Messages")]
        [switch]$ListMessages
    )

    $SplitPath = $Path -split "\\"
    $UserID = $SplitPath[0]

    if ($SplitPath.Length -eq 2) {
        # Only root folder is specified
        $RootFolder = Get-MgUserMailFolder -UserId $UserID | where { $_.DisplayName -eq $SplitPath[1] }
        if ($null -eq $RootFolder) {
            Write-Error "Root folder '$($SplitPath[1])' not found for user '$UserID'"
        }
        else {
            return $RootFolder
        }
    }
    else {
        $RootFolder = Get-MgUserMailFolder -UserId $UserID | where { $_.DisplayName -eq $SplitPath[1] }
        $ChildFolderNames = $SplitPath[2..($SplitPath.Length - 1)]

        foreach ($FolderName in $ChildFolderNames) {
            $ChildFolder = Get-MgUserMailFolderChildFolder -MailFolderId $RootFolder.Id -UserId $UserID | where { $_.DisplayName -eq $FolderName }
            if ($null -eq $ChildFolder) {
                Write-Error "Folder '$FolderName' not found under '$($RootFolder.DisplayName)'"
                break
            }
            $RootFolder = $ChildFolder
        }
        if ($ListChildren) {
            return Get-MgUserMailFolderChildFolder -MailFolderId $RootFolder.id -UserId $UserID
        }
        elseif ($ListMessages) {
            return Get-MgUserMailFolderMessage -MailFolderId $RootFolder.id -UserId $UserID
        }
        else {
            return $RootFolder
        }
    }
}

function Get-InitialMailMessages {
    param(
        $Path,
        $MaxPages = 1000
    )
    $UserID = ($Path -split "\\")[0]
    $Folder = Get-MgUserMailFolderFromPath -Path $path
    $Messages = [System.Collections.Generic.List[Object]]::new()
    $initialDeltaEndpoint = ('https://graph.microsoft.com/v1.0/users/{0}/mailFolders/{1}/messages/delta?$expand=Attachments' -f $UserID, $Folder.Id)
    $Response = Invoke-MgGraphRequest -Method GET -Uri $initialDeltaEndpoint -Headers @{Prefer = "odata.maxpagesize=$MaxPages" }
    do {
        $nextLink = $Response.'@odata.nextLink'
        if ($nextLink) {
            $response = Invoke-MgGraphRequest -Uri ("$nextLink{0}" -f '?$expand=Attachments')
        }
        $deltalink = $response.'@odata.deltaLink'
        foreach ($message in $response.value) {
            Write-host "`r$($messages.count)" -NoNewline
            $Messages.Add($message)
        }
    }
    until (
        $response.'@odata.deltaLink'
    )
    $deltalink | Out-File ".\$($path -replace "\\","." -replace "\s+","_").txt"
    return $Messages
}

function Get-DeltaMailMessages {
    param(
        $Path,
        $DeltaLinkFile
    )
    $Messages = [System.Collections.Generic.List[Object]]::new()
    $DeltaLink = ((Get-Content $DeltaLinkFile -Raw) -split "delta\?" -join 'delta?$expand=Attachments&changeType=created&')
    $Response = Invoke-MgGraphRequest -Method GET -Uri $DeltaLink
    do {
        $nextLink = $Response.'@odata.nextLink'
        if ($nextLink) {
            $response = Invoke-MgGraphRequest -Uri ("$nextLink{0}" -f '?$expand=Attachments')
        }
        $deltalink = $response.'@odata.deltaLink'
        foreach ($message in $response.value) {
            Write-host "`r$($messages.count)" -NoNewline
            $Messages.Add($message)
        }
    }
    until (
        $response.'@odata.deltaLink'
    )
    Write-host "$($Response.value.count) messages retrieved"
    Set-Content (Resolve-Path $DeltaLinkFile) -Value $response.'@odata.deltaLink'
    return $Messages
}

function Convert-HTMLToPlainText {
    param(
        [Parameter(ValueFromPipeline)]
        $HTML,
        [switch]$Pretty
    )

    # Replace some tags with a space and normalize whitespace
    $PlainText = $HTML `
        -replace "(</?(td|tr|p.*?|strong)>|<br>)|&nbsp;", " " `
        -replace "<[^>]+>", "" `
        -replace "\s+,\s+", ", " `
        -replace "\s+", " " `
        -replace '&quot;', '"' `
        -replace "&lt;", "<" `
        -replace "&gt;", ">"

    # More complext replacing of tables, spans, and font tags to match it's original intended format
    if ($Pretty) {
        $PlainText = $HTML `
            -replace "<p.*?>|<tr.*?>|<br>", "`n"`
            -replace "</td><td>", ": " `
            -replace "<li>", "* " `
            -replace "(</?(td|tr|p.*?|strong)>|<br>)" `
            -replace '&quot;', '"' `
            -replace "<[^>]+>" `
            -replace '(?s).*Protection by INKY' `
            -replace "\s+,\s+", ", " `
            -replace "^\s+" `
            -replace "&lt;", "<" `
            -replace "&gt;", ">" `
            -replace "(\r?\n){4,}", "`n" `
            -replace "&nbsp;", ""
    }

    return $PlainText
}

function ConvertFrom-MGMailMessage {
    param(
        [Parameter(ValueFromPipeline)]
        $Message,
        [Switch]$AsJson
    )
    PROCESS {
        $Attachment = $Message.Attachments
        $Object = [pscustomObject]@{
            subject        = $Message.Subject
            from           = $Message.From.EmailAddress.Address
            to             = $Message.ToRecipients[0].EmailAddress.Address
            sentDateTime   = $Message.SentDateTime
            body           = [pscustomObject]@{
                html      = $Message.Body.Content
                plainText = ($Message.Body.Content | Convert-HTMLToPlainText -Pretty)
            }
            
            attachments    = [pscustomObject]@{
                contentType  = $Attachment.ContentType
                name         = $Attachment.Name
                contentBytes = $Attachment.contentBytes
            }
            messageId      = $Message.Id
            parentFolderId = $MEssage.ParentFdlderId
        }
        
        if ($AsJson) {
            return $Object | convertto-Json -Depth 20
        }
        else {
            return $object
        }
    }
}

Export-ModuleMember -Function *