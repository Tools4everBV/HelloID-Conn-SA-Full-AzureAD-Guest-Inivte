# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = 'SilentlyContinue'
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# set from Global Variables
# $AADtenantID = ''
# $AADAppId = ''
# $AADAppSecret = ''

# variables configured in form
#Change mapping here
$invitation = [PSCustomObject]@{
    invitedUserDisplayName  = $form.givenName + " " + $form.lastName;
    invitedUserEmailAddress = $form.email;
    sendInvitationMessage   = $true;
    inviteRedirectUrl       = "https://portal.azure.com/";
    invitedUserMessageInfo  = @{
        customizedMessageBody = $form.messageArea # "Personalized message body."
        messageLanguage = "nl-NL" # If the customizedMessageBody is specified, this property is ignored, and the message is sent using the customizedMessageBody. The language format should be in ISO 639. The default is en-US.
    }
}

$groupsToAdd = $form.groups

# # Optional, fields to updated on account created from invitation
# $updateAccount = @{
#     CompanyName = $form.company
#     Department  = $form.department
#     jobTitle    = $form.title
# }


#region functions
function New-AuthorizationHeaders {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$TenantId/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}
#endregion functions

# Create Guest invitation
try {
    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    Write-Verbose "Creating invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress)). Invitation object: $($invitation | ConvertTo-Json -Depth 10)"

    $baseUri = "https://graph.microsoft.com/"
    $body = $invitation | ConvertTo-Json -Depth 10
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/invitations"
        Headers = $headers
        Method  = 'POST'
        Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
    }
    $createInvitationResponse = $null
    $createInvitationResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    Write-Information "Successfully created invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress))"

    $Log = @{
        Action            = "CreateAccount" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Successfully created invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress))" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUserEmailAddress))" # optional (free format text) 
        TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    # Clean up error variables
    $verboseErrorMessage = $null
    $auditErrorMessage = $null

    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObject = Resolve-HTTPError -Error $ex

        $verboseErrorMessage = $errorObject.ErrorMessage

        $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
    }

    # If error message empty, fall back on $ex.Exception.Message
    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
        $verboseErrorMessage = $ex.Exception.Message
    }
    if ([String]::IsNullOrEmpty($auditErrorMessage)) {
        $auditErrorMessage = $ex.Exception.Message
    }

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    $Log = @{
        Action            = "CreateAccount" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Error creating invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress)). Error message: $($auditErrorMessage)" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUserEmailAddress))" # optional (free format text) 
        TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log

    throw "Error creating invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress)). Error message: $($auditErrorMessage)"
}

# Add account created from invitation to group
try {
    foreach ($group in $groupsToAdd) {
        try {
            Write-Verbose "Adding AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' to AzureAD group '$($group.name) ($($group.id))'"

            $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($createInvitationResponse.invitedUser.id)" } | ConvertTo-Json -Depth 10
            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/groups/$($group.id)/members" + '/$ref'
                Headers = $headers
                Method  = 'POST'
                Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }
            $addGroupmemberResponse = $null
            $addGroupmemberResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false

            Write-Information "Successfully added AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' to AzureAD group '$($group.name) ($($group.id))'"

            $Log = @{
                Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                System            = "AzureActiveDirectory" # optional (free format text) 
                Message           = "Successfully added AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' to AzureAD group '$($group.name) ($($group.id))'." # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))" # optional (free format text) 
                TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            # Clean up error variables
            $verboseErrorMessage = $null
            $auditErrorMessage = $null

            $ex = $PSItem
            if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObject = Resolve-HTTPError -Error $ex

                $verboseErrorMessage = $errorObject.ErrorMessage

                $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
            }

            # If error message empty, fall back on $ex.Exception.Message
            if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                $verboseErrorMessage = $ex.Exception.Message
            }
            if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                $auditErrorMessage = $ex.Exception.Message
            }

            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

            if ($_ -like "*One or more added object references already exist for the following modified properties*") {
                $Log = @{
                    Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                    System            = "AzureActiveDirectory" # optional (free format text) 
                    Message           = "AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' is already a member of group '$($group.name) ($($group.id))'" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))" # optional (free format text) 
                    TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            else {
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "AzureActiveDirectory" # optional (free format text) 
                    Message           = "Could not add AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' to AzureAD group '$($group.name) ($($group.id))'. Error message: $($auditErrorMessage)" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))" # optional (free format text) 
                    TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log

                Write-Error "Error adding AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' to AzureAD group '$($group.name) ($($group.id))'. Error message: $($auditErrorMessage)"
            }
        }
    }
}
catch {
    throw "Error adding AzureAD account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))' to AzureAD groups '$($groupsToAdd|ConvertTo-Json)'. Error message: $($auditErrorMessage)"
}


# # Optional: Update account created from invitation
# try {
#     Write-Verbose "Updating account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))'. Account object: $($updateAccount | ConvertTo-Json -Depth 10)"

#     $body = $updateAccount | ConvertTo-Json -Depth 10
#     $splatWebRequest = @{
#         Uri     = "$baseUri/v1.0/users/$($createInvitationResponse.invitedUser.id)"
#         Headers = $headers
#         Method  = 'PATCH'
#         Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
#     }
#     $updateAccountResponse = $null
#     $updateAccountResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
#     Write-Information "Successfully updated account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))'"

#     $Log = @{
#         Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
#         System            = "AzureActiveDirectory" # optional (free format text) 
#         Message           = "Successfully updated account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))'" # required (free format text) 
#         IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
#         TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))" # optional (free format text) 
#         TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
#     }
#     #send result back  
#     Write-Information -Tags "Audit" -MessageData $log
# }
# catch {
#     # Clean up error variables
#     $verboseErrorMessage = $null
#     $auditErrorMessage = $null

#     $ex = $PSItem
#     if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
#         $errorObject = Resolve-HTTPError -Error $ex

#         $verboseErrorMessage = $errorObject.ErrorMessage

#         $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
#     }

#     # If error message empty, fall back on $ex.Exception.Message
#     if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
#         $verboseErrorMessage = $ex.Exception.Message
#     }
#     if ([String]::IsNullOrEmpty($auditErrorMessage)) {
#         $auditErrorMessage = $ex.Exception.Message
#     }

#     Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

#     $Log = @{
#         Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
#         System            = "AzureActiveDirectory" # optional (free format text) 
#         Message           = "Error updating account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))'. Error message: $($auditErrorMessage)" # required (free format text) 
#         IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
#         TargetDisplayName = "$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))" # optional (free format text) 
#         TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) 
#     }
#     #send result back  
#     Write-Information -Tags "Audit" -MessageData $log

#     throw "Error updating account '$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))'. Error message: $($auditErrorMessage)"
# }
