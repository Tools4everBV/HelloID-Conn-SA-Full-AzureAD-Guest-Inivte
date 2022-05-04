# your script here
$account = [PSCustomObject]@{
    invitedUserDisplayName = $givenName + " " + $lastName;
    invitedUserEmailAddress = $email;
    sendInvitationMessage = $true;
    inviteRedirectUrl = "https://portal.azure.com/";
}

$connected = $true
try{
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method Post -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    }
}catch{
        Write-Verbose -Verbose "Could not connect to AzureAD"
        $connected = $false             
}

if ($connected)
{
    $userExists = $false
    try{
        $userPrincipalName = $account.invitedUserEmailAddress.replace("@","_") + "#EXT#@$AADtenantDomain"
        $userPrincipalName = [System.Web.HttpUtility]::UrlEncode($userPrincipalName)
        Write-Verbose -Verbose "Searching for AzureAD user with userPrincipalName '$($userPrincipalName)'.."

        $baseSearchUri = "https://graph.microsoft.com/"
        $properties = @("id","displayName","userPrincipalName")        
        $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName" + '?$select=' + ($properties -join ",")
        $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        Write-Verbose -Verbose "Found AzureAD user [$($azureADUser.userPrincipalName)]"
        $userExists = $true
    }catch{
        Write-Verbose -Verbose "Could not find AzureAD user [$($account.invitedUserEmailAddress)]"
        $userExists = $false             
    }

    if($userExists -eq $false){
        Write-Verbose -Verbose "Inviting AzureAD user [$($account.invitedUserEmailAddress)] for domain $AADtenantDomain.."
        $baseCreateUri = "https://graph.microsoft.com/"
        $createUri = $baseCreateUri + "/v1.0/invitations"
        $body = $account | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false
        $aRef = $response.invitedUser.id
        
        $patchUri = $baseCreateUri + "/v1.0/users/" + $aRef
        $patchbody = @{
            CompanyName = $company
            Department = $department
            jobTitle = $title
        }
        Invoke-RestMethod -Uri $patchUri -Method PATCH -Headers $authorization -Body ($patchbody | ConvertTo-Json) -Verbose:$false
        
        $success = $True;
               
        Write-Information " invitation $($account.invitedUserEmailAddress) successfully";         
    }else{
        Write-Verbose -Verbose "AzureAD user [$($azureADUser.userPrincipalName)] already exists as a Guest in domain $AADtenantDomain"

        $aRef = $azureADUser.id

        $success = $True; 
        Write-Error " $($azureADUser.userPrincipalName) already exists for this person. Skipped action and treated like";       
    }
}
