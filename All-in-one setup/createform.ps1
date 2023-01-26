# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Azure Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = @'
b9efea7a-99c5-4c07-a65c-3d4013299ecf
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = @'
5rN8Q~WTYJ1arFUsQtIc9VOKiSZAvkjSkgXBCaKN
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = @'
6c10d9ab-94c2-44b2-8019-39473bdd3be8
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> companyName
$tmpName = @'
companyName
'@ 
$tmpValue = @'
{{company.name}}
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"
# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}
# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}
# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}
function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )
    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid
            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}
function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task
            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid
            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }
    $returnObject.Value = $taskGuid
}
function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }
    $returnObject.Value = $datasourceGuid
}
function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }
    $returnObject.Value = $formGuid
}
function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })
    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true
            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }
    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}

<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #><# End: HelloID Data sources #>

<# Begin: Dynamic Form "AzureAD Guest - Create - Clone" #>
$tmpSchema = @"
[{"label":"Details","fields":[{"key":"email","templateOptions":{"label":"Email","placeholder":"user@domain.com","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"givenname","templateOptions":{"label":"Givenname","placeholder":"John","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"lastname","templateOptions":{"label":"Last name","placeholder":"Poel","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AzureAD Guest - Create - Clone
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
AzureAD Guest - Invite
'@
$tmpTask = @'
{"name":"AzureAD Guest - Invite","script":"# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \u0027SilentlyContinue\u0027\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# set from Global Variables\r\n# $AADtenantDomain = \u0027enyoi.onmicrosoft.com\u0027\r\n# $AADtenantID = \u0027\u0027\r\n# $AADAppId = \u0027\u0027\r\n# $AADAppSecret = \u0027\u0027\r\n\r\n# variables configured in form\r\n#Change mapping here\r\n$invitation = [PSCustomObject]@{\r\n    invitedUserDisplayName  = $form.givenName + \" \" + $form.lastName;\r\n    invitedUserEmailAddress = $form.email;\r\n    sendInvitationMessage   = $true;\r\n    inviteRedirectUrl       = \"https://portal.azure.com/\";\r\n    invitedUserMessageInfo  = @{\r\n        # customizedMessageBody = \"Personalized message body.\"\r\n        messageLanguage = \"nl-NL\" # If the customizedMessageBody is specified, this property is ignored, and the message is sent using the customizedMessageBody. The language format should be in ISO 639. The default is en-US.\r\n    }\r\n}\r\n\r\n# # Optional, fields to updated on account created from invitation\r\n# $updateAccount = @{\r\n#     CompanyName = $form.company\r\n#     Department  = $form.department\r\n#     jobTitle    = $form.title\r\n# }\r\n\r\n#region functions\r\nfunction New-AuthorizationHeaders {\r\n    [CmdletBinding()]\r\n    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]\r\n    param(\r\n        [parameter(Mandatory)]\r\n        [string]\r\n        $TenantId,\r\n\r\n        [parameter(Mandatory)]\r\n        [string]\r\n        $ClientId,\r\n\r\n        [parameter(Mandatory)]\r\n        [string]\r\n        $ClientSecret\r\n    )\r\n    try {\r\n        Write-Verbose \"Creating Access Token\"\r\n        $baseUri = \"https://login.microsoftonline.com/\"\r\n        $authUri = $baseUri + \"$TenantId/oauth2/token\"\r\n    \r\n        $body = @{\r\n            grant_type    = \"client_credentials\"\r\n            client_id     = \"$ClientId\"\r\n            client_secret = \"$ClientSecret\"\r\n            resource      = \"https://graph.microsoft.com\"\r\n        }\r\n    \r\n        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType \u0027application/x-www-form-urlencoded\u0027\r\n        $accessToken = $Response.access_token\r\n    \r\n        #Add the authorization header to the request\r\n        Write-Verbose \u0027Adding Authorization headers\u0027\r\n\r\n        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()\r\n        $headers.Add(\u0027Authorization\u0027, \"Bearer $accesstoken\")\r\n        $headers.Add(\u0027Accept\u0027, \u0027application/json\u0027)\r\n        $headers.Add(\u0027Content-Type\u0027, \u0027application/json\u0027)\r\n        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)\r\n        $headers.Add(\u0027ConsistencyLevel\u0027, \u0027eventual\u0027)\r\n\r\n        Write-Output $headers  \r\n    }\r\n    catch {\r\n        $PSCmdlet.ThrowTerminatingError($_)\r\n    }\r\n}\r\n\r\nfunction Resolve-HTTPError {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        $httpErrorObj = [PSCustomObject]@{\r\n            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId\r\n            MyCommand             = $ErrorObject.InvocationInfo.MyCommand\r\n            RequestUri            = $ErrorObject.TargetObject.RequestUri\r\n            ScriptStackTrace      = $ErrorObject.ScriptStackTrace\r\n            ErrorMessage          = \u0027\u0027\r\n        }\r\n        if ($ErrorObject.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) {\r\n            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message\r\n        }\r\n        elseif ($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027) {\r\n            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\r\n        }\r\n        Write-Output $httpErrorObj\r\n    }\r\n}\r\n\r\nfunction Resolve-MicrosoftGraphAPIErrorMessage {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        try {\r\n            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop\r\n\r\n            if ($null -ne $errorObjectConverted.error_description) {\r\n                $errorMessage = $errorObjectConverted.error_description\r\n            }\r\n            elseif ($null -ne $errorObjectConverted.error) {\r\n                if ($null -ne $errorObjectConverted.error.message) {\r\n                    $errorMessage = $errorObjectConverted.error.message\r\n                    if ($null -ne $errorObjectConverted.error.code) { \r\n                        $errorMessage = $errorMessage + \" Error code: $($errorObjectConverted.error.code)\"\r\n                    }\r\n                }\r\n                else {\r\n                    $errorMessage = $errorObjectConverted.error\r\n                }\r\n            }\r\n            else {\r\n                $errorMessage = $ErrorObject\r\n            }\r\n        }\r\n        catch {\r\n            $errorMessage = $ErrorObject\r\n        }\r\n\r\n        Write-Output $errorMessage\r\n    }\r\n}\r\n#endregion functions\r\n\r\n# Create Guest invitation\r\ntry {\r\n    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret\r\n\r\n    Write-Verbose \"Creating invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress)). Invitation object: $($invitation | ConvertTo-Json -Depth 10)\"\r\n\r\n    $baseUri = \"https://graph.microsoft.com/\"\r\n    $body = $invitation | ConvertTo-Json -Depth 10\r\n    $splatWebRequest = @{\r\n        Uri     = \"$baseUri/v1.0/invitations\"\r\n        Headers = $headers\r\n        Method  = \u0027POST\u0027\r\n        Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))\r\n    }\r\n    $createInvitationResponse = $null\r\n    $createInvitationResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false\r\n    Write-Information \"Successfully created invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress))\"\r\n\r\n    $Log = @{\r\n        Action            = \"CreateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"AzureActiveDirectory\" # optional (free format text) \r\n        Message           = \"Successfully created invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress))\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = \"$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUserEmailAddress))\" # optional (free format text) \r\n        TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch {\r\n    # Clean up error variables\r\n    $verboseErrorMessage = $null\r\n    $auditErrorMessage = $null\r\n\r\n    $ex = $PSItem\r\n    if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n        $errorObject = Resolve-HTTPError -Error $ex\r\n\r\n        $verboseErrorMessage = $errorObject.ErrorMessage\r\n\r\n        $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage\r\n    }\r\n\r\n    # If error message empty, fall back on $ex.Exception.Message\r\n    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n        $verboseErrorMessage = $ex.Exception.Message\r\n    }\r\n    if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n        $auditErrorMessage = $ex.Exception.Message\r\n    }\r\n\r\n    Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n    $Log = @{\r\n        Action            = \"CreateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"AzureActiveDirectory\" # optional (free format text) \r\n        Message           = \"Error creating invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress)). Error message: $($auditErrorMessage)\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = \"$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUserEmailAddress))\" # optional (free format text) \r\n        TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n    throw \"Error creating invitation for $($invitation.invitedUserDisplayName) ($($invitation.invitedUserEmailAddress)). Error message: $($auditErrorMessage)\"\r\n}\r\n\r\n# # Optional: Update account created from invitation\r\n# try {\r\n#     Write-Verbose \"Updating account $($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id)). Account object: $($updateAccount | ConvertTo-Json -Depth 10)\"\r\n\r\n#     $body = $updateAccount | ConvertTo-Json -Depth 10\r\n#     $splatWebRequest = @{\r\n#         Uri     = \"$baseUri/v1.0/users/$($createInvitationResponse.invitedUser.id)\"\r\n#         Headers = $headers\r\n#         Method  = \u0027PATCH\u0027\r\n#         Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))\r\n#     }\r\n#     $updateAccountResponse = $null\r\n#     $updateAccountResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false\r\n#     Write-Information \"Successfully updated account $($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))\"\r\n\r\n#     $Log = @{\r\n#         Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n#         System            = \"AzureActiveDirectory\" # optional (free format text) \r\n#         Message           = \"Successfully updated account $($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))\" # required (free format text) \r\n#         IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n#         TargetDisplayName = \"$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))\" # optional (free format text) \r\n#         TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) \r\n#     }\r\n#     #send result back  \r\n#     Write-Information -Tags \"Audit\" -MessageData $log\r\n# }\r\n# catch {\r\n#     # Clean up error variables\r\n#     $verboseErrorMessage = $null\r\n#     $auditErrorMessage = $null\r\n\r\n#     $ex = $PSItem\r\n#     if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n#         $errorObject = Resolve-HTTPError -Error $ex\r\n\r\n#         $verboseErrorMessage = $errorObject.ErrorMessage\r\n\r\n#         $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage\r\n#     }\r\n\r\n#     # If error message empty, fall back on $ex.Exception.Message\r\n#     if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n#         $verboseErrorMessage = $ex.Exception.Message\r\n#     }\r\n#     if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n#         $auditErrorMessage = $ex.Exception.Message\r\n#     }\r\n\r\n#     Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n\r\n#     $Log = @{\r\n#         Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n#         System            = \"AzureActiveDirectory\" # optional (free format text) \r\n#         Message           = \"Error updating account $($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id)). Error message: $($auditErrorMessage)\" # required (free format text) \r\n#         IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n#         TargetDisplayName = \"$($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id))\" # optional (free format text) \r\n#         TargetIdentifier  = $createInvitationResponse.invitedUser.id # optional (free format text) \r\n#     }\r\n#     #send result back  \r\n#     Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n#     throw \"Error updating account $($createInvitationResponse.invitedUserDisplayName) ($($createInvitationResponse.invitedUser.id)). Error message: $($auditErrorMessage)\"\r\n# }","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

