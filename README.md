## Problem statement
AWS AppFlow supports the ability to create a connection profile from the Management Console using a point-and-click approach. However, this approach does not translate well into the world of automated deployments where developers rarely have the ability to even log into the management console of the production environment, let alone create resources. This Gist describes a process whereby a CI/CD pipeline could deploy AppFlow resources without any interaction with a UI or the management console

## Approach

### Step 1: Client ID and Client Secret
[Create a Salesforce connected application](https://docs.aws.amazon.com/appflow/latest/userguide/salesforce.html#salesforce-global-connected-app-instructions) and note down the Consumer Key and Consumer Secret. Create a secret using AWS Secrets Manager which contains these:

Powershell:
```PowerShell
aws secretsmanager create-secret --name SalesforceClientCredentials `
    --description "Consumer Key and Consumer Secret for Salesforce App" `
    --secret-string "{\`"clientId\`": \`"<consumer-key>\`", \`"clientSecret\`": \`"<consumer-secret>\`"}"
```
Note down the ARN of the secret thus created.

### Step 2: Access Token and Refresh Token
The next step uses the [Web Server OAuth Flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm&type=5) to obtain an access token and refresh token. Note that for this to work, the Connected App must have the `refresh_token`, `offline_access` scopes enabled. The script below needs to be run **locally** and only once. 

Powershell:
```PowerShell
<#
.SYNOPSIS
    This script implements the Web Server OAuth flow to obtain an access token and refresh token for Salesforce. These are then stored in an AWS Secrets Manager secret.

.PARAMETER secretName 
    Base name of the secret. Defaults to SalesforceCredentials. This is always suffixed by a timestamp in the format yyyy-mm-ddTHHmmss

.PARAMETER awsProfile
    AWS named profile for the account into whose secrets manager the credentials are saved
#>
param (

    [Parameter()]
    [String]
    $secretName="SalesforceCredentials",

    [Parameter()]
    [String]
    $awsProfile="dev"

)

$clientId = "<client-id>"
$redirectUri = "https://console.aws.amazon.com/console/home?region=eu-west-1" # Use the redirect-uri provided with the connected app

# Step 1: Request OAuth Code
$url1 = "https://<your-sf-domain>.my.salesforce.com/services/oauth2/authorize?response_type=code&client_id=$($clientId)&redirect_uri=$($redirectUri)"
Start-Process $url1

# Step 2: Get code from user
$prompt = Read-Host -Prompt "Enter the Salesforce OAuth Code"
$urlDecodedCode = [System.Web.HttpUtility]::UrlDecode($prompt)

# Step 3: Request OAuth tokens
$body = @{
    grant_type='authorization_code'
    client_id="$clientId"
    redirect_uri="$redirectUri"
    code="$urlDecodedCode"
}

$contentType = 'application/x-www-form-urlencoded' 
$response = Invoke-RestMethod -Uri "https://<your-sf-domain>.my.salesforce.com/services/oauth2/token" -Method 'POST' -Body $body -ContentType $contentType

# Step 4: Save tokens in secrets manager
aws secretsmanager create-secret --name "SalesforceCredentials_$(Get-Date -Format yyyy-MM-ddTHHmmss)"  --secret-string "{\`"accessToken\`":\`"$($response.access_token)\`",\`"refreshToken\`":\`"$($response.refresh_token)\`"}" --profile kdp-dev
```

After `Step-1` in the script above, the default browser opens and prompts for the username and password associated with the Salesforce App.

![image](./Step1.png)

Once authenticated, Salesforce redirects you to the Redirect URL specified with the Connected App. The OAuth code is included as a parameter in the redirected URL as seen below

![image](Step1a.png)

Note that the code is URL encoded and must be decoded. The script above also decodes the URL, so the entire code needs to be copied and pasted into the prompt. Next, the script creates a new secret with the access token and refresh token. After this, the CDK/Cloudformation code can be automatically deployed. Note that the above steps need to run exactly once before deploying the cloudformation stack.

### Step 3: Cloudformation/CDK
At this point, we have two secrets registered in AWS Secrets Manager:
1. The Client Credentials: (`clientId`, `clientSecret`)
2. Tokens: (`accessToken`, `refreshToken`)

The code below uses Python-flavoured AWS CDK, but the same ideas translate trivially to Cloudformation as well. 

Create an encryption key for AppFlow and allow the AppFlow service principal to use it
```Python
appflow_encyption_key_policy = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                principals=[iam.ServicePrincipal("appflow.amazonaws.com")],
                actions=["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
                resources=["*"],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:appflow:{self.region}:{self.account}:*"}
                }
            ),
            iam.PolicyStatement(
                principals=[iam.AccountRootPrincipal()],
                actions=["kms:*"],
                resources=["*"]
            )
        ]
    )
appflow_encryption_key = kms.Key(
    self, 
    "appflow-encryption-key",
    alias="appflow-sf-encryption-key",
    description="KMS key used by Appflow to encrypt Salesforce data",
    policy=appflow_encyption_key_policy
)
```

The [`SalesforceConnectorProfileCredentials`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofilecredentials.html) property needs to be configured with the `AccessToken`, `RefreshToken` and `ClientCredentialsArn` properties. 

The `ClientCredentialsArn` is the ARN of a Secrets Manager secret containing the `clientId` and `clientSecret` properties. However, AppFlow needs the secret to be encrypted with the same key as the one above. Thus we cannot use the secret created earlier. As a result, we need to create a new secret encrypted with the `appflow_encryption_key`created above.

```Python
salesforce_client_credentials_arn = "<client-credential-secret-arn>"
salesforce_client_credentials_secret_managed_key = sm.Secret.from_secret_attributes(
    self, 
    "salesforce-client-credentials-managed-key",
    secret_complete_arn=salesforce_client_credentials_arn
)
salesforce_client_credentials = sm.Secret(
    self, 
    "salesforce-client-credentials",
    encryption_key=appflow_encryption_key,
    secret_string_beta1=sm.SecretStringValueBeta1.from_token(
        salesforce_client_credentials_secret_managed_key.secret_value.to_string()
    )
)
salesforce_client_credentials.add_to_resource_policy(
    iam.PolicyStatement(
        principals=[iam.ServicePrincipal("appflow.amazonaws.com")],
        actions=["secretsmanager:GetSecretValue"],
        resources=["*"]
    )
)
```

Now, we can specify the credentials fully by reading the `AccessToken` and `RefreshToken` from the secret created by the PowerShell script above:

```Python
salesforce_token_secret_arn = "<salesforce-token-secret-arn>" 
salesforce_tokens = sm.Secret.from_secret_attributes(
    self, 
    "salesforce_tokens",
    secret_complete_arn=salesforce_token_secret_arn
)
salesforce_connector_profile = appflow.CfnConnectorProfile(
    self,
    "salesforce-connector-profile",
    connection_mode="Public",
    connector_profile_name="salesforce-connection-profile",
    connector_type="Salesforce",
    connector_profile_config=appflow.CfnConnectorProfile.ConnectorProfileConfigProperty(
        connector_profile_credentials=appflow.CfnConnectorProfile.ConnectorProfileCredentialsProperty(
            salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty(
                access_token=salesforce_tokens.secret_value_from_json("accessToken").to_string(),
                refresh_token=salesforce_tokens.secret_value_from_json("refreshToken").to_string(),
                client_credentials_arn=salesforce_client_credentials.secret_full_arn
            )
        ),
        connector_profile_properties=appflow.CfnConnectorProfile.ConnectorProfilePropertiesProperty(
            salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty(
                instance_url="https://<your-domain>.my.salesforce.com",
                is_sandbox_environment=False
            )
        )
    ),
    kms_arn=appflow_encryption_key.key_arn
)
```

To test this, create a flow which uses the Connector created above. 