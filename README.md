# Azure Key Vault Reporter
This Python solution reports statistics on the secrets and keys stored in the Azure Key Vaults across an Azure Subscription.

## What problem does this solve?
Azure Key Vault is Microsoft's key management service for Azure and is capable of storing and managing access to keys, secrets, and certificates.  Keys, secrets, and certificates stored within the Key Vault instance make a [number of properties](https://docs.microsoft.com/en-us/rest/api/keyvault/) available for consumption without requiring direct access to the credential.  Some of these properties, such as the creation date, whether or not the credential has an expiration date, can be important to track to ensure with compliance standards for credential age, expiration, and rotation.  

This solution pulls enumerates a list of Azure Key Vaults within a specified subscription or subscriptions and pulls properties from secrets and keys within each Key Vault instance.  These properties can be used to track for compliance with security policies and frameworks.  Data is written to an Azure Log Analytics Workspace via the [Azure Monitor HTTP Data Collector API](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api).  The data can then be analyzed using Azure Monitor to create operational dashboards or alerts.

A log file is created that contains debug and error information.  A sample parameters file is included in the repo.

The properties pulled include:
* Subscription ID
* Key Vault Name
* Data Id (Key Id or Secret Id)
* Data Type (Key or Secret)
* Created Date (UTC)
* Updated Date (UTC)
* Expiration Date (UTC) (if present)
* Enabled
* Age in Days (calculated by the solution)

## Requirements

### Python Runtime and Modules
* [Python 3.6.X](https://www.python.org/downloads/release/python-360/)
* [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python)

### Azure Requirements
* [Confidential Client Registered with Azure AD](https://docs.microsoft.com/en-us/azure/healthcare-apis/register-confidential-azure-ad-client-app)
* [Log Analytics Workspace](https://docs.microsoft.com/en-us/azure/azure-monitor/learn/quick-create-workspace)
* [Reader Role (or equivalent) on subscription](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#reader)
* [Get Keys permission](https://docs.microsoft.com/en-us/rest/api/keyvault/getkeys) and [Get Secrets permission](https://docs.microsoft.com/en-us/rest/api/keyvault/getsecrets) granted on [access policy](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-secure-your-key-vault) for each Key Vault

## Example

python azure-keyvault-reporter.py --parameterfile parameters.json --logfile log.txt

