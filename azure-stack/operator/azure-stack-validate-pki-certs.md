---
title: Validate Azure Stack Public Key Infrastructure certificates for Azure Stack integrated systems deployment | Microsoft Docs
description: Describes how to validate the Azure Stack PKI certificates for Azure Stack integrated systems. Covers using the Azure Stack Certificate Checker tool.
services: azure-stack
documentationcenter: ''
author: mattbriggs
manager: femila
editor: ''

ms.service: azure-stack
ms.workload: na
pms.tgt_pltfrm: na
ms.devlang: na
ms.topic: article
ms.date: 03/11/2019
ms.author: mabrigg
ms.reviewer: ppacent
ms.lastreviewed: 01/08/2019
---

# Validate Azure Stack PKI certificates

The Azure Stack Readiness Checker tool described in this article is available [from the PowerShell Gallery](https://aka.ms/AzsReadinessChecker). You can use the tool to validate that  the [generated PKI certificates](azure-stack-get-pki-certs.md) are suitable for pre-deployment. Validate certificates by leaving  enough time to test and reissue certificates if necessary.

The Readiness Checker tool performs the following certificate validations, by default:

- **PFX Encryption**  
    Checks for valid PFX file encrypted with TripleDES-SHA1, correct password, and whether the public information isn't protected by the password.
- **Expiry Date**  
    Checks that certificate expiry is more than 7 days in the future.    
- **Signature algorithm**  
    Checks that the signature algorithm isn't SHA1.
- **Private Key**  
    Checks that the private key is present and is exported with the local machine attribute. 
- **Cert chain**  
    Checks certificate chain is intact including a check for self-signed certificates.
- **DNS names**  
    Checks the SAN contains relevant DNS names for each endpoint, or if a supporting wildcard is present.
- **Key usage**  
    Checks if the key usage contains a digital signature and key encipherment and enhanced key usage contains server authentication and client authentication.
- **Key Length**  
    Checks if the key size is 2048 or larger.
- **Chain order**  
    Checks the order of the other certificates validating that the order is correct.
- **Other certificates**  
    Ensure no other certificates have been packaged in PFX other than the relevant leaf certificate and its chain.

> [!IMPORTANT]  
> The PKI certificate is a PFX file and password should be treated as sensitive information.

## Prerequisites

Your system should meet the following prerequisites before validating PKI certificates for an Azure Stack deployment:

- Microsoft Azure Stack Readiness Checker
- SSL Certificate(s) exported following the [preparation instructions](azure-stack-prepare-pki-certs.md)
- DeploymentData.json
- Windows 10 or Windows Server 2016

## Perform core services certificate validation

Use these steps to prepare and to validate the Azure Stack PKI certificates for deployment and secret rotation:

1. Install **AzsReadinessChecker** from a PowerShell prompt (5.1 or above), by running the following cmdlet:

    ```powershell  
        Install-Module Microsoft.AzureStack.ReadinessChecker -force 
    ```

2. Create the certificate directory structure. In the example below, you can change `<c:\certificates>` to a new directory path of your choice.
    ```powershell  
    New-Item C:\Certificates -ItemType Directory
    
    $directories = 'ACSBlob', 'ACSQueue', 'ACSTable', 'Admin Extension Host', 'Admin Portal', 'ARM Admin', 'ARM Public', 'KeyVault', 'KeyVaultInternal', 'Public Extension Host', 'Public Portal'
    
    $destination = 'c:\certificates'
    
    $directories | % { New-Item -Path (Join-Path $destination $PSITEM) -ItemType Directory -Force}
    ```
    
    > [!Note]  
    > AD FS and Graph are required if you are using AD FS as your identity system. For example:
    >
    > ```powershell  
    > $directories = 'ACSBlob', 'ACSQueue', 'ACSTable', 'ADFS', 'Admin Extension Host', 'Admin Portal', 'ARM Admin', 'ARM Public', 'Graph', 'KeyVault', 'KeyVaultInternal', 'Public Extension Host', 'Public Portal'
    > ```
    
     - Place your certificate(s) in the appropriate directories created in the previous step. For example:  
        - `c:\certificates\ACSBlob\CustomerCertificate.pfx`
        - `c:\certificates\Admin Portal\CustomerCertificate.pfx`
        - `c:\certificates\ARM Admin\CustomerCertificate.pfx`

3. In the PowerShell window, change the values of **RegionName** and **FQDN** appropriate to the Azure Stack environment and run the following:

    ```powershell  
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString 

    Invoke-AzsCertificateValidation -certificateType Deployment -CertificatePath c:\certificates -pfxPassword $pfxPassword -RegionName east -FQDN azurestack.contoso.com -IdentitySystem AAD  
    ```

4. Check the output and all certificates pass all tests. For example:

```powershell
Invoke-AzsCertificateValidation v1.1905.0.18 started.
Testing: ARM Public\ssl.pfx
Thumbprint: 7F6B27****************************E9C35A
	PFX Encryption: OK
	Expiry Date: OK
	Signature Algorithm: OK
	DNS Names: OK
	Key Usage: OK
	Key Size: OK
	Parse PFX: OK
	Private Key: OK
	Cert Chain: OK
	Chain Order: OK
	Other Certificates: OK
Testing: Admin Extension Host\ssl.pfx
Thumbprint: A631A5****************************35390A
	PFX Encryption: OK
	Signature Algorithm: OK
	DNS Names: OK
	Key Usage: OK
	Key Size: OK
	Parse PFX: OK
	Private Key: OK
	Cert Chain: OK
	Chain Order: OK
	Other Certificates: OK
Testing: Public Extension Host\ssl.pfx
Thumbprint: 4DBEB2****************************C5E7E6
	PFX Encryption: OK
	Signature Algorithm: OK
	DNS Names: OK
	Key Usage: OK
	Key Size: OK
	Parse PFX: OK
	Private Key: OK
	Cert Chain: OK
	Chain Order: OK
	Other Certificates: OK

Log location (contains PII): C:\Users\username\AppData\Local\Temp\AzsReadinessChecker\AzsReadinessChecker.log
Report location (contains PII): C:\Users\username\AppData\Local\Temp\AzsReadinessChecker\AzsReadinessCheckerReport.json
Invoke-AzsCertificateValidation Completed
```

### Known issues

**Symptom**: Tests are skipped

**Cause**: AzsReadinessChecker skips certain tests if a dependency isn't met:

 - Other certificates are skipped if certificate chain fails.

    ```powershell  
    Testing: ACSBlob\singlewildcard.pfx
        Read PFX: OK
        Signature Algorithm: OK
        Private Key: OK
        Cert Chain: OK
        DNS Names: Fail
        Key Usage: OK
        Key Size: OK
        Chain Order: OK
        Other Certificates: Skipped
    Details:
    The certificate records '*.east.azurestack.contoso.com' do not contain a record that is valid for '*.blob.east.azurestack.contoso.com'. Please refer to the documentation for how to create the required certificate file.
    The Other Certificates check was skipped because Cert Chain and/or DNS Names failed. Follow the guidance to remediate those issues and recheck. 
    Detailed log can be found C:\AzsReadinessChecker\CertificateValidation\CertChecker.log

    Log location (contains PII): C:\Users\username\AppData\Local\Temp\AzsReadinessChecker\AzsReadinessChecker.log
    Report location (contains PII): C:\Users\username\AppData\Local\Temp\AzsReadinessChecker\AzsReadinessCheckerReport.json
    Invoke-AzsCertificateValidation Completed
    ```

**Resolution**: Follow the tool's guidance in the details section under each set of tests for each certificate.

## Perform App Services certificate validation

Use these steps to prepare and validate the Azure Stack PKI certificates for App Services certificates, if App Services deployments or secret rotation are planned.

1.  Install **AzsReadinessChecker** from a PowerShell prompt (5.1 or above), by running the following cmdlet:

    ```powershell  
      Install-Module Microsoft.AzureStack.ReadinessChecker -force
    ```

2. Create the certificate directory structure. In the example below, you can change `<c:\certificates\AppServices>` to a new directory path of your choice. Due to multi certificate requirement for App Services, the individual certificates must to placed in folders specifically named for their intended purpose, API, DefaultDomain, Identity, Publishing. The pfx filename can be custom as long as their extension is .pfx. All PFX files need the same password.
    ```powershell  
    
    $destination = 'c:\certificates\AppServices'
    
    $directories = 'API', 'DefaultDomain', 'Identity', 'Publishing'
    
    $directories | % { New-Item -Path (Join-Path $destination $PSITEM) -ItemType Directory -Force}
    ```
    
     - Place your certificate(s) in the appropriate directories created in the previous step. For example:  
        - `c:\certificates\AppServices\API\api.appservice.local.azurestack.external.pfx`
        - `c:\certificates\ApsServices\DefaultDomain\_.appservice.local.azurestack.external.pfx`
        - `c:\certificates\ApsServices\Identity\sso.appservice.local.azurestack.external.pfx`
	- `c:\certificates\ApsServices\Publishing\ftp.appservice.local.azurestack.external.pfx`
	
	
3.  Change the values of **RegionName** and **FQDN** to match your Azure Stack environment to start the validation. Then run:

    ```powershell
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString
    Invoke-AzsCertificateValidation -CertificateType AppServices -certificatePassword $pfxPassword -CertificatePath $destination -RegionName east -FQDN azurestack.contoso.com 
    ```
4.  Check that the output and that all certificates pass all tests.

    ```powershell
    Invoke-AzsCertificateValidation v1.0 started.
    Testing: DefaultDomain\_.appservice.local.azurestack.external.pfx
    Thumbprint: 0D0853****************************93E699
        Expiry Date: OK
        Signature Algorithm: OK
        DNS Names: OK
        Key Usage: OK
        Key Length: OK
        Parse PFX: OK
        Private Key: OK
        Cert Chain: OK
        Chain Order: OK
        Other Certificates: OK
    Testing: API\api.appservice.local.azurestack.external.pfx
    Thumbprint: D17E89****************************F7E91D
        Expiry Date: OK
        Signature Algorithm: OK
        DNS Names: OK
        Key Usage: OK
        Key Length: OK
        Parse PFX: OK
        Private Key: OK
        Cert Chain: OK
        Chain Order: OK
        Other Certificates: OK
    Testing: Publishing\ftp.appservice.local.azurestack.external.pfx
    Thumbprint: 8E0AD2****************************63D47D
        Expiry Date: OK
        Signature Algorithm: OK
        DNS Names: OK
        Key Usage: OK
        Key Length: OK
        Parse PFX: OK
        Private Key: OK
        Cert Chain: OK
        Chain Order: OK
        Other Certificates: OK
    Testing: Identity\sso.appservice.local.azurestack.external.pfx
    Thumbprint: 86891E****************************DCF93E
        Expiry Date: OK
        Signature Algorithm: OK
        DNS Names: OK
        Key Usage: OK
        Key Length: OK
        Parse PFX: OK
        Private Key: OK
        Cert Chain: OK
        Chain Order: OK
        Other Certificates: OK
    ```

## Perform DBAdpater, IoTHub, EventHub, certificate validation

Use these steps to prepare and validate the Azure Stack PKI certificates for DBAdapter, IoTHub or EventHub.

1.  Install **AzsReadinessChecker** from a PowerShell prompt (5.1 or above), by running the following cmdlet:

    ```powershell  
      Install-Module Microsoft.AzureStack.ReadinessChecker -force
    ```

2. Create the certificate directory structure. In the example below, you can change `<c:\certificates\>` to a new directory path of your choice. These certificates are single certificate requirements   .
    ```powershell  
    
    $destination = 'c:\certificates'
    
    $directories = 'DBAdapter', 'IoTHub', 'EventHub' # delete as needed
    
    $directories | % { New-Item -Path (Join-Path $destination $PSITEM) -ItemType Directory -Force}
    ```
    
     - Place your certificate(s) as needed in the appropriate directories. For example:  
        - `c:\certificates\DBAdpater\dbadapter.local.azurestack.external.pfx`
        - `c:\certificates\IoTHub\iothub.local.azurestack.external.pfx`
        - `c:\certificates\EventHub\eventhub.local.azurestack.external.pfx`
	
	
3.  Change the values of **RegionName** and **FQDN** to match your Azure Stack environment to start the validation. Then run one or all  of the following as needed:

    ```powershell  
    # To Validate DBAdapter
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString
    Invoke-AzsCertificateValidation -CertificateType DBAdapter -CertificatePath c:\certificates\dbadapter -certificatePassword $pfxPassword -RegionName east -FQDN azurestack.contoso.com 
    
    # To Validate IoTHub
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString
    Invoke-AzsCertificateValidation -CertificateType IotHub -CertificatePath c:\certificates\IotHub -certificatePassword $pfxPassword -RegionName east -FQDN azurestack.contoso.com 
    
    # To Validate EventHub
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString
    Invoke-AzsCertificateValidation -CertificateType EventHub -CertificatePath c:\certificates\EventHub -certificatePassword $pfxPassword -RegionName east -FQDN azurestack.contoso.com 
    ```
4.  Check that the output and that all certificates pass all tests.

    ```powershell
    Invoke-AzsCertificateValidation v1.0 started.
    Testing: DBAdapter\dbadapter.local.azurestack.external.pfx
    Thumbprint: 7DB863****************************43A619
        Expiry Date: OK
        Signature Algorithm: OK
        DNS Names: OK
        Key Usage: OK
        Key Length: OK
        Parse PFX: OK
        Private Key: OK
        Cert Chain: OK
        Chain Order: OK
        Other Certificates: OK
    ```

## Perform custom certificate validation

Use these steps to prepare and validate the Azure Stack PKI certificates for a custom requirement such as a public/private Resource Provider preview.

1.  Install **AzsReadinessChecker** from a PowerShell prompt (5.1 or above), by running the following cmdlet:

    ```powershell  
      Install-Module Microsoft.AzureStack.ReadinessChecker -force
    ```

2. Create the certificate directory structure. In the example below, you can change `<c:\certificates\Custom>` to a new directory path of your choice. Validating multiple certificates at once requires parent folder name (e.g. CustomCert1) to be matched in the custom hashtable, the certificatePath value should be the next folder up (e.g. Custom) and all certificates need the same password. Validating a single certificate requires a single certificate in a folder, and that same folder provided for certificatePath value.
    ```powershell  
    
    $destination = 'c:\certificates\Custom'
    
    $directories = 'CustomCert1', 'CustomCert2' # delete as needed
    
    $directories | % { New-Item -Path (Join-Path $destination $PSITEM) -ItemType Directory -Force}
    ```
    
     - Place your certificate(s) as needed in the appropriate directories. For example:  
        - `c:\certificates\Custom\CustomCert1\custom1.local.azurestack.external.pfx`
        - `c:\certificates\Custom\CustomCert2\custom2.local.azurestack.external.pfx`
	
3.  Create custom hashtable for custom validation **DNSName** is a mandatory mininum key. 
    ```powershell  
    # To validate single custom certificate with custom names and custom key length.
    $customSingleConfig = @{CustomCert1 = @{
    			DNSName = @('*.customname1','customname2','*.customname3')
			keyLength = 4096
		}
	}
    
    # To validate a group of custom certificates with custom names and custom key length.
    $customGroupConfig = @{CustomCert1 = @{
    			DNSName = @('*.customname1','customname2','*.customname3')
			keyLength = 4096
		}
		CustomCert2 = @{
    			DNSName = @('*.customname4','customname5','*.customname6')
			keyLength = 4096
			HashAlgorithm = SHA384
		}
	}
    
    
    ```

	
4.  Change the values of **RegionName** and **FQDN** to match your Azure Stack environment to start the validation. Then run one or all  of the following as needed:

    ```powershell  
    # To validate single custom certificate
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString
    Invoke-AzsCertificateValidation -CustomCertConfig $CustomSingleConfig -CertificatePath c:\certificates\Custom\CustomCert1 -certificatePassword $pfxPassword -RegionName east -FQDN azurestack.contoso.com 
    
    # To validate multiple custom certificate
    $pfxPassword = Read-Host -Prompt "Enter PFX Password" -AsSecureString
    Invoke-AzsCertificateValidation -CustomCertConfig $CustomGroupConfig -CertificatePath c:\certificates\Custom -certificatePassword $pfxPassword -RegionName east -FQDN azurestack.contoso.com 
   
    ```
5.  Check that the output and that all certificates pass all tests.

    ```powershell
    Invoke-AzsCertificateValidation v1.0 started.
    Testing: CustomCert1\custom.local.azurestack.external.pfx
    Thumbprint: 9B7A64****************************33F929
        Expiry Date: OK
        Signature Algorithm: OK
        DNS Names: OK
        Key Usage: OK
        Key Length: OK
        Parse PFX: OK
        Private Key: OK
        Cert Chain: OK
        Chain Order: OK
        Other Certificates: OK
    ```

## Certificates

| Directory | Certificate |
| ---    | ----        |
| acsBlob | wildcard_blob_\<region>_\<externalFQDN> |
| ACSQueue  |  wildcard_queue_\<region>_\<externalFQDN> |
| ACSTable  |  wildcard_table_\<region>_\<externalFQDN> |
| Admin Extension Host  |  wildcard_adminhosting_\<region>_\<externalFQDN> |
| Admin Portal  |  adminportal_\<region>_\<externalFQDN> |
| ARM Admin  |  adminmanagement_\<region>_\<externalFQDN> |
| ARM Public  |  management_\<region>_\<externalFQDN> |
| KeyVault  |  wildcard_vault_\<region>_\<externalFQDN> |
| KeyVaultInternal  |  wildcard_adminvault_\<region>_\<externalFQDN> |
| Public Extension Host  |  wildcard_hosting_\<region>_\<externalFQDN> |
| Public Portal  |  portal_\<region>_\<externalFQDN> |

## Custom Validation Keys
| KeyName | Example/Default Values | Notes
| ---    | ----        | ----		|
| DNSName | @('*.custom.rp') | Mandatory key. Can be a string or string array, and should be everything left of region and externalFQDN parameter values.
| IncludeTests  |  'All' | 'Parse PFX','Signature Algorithm','Private Key','Cert Chain','DNS Names','Key Usage','Chain Order','Other Certificates','Key Size','PFX Encryption','Expiry Date'
| ExcludeTests  |  'CNG Key' | should typically exclude CNG Key if RP supports CNG Keys, plus any names from includetests as appropriate.
| KeyUsage  |  @('KeyEncipherment','DigitalSignature') | valid values: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keyusageflags?view=netframework-4.8#fields
| EnhancedKeyUsage  |  @('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1') | Default corresponds to Server Authentication and Client Authentication
| KeyLength  |  2048 | default is 2048 and should not be set to lower. valid values 4096, 8191 and so on.
| HashAlgorithm  |  'SHA256' | always fails for SHA1

## Using validated certificates

Once your certificates have been validated by the AzsReadinessChecker, you are ready to use them in your Azure Stack deployment or for Azure Stack secret rotation. 

 - For deployment, securely transfer your certificates to your deployment engineer so that they can copy them onto the deployment host as specified in the [Azure Stack PKI requirements documentation](azure-stack-pki-certs.md).
 - For secret rotation, you can use the certificates to update old certificates for your Azure Stack environment's public infrastructure endpoints by following the [Azure Stack Secret Rotation documentation](azure-stack-rotate-secrets.md).
 - For PaaS services, you can use the certificates to install SQL, MySQL, and App Services Resource Providers in Azure Stack by following the [Overview of offering services in Azure Stack documentation](azure-stack-offer-services-overview.md).

## Next steps

[Datacenter identity integration](azure-stack-integrate-identity.md)
