# Comprehensive Microsoft 365 Tenant Security Configuration Script (v2.14)

**Author:** Yasuke2000
**Date:** 2025-05-19
**Version:** 2.14

## Overview

This PowerShell script is designed to automate the configuration of numerous security settings within a Microsoft 365 tenant. It aims to establish strong security baselines across Azure Active Directory (Azure AD), Exchange Online, SharePoint Online, and Microsoft Defender for Office 365. The script is built with modularity in mind, allowing administrators to apply configurations in sections, and incorporates robust helper functions for logging, module installation, connection retries, and more.

## 🚨 CRITICAL WARNING 🚨

This script is intended for use by **experienced Microsoft 365 administrators**. It makes **SIGNIFICANT and WIDESPREAD** configuration changes to your tenant's security posture.

**BEFORE RUNNING THIS SCRIPT, YOU MUST:**

1.  **UNDERSTAND EVERY SECTION:** You are solely responsible for the changes made by this script. Review the code and comments thoroughly.
2.  **TEST THOROUGHLY:** Execute this script in a dedicated, **non-production TEST tenant** first. Validate all configurations and their impact on users and services.
3.  **CUSTOMIZE PARAMETERS:** Carefully review and set all script parameters to match your specific environment. This includes Tenant ID, admin account UPNs, company name, break-glass account details, domain information, etc. The script supports loading parameters from an external configuration file (`.json`, `.psd1`, `.xml`).
4.  **VERIFY LICENSING:** Many features configured (e.g., specific Conditional Access controls, Microsoft Defender plans) require appropriate Microsoft 365 or Azure AD licenses (e.g., Azure AD Premium P1/P2, Microsoft Defender for Office 365 Plan 1/P2). Ensure your tenant has the necessary licenses.
5.  **GRANT ADMIN CONSENT:** The script connects to Microsoft Graph using the "Microsoft Graph Command Line Tools" application. A Global Administrator **must grant tenant-wide admin consent** for this application for all the scopes listed in the `$graphScopes` variable within the script. This is done in the Azure portal (Azure AD > Enterprise applications).
6.  **CHECK CONDITIONAL ACCESS (CA) POLICIES:** Ensure that the administrative account used to run this script is not unduly blocked by pre-existing CA policies (e.g., policies requiring device compliance that the execution machine doesn't meet). Consider using break-glass accounts or excluding the admin account from such policies *temporarily and with caution*.
7.  **BACKUP CONFIGURATIONS:** Before running this script in an existing tenant, document or export any critical existing configurations.
8.  **INCREMENTAL ROLLOUT:** For production environments, consider applying the script's sections incrementally using the `$Apply*` switch parameters, monitoring the impact at each stage.
9.  **USE AT YOUR OWN RISK:** The author and any contributors assume no liability for any issues, misconfigurations, or damages that may arise from the use or misuse of this script.

## Features

* **Modular Design:** Apply configurations for Azure AD Conditional Access, Exchange Online, Defender for Office 365, SharePoint Online, and Auditing independently using master switch parameters.
* **Azure AD Conditional Access:**
    * Creates baseline policies (e.g., block legacy authentication, MFA for admins, MFA for risky sign-ins, require compliant/HAADJ devices).
    * Policies are created in "Report-only" mode by default, requiring manual enablement after review.
* **Exchange Online Security:**
    * Blocks global external email forwarding.
    * Enables detailed mailbox auditing (with parallel processing for speed).
    * Configures external email subject tagging.
    * Blocks common executable attachment types.
    * Configures outbound spam filter policies.
    * Enables DKIM signing for verified domains.
    * Configures default anti-malware and anti-spam (inbound) policies.
* **Microsoft Defender for Office 365:**
    * Configures custom Safe Links, Safe Attachments, and Anti-Phishing policies.
    * Enables ATP for SharePoint, OneDrive, and Teams (Safe Attachments & Safe Documents).
    * Optionally enables MDO Standard and Strict Preset Security Policies.
* **SharePoint Online & OneDrive Security:**
    * Configures external sharing capabilities.
    * Sets anonymous link expiration and permissions.
    * Allows configuration of sharing domain restrictions (allow/block lists).
    * Configures device access policies for unmanaged devices.
* **Audit Configuration:**
    * Ensures Unified Audit Log (UAL) ingestion is enabled.
    * Configures Exchange Admin Audit Log for verbose logging.
* **Robust Scripting:**
    * Advanced helper functions for logging (text and optional JSON), module installation (with version check and retries), and Graph/Exchange Online connections (with retries).
    * Parallel processing for mailbox auditing.
    * Pre-flight checks for basic environment validation.
    * Optional post-configuration tests.
    * Supports external configuration files.
* **`WhatIf` and `-Confirm` Support:** Leverages PowerShell's ShouldProcess capabilities.

## Prerequisites

* **PowerShell 7+ Recommended:** For best compatibility and feature support.
* **Execution Policy:** PowerShell execution policy on the machine running the script must allow script execution (e.g., `RemoteSigned` or `Unrestricted`).
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    ```
* **Required PowerShell Modules:**
    * Microsoft.Graph.Authentication
    * Microsoft.Graph.Identity.SignIns
    * Microsoft.Graph.Users
    * Microsoft.Graph.Groups
    * Microsoft.Graph.DeviceManagement
    * Microsoft.Graph.Applications
    * Microsoft.Graph.Identity.DirectoryManagement
    * Microsoft.Graph.Identity.ConditionalAccess (If this module is unavailable, the CA section will be skipped)
    * Microsoft.Graph.Reports
    * ExchangeOnlineManagement
    * Microsoft.Online.SharePoint.PowerShell
    * The script will attempt to install missing modules (except `Microsoft.Graph.Identity.ConditionalAccess` if it's the *only* one missing and you choose not to install others).
* **Permissions:** The account used to run the script (`$AdminUserUpn`) must have **Global Administrator** rights in the target Azure AD tenant.
* **Admin Consent:** Tenant-wide admin consent must be pre-granted for the **"Microsoft Graph Command Line Tools"** (App ID: `14d82eec-204b-4c2f-b7e8-296a70dab67e`) enterprise application in Azure AD for *all scopes listed in the `$graphScopes` variable* within the script.

## Parameters

The script accepts numerous parameters to customize its behavior. Key parameters include:

* `$ConfigFilePath`: (Optional) Path to an external configuration file (JSON, PSD1, XML) to load parameters.
* `$TenantId`: (Optional) Your Azure AD Tenant ID (GUID or domain like `yourtenant.onmicrosoft.com`). If blank, the script attempts to derive it.
* `$AdminUserUpn`: (Mandatory) UPN of the admin account to connect services (e.g., `admin@yourtenant.onmicrosoft.com`).
* `$BreakGlassAdminGroupObjectId`: (Optional, Recommended) Object ID of a security group for break-glass/emergency access accounts. Excluded from CA policies.
* `$BreakGlassAdminUserObjectIds`: (Optional) Array of Object IDs for individual break-glass user accounts (used if group ID is not provided).
* `$CompanyName`: (Optional) Your organization's name, used for naming policies. Defaults to "Yasuke Inc.".
* `$Apply*` switches (e.g., `$ApplyAzureADConditionalAccess`, `$ApplyExchangeOnlineSecurity`): Master switches to enable/disable entire configuration sections. Default to `$true`.
* `$EnableDefender*` switches (e.g., `$EnableDefenderSafeLinksCustomPolicy`): Fine-grained control for Defender policies.
* `$LogFilePath`: Path for the text log file.
* `$ExportJsonLog`: Switch to enable structured JSON logging.
* `$JsonLogFilePath`: Path for the JSON log file.
* ... and others (see the `param()` block in the script for a full list).

## How to Use

1.  **Review and Customize:**
    * Thoroughly review this README and the script code.
    * Update the `param()` block defaults or the `$Global:DomainSettings` / `$Global:ScriptConfig` sections within the script if not using an external config file.
    * Alternatively, create a configuration file (e.g., `config.json` or `config.psd1`) and use the `$ConfigFilePath` parameter.
        Example `config.json`:
        ```json
        {
          "TenantId": "YOUR_TENANT_ID",
          "AdminUserUpn": "admin@yourdomain.com",
          "CompanyName": "Your Actual Company Name",
          "BreakGlassAdminGroupObjectId": "GUID_OF_BREAKGLASS_GROUP",
          "ApplyExchangeOnlineSecurity": true,
          "ApplyDefenderForOffice365": true
          // Add other parameters as needed
        }
        ```

2.  **Meet Prerequisites:** Ensure all prerequisites listed above are met (PowerShell version, execution policy, admin rights, Graph API consent).

3.  **Run with `-WhatIf` (Highly Recommended First Step):**
    ```powershell
    .\M365_Tenant_Security_Setup.ps1 -AdminUserUpn "youradmin@yourtenant.com" -TenantId "yourtenant.onmicrosoft.com" -CompanyName "Your Company" -WhatIf
    ```
    This will show you what actions the script *would* take without actually making changes. Review the output carefully.

4.  **Run Interactively (with Confirmations):**
    ```powershell
    .\M365_Tenant_Security_Setup.ps1 -AdminUserUpn "youradmin@yourtenant.com" -TenantId "yourtenant.onmicrosoft.com" -CompanyName "Your Company" 
    ```
    The script will prompt for confirmation for high-impact changes.

5.  **Selective Execution:**
    Use the `$Apply*` switches to run only specific sections:
    ```powershell
    .\M365_Tenant_Security_Setup.ps1 -AdminUserUpn "youradmin@yourtenant.com" -ApplyExchangeOnlineSecurity $true -ApplyDefenderForOffice365 $true -ApplyAzureADConditionalAccess $false 
    ```

6.  **Review Logs:** After execution, thoroughly review the generated text log file (`$LogFilePath`) and JSON log file (if enabled) for any errors or warnings.

## Post-Execution Steps

* **Conditional Access Policies:** Manually review and enable policies from "Report-only" to "On" in the Azure portal after validating their impact.
* **DKIM:** Ensure CNAME records for DKIM selectors are published in your public DNS.
* **MFA Rollout:** Plan communication and rollout if MFA is newly enforced for users.
* **Review All Settings:** Double-check all applied configurations in the respective admin portals.
* **Monitor:** Continuously monitor sign-in logs, audit logs, and security dashboards.

## Disclaimer

This script is provided "as-is" without warranty of any kind. Always test thoroughly in a non-production environment before applying to a live tenant. The user of this script assumes all responsibility for its use and any consequences thereof.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request.
