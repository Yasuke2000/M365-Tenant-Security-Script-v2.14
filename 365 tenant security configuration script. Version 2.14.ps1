<#
.SYNOPSIS
    Comprehensive Microsoft 365 tenant security configuration script. Version 2.14.
    Establishes strong security baselines using robust helper functions for logging, module 
    installation, connections, parallel processing, and optional testing. Includes a dedicated
    section for global script variable declarations.

.DESCRIPTION
    This script automates security settings for Azure AD, Exchange Online, SharePoint Online, 
    and Microsoft Defender. It's designed for modularity and production-level use, 
    incorporating best practices and advanced error handling/retry mechanisms.

    -------------------------------------------------------------------------------------
    !! CRITICAL WARNING !!
    -------------------------------------------------------------------------------------
    For experienced M365 administrators. Makes SIGNIFICANT tenant changes.
    1.  UNDERSTAND EVERY SECTION.
    2.  TEST THOROUGHLY in a non-production environment.
    3.  CUSTOMIZE PARAMETERS (or use a configuration file/variable section).
    4.  VERIFY LICENSING.
    5.  GRANT ADMIN CONSENT for 'Microsoft Graph Command Line Tools' for necessary scopes.
    6.  CHECK CONDITIONAL ACCESS policies for admin account exclusions.
    7.  USE AT YOUR OWN RISK.
    -------------------------------------------------------------------------------------

.NOTES
    Version: 2.14
    Author: Yasuke2000 (refined from AI collaboration)
    Date: 2025-05-19

    Prerequisites:
    - PowerShell 7+ recommended.
    - Required modules (script attempts installation).
    - Global Administrator or equivalent permissions.
    - Tenant-wide Admin Consent for Microsoft Graph Command Line Tools.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigFilePath, # Path to an external configuration file (JSON, PSD1, XML)

    [Parameter(Mandatory = $false)]
    [string]$TenantId, 
    [Parameter(Mandatory = $true)]
    [string]$AdminUserUpn, 
    [Parameter(Mandatory = $false)]
    [string]$BreakGlassAdminGroupObjectId, 
    [Parameter(Mandatory = $false)]
    [string[]]$BreakGlassAdminUserObjectIds = @(), 
    [Parameter(Mandatory = $false)]
    [string]$CompanyName = "Yasuke Inc.", 
    [Parameter(Mandatory = $false)]
    [string]$DefaultExternalEmailPrependText = "[EXTERNAL]", 
    [Parameter(Mandatory = $false)]
    [string[]]$AllowedExternalSharingDomains = @(), 
    [Parameter(Mandatory = $false)]
    [string[]]$BlockedExternalSharingDomains = @(), 

    # Master Switches for major configuration sections
    [Parameter(Mandatory = $false)]
    [switch]$ApplyAzureADConditionalAccess = $true,
    [Parameter(Mandatory = $false)]
    [switch]$ApplyExchangeOnlineSecurity = $true,
    [Parameter(Mandatory = $false)]
    [switch]$ApplyDefenderForOffice365 = $true,
    [Parameter(Mandatory = $false)]
    [switch]$ApplySharePointOnlineSecurity = $true,
    [Parameter(Mandatory = $false)]
    [switch]$ApplyAuditLogConfiguration = $true,

    # Fine-grained switches for Defender
    [Parameter(Mandatory = $false)]
    [switch]$EnableDefenderSafeLinksCustomPolicy = $true, 
    [Parameter(Mandatory = $false)]
    [switch]$EnableDefenderSafeAttachmentsCustomPolicy = $true, 
    [Parameter(Mandatory = $false)]
    [switch]$EnableDefenderAntiPhishingCustomPolicy = $true, 
    [Parameter(Mandatory = $false)]
    [switch]$EnableDefenderPresetPolicies = $true, 
    [Parameter(Mandatory = $false)]
    [string[]]$AntiPhishTargetedUsersToProtectUpns = @(), 
    [Parameter(Mandatory = $false)]
    [string[]]$AntiPhishTargetedDomainsToProtect = @(),  

    # Graph Connection Parameters
    [Parameter(Mandatory=$false)]
    [switch]$UseCertificateForGraph = $false, 
    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprintForGraph,
    [Parameter(Mandatory=$false)]
    [string]$ClientIdForGraphCertAuth, 

    # Logging Parameters
    [Parameter(Mandatory = $false)]
    [string]$LogFilePath = "$PSScriptRoot\M365_Security_Setup_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [Parameter(Mandatory = $false)]
    [switch]$ExportJsonLog = $false, 
    [Parameter(Mandatory = $false)]
    [string]$JsonLogFilePath, 

    # Other Parameters
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLicenseOverview = $true,
    [Parameter(Mandatory = $false)]
    [string]$ExchangeEnvironmentName,
    [Parameter(Mandatory = $false)]
    [switch]$RunPostConfigurationTests = $false 
)

# --- Variable Declarations ---
# Add or modify configuration variables here. These can be overridden by an external config file.
$Global:DomainSettings = @{
    PrimaryDomain = "" # Example: "contoso.com". If left blank, some parts of the script might try to derive it.
    AltDomains = @()   # Example: @("fabrikam.com", "contoso.co.uk")
    DKIMEnabled = $true # General switch for DKIM processing; actual enablement is per domain.
    # Add other domain-related settings as needed
}

# Add any other global script variables here
$Global:ScriptConfig = @{
    # Script-wide settings can be defined here
    ModuleInstallMaxRetries = 2 # Max retries for Install-RequiredModule
    ModuleInstallRetryDelayBase = 2 # Base seconds for retry delay in Install-RequiredModule (exponential)
    GraphConnectMaxRetries = 2    # Max retries for Connect-MgGraphWithRetry
    GraphConnectRetryDelayBase = 2 # Base seconds for retry delay in Connect-MgGraphWithRetry (exponential)
    MailboxAuditMaxConcurrentJobs = 5
    MailboxAuditBatchSize = 20
    # Add additional configuration as needed
}

# --- Script Start ---
$scriptStartTime = Get-Date
$ErrorActionPreference = 'Stop' 

# --- Helper Functions ---

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info',
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Global:EXPORT_JSON_LOG_ENABLED -and -not [string]::IsNullOrWhiteSpace($Global:JSON_LOG_FILE_PATH_EFFECTIVE)) {
        $jsonLog = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString('o') 
            Level = $Level
            Message = $Message
        } | ConvertTo-Json -Compress
        try {
            $jsonLog | Out-File -FilePath $Global:JSON_LOG_FILE_PATH_EFFECTIVE -Append -Encoding utf8
        } catch {
            Write-Host "[$timestamp] [Error] CRITICAL: Failed to write to JSON log file: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    if (-not $NoConsole) {
        switch ($Level) {
            'Info'    { Write-Host $logMessage -ForegroundColor White }
            'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
            'Error'   { Write-Host $logMessage -ForegroundColor Red }
            'Success' { Write-Host $logMessage -ForegroundColor Green }
            'Debug'   { Write-Host $logMessage -ForegroundColor Cyan }
        }
    }
    
    try {
        $logMessage | Out-File -FilePath $Global:LOG_FILE_PATH_EFFECTIVE -Append -Encoding utf8
    } catch {
        Write-Host "[$timestamp] [Error] CRITICAL: Failed to write to text log file: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Error details: $($_ | ConvertTo-Json -Depth 1)" -ForegroundColor Red
    }
}

function Install-RequiredModule {
    param (
        [string]$ModuleName,
        [string]$MinimumVersion, 
        [switch]$AllowPrerelease = $false
    )
    
    $installedModule = Get-Module -ListAvailable -Name $ModuleName | 
                        Sort-Object Version -Descending | 
                        Select-Object -First 1
    
    $needsInstall = $false
    $needsUpdate = $false

    if ($null -eq $installedModule) {
        Write-Log -Message "Module $ModuleName is not installed." -Level 'Warning'
        $needsInstall = $true
    }
    elseif (-not [string]::IsNullOrWhiteSpace($MinimumVersion) -and $installedModule.Version -lt [System.Version]$MinimumVersion) {
        Write-Log -Message "Module $ModuleName version $($installedModule.Version) is below required version $MinimumVersion." -Level 'Warning'
        $needsInstall = $true 
        $needsUpdate = $true
    }
    else {
        Write-Log -Message "Module $ModuleName version $($installedModule.Version) meets requirements $(if($MinimumVersion){"(>= $MinimumVersion)"}else{''})." -Level 'Success'
        return $true 
    }
    
    if ($needsInstall) {
        $maxRetries = $Global:ScriptConfig.ModuleInstallMaxRetries
        $retryCount = 0
        $success = $false
        
        while (-not $success -and $retryCount -lt $maxRetries) {
            $retryCount++
            try {
                Write-Log -Message "$(if($needsUpdate){"Updating"}else{"Installing"}) module $ModuleName (Attempt $retryCount of $maxRetries)..." -Level 'Info'
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $installParams = @{ Name = $ModuleName; Force = $true; Scope = "CurrentUser"; AllowClobber = $true; ErrorAction = "Stop"; Repository = "PSGallery" }
                if (-not [string]::IsNullOrWhiteSpace($MinimumVersion)) { $installParams.Add("MinimumVersion", $MinimumVersion) }
                if ($AllowPrerelease) { $installParams.Add("AllowPrerelease", $true) }
                Install-Module @installParams
                $installedModule = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
                if ($null -ne $installedModule -and (-not $MinimumVersion -or $installedModule.Version -ge [System.Version]$MinimumVersion)) {
                    Write-Log -Message "Successfully $(if($needsUpdate){"updated"}else{"installed"}) $ModuleName version $($installedModule.Version)" -Level 'Success'
                    $success = $true; return $true
                } else { throw "Module verification failed after installation attempt for $ModuleName." }
            }
            catch {
                Write-Log -Message "Attempt $retryCount to install/update $ModuleName failed: $($_.Exception.Message)" -Level 'Error'
                if ($retryCount -lt $maxRetries) { Start-Sleep -Seconds ([math]::Pow($Global:ScriptConfig.RetryDelayBase, $retryCount)) } # Exponential backoff
            }
        }
        if (-not $success) { Write-Log -Message "Failed to install/update module $ModuleName after $maxRetries attempts." -Level 'Error'; return $false }
    }
    return $true 
}

function Connect-MgGraphWithRetry {
    param (
        [string]$TenantIdToUse, 
        [string[]]$ScopesToRequest, 
        [int]$MaxRetries = $Global:ScriptConfig.GraphConnectMaxRetries, 
        [switch]$UseDeviceAuth = $true, 
        [switch]$UseCert = $false, 
        [string]$CertThumbprint, 
        [string]$AppClientId, 
        [string]$Audience = 'organizations' 
    )
    $attempt = 0; $connected = $false; $mgContextResult = $null
    while (-not $connected -and $attempt -lt $MaxRetries) {
        $attempt++; try {
            Write-Log -Message "Connecting to Microsoft Graph (Attempt $attempt of $MaxRetries)..." -Level 'Info'
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            $connectParams = @{ Scopes = $ScopesToRequest; ErrorAction = 'Stop'; Audience = $Audience }
            if (-not [string]::IsNullOrWhiteSpace($TenantIdToUse)) { $connectParams.Add("TenantId", $TenantIdToUse) }
            if ($UseCert -and -not [string]::IsNullOrWhiteSpace($CertThumbprint) -and -not [string]::IsNullOrWhiteSpace($AppClientId)) {
                Write-Log -Message "Using certificate-based authentication for Graph." -Level 'Info'; $connectParams.Add("CertificateThumbprint", $CertThumbprint); $connectParams.Add("ClientId", $AppClientId)
            } elseif ($UseDeviceAuth) { Write-Log -Message "Using device code authentication for Graph." -Level 'Info'; $connectParams.Add("UseDeviceAuthentication", $true)
            } else { Write-Log -Message "Using interactive browser authentication for Graph." -Level 'Info' }
            Connect-MgGraph @connectParams 
            $mgContextResult = Get-MgContext
            if ($null -ne $mgContextResult -and $mgContextResult.Account) {
                Write-Log -Message "Successfully connected to Microsoft Graph as $($mgContextResult.Account). Tenant: $($mgContextResult.TenantId)" -Level 'Success'
                Write-Log -Message "Granted Scopes (from context): $($mgContextResult.Scopes -join '; ')" -Level 'Debug'; $connected = $true; return $mgContextResult
            } else { throw "Get-MgContext returned null or no account after Connect-MgGraph call." }
        } catch {
            Write-Log -Message "Graph connection attempt $attempt failed: $($_.Exception.Message)" -Level 'Error'
            if ($_.Exception.Message -match "AADSTS70011") { Write-Log -Message "AADSTS70011: Invalid scope. Current scopes: $($ScopesToRequest -join '; ')" -Level 'Error'; break }
            if ($_.Exception.Message -match "AADSTS65001") { Write-Log -Message "AADSTS65001: Consent missing. Ensure admin consent for 'Microsoft Graph Command Line Tools' for scopes: $($ScopesToRequest -join '; ')" -Level 'Error'; break }
            if ($attempt -lt $maxRetries) { Start-Sleep -Seconds ([math]::Pow($Global:ScriptConfig.RetryDelayBase, $attempt)) }
        }
    }
    if (-not $connected) { Write-Log -Message "Failed to connect to Microsoft Graph after $MaxRetries attempts." -Level 'Error' }
    return $mgContextResult 
}

function Set-MailboxAuditingInParallel {
    param ( 
        [int]$MaxConcurrentJobs = $Global:ScriptConfig.MailboxAuditMaxConcurrentJobs, 
        [int]$BatchSize = $Global:ScriptConfig.MailboxAuditBatchSize 
    )
    Write-Log -Message "[EXO] Starting parallel mailbox auditing configuration..." -Level 'Info'
    try {
        $mailboxes = Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox"}
        $totalMailboxes = $mailboxes.Count
        Write-Log -Message "[EXO] Found $totalMailboxes user mailboxes for audit configuration" -Level 'Info'
        if ($totalMailboxes -eq 0) { Write-Log -Message "[EXO] No mailboxes found. Skipping." -Level 'Warning'; return }
        $scriptBlockContent = {
            param($mailboxUPN)
            try {
                Set-Mailbox -Identity $mailboxUPN -AuditEnabled $true `
                    -AuditOwner "SendAs,Create,Update,MoveToDeletedItems,SoftDelete,HardDelete,UpdateFolderPermissions,UpdateInboxRules,UpdateCalendarDelegation" `
                    -AuditDelegate "SendAs,Create,Update,SoftDelete,HardDelete,SendOnBehalf,MoveToDeletedItems,UpdateFolderPermissions,UpdateInboxRules,UpdateCalendarDelegation" `
                    -AuditAdmin "Update,SoftDelete,HardDelete,SendAs,SendOnBehalf,Create,UpdateFolderPermissions,UpdateInboxRules,UpdateCalendarDelegation" -ErrorAction Stop
                return @{ Success = $true; Mailbox = $mailboxUPN; Error = $null }
            } catch { return @{ Success = $false; Mailbox = $mailboxUPN; Error = $_.Exception.Message } }
        }
        $processedCount = 0; $errorList = [System.Collections.ArrayList]::new()
        for ($i = 0; $i -lt $totalMailboxes; $i += $BatchSize) {
            $batchMailboxes = $mailboxes[$i..([System.Math]::Min(($i + $BatchSize - 1), ($totalMailboxes - 1)))]
            Write-Log -Message "[EXO] Processing audit batch starting with $($batchMailboxes[0].UserPrincipalName) ($($batchMailboxes.Count) mailboxes)..." -Level 'Debug'
            $jobs = @(); foreach ($mailbox in $batchMailboxes) {
                $jobs += Start-Job -ScriptBlock $scriptBlockContent -ArgumentList $mailbox.UserPrincipalName
                while ((Get-Job -State Running).Count -ge $MaxConcurrentJobs) {
                    Get-Job -State Completed | ForEach-Object { $result = Receive-Job -Job $_ -Keep; if (-not $result.Success) { [void]$errorList.Add($result) }; $processedCount++; Write-Progress -Activity "Mailbox Auditing" -Status "$processedCount/$totalMailboxes" -PercentComplete (($processedCount / $totalMailboxes) * 100); Remove-Job -Job $_ }
                    Start-Sleep -Milliseconds 500
                }
            }
            Wait-Job -Job $jobs | Out-Null
            Get-Job -Job $jobs | ForEach-Object { $result = Receive-Job -Job $_ -Keep; if (-not $result.Success) { [void]$errorList.Add($result) }; $processedCount++; Write-Progress -Activity "Mailbox Auditing" -Status "$processedCount/$totalMailboxes" -PercentComplete (($processedCount / $totalMailboxes) * 100); Remove-Job -Job $_ }
        }
        Write-Progress -Activity "Mailbox Auditing" -Completed
        Write-Log -Message "[EXO] Mailbox auditing configuration attempt completed for $processedCount mailboxes." -Level 'Success'
        if ($errorList.Count -gt 0) { Write-Log -Message "[EXO] Errors during mailbox auditing for $($errorList.Count) mailboxes." -Level 'Warning'; $errorList | ForEach-Object { Write-Log -Message "[EXO] Error for $($_.Mailbox): $($_.Error)" -Level 'Error' -NoConsole $true } } # Log errors to file only
    } catch { Write-Log -Message "[EXO] Critical error during parallel mailbox auditing setup: $($_.Exception.Message)" -Level 'Error' }
}

function Import-ConfigurationFile {
    param ([string]$ProvidedConfigFilePath)
    if ([string]::IsNullOrWhiteSpace($ProvidedConfigFilePath) -or -not (Test-Path -Path $ProvidedConfigFilePath -PathType Leaf)) {
        Write-Log -Message "No valid configuration file specified or file not found at '$ProvidedConfigFilePath'. Using script parameters." -Level 'Info'; return $null
    }
    try {
        Write-Log -Message "Importing configuration from $ProvidedConfigFilePath" -Level 'Info'
        $fileExtension = [System.IO.Path]::GetExtension($ProvidedConfigFilePath).ToLower(); $configData = $null
        if ($fileExtension -eq '.json') { $configData = Get-Content -Path $ProvidedConfigFilePath -Raw | ConvertFrom-Json } 
        elseif ($fileExtension -eq '.psd1') { $configData = Import-PowerShellDataFile -Path $ProvidedConfigFilePath } 
        elseif ($fileExtension -eq '.xml') { $configData = Import-Clixml -Path $ProvidedConfigFilePath } 
        else { Write-Log -Message "Unsupported configuration file format: $fileExtension." -Level 'Error'; return $null }
        if ($null -eq $configData) { Write-Log -Message "Config file '$ProvidedConfigFilePath' empty or unparsable." -Level 'Error'; return $null }
        Write-Log -Message "Successfully loaded configuration from '$ProvidedConfigFilePath'." -Level 'Success'; return $configData
    } catch { Write-Log -Message "Failed to import configuration from '$ProvidedConfigFilePath': $($_.Exception.Message)" -Level 'Error'; return $null }
}

function Invoke-PreflightCheck {
    param ([string]$TargetTenantId, [string]$TargetAdminUserUpn)
    $preflightResults = [PSCustomObject]@{ Success = $true; Messages = @(); Warnings = @(); Errors = @() }
    Write-Log -Message "--- Starting Pre-flight Checks ---" -Level 'Info'
    if (-not [string]::IsNullOrWhiteSpace($TargetTenantId)) {
        if (-not (Test-GuidFormat -Guid $TargetTenantId) -and -not ($TargetTenantId -like "*.onmicrosoft.com") -and -not ($TargetTenantId -match "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")) {
            $preflightResults.Success = $false; $preflightResults.Errors += "Invalid TenantId format: $TargetTenantId" }}
    if (-not ($TargetAdminUserUpn -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")) {
        $preflightResults.Success = $false; $preflightResults.Errors += "Invalid AdminUserUpn format: $TargetAdminUserUpn" }
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7) { $preflightResults.Warnings += "PowerShell version $($psVersion.ToString()) is below recommended v7.0." } 
    else { Write-Log -Message "PowerShell Version $($psVersion.ToString()) meets recommendation (>= 7.0)." -Level 'Debug' }
    $endpoints = @("graph.microsoft.com", "login.microsoftonline.com", "outlook.office365.com")
    foreach ($endpoint in $endpoints) {
        try { $result = Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
            if (-not $result.TcpTestSucceeded) { $preflightResults.Warnings += "Connection test to $endpoint:443 failed." }
            else { Write-Log -Message "Connection test to $endpoint:443 successful." -Level 'Debug' }
        } catch { $preflightResults.Warnings += "Unable to test connection to ${endpoint}: $($_.Exception.Message)" }}
    if ($preflightResults.Errors.Count -gt 0) { foreach ($errorItem in $preflightResults.Errors) { Write-Log -Message "PREFLIGHT ERROR: $errorItem" -Level 'Error' }}
    if ($preflightResults.Warnings.Count -gt 0) { foreach ($warningItem in $preflightResults.Warnings) { Write-Log -Message "PREFLIGHT WARNING: $warningItem" -Level 'Warning' }}
    if ($preflightResults.Success) { Write-Log -Message "Pre-flight check completed with $($preflightResults.Warnings.Count) warnings." -Level $(if($preflightResults.Warnings.Count -gt 0){'Warning'}else{'Success'}) }
    else { Write-Log -Message "Pre-flight check failed with $($preflightResults.Errors.Count) errors." -Level 'Error' }
    Write-Log -Message "--- Pre-flight Checks Finished ---" -Level 'Info'; return $preflightResults.Success
}

function Test-SecurityConfiguration {
    param ([switch]$IncludeMDOPolicies, [switch]$IncludeEXOPolicies, [switch]$IncludeCAPolicies, [switch]$IncludeSPOPolicies)
    Write-Log -Message "--- Starting Post-Configuration Security Test Suite ---" -Level 'Info'
    $testResults = [PSCustomObject]@{ PassedTests = 0; FailedTests = 0; SkippedTests = 0; Details = @() }
    function Add-TestResult { param ([string]$TestName, [string]$Component, [string]$Status, [string]$Details, [string]$RecommendedAction = "")
        $testResults.Details += [PSCustomObject]@{ TestName = $TestName; Component = $Component; Status = $Status; Details = $Details; RecommendedAction = $RecommendedAction }
        if ($Status -eq "Passed") { $testResults.PassedTests++ } elseif ($Status -eq "Failed") { $testResults.FailedTests++ } else { $testResults.SkippedTests++ }}
    if ($IncludeCAPolicies -and $Global:conditionalAccessModuleAvailable) {
        Write-Log -Message "[TEST] Testing Conditional Access Policies..." -Level 'Info'
        try { $policy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$($Global:CompanyName) - CA001 - Block Legacy Authentication'" -ErrorAction SilentlyContinue
            if ($policy) { Add-TestResult "Legacy Auth Blocking Policy" "CA" "Passed" "Policy exists. State: $($policy.State)" }
            else { Add-TestResult "Legacy Auth Blocking Policy" "CA" "Failed" "Policy not found." "Ensure CA001 policy was created."}}
        catch { Add-TestResult "Legacy Auth Blocking Policy" "CA" "Failed" "Error: $($_.Exception.Message)" }}
    elseif ($IncludeCAPolicies) { Add-TestResult "Conditional Access Policies" "CA" "Skipped" "CA Module not available or scope not granted." }
    if ($IncludeEXOPolicies) { Write-Log -Message "[TEST] Testing Exchange Online Policies..." -Level 'Info'
        try { $rd = Get-RemoteDomain Default; if (-not $rd.AutoForwardEnabled) { Add-TestResult "External Email Forwarding" "EXO" "Passed" "AutoForwardEnabled is false."}
            else { Add-TestResult "External Email Forwarding" "EXO" "Failed" "AutoForwardEnabled is true." "Set AutoForwardEnabled to $false."}}
        catch { Add-TestResult "External Email Forwarding" "EXO" "Failed" "Error: $($_.Exception.Message)" }}
    if ($IncludeMDOPolicies) { Write-Log -Message "[TEST] Testing Defender for Office 365 Policies..." -Level 'Info'
        try { $slp = Get-SafeLinksPolicy -Identity "$($Global:CompanyName) - MDO - Global Safe Links Policy" -ErrorAction SilentlyContinue
            if ($slp) { Add-TestResult "Safe Links Policy (Custom)" "MDO" "Passed" "Policy exists."}
            else { Add-TestResult "Safe Links Policy (Custom)" "MDO" "Failed" "Policy not found." "Ensure Safe Links custom policy was created."}}
        catch { Add-TestResult "Safe Links Policy (Custom)" "MDO" "Failed" "Error: $($_.Exception.Message)"}}
    if ($IncludeSPOPolicies) { Write-Log -Message "[TEST] Testing SharePoint Online Policies..." -Level 'Info'
        try { $spoTenant = Get-SPOTenant
            if ($spoTenant.SharingCapability -eq "ExistingExternalUserSharingOnly" -or $spoTenant.SharingCapability -eq "Disabled") { Add-TestResult "SPO External Sharing" "SPO" "Passed" "SharingCapability restrictive: $($spoTenant.SharingCapability)."}
            else { Add-TestResult "SPO External Sharing" "SPO" "Failed" "SharingCapability is $($spoTenant.SharingCapability)." "Consider restricting."}}
        catch { Add-TestResult "SPO External Sharing" "SPO" "Failed" "Error: $($_.Exception.Message)"}}
    Write-Log -Message "[TEST] Results: $($testResults.PassedTests) passed, $($testResults.FailedTests) failed, $($testResults.SkippedTests) skipped." -Level $(if ($testResults.FailedTests -eq 0) { 'Success' } else { 'Warning' })
    $testResults.Details | ForEach-Object { $level = if ($_.Status -eq "Passed") { "Success" } elseif ($_.Status -eq "Failed") { "Error" } else { "Warning" }
        Write-Log -Message "[TEST][RESULT][$($_.Component)] $($_.TestName): $($_.Status) - $($_.Details)" -Level $level
        if ($_.Status -eq "Failed" -and -not [string]::IsNullOrWhiteSpace($_.RecommendedAction)) { Write-Log -Message "  [RECO] $($_.RecommendedAction)" -Level 'Info' }}
    Write-Log -Message "--- Post-Configuration Security Test Suite Finished ---" -Level 'Info'
}

# --- SCRIPT MAIN LOGIC ---
$Global:LOG_FILE_PATH_EFFECTIVE = $LogFilePath
if ($ExportJsonLog) { $Global:EXPORT_JSON_LOG_ENABLED = $true; if ([string]::IsNullOrWhiteSpace($JsonLogFilePath)) { $Global:JSON_LOG_FILE_PATH_EFFECTIVE = [System.IO.Path]::ChangeExtension($LogFilePath, ".json") } else { $Global:JSON_LOG_FILE_PATH_EFFECTIVE = $JsonLogFilePath }; Write-Log -M "JSON logging enabled: $($Global:JSON_LOG_FILE_PATH_EFFECTIVE)" -L Info } else { $Global:EXPORT_JSON_LOG_ENABLED = $false }
if (-not [string]::IsNullOrWhiteSpace($ConfigFilePath)) { $loadedConfig = Import-ConfigurationFile -ProvidedConfigFilePath $ConfigFilePath; if ($null -ne $loadedConfig) { Write-Log -M "Applying params from config..." -L Info; foreach($key in $loadedConfig.PSObject.Properties.Name){ if($PSBoundParameters.ContainsKey($key) -or (Get-Variable -Name $key -EA SilentlyContinue)){ Write-Log -M "Overriding param '$key'." -L Debug; Set-Variable -Name $key -Value $loadedConfig.$key }}} else { Write-Log -M "Could not load config file." -L Warn }}
if (-not (Invoke-PreflightCheck -TargetTenantId $TenantId -TargetAdminUserUpn $AdminUserUpn)) { Write-Log -M "Pre-flight checks failed. Exiting." -L Error; exit 1 }

# --- Section 1: Connect to Services ---
$Global:conditionalAccessModuleAvailable = Test-ModuleInstalled -ModuleName "Microsoft.Graph.Identity.ConditionalAccess" 
$graphScopes = @( "User.Read.All"; "Group.Read.All"; "Policy.ReadWrite.ConditionalAccess"; "Policy.Read.All"; "AuditLog.Read.All"; "SubscribedSku.Read.All"; "Application.Read.All"; "IdentityRiskEvent.Read.All"; "Organization.Read.All" )
Write-Log -M "INFO: Graph connection with refined scopes using Device Code Auth." -L Info
if (-not $Global:conditionalAccessModuleAvailable) { Write-Log -M "ConditionalAccess module not found. Removing 'Policy.ReadWrite.ConditionalAccess' from Graph scopes." -L Warn; $graphScopes = $graphScopes | Where-Object { $_ -ne "Policy.ReadWrite.ConditionalAccess" } }
$mgConnectionResult = Connect-MgGraphWithRetry -TenantIdToUse $TenantId -ScopesToRequest $graphScopes -UseDeviceAuth:$true -UseCert:$UseCertificateForGraph -CertThumbprint $CertificateThumbprintForGraph -AppClientId $ClientIdForGraphCertAuth
if ($null -eq $mgConnectionResult) { Write-Log -M "Failed Graph connection. Exiting." -L Error; exit 1 }
$Global:mgContext = $mgConnectionResult; if ([string]::IsNullOrWhiteSpace($TenantId)) { $TenantId = $Global:mgContext.TenantId; Write-Log -M "Effective TenantId: $TenantId" -L Info }
try { Write-Log -M "Connecting to Exchange Online..." -L Info; Get-PSSession | Where {$_.ConfigurationName -eq 'Microsoft.Exchange'} | Remove-PSSession -EA SilentlyContinue; $exoParams = @{ UserPrincipalName = $AdminUserUpn; ShowBanner = $false; EA = 'Stop' }; if (-not [string]::IsNullOrWhiteSpace($ExchangeEnvironmentName)) { $exoParams.Add("ExchangeEnvironmentName", $ExchangeEnvironmentName); Write-Log -M "EXO Env: $ExchangeEnvironmentName" -L Info }; Connect-ExchangeOnline @exoParams; Write-Log -M "Connected to Exchange Online." -L Success } catch { Write-Log -M "Failed EXO connection: $($_.Exception.Message)" -L Error; Disconnect-MgGraph -EA SilentlyContinue; exit 1 }

# --- Section 2: Identity and Access Management (IAM) ---
if ($ApplyAzureADConditionalAccess -and $Global:conditionalAccessModuleAvailable) {
    Write-Log -Message "--- Starting Section 2: Identity and Access Management (IAM) ---" -Level 'Info'; if (-not ($Global:mgContext.Scopes -contains "Policy.ReadWrite.ConditionalAccess")) { Write-Log -M "Scope 'Policy.ReadWrite.ConditionalAccess' not in context. Skipping CA policies." -L Warn } else {
        function Set-CAPolicy { param ([string]$PolicyName, [hashtable]$PolicyParameters)
            Write-Log -M "CA Policy: $PolicyName" -L Info; try { $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$PolicyName'" -EA SilentlyContinue; if ($existingPolicy) { Write-Log -M "CA Policy '$PolicyName' exists. Skipping." -L Info } else { if ($PSCmdlet.ShouldProcess("CA Policy '$PolicyName'", "Create?")) { New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyParameters -EA Stop; Write-Log -M "CA Policy '$PolicyName' created in 'Report-only'." -L Success }}} catch { Write-Log -M "Failed CA policy '$PolicyName': $($_.Exception.Message)." -L Error }}
        $caExclusions = @{}; if ($effectiveBreakGlassExclusions.Count -gt 0) { if (-not [string]::IsNullOrWhiteSpace($BreakGlassAdminGroupObjectId)) { $caExclusions.Add("ExcludeGroups", $effectiveBreakGlassExclusions) } else { $caExclusions.Add("ExcludeUsers", $effectiveBreakGlassExclusions) }}
        $caPolicy1Name = "$CompanyName - CA001 - Block Legacy Authentication"; $legacyAuthConditions = @{ ClientAppTypes = @("exchangeActiveSync", "other"); Applications = @{ IncludeApplications = @("All") }; Users = @{ IncludeUsers = @("All") }}; if ($caExclusions.Count -gt 0) { $legacyAuthConditions.Users = $legacyAuthConditions.Users + $caExclusions }; $legacyAuthGrantControls = @{ Operator = "OR"; BuiltInControls = @("block") }; $legacyAuthPolicyParams = @{ DisplayName = $caPolicy1Name; State = "enabledForReportingButNotEnforced"; Conditions = $legacyAuthConditions; GrantControls = $legacyAuthGrantControls }; Set-CAPolicy -PolicyName $caPolicy1Name -PolicyParameters $legacyAuthPolicyParams
        $caPolicy2Name = "$CompanyName - CA002 - Require MFA for Admins"; $adminRoleIds = @("62e90394-69f5-4237-9190-012177145e10";"29232cdf-9323-42fd-ade2-1d097af3e4de";"f28a1f50-f6e7-4571-818b-6a12f2af6b6c";"fe930be7-5e62-47db-91af-98c3a49a38b1";"c4e39bd9-1100-46d3-8c65-fb160da0071f";"194ae4cb-b126-40b2-bd5b-6091b380977d";"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"); $mfaAdminUserConditions = @{ IncludeRoles = $adminRoleIds }; if ($caExclusions.Count -gt 0) { $mfaAdminUserConditions = $mfaAdminUserConditions + $caExclusions }; $mfaAdminConditions = @{ Applications = @{ IncludeApplications = @("All") }; Users = $mfaAdminUserConditions }; $mfaAdminGrantControls = @{ Operator = "OR"; BuiltInControls = @("mfa") }; $mfaAdminPolicyParams = @{ DisplayName = $caPolicy2Name; State = "enabledForReportingButNotEnforced"; Conditions = $mfaAdminConditions; GrantControls = $mfaAdminGrantControls }; Set-CAPolicy -PolicyName $caPolicy2Name -PolicyParameters $mfaAdminPolicyParams
        $caPolicy3Name = "$CompanyName - CA003 - Require MFA for Risky Sign-ins (P2)"; $mfaRiskUserConditions = @{ IncludeUsers = @("All") }; if ($caExclusions.Count -gt 0) { $mfaRiskUserConditions = $mfaRiskUserConditions + $caExclusions }; $mfaRiskConditions = @{ Applications = @{ IncludeApplications = @("All") }; Users = $mfaRiskUserConditions; SignInRiskLevels = @("high", "medium")}; $mfaRiskGrantControls = @{ Operator = "OR"; BuiltInControls = @("mfa") }; $mfaRiskPolicyParams = @{ DisplayName = $caPolicy3Name; State = "enabledForReportingButNotEnforced"; Conditions = $mfaRiskConditions; GrantControls = $mfaRiskGrantControls }; Set-CAPolicy -PolicyName $caPolicy3Name -PolicyParameters $mfaRiskPolicyParams
        $caPolicy4Name = "$CompanyName - CA004 - Require Compliant or HAADJ Device"; $complianceUserConditions = @{ IncludeUsers = @("All") }; if ($caExclusions.Count -gt 0) { $complianceUserConditions = $complianceUserConditions + $caExclusions }; $complianceConditions = @{ Applications = @{ IncludeApplications = @("All") }; Users = $complianceUserConditions; Platforms = @{ IncludePlatforms = @("android", "iOS", "windows", "macOS") }}; $complianceGrantControls = @{ Operator = "OR"; BuiltInControls = @("compliantDevice", "domainJoinedDevice")}; $compliancePolicyParams = @{ DisplayName = $caPolicy4Name; State = "enabledForReportingButNotEnforced"; Conditions = $complianceConditions; GrantControls = $complianceGrantControls}; Set-CAPolicy -PolicyName $caPolicy4Name -PolicyParameters $compliancePolicyParams
        Write-Log -M "CA Policy for MCAS session control is commented out." -L Warn }}
else { if (-not $Global:conditionalAccessModuleAvailable -and $ApplyAzureADConditionalAccess) { Write-Log -M "Skipping Section 2: CA Policies - Module not available." -L Warn } elseif (-not $ApplyAzureADConditionalAccess) { Write-Log -M "Skipping Section 2: CA Policies as per parameter." -L Info }}

# --- Section 3: Exchange Online Security Configuration ---
if ($ApplyExchangeOnlineSecurity) {
    Write-Log -Message "--- Starting Section 3: Exchange Online Security ---" -Level 'Info'
    if ($PSCmdlet.ShouldProcess("All User Mailboxes", "Enable detailed mailbox auditing (parallel)?")) { Set-MailboxAuditingInParallel }
    Write-Log -M "[EXO] External email forwarding..." -L Info; try { if ($PSCmdlet.ShouldProcess("Remote Domain 'Default'", "Set AutoForwardEnabled=false?")) { Set-RemoteDomain Default -AutoForwardEnabled $false; Write-Log -M "[EXO] AutoForwardEnabled=false." -L Success } Get-RemoteDomain Default | Select Name, AutoForwardEnabled | FT | Out-String | Write-Log -L Debug } catch { Write-Log -M "[EXO] Failed AutoForward: $($_.Exception.Message)" -L Error }
    if (-not [string]::IsNullOrWhiteSpace($DefaultExternalEmailPrependText)) { $prependSubjectRuleName = "$CompanyName - Rule - Prepend Subject External"; Write-Log -M "[EXO] Rule: $prependSubjectRuleName" -L Info; try { if (Get-TransportRule -Identity $prependSubjectRuleName -EA SilentlyContinue) { Write-Log -M "[EXO] Rule '$prependSubjectRuleName' exists." -L Info } else { if ($PSCmdlet.ShouldProcess("Rule '$prependSubjectRuleName'", "Create?")) { New-TransportRule -Name $prependSubjectRuleName -Comments "Prepends '$DefaultExternalEmailPrependText'" -FromScope NotInOrganization -PrependSubject $DefaultExternalEmailPrependText -SetSCL -1 -SetHeaderName "X-ExternalSenderTag" -SetHeaderValue "External" -Priority 0 -EA Stop; Write-Log -M "[EXO] Rule '$prependSubjectRuleName' created." -L Success }}} catch { Write-Log -M "[EXO] Failed rule '$prependSubjectRuleName': $($_.Exception.Message)" -L Error }} else { Write-Log -M "[EXO] Skipping Prepend Subject rule." -L Info }
    $blockExecutableRuleName = "$CompanyName - Rule - Block Executable Attachments"; Write-Log -M "[EXO] Rule: $blockExecutableRuleName" -L Info; try { if (Get-TransportRule -Identity $blockExecutableRuleName -EA SilentlyContinue) { Write-Log -M "[EXO] Rule '$blockExecutableRuleName' exists." -L Info } else { if ($PSCmdlet.ShouldProcess("Rule '$blockExecutableRuleName'", "Create?")) { $exeTypes = @("ade","adp","app","asp","bas","bat","cmd","com","cpl","crt","csh","der","exe","fxp","gadget","hlp","hta","inf","ins","isp","its","jar","js","jse","ksh","lnk","mad","maf","mag","mam","maq","mar","mas","mat","mau","mav","maw","mda","mdb","mde","mdt","mdw","mdz","msc","msh","msh1","msh2","mshxml","msh1xml","msh2xml","msi","msp","mst","ops","pcd","pif","plg","prf","prg","ps1","ps1xml","ps2","ps2xml","psc1","psc2","pst","reg","scf","scr","sct","shb","shs","tmp","url","vb","vbe","vbs","vsmacros","vsw","ws","wsc","wsf","wsh","xnk"); New-TransportRule -Name $blockExecutableRuleName -Comments "Blocks common executables" -AttachmentMatchesPatterns $exeTypes -RejectMessageReasonText "Executable attachment blocked." -SetHeaderName "X-BlockedExecutable" -SetHeaderValue "True" -Priority 0 -Mode Enforce -EA Stop; Write-Log -M "[EXO] Rule '$blockExecutableRuleName' created." -L Success }}} catch { Write-Log -M "[EXO] Failed rule '$blockExecutableRuleName': $($_.Exception.Message)" -L Error }
    Write-Log -M "[EXO] Outbound spam filter policy..." -L Info; try { if ($PSCmdlet.ShouldProcess("Outbound Spam Policy 'Default'", "Apply settings?")) { Set-HostedOutboundSpamFilterPolicy Default -RecipientLimitExternalPerHour 500 -RecipientLimitInternalPerHour 1000 -RecipientLimitPerDay 1000 -ActionWhenThresholdReached BlockUser -NotifyOutboundSpamRecipients $AdminUserUpn -AutoForwardingMode Automatic; Write-Log -M "[EXO] Outbound spam policy updated." -L Success } Get-HostedOutboundSpamFilterPolicy Default | Select RecipientLimit*, ActionWhen*, AutoForwardingMode, NotifyOutboundSpamRecipients | FT | Out-String | Write-Log -L Debug } catch { Write-Log -M "[EXO] Failed outbound spam: $($_.Exception.Message)" -L Error }
    Write-Log -M "[EXO] DKIM Signing..." -L Info; try { $verifiedDomains = Get-AcceptedDomain | Where {$_.DomainType -eq "Authoritative"} | Select -Expand DomainName; if ($verifiedDomains.Count -eq 0) { Write-Log -M "[EXO] No authoritative domains for DKIM." -L Warn }; foreach ($domain in $verifiedDomains) { Write-Log -M "[EXO] DKIM for $domain" -L Debug; $dkimConfig = Get-DkimSigningConfig -Identity $domain -EA SilentlyContinue; if ($dkimConfig -and $dkimConfig.Enabled) { Write-Log -M "[EXO] DKIM enabled for $domain." -L Info } else { if ($PSCmdlet.ShouldProcess("DKIM for $domain", "Enable?")) { try { Set-DkimSigningConfig -Identity $domain -Enabled $true -BodyCanonicalization Relaxed -HeaderCanonicalization Relaxed -EA Stop; Write-Log -M "[EXO] DKIM enabled for $domain. Publish CNAMEs." -L Success; $updatedDkimConfig = Get-DkimSigningConfig -Identity $domain; Write-Log -M "[EXO] $domain Sel1 CNAME: $($updatedDkimConfig.Selector1CNAME)" -L Info; Write-Log -M "[EXO] $domain Sel2 CNAME: $($updatedDkimConfig.Selector2CNAME)" -L Info } catch { Write-Log -M "[EXO] Failed DKIM for $domain = "" $($_.Exception.Message)." -L Error }}}}} catch { Write-Log -M "[EXO] DKIM config error: $($_.Exception.Message)" -L Error }
    Write-Log -M "[EXO] Anti-Malware policy..." -L Info; try { if ($PSCmdlet.ShouldProcess("Anti-Malware Policy 'Default'", "Apply settings?")) { Set-MalwareFilterPolicy Default -EnableFileFilter $true -Action DeleteMessage -AdminDisplayName "Default Anti-Malware Policy" -EnableInternalSenderAdminNotifications $true -EnableExternalSenderAdminNotifications $true -InternalSenderAdminAddress $AdminUserUpn -ExternalSenderAdminAddress $AdminUserUpn; Write-Log -M "[EXO] Anti-Malware policy updated." -L Success } Get-MalwareFilterPolicy Default | Select EnableFileFilter, Action, *AdminNotifications, *AdminAddress | FT | Out-String | Write-Log -L Debug } catch { Write-Log -M "[EXO] Failed Anti-Malware: $($_.Exception.Message)" -L Error }
    Write-Log -M "[EXO] Anti-Spam policy..." -L Info; try { if ($PSCmdlet.ShouldProcess("Content Filter Policy 'Default'", "Apply SCL actions?")) { Set-HostedContentFilterPolicy Default -SpamAction MoveToJmf -HighConfidenceSpamAction Quarantine -PhishSpamAction Quarantine -BulkSpamAction MoveToJmf -InlineSafetyTipsEnabled $true -MakeDefault $true; Write-Log -M "[EXO] Anti-Spam policy updated." -L Success } Get-HostedContentFilterPolicy Default | Select SpamAction, HighConfidenceSpamAction, PhishSpamAction, BulkSpamAction, InlineSafetyTipsEnabled | FT | Out-String | Write-Log -L Debug } catch { Write-Log -M "[EXO] Failed Anti-Spam: $($_.Exception.Message)" -L Error }
} else { Write-Log -M "Skipping Section 3: EXO Security." -L Info }

# --- Section 4: Microsoft Defender for Office 365 Configuration ---
if ($ApplyDefenderForOffice365) {
    Write-Log -Message "--- Starting Section 4: Microsoft Defender for Office 365 (MDO) ---" -Level 'Info'; $tenantDomain = ($AdminUserUpn -split "@")[1] 
    if ($EnableDefenderSafeLinksCustomPolicy) { $safeLinksPolicyName = "$CompanyName - MDO - Global Safe Links Policy"; $safeLinksRuleName = "$CompanyName - MDO - Global Safe Links Rule"; Write-Log -M "[MDO] Safe Links: $safeLinksPolicyName" -L Info; try { if (Get-SafeLinksPolicy -Identity $safeLinksPolicyName -EA SilentlyContinue) { Write-Log -M "[MDO] Policy '$safeLinksPolicyName' exists." -L Info } else { if ($PSCmdlet.ShouldProcess("Policy '$safeLinksPolicyName'", "Create?")) { New-SafeLinksPolicy -Name $safeLinksPolicyName -EnableSafeLinksForEmail $true -EnableSafeLinksForTeams $true -EnableSafeLinksForOffice $true -TrackClicks $true -AllowClickThrough $false -ScanUrls $true -EnableForInternalSenders $true -DeliverMessageAfterScan $true -DisableUrlRewrite $false -EA Stop; Write-Log -M "[MDO] Policy '$safeLinksPolicyName' created." -L Success; New-SafeLinksRule -Name $safeLinksRuleName -SafeLinksPolicy $safeLinksPolicyName -RecipientDomainIs $tenantDomain -Enabled $true -Priority 0 -EA Stop; Write-Log -M "[MDO] Rule '$safeLinksRuleName' created." -L Success }}} catch { Write-Log -M "[MDO] Failed Safe Links: $($_.Exception.Message)." -L Error }} else { Write-Log -M "[MDO] Custom Safe Links skipped." -L Info }
    if ($EnableDefenderSafeAttachmentsCustomPolicy) { $safeAttachmentsPolicyName = "$CompanyName - MDO - Global Safe Attachments Policy"; $safeAttachmentsRuleName = "$CompanyName - MDO - Global Safe Attachments Rule"; Write-Log -M "[MDO] Safe Attachments: $safeAttachmentsPolicyName" -L Info; try { if (Get-SafeAttachmentPolicy -Identity $safeAttachmentsPolicyName -EA SilentlyContinue) { Write-Log -M "[MDO] Policy '$safeAttachmentsPolicyName' exists." -L Info } else { if ($PSCmdlet.ShouldProcess("Policy '$safeAttachmentsPolicyName'", "Create?")) { New-SafeAttachmentPolicy -Name $safeAttachmentsPolicyName -Enable $true -Action Block -ActionOnError $true -Redirect $true -RedirectAddress $AdminUserUpn -EA Stop; Write-Log -M "[MDO] Policy '$safeAttachmentsPolicyName' created." -L Success; New-SafeAttachmentRule -Name $safeAttachmentsRuleName -SafeAttachmentPolicy $safeAttachmentsPolicyName -RecipientDomainIs $tenantDomain -Enabled $true -Priority 0 -EA Stop; Write-Log -M "[MDO] Rule '$safeAttachmentsRuleName' created." -L Success }}} catch { Write-Log -M "[MDO] Failed Safe Attachments: $($_.Exception.Message)." -L Error }} else { Write-Log -M "[MDO] Custom Safe Attachments skipped." -L Info }
    if ($EnableDefenderAntiPhishingCustomPolicy) { $antiPhishingPolicyName = "$CompanyName - MDO - Global Anti-Phishing Policy"; $antiPhishingRuleName = "$CompanyName - MDO - Global Anti-Phishing Rule"; Write-Log -M "[MDO] Anti-Phishing: $antiPhishingPolicyName" -L Info; try { if (Get-AntiPhishPolicy -Identity $antiPhishingPolicyName -EA SilentlyContinue) { Write-Log -M "[MDO] Policy '$antiPhishingPolicyName' exists." -L Info } else { if ($PSCmdlet.ShouldProcess("Policy '$antiPhishingPolicyName'", "Create?")) { $apParams = @{Name = $antiPhishingPolicyName; Enabled = $true; EnableSpoofIntelligence = $true; EnableUnauthenticatedSender = $true; EnableMailboxIntelligenceProtection = $true; EnableSimilarUsersSafetyTips = $true; EnableSimilarDomainsSafetyTips = $true; EnableUnusualCharactersSafetyTips = $true; PhishThresholdLevel = 2; MailboxIntelligenceProtectionAction = 'MoveToJmf'; SpoofQuarantineTag = 'DefaultFullAccessWithNotificationPolicy'; TargetedUserProtectionAction = 'Quarantine'; TargetedDomainProtectionAction = 'Quarantine'; ImpersonationProtectionAction = 'Quarantine'; PhishZapEnabled = $true; EnableOrganizationDomainsProtection = $true; EnableTargetedDomainsProtection = $true; EnableTargetedUserProtection = $true}; if ($AntiPhishTargetedUsersToProtectUpns.Count -gt 0) { $apParams.Add("TargetedUsersToProtect", $AntiPhishTargetedUsersToProtectUpns) }; if ($AntiPhishTargetedDomainsToProtect.Count -gt 0) { $apParams.Add("TargetedDomainsToProtect", $AntiPhishTargetedDomainsToProtect) }; New-AntiPhishPolicy @apParams -EA Stop; Write-Log -M "[MDO] Policy '$antiPhishingPolicyName' created." -L Success; New-AntiPhishRule -Name $antiPhishingRuleName -AntiPhishPolicy $antiPhishingPolicyName -RecipientDomainIs $tenantDomain -Enabled $true -Priority 0 -EA Stop; Write-Log -M "[MDO] Rule '$antiPhishingRuleName' created." -L Success }}} catch { Write-Log -M "[MDO] Failed Anti-Phishing: $($_.Exception.Message)." -L Error }} else { Write-Log -M "[MDO] Custom Anti-Phishing skipped." -L Info }
    Write-Log -M "[MDO] ATP for SPO/ODB/Teams & Safe Docs..." -L Info; try { if ($PSCmdlet.ShouldProcess("ATP Policy For O365 'Default'", "Enable?")) { Set-AtpPolicyForO365 Default -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -AllowSafeDocsOpen $false; Write-Log -M "[MDO] ATP for SPO/ODB/Teams & Safe Docs updated." -L Success } Get-AtpPolicyForO365 Default | Select Identity, EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen | FT | Out-String | Write-Log -L Debug } catch { Write-Log -M "[MDO] Failed ATP for SPO/ODB: $($_.Exception.Message)." -L Error }
    if ($EnableDefenderPresetPolicies) { Write-Log -M "[MDO] Preset Security Policies..." -L Info; Write-Log -M "[MDO] WARNING: Enabling presets for 'AllRecipients'. Review carefully." -L Warn; try { if ($PSCmdlet.ShouldProcess("MDO Standard Preset", "Enable?")) { Enable-PresetSecurityPolicy -Identity "Standard Preset Security Policy" -EnableAllRecipients $true -EA Stop; Write-Log -M "[MDO] Standard Preset enabled." -L Success } Get-PresetSecurityPolicy -Identity "Standard Preset Security Policy" | FL | Out-String | Write-Log -L Debug } catch { Write-Log -M "[MDO] Failed Standard Preset: $($_.Exception.Message)." -L Error }; try { if ($PSCmdlet.ShouldProcess("MDO Strict Preset", "Enable? (AGGRESSIVE)")) { Enable-PresetSecurityPolicy -Identity "Strict Preset Security Policy" -EnableAllRecipients $true -EA Stop; Write-Log -M "[MDO] Strict Preset enabled. REVIEW." -L Warn } Get-PresetSecurityPolicy -Identity "Strict Preset Security Policy" | FL | Out-String | Write-Log -L Debug } catch { Write-Log -M "[MDO] Failed Strict Preset: $($_.Exception.Message)." -L Error }} else { Write-Log -M "[MDO] Preset Policies skipped." -L Info }
} else { Write-Log -M "Skipping Section 4: MDO as per parameter." -L Info }

if ($ApplySharePointOnlineSecurity) {
    Write-Log -Message "--- Starting Section 5: SharePoint Online and OneDrive Security ---" -Level 'Info'; $tenantNameForSPO = ($AdminUserUpn.Split('@')[1]).Split('.')[0]; $spoAdminUrl = "https://$tenantNameForSPO-admin.sharepoint.com"; Write-Log -M "[SPO] Connecting to SPO Admin: $spoAdminUrl..." -L Info; try { Get-SPOSite -Limit 1 -EA SilentlyContinue | Out-Null; if (-not $?) { Disconnect-SPOService -EA SilentlyContinue }; Connect-SPOService -Url $spoAdminUrl -EA Stop; Write-Log -M "[SPO] Connected to SPO Admin." -L Success; $sharePointSharingCap = "ExistingExternalUserSharingOnly"; $oneDriveSharingCap = "ExistingExternalUserSharingOnly"; if ($PSCmdlet.ShouldProcess("SPO Tenant", "Set SharingCaps?")) { Set-SPOTenant -SharingCapability $sharePointSharingCap -OneDriveSharingCapability $oneDriveSharingCap; Write-Log -M "[SPO] Sharing caps updated." -L Success }; Get-SPOTenant | Select SharingCapability, OneDriveSharingCapability | FT | Out-String | Write-Log -L Debug; if ($PSCmdlet.ShouldProcess("SPO Tenant", "Configure Anonymous Links?")) { Set-SPOTenant -RequireAnonymousLinksExpireInDays 14 -DefaultSharingLinkType Internal -FileAnonymousLinkType View -FolderAnonymousLinkType View -PreventExternalUsersFromResharing $true -NotifyOwnersWhenItemsReshared $true -NotifyOwnersWhenInvitationsAccepted $true; Write-Log -M "[SPO] Anonymous links configured." -L Success }; Get-SPOTenant | Select ReqAnon*, DefSharing*, FileAnon*, FolderAnon*, PreventExt* | FT | Out-String | Write-Log -L Debug; if ($AllowedExternalSharingDomains.Count -gt 0) { if ($PSCmdlet.ShouldProcess("SPO Tenant", "Set AllowList?")) { Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList ($AllowedExternalSharingDomains -join ','); Write-Log -M "[SPO] Sharing AllowList set." -L Success }} elseif ($BlockedExternalSharingDomains.Count -gt 0) { if ($PSCmdlet.ShouldProcess("SPO Tenant", "Set BlockList?")) { Set-SPOTenant -SharingDomainRestrictionMode BlockList -SharingBlockedDomainList ($BlockedExternalSharingDomains -join ','); Write-Log -M "[SPO] Sharing BlockList set." -L Success }} else { Write-Log -M "[SPO] No sharing domain lists." -L Info }; Get-SPOTenant | Select SharingDomainRestrictionMode, SharingAllowedDomainList, SharingBlockedDomainList | FT | Out-String | Write-Log -L Debug; if ($PSCmdlet.ShouldProcess("SPO Tenant", "Set Device Access Policy?")) { Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess -AllowDownloadingNonWebViewableFiles $false -AllowEditing $false -LimitedAccessFileType OfficeOnlineFilesOnly; Write-Log -M "[SPO] Device access policies updated." -L Success }; Get-SPOTenant | Select ConditionalAccessPolicy, AllowDownloadingNonWebViewableFiles, AllowEditing, LimitedAccessFileType | FT | Out-String | Write-Log -L Debug; Write-Log -M "[SPO] Disconnecting..." -L Info; Disconnect-SPOService -EA SilentlyContinue } catch { Write-Log -M "[SPO] Failed SPO ops: $($_.Exception.Message)" -L Error }} else { Write-Log -M "Skipping Section 5: SPO Security." -L Info }

if ($ApplyAuditLogConfiguration) {
    Write-Log -Message "--- Starting Section 6: Audit Configuration ---" -Level 'Info'; Write-Log -M "[AUDIT] UAL enabling..." -L Info; try { $ualStatus = Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled; Write-Log -M "[AUDIT] UAL Status: $($ualStatus.UnifiedAuditLogIngestionEnabled)" -L Info; if (-not $ualStatus.UnifiedAuditLogIngestionEnabled) { if ($PSCmdlet.ShouldProcess("Admin Audit Log", "Set UAL Ingestion?")) { Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true; Write-Log -M "[AUDIT] UAL ingestion enabled." -L Success }}} catch { Write-Log -M "[AUDIT] Failed UAL: $($_.Exception.Message)" -L Error }; Write-Log -M "[AUDIT] Exchange Admin Audit Log..." -L Info; try { if ($PSCmdlet.ShouldProcess("Exchange Admin Audit Log", "Enable full logging?")) { Set-AdminAuditLogConfig -AdminAuditLogEnabled $true -AdminAuditLogCmdlets "*" -AdminAuditLogParameters "*" -LogLevel Verbose; Write-Log -M "[AUDIT] Exchange Admin Audit configured." -L Success } Get-AdminAuditLogConfig | Select AdminAuditLogEnabled, LogLevel, AdminAuditLogCmdlets, AdminAuditLogParameters | FT | Out-String | Write-Log -L Debug } catch { Write-Log -M "[AUDIT] Failed Exchange Admin Audit: $($_.Exception.Message)" -L Error }} else { Write-Log -M "Skipping Section 6: Audit Config." -L Info }

if ($IncludeLicenseOverview) {
    Write-Log -Message "--- Starting Section 7: License Overview ---" -Level 'Info'; try { Write-Log -M "[LICENSE] Fetching SKUs..." -L Info; if (-not ($Global:mgContext.Scopes -contains "SubscribedSku.Read.All")) { Write-Log -M "Scope 'SubscribedSku.Read.All' not in context. Skipping License Overview." -L Warn } else { $subscribedSkus = Get-MgSubscribedSku -All | Select SkuId, SkuPartNumber, ConsumedUnits, @{N="TotalUnits";E={$_.PrepaidUnits.Enabled + $_.PrepaidUnits.Suspended + $_.PrepaidUnits.Warning}}; if ($subscribedSkus) { Write-Log -M "[LICENSE] SKUs:" -L Info; $subscribedSkus | FT -AutoSize | Out-String | Write-Log -L Info } else { Write-Log -M "[LICENSE] No SKUs found." -L Warn }}} catch { Write-Log -M "[LICENSE] Failed license overview: $($_.Exception.Message)" -L Error }} else { Write-Log -M "License overview skipped." -L Info }

Write-Log -Message "--- Section 8: Microsoft Teams Security (Placeholder) ---" -Level 'Info'; Write-Log -M "Teams security config is a placeholder." -L Info

# Run Post-Configuration Tests if requested
if ($RunPostConfigurationTests) {
    Test-SecurityConfiguration -IncludeCAPolicies $ApplyAzureADConditionalAccess `
                               -IncludeEXOPolicies $ApplyExchangeOnlineSecurity `
                               -IncludeMDOPolicies $ApplyDefenderForOffice365 `
                               -IncludeSPOPolicies $ApplySharePointOnlineSecurity
}

# --- Script End ---
Write-Log -Message "--- Script Execution Finished ---" -Level 'Info'
# Disconnect logic
try { Write-Log -M "Disconnecting from Graph..." -L Info; Disconnect-MgGraph -ErrorAction SilentlyContinue; Write-Log -M "Disconnected from Graph." -L Success } catch { Write-Log -M "Graph disconnect error: $($_.Exception.Message)" -L Warn }
try { Write-Log -M "Disconnecting from Exchange..." -L Info; Get-PSSession | Where {$_.ConfigurationName -eq 'Microsoft.Exchange'} | Remove-PSSession -EA SilentlyContinue; Write-Log -M "Disconnected from Exchange." -L Success } catch { Write-Log -M "Exchange disconnect error: $($_.Exception.Message)" -L Warn }

$scriptEndTime = Get-Date; $executionTime = $scriptEndTime - $scriptStartTime
Write-Log -M "Script completed for $CompanyName. Total time: $($executionTime.ToString())" -L Success
Write-Log -M "Log file: $Global:LOG_FILE_PATH_EFFECTIVE" -L Info 
# Post-script reminders
Write-Log -Message "----------------------------------------------------------------" -Level 'Warning'
Write-Log -Message "IMPORTANT POST-SCRIPT ACTIONS & REMINDERS:" -Level 'Warning'
Write-Log -Message "1. REVIEW ALL LOGS ($($Global:LOG_FILE_PATH_EFFECTIVE)) FOR ERRORS OR WARNINGS." -Level 'Warning'
Write-Log -Message "2. CONDITIONAL ACCESS POLICIES: Created in 'Report-only' mode. Monitor and enable to 'On' after validation." -Level 'Warning'
Write-Log -Message "3. DEFENDER PRESET POLICIES: If enabled, review their impact. 'Strict' preset is aggressive." -Level 'Warning'
Write-Log -Message "4. DKIM: Ensure CNAME records for DKIM selectors are published in public DNS." -Level 'Warning'
Write-Log -Message "5. MFA ROLLOUT: Plan and communicate MFA registration." -Level 'Warning'
Write-Log -Message "6. BREAK-GLASS ACCOUNTS: Verify functionality and exclusions." -Level 'Warning'
Write-Log -Message "7. DNS RECORDS (SPF, DMARC): Ensure comprehensive email authentication." -Level 'Warning'
Write-Log -Message "8. REVIEW ALL OTHER APPLIED SETTINGS AND TEST THOROUGHLY." -Level 'Warning'
Write-Log -Message "----------------------------------------------------------------" -Level 'Warning'

