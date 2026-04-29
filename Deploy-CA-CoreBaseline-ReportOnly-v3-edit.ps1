<#
.SYNOPSIS
    Deploy core Conditional Access baseline policies in Report-Only mode.

.DESCRIPTION
    Creates or updates these policies, all in report-only state:
      - CA-01 Block Legacy Authentication
      - CA-02 Require MFA – All Users
      - CA-03 Require Phishing-Resistant MFA – Admin Roles
      - CA-04 Block High Sign-In Risk
      - CA-05 Require MFA – Medium Sign-In Risk
      - CA-08 Block High User Risk
      - CA-09 Require Password Reset – High User Risk
      - CA-06 Require Compliant Device – M365 Access
#>

param(
    [string]$TenantId = "",
    [switch]$UpdateExisting,
    [string]$OutputFolder = ".\CA_v3_Output"
)

# -----------------------------
# Fixed policy state
# -----------------------------
$ReportOnlyState = "enabledForReportingButNotEnforced"

# -----------------------------
# Tenant-specific variables
# -----------------------------
$BreakGlassUPNs = @(
     ""
)

$StandardUsersGroupId = ""

$PrivilegedRoleIds = @(
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5", # Intune Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c", # Groups Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8", # Helpdesk Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # Hybrid Identity Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e", # Identity Governance Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f"  # Authentication Administrator
)

$M365AppTarget = @("Office365")

$BuiltInAuthStrengths = @{
    MultifactorAuthentication = "00000000-0000-0000-0000-000000000002"
    PhishingResistantMFA      = "00000000-0000-0000-0000-000000000004"
}

# -----------------------------
# Prep
# -----------------------------
$null = New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction SilentlyContinue
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogPath = Join-Path $OutputFolder "Deploy-CA-CoreBaseline-ReportOnly-v3_$Timestamp.log"
$CsvPath = Join-Path $OutputFolder "Deploy-CA-CoreBaseline-ReportOnly-v3_$Timestamp.csv"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    $line | Tee-Object -FilePath $LogPath -Append
}

function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Missing module: $Name"
    }
    Import-Module $Name -ErrorAction Stop
}

function Resolve-BreakGlassIds {
    param([string[]]$UPNs)

    $ids = @()
    foreach ($upn in $UPNs) {
        try {
            $u = Get-MgUser -UserId $upn -Property Id,UserPrincipalName
            $ids += $u.Id
        }
        catch {
            throw "Failed to resolve break-glass user '$upn'"
        }
    }
    return $ids
}

function Validate-Inputs {
    if ($StandardUsersGroupId -eq "<STANDARD_USERS_GROUP_OBJECT_ID>") {
        throw "Replace `$StandardUsersGroupId with a real group object ID."
    }
}

function Get-ExistingPolicies {
    Get-MgIdentityConditionalAccessPolicy -All
}

function Get-PolicyByName {
    param([array]$Policies, [string]$DisplayName)
    $Policies | Where-Object { $_.DisplayName -eq $DisplayName } | Select-Object -First 1
}

$Results = New-Object System.Collections.Generic.List[object]

function Save-Result {
    param(
        [string]$PolicyName,
        [string]$Action,
        [string]$State,
        [string]$Result,
        [string]$PolicyId = "",
        [string]$ErrorMessage = ""
    )

    $Results.Add([PSCustomObject]@{
        PolicyName = $PolicyName
        Action     = $Action
        State      = $State
        Result     = $Result
        PolicyId   = $PolicyId
        Error      = $ErrorMessage
    })
}

function Set-CAPolicySafe {
    param(
        [hashtable]$Body,
        [array]$ExistingPolicies
    )

    $name = $Body.displayName
    $existing = Get-PolicyByName -Policies $ExistingPolicies -DisplayName $name

    try {
        if ($existing) {
            if ($UpdateExisting) {
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $existing.Id -BodyParameter $Body | Out-Null
                Write-Log "Updated policy: $name" "SUCCESS"
                Save-Result -PolicyName $name -Action "Update" -State $Body.state -Result "Success" -PolicyId $existing.Id
            }
            else {
                Write-Log "Skipped existing policy: $name" "WARN"
                Save-Result -PolicyName $name -Action "Skip" -State $existing.State -Result "Exists" -PolicyId $existing.Id
            }
        }
        else {
            $created = New-MgIdentityConditionalAccessPolicy -BodyParameter $Body
            Write-Log "Created policy: $name" "SUCCESS"
            Save-Result -PolicyName $name -Action "Create" -State $Body.state -Result "Success" -PolicyId $created.Id
        }
    }
    catch {
        Write-Log "Failed policy: $name :: $($_.Exception.Message)" "ERROR"
        Save-Result -PolicyName $name -Action "Create/Update" -State $Body.state -Result "Failed" -ErrorMessage $_.Exception.Message
    }
}

# -----------------------------
# Connect
# -----------------------------
Ensure-Module "Microsoft.Graph.Authentication"
Ensure-Module "Microsoft.Graph.Identity.SignIns"
Ensure-Module "Microsoft.Graph.Users"

$scopes = @(
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.Read.All",
    "Directory.Read.All",
    "Application.Read.All"
)

Validate-Inputs

if ([string]::IsNullOrWhiteSpace($TenantId)) {
    Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
}
else {
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome | Out-Null
}

$ctx = Get-MgContext
Write-Log "Starting core CA deployment (Report-Only preset)"
Write-Log "Connected Tenant: $($ctx.TenantId)"
Write-Log "Connected Account: $($ctx.Account)"

$BreakGlassUserIds = Resolve-BreakGlassIds -UPNs $BreakGlassUPNs
$existingPolicies = Get-ExistingPolicies

# -----------------------------
# Policies
# -----------------------------
$Policies = @(
    @{
        displayName = "CA-01 Block Legacy Authentication"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("exchangeActiveSync", "other")
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")
        }
    },
    @{
        displayName = "CA-02 Require MFA – All Users"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("all")
        }
        grantControls = @{
            operator               = "OR"
            authenticationStrength = @{
                id = $BuiltInAuthStrengths.MultifactorAuthentication
            }
        }
    },
    @{
        displayName = "CA-03 Require Phishing-Resistant MFA – Admin Roles"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeRoles = $PrivilegedRoleIds
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("all")
        }
        grantControls = @{
            operator               = "OR"
            authenticationStrength = @{
                id = $BuiltInAuthStrengths.PhishingResistantMFA
            }
        }
    },
    @{
        displayName = "CA-04 Block High Sign-In Risk"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes   = @("all")
            signInRiskLevels = @("high")
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")
        }
    },
    @{
        displayName = "CA-05 Require MFA – Medium Sign-In Risk"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes   = @("all")
            signInRiskLevels = @("medium")
        }
        grantControls = @{
            operator               = "OR"
            authenticationStrength = @{
                id = $BuiltInAuthStrengths.MultifactorAuthentication
            }
        }
    },
    @{
        displayName = "CA-08 Block High User Risk"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("all")
            userRiskLevels = @("high")
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")
        }
    },
    @{
        displayName = "CA-09 Require Password Reset – High User Risk"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeUsers = @("All")
                excludeUsers = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("all")
            userRiskLevels = @("high")
        }
        grantControls = @{
            operator        = "AND"
            builtInControls = @("passwordChange", "mfa")
        }
    },
    @{
        displayName = "CA-06 Require Compliant Device – M365 Access"
        state       = $ReportOnlyState
        conditions  = @{
            users = @{
                includeGroups = @($StandardUsersGroupId)
                excludeUsers  = $BreakGlassUserIds
            }
            applications = @{
                includeApplications = $M365AppTarget
            }
            clientAppTypes = @("all")
        }
        grantControls = @{
            operator        = "OR"
            builtInControls = @("compliantDevice")
        }
    }
)

foreach ($policy in $Policies) {
    Set-CAPolicySafe -Body $policy -ExistingPolicies $existingPolicies
}

$Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Log "Results exported: $CsvPath" "SUCCESS"
Write-Log "Core CA deployment (Report-Only preset) finished" "SUCCESS"