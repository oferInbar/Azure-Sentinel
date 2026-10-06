function Add-CustomerUsageAttribution {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SolutionMetadataPath,
        [Parameter(Mandatory = $true)]
        [psobject]$Template,
        [bool]$WarnIfMissing = $false
    )

    # Consolidated Data metadata is not authoritative for this packaging-only setting.
    $metadata = Get-Content -LiteralPath $SolutionMetadataPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $trackingId = $metadata.trackingId
    if ($null -eq $trackingId -or ($trackingId -is [string] -and [string]::IsNullOrWhiteSpace($trackingId))) {
        if ($WarnIfMissing) {
            Write-Warning "CUSTOMER USAGE ATTRIBUTION: No attribution marker will be emitted because trackingId is absent or blank in '$SolutionMetadataPath'. Partner Center cannot automatically add tracking when the template contains functional nested deployments (including XDR). Obtain the COMPLETE customer usage attribution tracking ID from Partner Center > offer > plan > Technical configuration, add trackingId to SolutionMetadata.json, and rebuild. Do not use a Partner ID, plan ID, or a newly generated GUID. See https://learn.microsoft.com/partner-center/marketplace-offers/azure-partner-customer-usage-attribution#microsoft-marketplace-azure-apps"
        }
        return
    }

    if ($trackingId -isnot [string] -or $trackingId.Length -gt 64 -or
        $trackingId -cnotmatch '\Apid-[A-Za-z0-9][A-Za-z0-9_.()-]*\z') {
        throw "Invalid trackingId in '$SolutionMetadataPath'. Copy the complete pid- tracking ID from Partner Center unchanged (not a bare GUID, Partner ID, or plan ID). It must be a literal deployment name of at most 64 characters using letters, digits, hyphens, underscores, periods, or parentheses."
    }

    if (@($Template.resources | Where-Object {
        $_.type -eq 'Microsoft.Resources/deployments' -and $_.name -eq $trackingId
    }).Count -gt 0) {
        throw "Duplicate customer usage attribution deployment name '$trackingId'."
    }

    $Template.resources = @($Template.resources) + @([pscustomobject]@{
        type       = 'Microsoft.Resources/deployments'
        apiVersion = '2025-04-01'
        name       = $trackingId
        properties = [pscustomobject]@{
            mode     = 'Incremental'
            template = [pscustomobject]@{
                '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion = '1.0.0.0'
                resources      = @()
            }
        }
    })
}
