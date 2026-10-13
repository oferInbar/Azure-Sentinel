# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the repository root.

function Get-DefenderWorkbookSelection {
    param([psobject]$ContentToImport, [string]$SolutionRoot, [string]$SolutionName)

    $property = $ContentToImport.PSObject.Properties['XDR Workbooks']
    if ($null -eq $property) {
        $directory = Join-Path $SolutionRoot 'XDR Workbooks'
        if (Test-Path -LiteralPath $directory) {
            Assert-NoSolutionContentSymlinks -SolutionRoot $SolutionRoot
            if (@(Get-ChildItem -LiteralPath $directory -Recurse -File -Force |
                    Where-Object { $_.Extension -ieq '.json' }).Count -gt 0) {
                throw "Existing XDR Workbooks require an explicit 'XDR Workbooks' selection array; use [] to exclude them."
            }
        }
        return
    }
    if ($property.Value -isnot [array]) {
        throw "Solution Data 'XDR Workbooks' must be an explicit array."
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($reference in $property.Value) {
        if ($reference -isnot [string] -or [string]::IsNullOrWhiteSpace($reference)) {
            throw "XDR Workbooks selection must contain nonempty local path strings."
        }
        $resolved = Resolve-SolutionContentPath -SolutionRoot $SolutionRoot -SolutionName $SolutionName `
            -ContentPath $reference -RequireFile
        if (-not $resolved.RelativePath.StartsWith('XDR Workbooks/', [System.StringComparison]::Ordinal) -or
            [System.IO.Path]::GetExtension($resolved.FullPath) -ine '.json') {
            throw "Defender Workbook selection must reference JSON files under XDR Workbooks: $reference"
        }
        if (-not $seen.Add($resolved.FullPath)) {
            throw "Duplicate Defender Workbook selection: $reference"
        }
        $resolved
    }
}

function Assert-DefenderWorkbookReleaseVersion {
    param([string]$Version)
    if ($Version -cnotmatch '\A3\.[1-9][0-9]*\.(?:0|[1-9][0-9]*)\z') {
        throw "Defender Workbook release version '$Version' must be canonical major.minor.patch in [3.1.0, 4.0.0)."
    }
}

function Assert-DefenderWorkbookDocument {
    param([psobject]$Document, [string]$SolutionRoot, [string]$SolutionName, [string]$ContentPath)

    if ($Document -isnot [pscustomobject] -or $Document.version -cne 'Notebook/1.0' -or
        $Document.items -isnot [array]) {
        throw "Defender Workbook '$ContentPath' must be a complete Notebook/1.0 object with an items array."
    }
    Assert-DefenderWorkbookSerializationDepth -Value $Document
    $metadata = $Document.xdrMetadata
    $guidPattern = '\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z'
    if ($metadata -isnot [pscustomobject] -or $metadata.schemaVersion -cne '1.0.0' -or
        $metadata.contentId -isnot [string] -or $metadata.contentId -cnotmatch $guidPattern -or
        $metadata.instanceId -isnot [string] -or $metadata.instanceId -cnotmatch $guidPattern -or
        $metadata.contentId -ieq $metadata.instanceId -or
        $metadata.displayName -isnot [string] -or [string]::IsNullOrWhiteSpace($metadata.displayName)) {
        throw "Defender Workbook '$ContentPath' requires distinct canonical contentId/instanceId GUIDs and reviewed displayName."
    }
    Assert-DefenderWorkbookReleaseVersion -Version $metadata.version
    $provenance = $Document.contentProvenance
    if ($provenance -isnot [pscustomobject] -or
        $provenance.dependencyReviewRequired -isnot [bool] -or $provenance.dependencyReviewRequired -or
        $provenance.conversion -isnot [pscustomobject] -or
        $provenance.conversion.tool -isnot [string] -or [string]::IsNullOrWhiteSpace($provenance.conversion.tool) -or
        $provenance.conversion.version -isnot [string] -or [string]::IsNullOrWhiteSpace($provenance.conversion.version) -or
        $provenance.conversion.reviewRequired -isnot [bool] -or $provenance.conversion.reviewRequired) {
        throw "Defender Workbook '$ContentPath' requires explicitly reviewed conversion and dependency provenance."
    }
    $source = $provenance.source
    if ($source -isnot [pscustomobject] -or $source.path -isnot [string] -or
        $source.sha256 -isnot [string] -or $source.sha256 -cnotmatch '\A[0-9a-fA-F]{64}\z') {
        throw "Defender Workbook '$ContentPath' requires its current source path and SHA256."
    }
    $resolvedSource = Resolve-SolutionContentPath -SolutionRoot $SolutionRoot -SolutionName $SolutionName `
        -ContentPath $source.path -RequireFile
    if (-not $resolvedSource.RelativePath.StartsWith('Workbooks/', [System.StringComparison]::Ordinal) -or
        [System.IO.Path]::GetExtension($resolvedSource.FullPath) -ine '.json' -or
        (Get-FileHash -LiteralPath $resolvedSource.FullPath -Algorithm SHA256).Hash -ine $source.sha256) {
        throw "Defender Workbook '$ContentPath' source identity/hash is stale or outside Workbooks."
    }
    if ($provenance.conversion.queries -isnot [array]) {
        throw "Defender Workbook '$ContentPath' requires conversion.queries as an array."
    }
    $sourceNotebook = Get-Content -LiteralPath $resolvedSource.FullPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ($sourceNotebook -isnot [pscustomobject] -or $sourceNotebook.version -cne 'Notebook/1.0' -or
        $sourceNotebook.items -isnot [array]) {
        throw "Defender Workbook '$ContentPath' source must be a complete Notebook/1.0."
    }
    $sourcePointers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $targetPointers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($query in $provenance.conversion.queries) {
        if ($query -isnot [pscustomobject] -or
            $query.status -cnotin @('converted', 'removed-scope-helper') -or
            $query.sourcePath -isnot [string] -or -not $query.sourcePath.StartsWith('/') -or
            $query.sourceSha256 -isnot [string] -or $query.sourceSha256 -cnotmatch '\A[0-9a-fA-F]{64}\z' -or
            -not $sourcePointers.Add($query.sourcePath)) {
            throw "Defender Workbook '$ContentPath' has unreviewed or malformed query provenance."
        }
        $sourceQuery = Get-DefenderWorkbookJsonPointer -Document $sourceNotebook -Pointer $query.sourcePath
        if ($sourceQuery -isnot [string]) {
            throw "Defender Workbook '$ContentPath' source query pointer must resolve to a string."
        }
        $sourceBytes = [System.Text.Encoding]::UTF8.GetBytes($sourceQuery)
        $sourceHash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($sourceBytes))
        if ($sourceHash -ine $query.sourceSha256) {
            throw "Defender Workbook '$ContentPath' source query hash is stale."
        }
        if ($query.status -ceq 'removed-scope-helper') {
            if ($null -ne $query.outputPath -or $null -ne $query.targetSha256) {
                throw "Defender Workbook '$ContentPath' removed scope query must have null output identity."
            }
            continue
        }
        if ($query.outputPath -isnot [string] -or -not $query.outputPath.StartsWith('/') -or
            $query.targetSha256 -isnot [string] -or $query.targetSha256 -cnotmatch '\A[0-9a-fA-F]{64}\z' -or
            -not $targetPointers.Add($query.outputPath)) {
            throw "Defender Workbook '$ContentPath' requires current target query provenance."
        }
        $targetQuery = Get-DefenderWorkbookJsonPointer -Document $Document -Pointer $query.outputPath
        if ($targetQuery -isnot [string]) {
            throw "Defender Workbook '$ContentPath' target query pointer must resolve to a string."
        }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($targetQuery)
        $hash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))
        if ($hash -ine $query.targetSha256) {
            throw "Defender Workbook '$ContentPath' target query hash is stale."
        }
    }
    $workloads = @('mde', 'mdo', 'mdi', 'mda', 'mdc', 'entraid', 'purview', 'appgovernance', 'sentinel', 'mtp')
    foreach ($field in @('requiredWorkloads', 'requiredDataConnectors')) {
        $value = $provenance.PSObject.Properties[$field]
        if ($null -eq $value -or $value.Value -isnot [array]) {
            throw "Defender Workbook '$ContentPath' requires contentProvenance.$field as an array."
        }
        $identityField = if ($field -eq 'requiredWorkloads') { 'workload' } else { 'connectorId' }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $value.Value) {
            if ($record -isnot [pscustomobject] -or $record.$identityField -isnot [string] -or
                [string]::IsNullOrWhiteSpace($record.$identityField) -or
                $record.dataTypes -isnot [array] -or -not $seen.Add($record.$identityField)) {
                throw "Defender Workbook '$ContentPath' has malformed or duplicate $field records."
            }
            if ($field -eq 'requiredWorkloads' -and $record.workload -cnotin $workloads) {
                throw "Defender Workbook '$ContentPath' has unknown workload '$($record.workload)'."
            }
            $types = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($dataType in $record.dataTypes) {
                if ($dataType -isnot [string] -or [string]::IsNullOrWhiteSpace($dataType) -or
                    -not $types.Add($dataType)) {
                    throw "Defender Workbook '$ContentPath' has malformed or duplicate dependency dataTypes."
                }
            }
        }
    }
}

function Assert-DefenderWorkbookSerializationDepth {
    param([AllowNull()][object]$Value, [int]$Depth = 0)
    if ($Depth -gt 85) {
        throw 'Defender Workbook exceeds safe package JSON serialization depth; content cannot be truncated.'
    }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            Assert-DefenderWorkbookSerializationDepth -Value $property.Value -Depth ($Depth + 1)
        }
    }
    elseif ($Value -is [array]) {
        foreach ($item in $Value) {
            Assert-DefenderWorkbookSerializationDepth -Value $item -Depth ($Depth + 1)
        }
    }
}

function Get-DefenderWorkbookJsonPointer {
    param([psobject]$Document, [string]$Pointer)
    $value = $Document
    foreach ($part in $Pointer.Substring(1).Split('/')) {
        if ($part -cmatch '~(?:[^01]|$)') { throw "Invalid Defender Workbook query JSON pointer: $Pointer" }
        $key = $part.Replace('~1', '/').Replace('~0', '~')
        if ($value -is [array] -and $key -cmatch '\A(?:0|[1-9][0-9]*)\z' -and
            [System.Numerics.BigInteger]::Parse($key) -lt $value.Count) {
            $value = $value[[int]$key]
        }
        elseif ($value -is [pscustomobject] -and $null -ne $value.PSObject.Properties[$key]) {
            $value = $value.PSObject.Properties[$key].Value
        }
        else { throw "Unresolvable Defender Workbook query JSON pointer: $Pointer" }
    }
    return $value
}

function Get-DefenderWorkbookDeploymentName {
    param([string]$SolutionName, [string]$ContentId)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$SolutionName/$ContentId")
    $hash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    return 'DefenderWorkbook-' + $hash.Substring(0, 32)
}

function ConvertTo-DefenderWorkbookArmCopy {
    param([AllowNull()][object]$Value)

    if ($Value -is [string]) {
        # ARM consumes one leading '[' from escaped literals, including authored '[['.
        if ($Value.StartsWith('[')) { return '[' + $Value }
        return $Value
    }
    if ($Value -is [pscustomobject]) {
        $result = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-DefenderWorkbookArmCopy -Value $property.Value
        }
        return [pscustomobject]$result
    }
    if ($Value -is [array]) {
        $result = @(
            foreach ($item in $Value) { ConvertTo-DefenderWorkbookArmCopy -Value $item }
        )
        return ,$result
    }
    return $Value
}

function New-DefenderWorkbookInstallDeployment {
    param([string]$DeploymentName, [psobject]$WorkbookResource)

    [pscustomobject]@{
        type = 'Microsoft.Resources/deployments'
        apiVersion = '2025-04-01'
        name = $DeploymentName
        condition = "[parameters('DeployDefenderWorkbook')]"
        dependsOn = @(
            "[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
        )
        properties = [pscustomobject]@{
            mode = 'Incremental'
            expressionEvaluationOptions = [pscustomobject]@{ scope = 'inner' }
            template = [pscustomobject]@{
                '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                languageVersion = '2.0'
                contentVersion = '1.0.0.0'
                imports = [pscustomobject]@{
                    MicrosoftSecurity = [pscustomobject]@{ provider = 'MicrosoftSecurity'; version = '1.0.0' }
                }
                resources = [pscustomobject]@{ workbook = $WorkbookResource }
            }
        }
    }
}

function New-DefenderWorkbookRegistration {
    param(
        [string]$DeploymentName, [psobject]$InstallDeployment, [psobject]$Document,
        [psobject]$ResolvedProvenance, [string]$PackageName
    )

    $contentId = $ResolvedProvenance.contentId
    $version = $ResolvedProvenance.contentVersion
    $productId = "[concat(take(variables('_solutionId'),50),'-','dwb','-', uniqueString(concat(variables('_solutionId'),'-','DefenderWorkbook','-','$contentId','-','$version')))]"
    $fullProvenance = $ResolvedProvenance | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $fullProvenance | Add-Member -NotePropertyName requiredWorkloads -NotePropertyValue @($Document.contentProvenance.requiredWorkloads)
    $fullProvenance | Add-Member -NotePropertyName requiredDataConnectors -NotePropertyValue @($Document.contentProvenance.requiredDataConnectors)
    [pscustomobject]@{
        type = 'Microsoft.OperationalInsights/workspaces/providers/contentTemplates'
        apiVersion = '2023-04-01-preview'
        name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',concat(parameters('workspace'),'-dwb-',uniqueString('$contentId')))]"
        location = "[parameters('workspace-location')]"
        condition = "[parameters('DeployDefenderWorkbook')]"
        dependsOn = @(
            "[resourceId('Microsoft.Resources/deployments', '$DeploymentName')]",
            "[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
        )
        properties = [pscustomobject]@{
            description = "Defender Workbook: $($Document.xdrMetadata.displayName)"
            mainTemplate = ($InstallDeployment.properties.template | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
            packageKind = 'Solution'
            packageVersion = $ResolvedProvenance.packageVersion
            packageName = (ConvertTo-DefenderWorkbookArmCopy -Value $PackageName)
            packageId = $ResolvedProvenance.packageId
            contentSchemaVersion = '3.0.0'
            contentId = $contentId
            contentKind = 'DefenderWorkbook'
            displayName = (ConvertTo-DefenderWorkbookArmCopy -Value $Document.xdrMetadata.displayName)
            contentProductId = $productId
            id = $productId
            version = $version
            contentProvenance = (ConvertTo-DefenderWorkbookArmCopy -Value $fullProvenance)
        }
    }
}

function Add-XdrDefenderWorkbooksToSolution {
    param(
        [Parameter(Mandatory = $true)][string]$SolutionName,
        [Parameter(Mandatory = $true)][psobject]$ContentToImport,
        [Parameter(Mandatory = $true)][psobject]$Template,
        [string]$RepositoryRoot = ''
    )

    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        $RepositoryRoot = git rev-parse --show-toplevel
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($RepositoryRoot)) {
            throw 'Unable to resolve the repository root while packaging Defender Workbooks.'
        }
    }
    Assert-SolutionName -SolutionName $SolutionName -SelectedSolutionName $SolutionName
    $solutionRoot = Join-Path $RepositoryRoot "Solutions/$SolutionName"
    $selected = @(Get-DefenderWorkbookSelection -ContentToImport $ContentToImport `
        -SolutionRoot $solutionRoot -SolutionName $SolutionName)
    if ($selected.Count -eq 0) { return 0 }

    $packageId = [string]$Template.variables.solutionId
    $packageVersion = [string]$Template.variables._solutionVersion
    if ([string]::IsNullOrWhiteSpace($packageId) -or $packageId.StartsWith('[')) {
        throw 'Defender Workbook packaging requires a resolved packageId.'
    }
    Assert-DefenderWorkbookReleaseVersion -Version $packageVersion
    if ($packageVersion -cne [string]$ContentToImport.Version) {
        throw 'Defender Workbook package version must match the selected solution release.'
    }
    $contentPackages = @($Template.resources | Where-Object {
        $_.type -ieq 'Microsoft.OperationalInsights/workspaces/providers/contentPackages'
    })
    if ($contentPackages.Count -ne 1 -or
        $null -eq $contentPackages[0].properties.dependencies.PSObject.Properties['criteria']) {
        throw 'Defender Workbook packaging requires exactly one contentPackages dependency criteria resource.'
    }
    $resources = @()
    $criteria = @()
    $identities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $selected) {
        $document = Get-Content -LiteralPath $file.FullPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        Assert-DefenderWorkbookDocument -Document $document -SolutionRoot $solutionRoot `
            -SolutionName $SolutionName -ContentPath $file.RelativePath
        foreach ($id in @($document.xdrMetadata.contentId, $document.xdrMetadata.instanceId)) {
            if (-not $identities.Add($id)) { throw "Duplicate Defender Workbook content/instance identity '$id'." }
        }
        $resolved = [pscustomobject]@{
            packageId = $packageId
            packageVersion = $packageVersion
            contentId = $document.xdrMetadata.contentId
            contentVersion = $packageVersion
        }
        $notebook = $document | ConvertTo-Json -Depth 100 | ConvertFrom-Json
        $notebook.PSObject.Properties.Remove('xdrMetadata')
        $notebook.contentProvenance = $resolved
        $resource = [pscustomobject]@{
            import = 'MicrosoftSecurity'
            type = 'Microsoft.Security/workbooks@2026-06-01-preview'
            properties = [pscustomobject]@{
                id = $document.xdrMetadata.instanceId
                name = $document.xdrMetadata.displayName
                content = $notebook
            }
        }
        $resource = ConvertTo-DefenderWorkbookArmCopy -Value $resource
        $deploymentName = Get-DefenderWorkbookDeploymentName -SolutionName $SolutionName -ContentId $document.xdrMetadata.contentId
        $installation = New-DefenderWorkbookInstallDeployment -DeploymentName $deploymentName -WorkbookResource $resource
        $registration = New-DefenderWorkbookRegistration -DeploymentName $deploymentName `
            -InstallDeployment $installation -Document $document -ResolvedProvenance $resolved -PackageName $SolutionName
        $resources += @($installation, $registration)
        $criteria += [pscustomobject]@{
            kind = 'DefenderWorkbook'
            contentId = $resolved.contentId
            version = $resolved.contentVersion
        }
    }
    $Template.resources += $resources
    $existing = @($contentPackages[0].properties.dependencies.criteria | Where-Object { $_.kind -ine 'DefenderWorkbook' })
    $contentPackages[0].properties.dependencies.criteria = @($existing) + @($criteria)
    Write-Warning 'Defender Workbook install/registration is an UNVERIFIED candidate contract. Approved lab installation, registration readback, identity/provenance and repeat-install/update evidence are required; generation does not establish provider acceptance.'
    Write-Host "Added $($selected.Count) Defender Workbook(s) to the hybrid solution template."
    return $selected.Count
}
