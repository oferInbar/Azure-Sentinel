function Assert-V31ReleaseVersion {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Version,
        [string]$ContentKind,
        [string]$ContentPath
    )

    if (-not $v31VersionPolicy) { return }

    $minimum = if ($ContentKind -in @('Solution', 'CustomDetection')) { [version]'3.1.0.0' } else { [version]'0.0.0.0' }
    $range = if ($ContentKind -in @('Solution', 'CustomDetection')) { '>= 3.1.0 and < 4.0.0' } else { '< 4.0.0' }
    $parsed = $null
    $valid = $Version -cmatch '\A[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}\z' -and
        [version]::TryParse($Version, [ref]$parsed)
    if ($ContentKind -eq 'CustomDetection') {
        $valid = $valid -and $Version -cmatch '\A3\.[1-9][0-9]*\.(?:0|[1-9][0-9]*)\z'
    }
    if ($valid) {
        $normalized = [version]::new($parsed.Major, $parsed.Minor, [Math]::Max(0, $parsed.Build), [Math]::Max(0, $parsed.Revision))
        $valid = $normalized -ge $minimum -and $normalized -lt [version]'4.0.0.0'
    }
    if (-not $valid) {
        $message = "V3.1 version policy: $ContentKind '$ContentPath' has effective release version '$Version'; required $range (numeric release version). No version is automatically promoted."
        if ($ContentKind -eq 'CustomDetection') {
            $message += " Set the XDR YAML top-level version to its own major.minor.patch release. For older files without version, reconvert with --overwrite (initial version 3.1.0), or explicitly author the XDR version. Do not change contentProvenance.source.version; Data 'XDR Detection Version' and solution Version are not fallbacks in V3.1."
        }
        $v31VersionPolicy.Errors.Add($message)
        throw $message
    }
}

function Assert-V31SolutionVersion {
    param(
        [string]$SolutionName,
        [string]$Version,
        [string]$CalculatedVersion = ''
    )
    if (-not $v31VersionPolicy) { return }
    Assert-V31ReleaseVersion -Version $Version -ContentKind Solution -ContentPath $SolutionName
    if (-not [string]::IsNullOrEmpty($CalculatedVersion)) {
        Assert-V31ReleaseVersion -Version $CalculatedVersion -ContentKind Solution -ContentPath "$SolutionName (calculated package version)"
        if ($Version -cne $CalculatedVersion) {
            $message = "V3.1 version policy: Solution '$SolutionName' declares version '$Version' but calculated package version is '$CalculatedVersion'. Align the input Version and calculated package version before packaging; emitted solution fields and ZIP version must agree."
            $v31VersionPolicy.Errors.Add($message)
            throw $message
        }
    }
}

function Assert-V31VersionChecksPassed {
    if ($v31VersionPolicy -and $v31VersionPolicy.Errors.Count -gt 0) {
        # Some legacy content readers catch exceptions. Never emit a partial package after a failed guard.
        throw ($v31VersionPolicy.Errors -join [Environment]::NewLine)
    }
}

function Save-V31LocalPackageVersion {
    param([string]$DataFilePath, [string]$Version)

    $data = Get-Content -LiteralPath $DataFilePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $metadataPath = Join-Path (Split-Path (Split-Path $DataFilePath -Parent) -Parent) $data.Metadata
    $metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $data | Add-Member -NotePropertyName Version -NotePropertyValue $Version -Force
    $metadata | Add-Member -NotePropertyName version -NotePropertyValue $Version -Force
    $dataJson = $data | ConvertTo-Json -Depth 100
    $metadataJson = $metadata | ConvertTo-Json -Depth 100
    Set-Content -LiteralPath $DataFilePath -Value $dataJson -Encoding utf8 -ErrorAction Stop
    Set-Content -LiteralPath $metadataPath -Value $metadataJson -Encoding utf8 -ErrorAction Stop
}
