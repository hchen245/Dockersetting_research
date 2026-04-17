# Security Vulnerability Scanning Script
# For AI-generated code evaluation

param(
    [string]$ProjectPath = ".",
    [string]$OutputFile = "vulnerability-report.json"
)

Write-Host "🔍 Starting vulnerability scan..." -ForegroundColor Cyan

# Initialize report structure
$report = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    project_path = $ProjectPath
    vulnerabilities = @()
    summary = @{
        total = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
    }
    scanner_tools = @()
}

# ===== TOOL 1: Semgrep (Static Analysis) =====
Write-Host "`n📋 Running Semgrep..." -ForegroundColor Yellow

$semgrepInstalled = semgrep --version 2>$null
if ($semgrepInstalled) {
    $report.scanner_tools += "semgrep"
    
    $semgrepOutput = semgrep scan --config=.semgrep.yml --json $ProjectPath 2>&1
    $semgrepJson = $semgrepOutput | ConvertFrom-Json -ErrorAction SilentlyContinue
    
    if ($semgrepJson.results) {
        foreach ($finding in $semgrepJson.results) {
            $severity = if ($finding.extra.severity) { $finding.extra.severity } else { "MEDIUM" }
            $vulnRecord = @{
                tool = "semgrep"
                file = $finding.path
                line = $finding.start.line
                rule_id = $finding.check_id
                message = $finding.extra.message
                severity = $severity
                code = $finding.extra.lines
            }
            $report.vulnerabilities += $vulnRecord
            $report.summary.$($severity.ToLower())++
            $report.summary.total++
        }
    }
} else {
    Write-Host "⚠️  Semgrep not installed. Install with: pip install semgrep" -ForegroundColor Yellow
}

# ===== TOOL 2: NodeJS pattern matching =====
Write-Host "`n📋 Running pattern-based scanning..." -ForegroundColor Yellow

$patterns = @(
    @{ pattern = "\.innerHTML\s*="; severity = "HIGH"; rule = "XSS-innerHTML" }
    @{ pattern = "eval\("; severity = "CRITICAL"; rule = "code-injection-eval" }
    @{ pattern = "fs\.readFile\(\s*\$"; severity = "HIGH"; rule = "path-traversal" }
    @{ pattern = "res\.redirect\("; severity = "MEDIUM"; rule = "open-redirect" }
    @{ pattern = "Object\.assign\("; severity = "MEDIUM"; rule = "prototype-pollution" }
)

$jsFiles = Get-ChildItem -Path $ProjectPath -Include "*.js", "*.jsx" -Recurse
foreach ($file in $jsFiles) {
    $content = Get-Content $file -Raw
    $lineNum = 0
    
    foreach ($line in @($content -split "`n")) {
        $lineNum++
        foreach ($pat in $patterns) {
            if ($line -match $pat.pattern) {
                $vulnRecord = @{
                    tool = "pattern-scan"
                    file = $file.FullName
                    line = $lineNum
                    rule_id = $pat.rule
                    message = "Pattern match: $($pat.rule)"
                    severity = $pat.severity
                    code = $line
                }
                $report.vulnerabilities += $vulnRecord
                $report.summary.$($pat.severity.ToLower())++
                $report.summary.total++
            }
        }
    }
}

# ===== OUTPUT REPORT =====
Write-Host "`n📊 Vulnerability Scan Summary:" -ForegroundColor Green
Write-Host "Total vulnerabilities found: $($report.summary.total)"
Write-Host "  🔴 CRITICAL: $($report.summary.critical)"
Write-Host "  🟠 HIGH: $($report.summary.high)"
Write-Host "  🟡 MEDIUM: $($report.summary.medium)"
Write-Host "  🟢 LOW: $($report.summary.low)"

# Save JSON report
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "`n✅ Report saved to: $OutputFile" -ForegroundColor Green

# Display vulnerabilities
if ($report.vulnerabilities.Count -gt 0) {
    Write-Host "`n🚨 Vulnerabilities:" -ForegroundColor Red
    $report.vulnerabilities | ForEach-Object {
        Write-Host "  [$($_.severity)] $($_.file):$($_.line) - $($_.rule_id)"
        Write-Host "    Message: $($_.message)"
    }
}

exit $report.summary.critical
