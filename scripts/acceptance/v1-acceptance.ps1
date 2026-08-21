# Clean-environment-ish acceptance: doctor → assess demos → report (Windows).
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root
function Invoke-Das {
  param([Parameter(ValueFromRemainingArguments=$true)]$Args)
  & cargo run -q -p dare-agent-security -- @Args
  if ($LASTEXITCODE -ne 0 -and $Args[0] -ne "assess") {
    throw "command failed: $Args (exit $LASTEXITCODE)"
  }
  return $LASTEXITCODE
}

Write-Host "== doctor =="
Invoke-Das doctor | Out-Null

Write-Host "== vulnerable =="
$vuln = 0
try { Invoke-Das assess examples/vulnerable-mcp --offline --confidential --run run-accept-vuln } catch { $vuln = 1 }
if (-not (Test-Path "examples\vulnerable-mcp\.dare-security\runs\run-accept-vuln\reports\executive.html")) {
  throw "missing vulnerable executive report"
}
Invoke-Das report --path examples/vulnerable-mcp --run run-accept-vuln | Out-Null

Write-Host "== secure =="
$code = Invoke-Das assess examples/secure-mcp --offline --run run-accept-secure
if ($code -ne 0) { throw "secure assess expected exit 0, got $code" }
Invoke-Das report --path examples/secure-mcp --run run-accept-secure | Out-Null

Write-Host "== agentic =="
Invoke-Das assess examples/agentic-demo --offline --confidential --run run-accept-agentic | Out-Null

$tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath() + [guid]::NewGuid().ToString())
Invoke-Das init $tmp.FullName --name accept-tmp | Out-Null
Invoke-Das doctor $tmp.FullName | Out-Null
Invoke-Das assess $tmp.FullName --offline --run run-accept-tmp | Out-Null
Invoke-Das report --path $tmp.FullName --run run-accept-tmp | Out-Null
Remove-Item -Recurse -Force $tmp.FullName

Write-Host "v1 acceptance harness completed (vulnerable handled)"
