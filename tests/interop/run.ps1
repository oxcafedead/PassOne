# GnuPG <-> gopass-desktop interoperability test (development harness).
# Requires GnuPG installed (e.g. "winget install GnuPG.GnuPG"). GnuPG is used
# ONLY to generate test fixtures and to verify our output; the application
# itself never invokes it.
#
# The test key passphrase is fixed here and fed via --pinentry-mode loopback so
# no interactive pinentry window ever appears. Application stdin is fed through
# "cmd /c echo ... |" because PowerShell 5.1 pipes to native stdin silently
# break in the same script after a GnuPG keygen runs.

param()
$ErrorActionPreference = "Continue"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe  = Join-Path $root "..\..\gopass-desktop.exe"
$gpg  = "C:\Program Files (x86)\gnupg\bin\gpg.exe"
if (-not (Test-Path $gpg)) { $gpg = "C:\Program Files\gnupg\bin\gpg.exe" }
if (-not (Test-Path $exe)) { throw "build the app first: go build -o gopass-desktop.exe ./cmd/app" }

$work  = Join-Path $env:TEMP "gopass-interop-$PID"
$gnupg = Join-Path $work "gnupg"
$data  = Join-Path $work "appdata"
$store = Join-Path $work "store"
New-Item -ItemType Directory -Force -Path $gnupg, $data, (Join-Path $store "github") | Out-Null

$env:GNUPGHOME = $gnupg
$env:GOPASS_DESKTOP_DIR = $data
$pass = "interop-pass-8791"

# Run a gpg command programmatically (never opens a GUI pinentry).
function Run-Gpg {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
    & $gpg --batch --pinentry-mode loopback --passphrase $pass @Args > $null 2> (Join-Path $env:TEMP "gpg-err.log")
    if ($LASTEXITCODE -ne 0) {
        $err = Get-Content (Join-Path $env:TEMP "gpg-err.log") -Raw -ErrorAction SilentlyContinue
        throw "gpg failed (exit $LASTEXITCODE): $Args`n$err"
    }
}

# Capture a gpg command's stdout via "cmd /c ... > file" (deterministic
# byte-exact capture; PowerShell native stdout capture is unreliable here).
function Capture-GpgText {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
    $outFile = Join-Path $env:TEMP "gpg-out-$PID.txt"
    $argEsc = $Args | ForEach-Object { '"' + $_ + '"' }
    $line = "`"$gpg`" --batch --pinentry-mode loopback --passphrase $pass " + ($argEsc -join " ") + " > `"$outFile`" 2>nul"
    cmd /c $line
    if ($LASTEXITCODE -ne 0) { throw "gpg failed (exit $LASTEXITCODE): $Args" }
    $text = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
    if ($null -eq $text) { $text = "" }
    return $text
}

# Run the application with the given passphrase offered on stdin.
# Returns @( exitCode, stdoutLines(string[]), stderrText(string) ). stdout is
# clean so that value comparisons (e.g. decrypted passwords) are exact.
function Run-App {
    param([Parameter(Mandatory=$true)][string]$Stdin, [Parameter(Mandatory=$true)][string]$ArgsLine)
    $errFile = Join-Path $env:TEMP "app-err.log"
    $line = "echo $Stdin| `"$exe`" $ArgsLine 2> `"$errFile`""
    $out = @(cmd /c $line)
    $err = if (Test-Path $errFile) { Get-Content $errFile -Raw -ErrorAction SilentlyContinue } else { "" }
    return ,@($LASTEXITCODE, $out, $err)
}

function ToSingle([object[]]$Lines) { return ($Lines -join "`n") }

Write-Host "gpg: $gpg"
Write-Host "app: $exe"
Write-Host "work: $work"
Write-Host ""

try {
    # ---- 1. Generate GnuPG key (Ed25519 sign + CV25519 encrypt, passphrase) ----
    $parms = @"
%no-ask-passphrase
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: Interop Tester
Name-Email: interop@example.com
Expire-Date: 0
Passphrase: $pass
%commit
"@
    Set-Content -Path (Join-Path $work "keyparms") -Value $parms
    Run-Gpg --generate-key (Join-Path $work "keyparms")

    $fp = ((Capture-GpgText --with-colons --list-secret-keys) -split "`n" |
        Where-Object { $_ -like "fpr::*" } |
        Select-Object -First 1)
    $fp = (($fp -split ":")[9]).Trim()
    Write-Host "GnuPG fingerprint: $fp"

    $secret = Join-Path $work "secret.asc"
    Set-Content -Path $secret -Value (Capture-GpgText --armor --export-secret-keys $fp)

    # ---- 2. Encrypt a pass-style file with GnuPG ----
    $plain = Join-Path $work "plain.txt"
    $plainContent = "super-secret-password`nusername: john@example.com`nurl: https://example.com`nnotes: production account`n"
    Set-Content -Path $plain -Value $plainContent
    Run-Gpg -r $fp --encrypt --output (Join-Path $store "github\personal.gpg") $plain
    Set-Content -Path (Join-Path $store ".gpg-id") -Value $fp

    # ---- 3. Import the GnuPG key into the app (validates passphrase) ----
    $imp = Run-App $pass "import-pgp-key `"$secret`""
    if ($imp[0] -ne 0) { throw "import-pgp-key failed (exit $($imp[0])): $($imp[2])" }

    $op = Run-App $pass "open `"$store`""
    if ($op[0] -ne 0) { throw "open failed (exit $($op[0])): $($op[2])" }

    # ---- 4. gpg -> app: decrypt a GnuPG-encrypted pass file ----
    $sh = Run-App $pass "show github/personal"
    if ($sh[0] -ne 0) { throw "show failed (exit $($sh[0])): $($sh[2])" }
    $shout = ToSingle $sh[1]
    if ($shout.Trim() -ne "super-secret-password") { throw "app failed to decrypt GnuPG file. OUT: $shout" }
    Write-Host "PASS: gpg -> app decrypt (pass format)"

    # ---- 5. app -> gpg: application-encrypted file decrypts in GnuPG ----
    $edited = Join-Path $work "edited.txt"
    Set-Content -Path $edited -Value "edited-password-123`nusername: alice`n"
    $sv = Run-App $pass "save github/fromapp `"$edited`""
    if ($sv[0] -ne 0) { throw "save failed (exit $($sv[0])): $($sv[2])" }

    $dec = Capture-GpgText --decrypt (Join-Path $store "github\fromapp.gpg")
    if ($dec.Trim() -ne "edited-password-123`nusername: alice") { throw "gpg could not decrypt app output: $dec" }
    Write-Host "PASS: app -> gpg decrypt"

    # ---- 6. Full content (password + metadata) preserved exactly ----
    $full = Run-App $pass "show github/personal --full"
    if ($full[0] -ne 0) { throw "show --full failed" }
    $fullOut = ToSingle $full[1]
    $expected = $plainContent.TrimEnd("`r", "`n")
    if ($fullOut.Trim() -ne $expected) { throw "content mismatch`nGOT:`n$fullOut`nEXP:`n$expected" }
    Write-Host "PASS: full plaintext preserved byte-for-byte"

    # ---- 7. list without decrypting ----
    $listed = cmd /c "`"$exe`" list"
    $listOut = ToSingle $listed
    if ("$listOut" -notmatch "github/personal" -or "$listOut" -notmatch "github/fromapp") {
        throw "list mismatch: $listOut"
    }
    Write-Host "PASS: list shows all passwords (no decryption)"

    # ---- 8. wrong passphrase must fail cleanly ----
    $bad = Run-App "wrong-pass-0000" "import-pgp-key `"$secret`""
    if ($bad[0] -eq 0) { throw "wrong passphrase was accepted: $($bad[2])" }
    Write-Host "PASS: wrong passphrase rejected"

    # ---- 9. GnuPG and the app produce identical plaintext for the same file ----
    $sameFile = Run-App $pass "show github/personal --full"
    if ($sameFile[0] -ne 0) { throw "show --full failed" }
    $gpgPlain = Capture-GpgText --decrypt (Join-Path $store "github\personal.gpg")
    $appPlain = (ToSingle $sameFile[1]).Trim()
    if ($gpgPlain.Trim() -ne $appPlain) {
        throw "plaintext mismatch for the same file`nGPG:$gpgPlain`nAPP:$appPlain"
    }
    Write-Host "PASS: GnuPG and app produce identical plaintext for the GnuPG-made file"

    Write-Host ""
    Write-Host "INTEROP OK"
    Write-Host "fixtures kept at: $work"
    Write-Host "gpg fingerprint:  $fp"
} catch {
    Write-Host ""
    Write-Host "FAILED: $_"
    exit 1
} finally {
    $gpgconfBin = if (Test-Path (Join-Path (Split-Path $gpg) "gpgconf.exe")) { Join-Path (Split-Path $gpg) "gpgconf.exe" } else { $gpg }
    cmd /c "`"$gpgconfBin`" --kill gpg-agent 2>nul"
}