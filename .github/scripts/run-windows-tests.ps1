Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class CodeCommTestTokenOwner
{
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenQuery = 0x0008;
    private const int TokenOwner = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenOwnerInformation
    {
        internal IntPtr Owner;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr process,
        uint access,
        out IntPtr token
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
        IntPtr token,
        int informationClass,
        ref TokenOwnerInformation information,
        uint informationLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static void SetCurrent(string sidValue)
    {
        var sid = new SecurityIdentifier(sidValue);
        var encoded = new byte[sid.BinaryLength];
        sid.GetBinaryForm(encoded, 0);
        IntPtr sidBuffer = Marshal.AllocHGlobal(encoded.Length);
        IntPtr token = IntPtr.Zero;
        try
        {
            Marshal.Copy(encoded, 0, sidBuffer, encoded.Length);
            if (!OpenProcessToken(
                Process.GetCurrentProcess().Handle,
                TokenAdjustDefault | TokenQuery,
                out token
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "OpenProcessToken failed"
                );
            }
            var owner = new TokenOwnerInformation { Owner = sidBuffer };
            if (!SetTokenInformation(
                token,
                TokenOwner,
                ref owner,
                (uint) Marshal.SizeOf<TokenOwnerInformation>()
            ))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetTokenInformation(TokenOwner) failed"
                );
            }
        }
        finally
        {
            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }
            Marshal.FreeHGlobal(sidBuffer);
        }
    }
}
'@

function Get-CurrentOwnerSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$user = $identity.User
$originalOwner = $identity.Owner.Value
$system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
if ($originalOwner -ne $user.Value -and
    $originalOwner -ne $administrators.Value) {
    throw "unexpected hosted-runner token owner $originalOwner"
}

$testTemp = Join-Path $env:SystemDrive (
    "codecomm-test-{0}-{1}-{2}" -f
        $env:GITHUB_RUN_ID, $env:GITHUB_RUN_ATTEMPT, $PID
)
$ownerChanged = $false
$testExitCode = 1
try {
    if ($originalOwner -ne $user.Value) {
        [CodeCommTestTokenOwner]::SetCurrent($user.Value)
        $ownerChanged = $true
    }
    $effectiveOwner = Get-CurrentOwnerSid
    if ($effectiveOwner -ne $user.Value) {
        throw "test token owner is $effectiveOwner, want $($user.Value)"
    }

    New-Item -ItemType Directory -Path $testTemp -Force | Out-Null
    $inheritance =
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($user)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($user, $system, $administrators)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void] $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $testTemp -AclObject $acl

    $env:TEMP = $testTemp
    $env:TMP = $testTemp
    $env:GOTMPDIR = $testTemp
    & go test -p 2 -parallel 2 -timeout 20m ./...
    $testExitCode = $LASTEXITCODE
}
finally {
    if ($ownerChanged) {
        [CodeCommTestTokenOwner]::SetCurrent($originalOwner)
    }
    $restoredOwner = Get-CurrentOwnerSid
    if ($restoredOwner -ne $originalOwner) {
        throw "restored token owner is $restoredOwner, want $originalOwner"
    }
    if (Test-Path -LiteralPath $testTemp) {
        Remove-Item -LiteralPath $testTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
exit $testExitCode
