# Adapted from herdr-music-mod.
param([int]$Port, [string]$Challenge)
$ErrorActionPreference = 'Stop'
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
$listener.Server.ExclusiveAddressUse = $true
$client = $null
[Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal
try {
    $listener.Start(1)
    $accept = $listener.AcceptTcpClientAsync()
    if (!$accept.Wait(3000)) { throw 'Worker connection timed out' }
    $client = $accept.Result
    $listener.Stop()
    $stream = $client.GetStream()
    $stream.ReadTimeout = 3000
    $stream.WriteTimeout = 3000
    $reader = [IO.StreamReader]::new($stream)
    $writer = [IO.StreamWriter]::new($stream)
    $writer.AutoFlush = $true
    # Authenticate both ends before transmitting any vault material.
    function Proof([string]$role) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [Text.Encoding]::ASCII.GetBytes("${role}:$Challenge")
            [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
    }
    $writer.WriteLine((Proof 'server'))
    if ($reader.ReadLine() -cne (Proof 'client')) { throw 'Invalid handshake' }
    $password = [Convert]::FromBase64String($reader.ReadLine())
    $salt = [Convert]::FromBase64String($reader.ReadLine())
    if ($salt.Length -ne 16) { throw 'Invalid salt' }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class HerdrVaultKdf
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr handle, string algorithm, string implementation, uint flags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDeriveKeyPBKDF2(IntPtr handle, byte[] password, uint passwordLength,
        byte[] salt, uint saltLength, ulong iterations, [Out] byte[] output, uint outputLength, uint flags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr handle, uint flags);

    public static void Derive(byte[] password, byte[] salt, byte[] output)
    {
        IntPtr handle;
        if (BCryptOpenAlgorithmProvider(out handle, "SHA256", null, 8) != 0)
            throw new InvalidOperationException("Could not open the Windows HMAC provider.");
        try
        {
            if (BCryptDeriveKeyPBKDF2(handle, password, (uint)password.Length, salt, (uint)salt.Length,
                600000, output, (uint)output.Length, 0) != 0)
                throw new InvalidOperationException("Windows PBKDF2 failed.");
        }
        finally
        {
            BCryptCloseAlgorithmProvider(handle, 0);
        }
    }
}
'@
    $key = New-Object byte[] 32
    [HerdrVaultKdf]::Derive($password, $salt, $key)
    $writer.WriteLine([BitConverter]::ToString($key).Replace('-', '').ToLowerInvariant())
} finally {
    if ($key) { [Array]::Clear($key, 0, $key.Length) }
    if ($password) { [Array]::Clear($password, 0, $password.Length) }
    if ($client) { $client.Dispose() }
    $listener.Stop()
}
