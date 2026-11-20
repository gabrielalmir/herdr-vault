$ErrorActionPreference = 'Stop'
$worker = Join-Path (Split-Path $PSScriptRoot) 'vault-kdf.ps1'
$port = Get-Random -Minimum 49152 -Maximum 65536
$challenge = [Guid]::NewGuid().ToString('N')
function Proof([string]$role) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes("${role}:$challenge"))
        [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $worker + '"'),
    $port, $challenge)
$client = $null
try {
    for ($attempt = 0; $attempt -lt 45 -and !$client; $attempt++) {
        if ($process.HasExited) { throw 'Worker did not start.' }
        try { $client = [Net.Sockets.TcpClient]::new('127.0.0.1', $port) }
        catch { Start-Sleep -Milliseconds 35 }
    }
    if (!$client) { throw 'Could not connect to the worker.' }
    $client.ReceiveTimeout = 6000
    $stream = $client.GetStream()
    $reader = [IO.StreamReader]::new($stream)
    $writer = [IO.StreamWriter]::new($stream)
    $writer.AutoFlush = $true
    if ($reader.ReadLine() -cne (Proof 'server')) { throw 'Worker authentication failed.' }
    $writer.WriteLine((Proof 'client'))
    $writer.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('$@!$' * 128)))
    $writer.WriteLine([Convert]::ToBase64String((New-Object byte[] 16)))
    if ($reader.ReadLine() -cne '5a07f43e2566e6257ef04e2786103b0b55138934500a606c8916e8f2de2bbffa') {
        throw 'Worker returned the wrong PBKDF2 key.'
    }
    $elapsed = $timer.ElapsedMilliseconds
    if (!$process.WaitForExit(3000) -or $process.ExitCode -ne 0) { throw 'Worker did not exit cleanly.' }
    Write-Output ('Windows vault key ready in ' + $elapsed + ' ms.')
} finally {
    if ($client) { $client.Dispose() }
    if (!$process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $process.Dispose()
}
