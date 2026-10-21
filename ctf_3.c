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
