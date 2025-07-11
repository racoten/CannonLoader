#include <Windows.h>
#include <cstdio>
#include <cctype>
#include "Structs.h"

constexpr UINT32 INITIAL_SEED = 7;

UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

UINT32 HashStringJenkinsOneAtATime32BitW(PWCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenW(String);

    while (Index != Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

inline UINT32 HASHA(const char* API)
{
    return HashStringJenkinsOneAtATime32BitA(const_cast<PCHAR>(API));
}

inline UINT32 HASHW(const wchar_t* API)
{
    return HashStringJenkinsOneAtATime32BitW(const_cast<PWCHAR>(API));
}

FARPROC GetProcAddressHash(HMODULE hModule, DWORD dwApiNameHash)
{
    if (hModule == nullptr || dwApiNameHash == 0)
        return nullptr;

    auto pBase = reinterpret_cast<PBYTE>(hModule);

    auto pImgDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto& ImgOptHdr = pImgNtHdrs->OptionalHeader;
    auto pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto FunctionNameArray = reinterpret_cast<PDWORD>(pBase + pImgExportDir->AddressOfNames);
    auto FunctionAddressArray = reinterpret_cast<PDWORD>(pBase + pImgExportDir->AddressOfFunctions);
    auto FunctionOrdinalArray = reinterpret_cast<PWORD>(pBase + pImgExportDir->AddressOfNameOrdinals);

    char UpperFunctionName[256] = { 0 };

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        auto pFunctionName = reinterpret_cast<CHAR*>(pBase + FunctionNameArray[i]);
        errno_t err = strncpy_s(UpperFunctionName, sizeof(UpperFunctionName), pFunctionName, _TRUNCATE);
        if (err != 0) {
            continue;
        }
        for (size_t j = 0; UpperFunctionName[j]; j++) {
            UpperFunctionName[j] = static_cast<char>(toupper(UpperFunctionName[j]));
        }

        auto pFunctionAddress = reinterpret_cast<FARPROC>(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
        if (dwApiNameHash == HASHA(UpperFunctionName)) {
            return pFunctionAddress;
        }
    }

    return nullptr;
}

HMODULE GetModuleHandleHash(DWORD dwModuleNameHash)
{
    if (dwModuleNameHash == 0)
        return nullptr;

#ifdef _WIN64
    PPEB pPeb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListEntry = pLdr->InMemoryOrderModuleList.Flink;

    while (pListEntry != &pLdr->InMemoryOrderModuleList) {
        auto pDte = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (pDte->BaseDllName.Length != 0 && pDte->BaseDllName.Length < MAX_PATH) {
            char UpperCaseDllName[MAX_PATH] = {};
            DWORD i = 0;
            while (i < (pDte->BaseDllName.Length / sizeof(WCHAR)) && pDte->BaseDllName.Buffer[i])
            {
                UpperCaseDllName[i] = static_cast<char>(toupper(pDte->BaseDllName.Buffer[i]));
                i++;
            }
            UpperCaseDllName[i] = '\0';

            if (HASHA(UpperCaseDllName) == dwModuleNameHash)
                return reinterpret_cast<HMODULE>(pDte->DllBase);
        }

        pListEntry = pListEntry->Flink;
    }

    return nullptr;
}
