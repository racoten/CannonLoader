#pragma once

#include <Windows.h>

HMODULE GetModuleHandleHash(DWORD dwModuleNameHash);
FARPROC GetProcAddressHash(HMODULE hModule, DWORD dwApiNameHash);