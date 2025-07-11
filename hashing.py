INITIAL_SEED = 7
MASK32 = 0xFFFFFFFF

def hash_string_jenkins_one_at_a_time_32bit_a(string: str) -> int:
    """ANSI version: processes each character as an 8-bit value."""
    hash_val = 0
    for ch in string:
        hash_val = (hash_val + ord(ch)) & MASK32
        hash_val = (hash_val + ((hash_val << INITIAL_SEED) & MASK32)) & MASK32
        hash_val = (hash_val ^ (hash_val >> 6)) & MASK32
    hash_val = (hash_val + ((hash_val << 3) & MASK32)) & MASK32
    hash_val = (hash_val ^ (hash_val >> 11)) & MASK32
    hash_val = (hash_val + ((hash_val << 15) & MASK32)) & MASK32
    return hash_val

def hash_string_jenkins_one_at_a_time_32bit_w(string: str) -> int:
    """Wide version: processes each wide character (16-bit) as its Unicode code point.
       For BMP characters this behaves similarly to the ANSI version."""
    hash_val = 0
    for ch in string:
        hash_val = (hash_val + ord(ch)) & MASK32
        hash_val = (hash_val + ((hash_val << INITIAL_SEED) & MASK32)) & MASK32
        hash_val = (hash_val ^ (hash_val >> 6)) & MASK32
    hash_val = (hash_val + ((hash_val << 3) & MASK32)) & MASK32
    hash_val = (hash_val ^ (hash_val >> 11)) & MASK32
    hash_val = (hash_val + ((hash_val << 15) & MASK32)) & MASK32
    return hash_val

# Macros from the original code are implemented as simple functions:
def HASHA(api: str) -> int:
    # Ensure the API name is upper case.
    return hash_string_jenkins_one_at_a_time_32bit_a(api.upper())

def HASHW(api: str) -> int:
    return hash_string_jenkins_one_at_a_time_32bit_w(api.upper())

def main():
    # Print out the macros in the desired format.
    print(f'#define KERNEL32DLL_HASH\t0x{HASHA("KERNEL32.DLL"):08X}')
    
    function_names = [
        "VIRTUALALLOC",
        "VIRTUALFREE",
        "CREATETIMERQUEUE",
        "CREATETIMERQUEUETIMER",
        "DELETETIMERQUEUETIMER",
        "DELETETIMERQUEUE"
    ]
    
    for func in function_names:
        print(f'#define {func}_HASH\t0x{HASHA(func):08X}')

if __name__ == '__main__':
    main()
