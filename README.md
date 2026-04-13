# kdhacker64

kdhacker64_ev.sys from Kingsoft AntiVirus. EV signed. Kernel heap overflow. No auth required.

## Vulnerability

**IOCTL:** `0x120140` (ProcessRules)

Input validation checks `count * 0x488 == input_size - 4`. The allocation uses `count * 0x248`. The buffer is undersized relative to what the driver processes.

For each element, the driver calls `RtlInitUnicodeString` on input at offset `+0x008`. There is no bounds check. The string field is 128 bytes (`0x80`). Without a null terminator, the scan continues into the adjacent string2 field at `+0x088` (1024 bytes, `0x400`). `RtlUnicodeStringToAnsiString` converts the full scanned range, producing approximately 576 ANSI bytes. This is then `memcpy`'d into a 64-byte destination buffer. The result is a 512-byte overflow into the kernel pool.

```
Validation: count * 0x488 == input_size - 4  [passes]
Allocation: count * 0x248                    [undersized]

RtlInitUnicodeString(input + 0x008)  -- no bounds check
RtlUnicodeStringToAnsiString()       -- ~576 bytes
memcpy(output + 0x008, ansi, len)    -- overflow
```

Overflow data is attacker-controlled via string content. Adjacent kernel pool allocations are corrupted. Leads to arbitrary read/write or code execution.

**Impact:** Local Privilege Escalation  
**CVSS:** 7.8 (High)  
**Auth:** None required

## Driver Info

**SHA256:** `597eff2718073b11da3d4bcade9a03fb4684f9be57d184fce65ac70a2ef07246`  
**Signed by:** Kingsoft Corporation (EV certificate)  
**LOLDrivers:** Not yet listed  
**CVE:** None assigned

## Usage

Requires Administrator. Place `kdhacker64_ev.sys` in the same directory as the script.

```
python kdhacker_poc.py
```

The PoC loads the driver, opens the device, builds both a safe reference payload and the overflow payload, prints analysis, then unloads the driver. The overflow payload is constructed but not sent -- sending it will crash the kernel.

## Credit

X: [@weezerOSINT](https://x.com/weezerOSINT)  
Telegram: @weezer
