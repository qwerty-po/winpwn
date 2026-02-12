## wpwn

```python
from wpwn import *

p = process(r".\hello") # Spawn process
	
context.windbgx = r"C:\Users\user\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe"
context.newline = "\r\n"
context.arch = "amd64"
context.noout = True

windbgx.attach(p, script="""
.load /Users/user/Desktop/pykd/x64/pykd.dll
!pykd.select -3.9

!py /Users/user/Desktop/qwef/qwef.py
"""
)

def sendafter(s, data):
    p.recvuntil(s)
    p.send(data)

def sendlineafter(s, data):
    p.recvuntil(s)
    p.sendline(data)

ntdll = PE(r"C:\WINDOWS\SYSTEM32\ntdll.dll")
ntdll.address = 0
ntdll_base = (ntdll_leak - ntdll["RtlpStaticDebugInfo"]) & (~0xfff)
ntdll.address = ntdll_base
print(f"ntdll_base: {hex(ntdll_base)}")

p.interactive()
```