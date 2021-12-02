// petype.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdarg.h>
#include <string.h>
#include <imagehlp.h>

// 链接wsetargv.obj可展开通配符

void wucprintf(const wchar_t* fmt, ...)
{
    wchar_t buf[1024] = L"";
    va_list va;
    va_start(va, fmt);
    wvsprintfW(buf, fmt, va);
    va_end(va);
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0, number = 0;
    if (GetConsoleMode(hout, &mode))
    {
        WriteConsoleW(hout, buf, lstrlenW(buf), &number, NULL);
    }
    else
    {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, buf, -1, NULL, 0, NULL, NULL);
        if (bytes < 1)
            return;
        char* bbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
        int bytes2 = WideCharToMultiByte(CP_UTF8, 0, buf, -1, NULL, 0, NULL, NULL);
        if (bytes2 >= 1)
            WriteFile(hout, buf, bytes2 - 1, &number, NULL);
        HeapFree(GetProcessHeap(), 0, bbuf);
    }
}

BYTE* LoadPEImage(const wchar_t* filename, DWORD* pimagesize, IMAGE_NT_HEADERS32** ppnthdr32, IMAGE_SECTION_HEADER** ppsections)
{
    IMAGE_DOS_HEADER doshdr;
    union {
        IMAGE_NT_HEADERS32 nthdr32;
        IMAGE_NT_HEADERS64 nthdr64;
    }nthdr;

    DWORD nret = 0;
    BOOL bret = FALSE;
    HANDLE hfile = INVALID_HANDLE_VALUE;

    memset(&doshdr, 0, sizeof doshdr);
    memset(&nthdr, 0, sizeof nthdr);

    hfile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE)
        return NULL;

    // 读取DOS文件头并检查是不是MZ格式，然后找到新文件头偏移
    ReadFile(hfile, &doshdr, sizeof doshdr, &nret, NULL);
    if (doshdr.e_magic != 'ZM' || doshdr.e_lfanew == 0)
    {
        CloseHandle(hfile);
        return NULL;
    }

    // 读取新文件头并检查是不是PE32/PE32+格式
    SetFilePointer(hfile, doshdr.e_lfanew, NULL, FILE_BEGIN);
    ReadFile(hfile, &nthdr, sizeof nthdr, &nret, NULL);
    if (nthdr.nthdr32.Signature != 'EP' ||
        (nthdr.nthdr32.OptionalHeader.Magic != 0x10b && nthdr.nthdr32.OptionalHeader.Magic != 0x20b))
    {
        CloseHandle(hfile);
        return NULL;
    }

    // SizeOfStackReserve之前，除BaseOfData和ImageBase之外的元素，32位和64位是通用的
    // 所以这里直接用nthdr32读取需要的值
    // 计算需要的偏移量
    DWORD imagesize = nthdr.nthdr32.OptionalHeader.SizeOfImage;
    DWORD sectionbias = doshdr.e_lfanew
        + sizeof nthdr.nthdr32.Signature
        + sizeof nthdr.nthdr32.FileHeader
        + nthdr.nthdr32.FileHeader.SizeOfOptionalHeader;
    DWORD headersize = sectionbias
        + nthdr.nthdr32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (headersize > imagesize)
    {
        CloseHandle(hfile);
        return NULL;
    }

    BYTE* rvalayout = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, imagesize);
    SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
    ReadFile(hfile, rvalayout, headersize, &nret, NULL);

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(rvalayout + sectionbias);
    for (int i = 0; i < nthdr.nthdr32.FileHeader.NumberOfSections; i++)
    {
        if (sections[i].VirtualAddress < headersize ||
            sections[i].VirtualAddress + sections[i].Misc.VirtualSize > imagesize)
            continue;

        DWORD loadsize = min(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);

        SetFilePointer(hfile, sections[i].PointerToRawData, NULL, FILE_BEGIN);
        ReadFile(hfile, rvalayout + sections[i].VirtualAddress, loadsize, &nret, NULL);
    }

    CloseHandle(hfile);

    *pimagesize = imagesize;
    *ppnthdr32 = (IMAGE_NT_HEADERS32*)(rvalayout + doshdr.e_lfanew);
    *ppsections = (IMAGE_SECTION_HEADER*)(rvalayout + sectionbias);
    return rvalayout;
}

void FreePEImage(BYTE* image)
{
    HeapFree(GetProcessHeap(), 0, image);
}

void ParsePEFile(const wchar_t* filename)
{
    DWORD imagesize = 0;
    IMAGE_NT_HEADERS32* nthdr32 = NULL;
    IMAGE_SECTION_HEADER* sections = NULL;
    BYTE* image = LoadPEImage(filename, &imagesize, &nthdr32, &sections);
    if (image == NULL)
    {
        wucprintf(L"[        ] %s\r\n", filename);
        return;
    }
    IMAGE_NT_HEADERS64* nthdr64 = (IMAGE_NT_HEADERS64*)nthdr32;

    IMAGE_LOAD_CONFIG_DIRECTORY32* loadcfg32 = NULL;
    IMAGE_LOAD_CONFIG_DIRECTORY64* loadcfg64 = NULL;
    DWORD loadcfgsize = 0;
    if (nthdr32->OptionalHeader.Magic == 0x20b)
    {
        loadcfg64 = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(image +
            nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        loadcfgsize = nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    }
    else
    {
        loadcfg32 = (IMAGE_LOAD_CONFIG_DIRECTORY32*)(image +
            nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        loadcfgsize = nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    }

    switch (nthdr32->FileHeader.Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        // 检查CHPEMetadataPointer，为指向IMAGE_CHPE_METADATA_X86的VA（RVA要减去nthdr32->OptionalHeader.ImageBase）
        // 见WDK的ntimage.h
        if (loadcfg32 && loadcfgsize >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardRFFailureRoutine)
            && loadcfg32->CHPEMetadataPointer != 0)
            wucprintf(L"[CHPE    ] %s\r\n", filename);
        else
            wucprintf(L"[x86     ] %s\r\n", filename);
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        // 检查CHPEMetadataPointer，为指向IMAGE_ARM64EC_METADATA的VA（RVA要减去nthdr32->OptionalHeader.ImageBase）
        // 见WDK的ntimage.h
        if (loadcfg64 && loadcfgsize >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardRFFailureRoutine)
            && loadcfg64->CHPEMetadataPointer != 0)
            wucprintf(L"[ARM64EC ] %s\r\n", filename);
        else
            wucprintf(L"[x64     ] %s\r\n", filename);
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        // 检查CHPEMetadataPointer，为指向IMAGE_ARM64EC_METADATA的VA（RVA要减去nthdr32->OptionalHeader.ImageBase）
        // 见WDK的ntimage.h
        // 实际上还有DynamicValueRelocTableSection和DynamicValueRelocTableOffset
        // 指向用于描述如何将ARM64X可执行文件patch成ARM64EC可执行文件的信息
        // 但这里已经不需要检查这个了，因为ARM64X可执行文件一定存在CHPEMetadataPointer
        // 见https://ffri.github.io/ProjectChameleon/new_reloc_chpev2/
        if (loadcfg64 && loadcfgsize >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardRFFailureRoutine)
            && loadcfg64->CHPEMetadataPointer != 0)
            wucprintf(L"[ARM64X  ] %s\r\n", filename);
        else
            wucprintf(L"[ARM64   ] %s\r\n", filename);
        break;
    case IMAGE_FILE_MACHINE_ARM:
        wucprintf(L"[ARM     ] %s\r\n", filename);
        break;
    case IMAGE_FILE_MACHINE_ARMNT:
        wucprintf(L"[ARMNT   ] %s\r\n", filename);
        break;
    case IMAGE_FILE_MACHINE_THUMB:
        wucprintf(L"[THUMB   ] %s\r\n", filename);
        break;
    default:
        wucprintf(L"[0x%04x  ] %s\r\n", nthdr32->FileHeader.Machine, filename);
        break;
    }

    FreePEImage(image);
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2)
    {
        wucprintf(L"usage: petype file1.exe file2.dll *.exe *.dll ...\r\n");
        return 0;
    }
    for (int i = 1; i < argc; i++)
    {
        ParsePEFile(argv[i]);
    }
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
