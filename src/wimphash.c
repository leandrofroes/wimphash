/*
* 	wimphash - windows import hash tool
*
* 	Author: Leandro Fróes
*
*	Copyright (C) 2019 Leandro Fróes
*
*	This program is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*	You should have received a copy of the GNU General Public License
*	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/wimphash.h"
#include "../include/ordlookup.h"

void error(const char *msg)
{
    fprintf(stderr, "[+] Error - %s\n", msg);
    ExitProcess(1);
}

void usage()
{
    fprintf(stdout, "\nUsage: wimphash.exe <file>\n");
    ExitProcess(1);
}

bool isPE(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS pe)
{
    if(dos == NULL || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if(pe->Signature != IMAGE_NT_SIGNATURE)
        return false;

    return true;
}

void cat(char *dest, char *dll, char *funcName)
{
    if(dest && dll && funcName != NULL)
    {
        strcat(dest, (const char *)dll);
        strcat(dest, (const char *)funcName);
        strcat(dest, (const char *)",");
    }
    else
    {
        error("Concating a NULL string\n");
    }

}

void clean(LPVOID baseAddr, HANDLE mapH, HANDLE fH)
{
    UnmapViewOfFile(baseAddr);
    CloseHandle(mapH);
    CloseHandle(fH);
}

void getHash(char *impStr, DWORD len)
{
    HCRYPTPROV csp = 0;
    HCRYPTHASH hash = 0;
    BYTE hashBuffer[len];
    DWORD hashSize = sizeof(hashBuffer);
    CHAR digits[] = "0123456789abcdef";

    if(!CryptAcquireContext(&csp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        error("Fail during hash operation");

    if(!CryptCreateHash(csp, CALG_MD5, 0, 0, &hash))
        error("Fail during hash operation");

    if(!CryptHashData(hash, (PBYTE)impStr, strlen((const char *)impStr), 0))
        error("Fail during hash operation");

    if (CryptGetHashParam(hash, HP_HASHVAL, hashBuffer, &hashSize, 0))
    {

        fprintf(stdout, "\n");

        for (DWORD i = 0; i < hashSize; i++)
        {
            fprintf(stdout, "%c%c", digits[hashBuffer[i] >> 4], digits[hashBuffer[i] & 0xf]);
        }
    }
     else
    {
        error("Fail to get the hash.");
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(csp, 0);
}


void getFunctions(PIMAGE_THUNK_DATA impTable, LPVOID baseAddr, char *impStr, char *dll)
{
    while(impTable->u1.AddressOfData != 0)
    {
        if(!(impTable->u1.AddressOfData & IMAGE_ORDINAL_FLAG))
        {
            //IMAGE_IMPORT_BY_NAME
            PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)(impTable->u1.AddressOfData + (char *)baseAddr);

            char *funcName = (char *)name->Name;

            cat(impStr, dll, funcName);

        }
        else
        {
            DWORD ord = impTable->u1.Ordinal & ~IMAGE_ORDINAL_FLAG;

            // The checks bellow are necessary cause everyone uses imphash from pefile and
            // there they implemented this way.

            if(!strncmp(dll, "oleaut32", 8))
            {
                for (DWORD i = 0; i < sizeof(oleaut32_arr) / sizeof(ord_t); i++)
                    if(ord == oleaut32_arr[i].number)
                        cat(impStr, dll, oleaut32_arr[i].fname);
            }
            else if (!strncmp(dll, "ws2_32", 6))
            {
                for (DWORD i = 0; i < sizeof(ws2_32_arr) / sizeof(ord_t); i++)
                    if(ord == ws2_32_arr[i].number)
                        cat(impStr, dll, ws2_32_arr[i].fname);
            }
            else
            {
                fprintf(stdout, "DLL %s imported a function using the ordinal number %ld\n", dll, ord);
            }

        }

        impTable++;
    }

    for (DWORD i = 0; i < strlen(impStr); i++)
        impStr[i] = tolower(impStr[i]);
}

void init(LPVOID baseAddr)
{

    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS peHeader;
    IMAGE_OPTIONAL_HEADER optHeader;
    IMAGE_DATA_DIRECTORY impDir;
    PIMAGE_IMPORT_DESCRIPTOR impDesc;
    PIMAGE_THUNK_DATA impTable;
    DWORD descRva;

    //IMAGE_DOS_HEADER
    dosHeader = (PIMAGE_DOS_HEADER)baseAddr;

    // IMAGE_NT_HEADER
    peHeader = (PIMAGE_NT_HEADERS)((DWORD)baseAddr + dosHeader->e_lfanew);

    if(!isPE(dosHeader, peHeader))
        error("The file is not a valid PE file.\n");

    // IMAGE_OPTIONAL_HEADER
    optHeader = peHeader->OptionalHeader;

    if(optHeader.Magic != 0x10b)
        error("This file is not a PE32 file.");

    // IMAGE_DATA_DIRECTORY
    impDir = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    descRva = impDir.VirtualAddress;

    if(!descRva)
        error("Invalid Import Directory RVA");

    // IMAGE_IMPORT_DESCRIPTOR
    impDesc = (PIMAGE_IMPORT_DESCRIPTOR)(descRva + (LPVOID)baseAddr);

    if (IsBadReadPtr((char*)baseAddr + impDir.VirtualAddress, (DWORD)impDir.Size))
        error("Bad pointer - Cannot access Import Directory.\n");

    DWORD i = 0;
    DWORD impSize = 0;

    while(impDesc[i].OriginalFirstThunk != 0)
    {
        // IMAGE_THUNK_DATA
        impTable = (PIMAGE_THUNK_DATA)(impDesc[i].OriginalFirstThunk + (LPVOID)baseAddr);

        while(impTable->u1.AddressOfData != 0)
        {
            impSize++;
            impTable++;
        }

        i++;
    }

    impSize *= MAX_FUNCTION_NAME + (i * MAX_DLL_NAME);
    char *impStr;
    impStr = calloc(sizeof(char), impSize);

    if(impStr == NULL)
        error("Fail allocating import string");

    i = 0;

    // This loop get all the functions from all DLLs inside IMAGE_IMPORT_DESCRIPTOR
    while(impDesc[i].OriginalFirstThunk != 0)
    {
        // IMAGE_THUNK_DATA
        impTable = (PIMAGE_THUNK_DATA)(impDesc[i].OriginalFirstThunk + (LPVOID)baseAddr);

        char *temp = (char *)(impDesc[i].Name + (DWORD)baseAddr);
        char dllName[MAX_DLL_NAME] = {};
        memcpy(dllName, temp, strlen(temp) - 3);

        if(dllName == NULL)
            fprintf(stdout, "DLL number %ld have a NULL name.\n", i);

        for (DWORD j = 0; j < strlen(dllName); j++)
            dllName[j] = tolower(dllName[j]);

        getFunctions(impTable, baseAddr, impStr, dllName);

        i++;
    }

    // Remove the last comma
    impStr[strlen((const char *)impStr) - 1] = '\0';

    getHash(impStr, MD5LEN);
    fprintf(stdout, "\n");

    free(impStr);

}

void createMap(LPCSTR filePath)
{
    HANDLE fH;
    HANDLE mapH;
    LPVOID baseAddr;

    // Open the file
    fH = CreateFile(filePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (fH == INVALID_HANDLE_VALUE)
        error("Fail to open the file.");

    mapH = CreateFileMapping(fH, NULL , PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

    if(!mapH)
    {
        CloseHandle(fH);
        error("Fail to create a File Mapping. Is it an executable file?");
    }

    // Get Image Base Address
    baseAddr = MapViewOfFile(mapH, FILE_MAP_READ, 0, 0, 0);

    if(!baseAddr)
    {
        CloseHandle(fH);
        CloseHandle(mapH);
        error("Fail to map a View of File.");
    }

    init(baseAddr);
    clean(baseAddr, mapH, fH);
}
