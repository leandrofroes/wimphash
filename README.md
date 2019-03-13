# wimphash

Wimphash is a tool to get MD5 hash from Import Table. The idea is use Windows API functions to map a file in memory and parse PE Structures to get DLL names and import (function) names. After that the tool put everything together in a string and get the MD5 hash from it.

The way that this big string is organized is like this:

```kernel32.deletecriticalsection,kernel32.entercriticalsection,kernel32.exitprocess```

Most part of security technologies uses a tool called imphash (from pefile https://github.com/erocarrera/pefile) to calculate the import hash from a PE file and due to it wimphash uses a database called ordlookup (used by imphash) to calculate the hash from 2 specific DLL (exactly like pefile). This is not a good idea, but is necessary to match with all the other tools that uses imphash (e.g Virus Total).

The diference between this tool and the others is the simple fact that this is a tool created in C, uses only windows functions and access the file from memory, ensuring no dependencys and a better compatibility.

Comments, suggestions and feedbacks are always welcome!!

## **Usage**

```wimphash.exe <file>```

## **Examples**

```
wimphash.exe putty.exe

63e5ceb1f07221fa9448d107ccf4ab5f

wimphash.exe WinSCPnet.dll

dae02f32a21e03ce65412f6e56942daa

```
    
```    
wimphash.exe C:\Users\user01\dir\*

C:\Users\user01\dir\test1.exe:

ac26ec265bddf0998cd4736b8bcb8691

C:\Users\user01\dir\test2.exe:

e3d89ddd7a832a388830b2d9e6596065

C:\Users\user01\dir\test3.exe:

ce98018b85b0454843035df8b2e3bc2a

```

## **Future Features**

- Support for x64 PE Files (PE32+)

## **License**

The wimpash is published under the GPL v3 License. Please refer to the file named LICENSE for more information.

