# wimphash

Wimphash is a C version of [imphash](https://github.com/erocarrera/pefile). Please note that this is only a PoC I created while studying about PECOFF.

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

## **License**

The wimpash is published under the GPL v3 License. Please refer to the file named LICENSE for more information.

