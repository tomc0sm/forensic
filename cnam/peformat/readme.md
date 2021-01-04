
## Analyse statique PE Format

- Date : 2017-05-10
- Files 
  - `2F6C816B54070557F45CA0365B3902DA`
  - `0533955D39F432641484679E51B00EF9`
  - `B8A97C611FBD204F49005CB2CA32B409`
  - `B28223A524EF416D902537B090B29D8A`
  - `CA55ACA3290A690BD8F7DB37B4DA40CA`
- Files size : 37KB/44KB
- Resources :
  - Configuration file 
    - Permissions as Invoker 
    - No UI Access



| File hash                          | DLL                                                          | Significants functions                                       |
| ---------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `2F6C816B54070557F45CA0365B3902DA` | `WININET.dll` / `VCRUNTIME140D.dll` / `ucrtbased.dll` / `KERNEL32.dll` | `HttpOpenRequestA / InternetReadFile / InternetConnectA / InternetCloseHandle / HttpSendRequestA / InternetOpenA` |
| `0533955D39F432641484679E51B00EF9` | `WS2_32.dll` / `VCRUNTIME140D.dll`  / `ucrtbased.dll` / `KERNEL32.dll` | `getaddrinfo / freeaddrinfo`                                 |
| `B8A97C611FBD204F49005CB2CA32B409` | `KERNEL32.dll` / `VCRUNTIME140D.dll` / `ucrtbased.dll`       | `K32EnumProcesses / K32EnumProcessModulesEx / K32GetModuleBaseNameA / K32GetModuleFileNameExA / 32GetModuleInformation / K32GetProcessImageFileNameA` |
| `B28223A524EF416D902537B090B29D8A` | `KERNEL32.dll` / `USER32.dll` / `ADVAPI32.dll` / `VCRUNTIME140D.dll` / `ucrtbased.dll` | `RegEnumValueA / RegEnumKeyExA / RegCloseKey / RegOpenKeyExA` |
| `CA55ACA3290A690BD8F7DB37B4DA40CA` | `KERNEL32.dll` / `VCRUNTIME140D.dll` / `ucrtbased.dll`       | `FindFirstFileA / FindNextFileA`                             |

Conclusions: 

The files don't seem malicious. Functions called look like process explorer : network called, process enumeration, image files lists, registry reads. 
