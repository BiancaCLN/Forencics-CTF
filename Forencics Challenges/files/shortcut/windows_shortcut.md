`windows_shortcut.lnk` 

## ❓ Is `.lnk` safe?

Short answer: **No — not inherently.** A `.lnk` file is a simple Windows shortcut, but it can contain executable targets and command-line arguments that will run when the shortcut is activated. From a forensics point of view, `.lnk` files are valuable evidence: they record target paths, working directories, icon locations, and time metadata that help reconstruct user actions and intrusion timelines. However, because they can carry arguments (including `-EncodedCommand`) they may also be used as a delivery mechanism for malicious scripts.

**Forensic highlights:**
- **Artifact fields:** `.lnk` files contain structured data such as the target path, relative path, working directory, command-line arguments, and icon location. These fields can indicate what was executed and from where.
- **Timestamps:** `.lnk` files often include access/creation/modify times that help place a shortcut in a timeline.
- **User context:** Combined with other artifacts (prefetch, registry UserAssist, shellbags, and event logs) `.lnk` files can show whether a user actually interacted with the shortcut or if an automated process used it.
- **Obfuscation:** Attackers frequently hide payloads with `-EncodedCommand` or point to `powershell.exe`/`wscript.exe` with arguments. The encoded payload itself should never be executed in the host — decode it as text to inspect behavior.

> **Files Provided:** `windows_shortcut.lnk"
}]} `windows_shortcut.lnk`

---

## 💡 What is a `.lnk` file?
A `.lnk` file is a **Windows shortcut** that points to a file, folder, or executable. When double-clicked, Windows launches the target with any provided command-line arguments.

Attackers (and CTF challenges) can use `.lnk` files to disguise commands. For example, a shortcut can call:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <Base64 string>
```

This makes it look like an innocent shortcut, but it actually executes a hidden PowerShell script.

> ⚠️ **Important:** `.lnk` files can be dangerous. Always analyze them in a sandbox or virtual machine — never double-click to open.

---

## 🔍 Initial Inspection
Start with safe, read-only inspection tools to examine the contents.

```bash
# Check file type
file windows_shortcut.lnk

# Extract readable text to look for PowerShell or encoded commands
strings windows_shortcut.lnk | egrep -i 'powershell|EncodedCommand|.exe|.ps1|-NoProfile|-ExecutionPolicy'
```

From the output, we can already see hints of `powershell.exe` and a Base64-encoded argument. That’s our main lead.

---

## 🧰 Metadata Extraction
Next, use `exiftool` to extract structured metadata safely:

```bash
exiftool windows_shortcut.lnk
```

Example output:

```
Local Base Path                 : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Description                     : Shortcut
Command Line Arguments          : -NoProfile -ExecutionPolicy Bypass -EncodedCommand BfAGQANABuAGcAMwByAG8AdQBzAH0A
Icon File Name                  : %windir%\system32\shell32.dll
```

This confirms that the shortcut is launching PowerShell with an encoded payload.

---

## 🔠 Understanding `-EncodedCommand`
PowerShell’s `-EncodedCommand` switch allows passing a Base64 string that represents UTF-16LE–encoded text. It’s often used for obfuscation or to hide commands from casual inspection.

To decode it:
1. Extract the Base64 text after `-EncodedCommand`
2. Base64-decode it to binary
3. Interpret the result as UTF-16LE text

---

## 🧮 Safe Decoding Example
Use Python or PowerShell **without executing** the result.

### 🐍 Using Python
```bash
python3 - <<'PY'
import base64
s = "BfAGQANABuAGcAMwByAG8AdQBzAH0A"
print(base64.b64decode(s).decode('utf-16le'))
PY
```

> ✅ This decoding is safe — it only converts text and never runs the command.

---

## 🧠 Lessons Learned
- `.lnk` shortcuts are **not harmless** — they can execute arbitrary code.
- `-EncodedCommand` hides a PowerShell script inside a Base64 string.
- Always decode in a **controlled environment** using text tools, never execution.
- Tools like `exiftool`, `strings`, and `file` are powerful for static inspection.

---


> 🧩 *Even a simple shortcut can hide a full PowerShell script — never underestimate the small files.*
