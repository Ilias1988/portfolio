---
title: "Hack The Box Sherlock — LogJammer"
summary: "A reproducible Windows EVTX investigation correlating logons, Defender detections, firewall changes, scheduled tasks, PowerShell activity and log clearing."
platform: "Hack The Box"
contentType: "sherlock"
publicationPolicy: "retired"
sherlockCategory: "DFIR"
difficulty: "Easy"
solvedAt: 2026-10-07
publishedAt: 2026-10-07
tags:
  - windows-event-logs
  - dfir
  - evtx-analysis
  - defender
  - firewall
  - scheduled-tasks
  - powershell-logging
tools:
  - Python 3
  - python-evtx
  - sha256sum
cves: []
htbUrl: "https://app.hackthebox.com/sherlocks/LogJammer"
cover: "/images/writeups/hackthebox/sherlocks/dfir/logjammer/logjammer-cover.png"
coverAlt: "Hack The Box LogJammer artwork: green shield surrounding a Log Flavour jar"
featured: false
draft: false
---

> **Authorized-lab notice:** This article documents the retired Hack The Box Sherlock LogJammer. Its status was checked in the platform's **Retired** Sherlocks list on 7 October 2026. The accepted task answers, original evidence archive and potentially unsafe files are not redistributed. The code below lets readers derive findings from their own authorized copy of the logs.

Browse the [full write-up archive](/writeups/) or the [Sherlocks archive](/writeups/sherlocks/) for related investigations.

## Executive summary

LogJammer is a Windows Event Log investigation based on five EVTX files. I used a small Python parser to read their native XML, filtered on event IDs and named fields, then correlated events by UTC time and security identifier (SID). The relevant sequence contains an interactive user logon, a Defender detection and remediation, a user-owned firewall rule addition, an audit-policy change, a scheduled task, a PowerShell script block and a later log-clear event.

The most important analytical distinction was **time**. The Defender log also contains 137 detections of a different payload on 10 March, and the System log records repeated clears of a different channel on 24 March. Those entries are real, but they precede the 27 March activity at issue. A simple keyword match on “malware” or “log cleared” would have selected the wrong event.

## Case information and objectives

| Item | Value |
| --- | --- |
| Scenario | Junior DFIR assessment for the fictional Forela-Security consultancy |
| Platform | Hack The Box Sherlock [LogJammer](https://app.hackthebox.com/sherlocks/LogJammer) |
| Category and difficulty | DFIR · Easy |
| Publication status | Retired, verified on the HTB Retired list on 7 October 2026 |
| Evidence | Five Windows EVTX files |
| Analysis environment | Kali Linux in WSL, using Python and `python-evtx` |

The investigation asked us to establish when the user logged on, identify changes to host controls, inspect a scheduled task, understand a Defender alert, recover a PowerShell command and determine which event-log channel was cleared. These are separate questions, but the evidence becomes more convincing when read as one timeline.

## Evidence inventory and handling

The supplied `Event-Logs` directory contained these five files. SHA-256 values were calculated over the extracted EVTX files, not over the parent ZIP:

| Evidence file | SHA-256 |
| --- | --- |
| `Powershell-Operational.evtx` | `aa6a620bb16e34433395d0f3bb6a99f29fec22414d9796e02090c1106412ca35` |
| `Security.evtx` | `83979ad971fa5d3646bf30655e81f3e4f6d0e31c0bec694b33c22e5e593162aa` |
| `System.evtx` | `0cff977d864705027774815e0255c99c4e21e9919f663b5f5d4bc52fc651e7f3` |
| `Windows Defender-Operational.evtx` | `9ddeb039f6a730dfea5463d5efd5ddf38a6234e3fba16cd96ee397c5a247971c` |
| `Windows Firewall-Firewall.evtx` | `898085c98b75e12fe3483ef11e4bcb6e6f9bd999e357493c43d804b297d53f67` |

To reproduce the hashes from inside `Event-Logs`:

```bash
sha256sum *.evtx
```

I parsed the event logs as data. I did not execute any file named in the telemetry or treat WSL as a malware sandbox. The original HTB archive and its EVTX files remain outside this public repository.

### Parser setup

The following commands were run from the directory containing the five EVTX files:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install python-evtx
```

`python-evtx` provides `Evtx(...).records()` and `record.xml()`. Each snippet below reads an EVTX record, converts its XML to an element tree and selects fields by their `Name` attributes. The namespace is necessary because Windows event XML uses a default namespace.

## Timeline reconstruction

All times in this table are **UTC and rounded to the minute**. The parser retained subsecond timestamps; minute precision is sufficient to show event order without turning the timeline into an answer sheet.

| Time, 27 March 2023 UTC | Evidence source | Event | Significance |
| --- | --- | --- | --- |
| 14:37 | Security, 4624 | Interactive logon for the scenario user | Establishes the day's user session and its SID. |
| 14:42 | Defender Operational, 1116 and 1117 | Detection in a downloaded archive, followed by a remediation event | Shows a contemporary alert and the action Defender reported. |
| 14:44 | Firewall, 2004 | Custom firewall rule added | `ModifyingUser` matches the SID from the logon. |
| 14:50 | Security, 4719 | Audit-policy subcategory changed | The event names the **computer account** as subject; user attribution requires care. |
| 14:51 | Security, 4698 | Scheduled task created | `SubjectUserSid` matches the logged-on user; task XML contains the action. |
| 14:58 | PowerShell Operational, 4104 | Script block recorded | Provides the command text, without proving its final effect. |
| 15:01 | System, 104 | Event-log channel cleared | The embedded `Channel` field identifies which log was affected. |

This order is observed in the logs. It does **not** establish that the flagged tool ran, that the firewall rule carried actual command-and-control traffic, or that the scheduled task executed.

## Initial triage: establish the logon session

Windows Security event **4624** records a successful logon. The fields `TargetUserName`, `LogonType` and `System/TimeCreated/@SystemTime` answer different parts of the question: who logged on, how, and when. I printed all matches in time order instead of assuming the earliest record in file order was the first relevant interactive session.

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
matches = []

with Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "4624":
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        if (data.get("TargetUserName") or "").lower() != "cyberjunkie":
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        matches.append((time, data.get("LogonType"), data.get("TargetUserSid")))

for time, logon_type, sid in sorted(matches):
    print(time, "LogonType=", logon_type, "SID=", sid)
PY
```

Four matching records appeared in two pairs less than a millisecond apart. Each had `LogonType=2`, which is an interactive logon. The shared SID, ending in `-1001`, became a stronger correlation key than the account's capitalization. The near-identical timestamps are separate event records; they are not evidence of four distinct human sign-ins.

## Firewall rule triage and SID correlation

Firewall event **2004** records a rule addition. I initially printed each addition and its named XML fields; that was useful for learning the event structure but produced too much output:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Windows Firewall-Firewall.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        event_id = root.findtext("./e:System/e:EventID", namespaces=ns)
        if event_id not in ("2004", "2097"):
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        print("\n", time, "Event ID", event_id)
        for key, value in data.items():
            print(" ", key, ":", value)
PY
```

For a smaller candidate list, the next pass printed distinct rule names and skipped resource-string names beginning with `@`:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
rules = set()

with Evtx("Windows Firewall-Firewall.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) not in ("2004", "2097"):
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        name = data.get("RuleName") or data.get("Name")
        if name and not name.startswith("@"):
            rules.add(name)

for name in sorted(rules):
    print(name)
print("Distinct names:", len(rules))
PY
```

That reduced the list to 50 names. A rule with an unusually explicit C2-related label warranted closer inspection. The focused query below prints the complete definition for **any name selected from your own result list**:

```bash
RULE_NAME='<RULE_NAME_FROM_THE_LIST>' python3 - <<'PY'
import os
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Windows Firewall-Firewall.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        if (data.get("RuleName") or data.get("Name")) != os.environ["RULE_NAME"]:
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        print("Time:", time)
        for key in ("RuleName", "Direction", "Protocol", "RemotePorts", "Action", "ModifyingUser", "ModifyingApplication"):
            print(f"{key}: {data.get(key)}")
PY
```

The relevant record showed `Protocol=6` (TCP), a specific remote port and `ModifyingApplication` pointing to the Windows management console. Its `ModifyingUser` SID matched the 4624 user's SID. `Direction=2` maps to outbound traffic; that number alone is more reliable than guessing from the rule's label. A rule definition is evidence of a configuration change, not of a successful connection.

## Audit-policy change

Security event **4719** carries the changed subcategory as a GUID. The log contains one such event in the incident window. This query shows the subject and the policy fields without dumping the whole Security log:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "4719":
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        print(time)
        for key in ("SubjectUserName", "CategoryId", "SubcategoryId", "SubcategoryGuid", "AuditPolicyChanges"):
            print(f"{key}: {data.get(key)}")
PY
```

The `SubcategoryGuid` can be translated with Microsoft's [audit subcategory table](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d), or with `auditpol /list /subcategory:* /v` on a Windows analysis host. The event's `SubjectUserName` was the **computer account**, not `CyberJunkie`. Its timing places it in the same activity window, but the 4719 record alone does not prove which human initiated the change.

## Scheduled task and its action

Security event **4698** records a new scheduled task. The top-level `TaskName` is separate from the nested `TaskContent` XML. I first filtered creation events by `SubjectUserName`:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "4698":
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        if (data.get("SubjectUserName") or "").lower() == "cyberjunkie":
            print("TaskName:", data.get("TaskName"))
            print("SubjectUserSid:", data.get("SubjectUserSid"))
PY
```

The task's `SubjectUserSid` matched the interactive logon SID and the firewall `ModifyingUser` SID. To inspect what the task **was configured to run**, parse the XML in `TaskContent`. The XML declaration may specify UTF-16 even though `python-evtx` has already returned a Python string; removing that declaration avoids a Unicode parsing error.

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import re

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "4698":
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        if (data.get("SubjectUserName") or "").lower() != "cyberjunkie":
            continue
        content = re.sub(r'^\s*<\?xml[^>]*\?>', '', data["TaskContent"])
        task = ET.fromstring(content)
        for command in task.findall(".//{*}Exec/{*}Command"):
            print("TaskName:", data.get("TaskName"))
            print("Command:", command.text)
PY
```

The sibling `Arguments` element holds the command-line options. This was a separate query in the original investigation because the task question asked for the arguments independently:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import re

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Security.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "4698":
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        if (data.get("SubjectUserName") or "").lower() != "cyberjunkie":
            continue
        content = re.sub(r'^\s*<\?xml[^>]*\?>', '', data["TaskContent"])
        task = ET.fromstring(content)
        for arguments in task.findall(".//{*}Exec/{*}Arguments"):
            print("TaskName:", data.get("TaskName"))
            print("Arguments:", arguments.text)
PY
```

The creation event proves registration of the task and its configured action. It does not, by itself, prove the task ran. A task execution claim would need Task Scheduler Operational events, process creation telemetry or equivalent evidence that was not provided here.

## Defender detection and remediation

Defender Operational **1116** reports a detection, while **1117** reports an action. I first extracted the fields most likely to identify the tool, file and response:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
results = set()

with Evtx("Windows Defender-Operational.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        event_id = root.findtext("./e:System/e:EventID", namespaces=ns)
        if event_id not in ("1116", "1117"):
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        details = tuple((key, value) for key, value in data.items()
                        if key and any(word in key.lower() for word in ("name", "path", "threat", "action")))
        results.add((event_id, details))

for event_id, details in sorted(results):
    print("\nEvent ID", event_id)
    for key, value in details:
        print(f"  {key}: {value}")
PY
```

The output was still repetitive because the log contains many older detections. The incident-window 1116 records described two components inside one downloaded ZIP. A focused detection query prints the threat name and the native Defender `Path` field:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("Windows Defender-Operational.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "1116":
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        if not time.startswith("2023-03-27"):
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        print(time, data.get("Threat Name"), data.get("Path"))
PY
```

In Defender's `Path`, `containerfile:_` introduces the archive, `file:_` introduces a detected member within it, and `webfile:_` may include a source URL. For a requested **full Windows path**, use the path after `containerfile:_` and before the next semicolon; do not include those field prefixes or a signed download URL. The exact archive basename is left to the reader's query.

To examine only the related action events, filter 1117 on the tool name discovered from 1116:

```bash
TOOL_NAME='<TOOL_NAME_FROM_1116>' python3 - <<'PY'
import os
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
tool = os.environ["TOOL_NAME"].lower()
with Evtx("Windows Defender-Operational.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "1117":
            continue
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        if not any(tool in str(value).lower() for value in data.values()):
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        print(time, "Threat:", data.get("Threat Name"), "Action:", data.get("Action Name"))
PY
```

The 1117 action follows the 1116 detection by about 14 seconds. The older detections concerned another payload on **10 March**; they should not be attached to the 27 March alert simply because they occur in the same EVTX file. Detection of an archive member does not demonstrate that member's execution.

## PowerShell command evidence

PowerShell Operational event **4104** stores `ScriptBlockText`. Printing distinct, short script blocks kept the output manageable while preserving the exact command syntax:

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
seen = set()

with Evtx("Powershell-Operational.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "4104":
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        data = {x.get("Name"): x.text for x in root.findall("./e:EventData/e:Data", ns)}
        command = (data.get("ScriptBlockText") or "").strip()
        if command and command not in seen and len(command) < 300:
            seen.add(command)
            print(time, "|", command)
PY
```

The relevant short command calculates an MD5 hash of the Desktop script referenced by the scheduled task. This cross-reference makes the PowerShell event relevant to the case, but the provided command text alone does not tell us why the user wanted the hash or whether the task executed successfully. For real investigations, SHA-256 is preferable for evidence integrity; the MD5 algorithm here is part of the observed command, not a recommendation.

## Event-log clearing and false leads

System event **104** records a log clear. Its useful channel name is under `UserData/LogFileCleared/Channel`, **not** the outer `System/Channel` that tells us where the 104 record was stored.

```bash
python3 - <<'PY'
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
with Evtx("System.evtx") as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        if root.findtext("./e:System/e:EventID", namespaces=ns) != "104":
            continue
        time = root.find("./e:System/e:TimeCreated", ns).get("SystemTime")
        cleared = root.find(".//{*}LogFileCleared/{*}Channel")
        subject = root.find(".//{*}LogFileCleared/{*}SubjectUserName")
        print(time, "| channel:", cleared.text if cleared is not None else "unknown",
              "| user:", subject.text if subject is not None else "unknown")
PY
```

The case log contained **14** clears of a different channel on 24 March and **one** clear in the 27 March incident window. The latter event's `SubjectUserName` was the scenario user. This is stronger attribution than timing alone. Readers should use that event's `Channel` value to identify the cleared log.

## Correlation and evidentiary limits

Three independent records tie the user to activity in the incident window: the 4624 `TargetUserSid`, the firewall event's `ModifyingUser` SID and the 4698 `SubjectUserSid` are identical. The 104 log-clear record names the user directly. Defender records a file detection under that user's profile, but it does not itself identify the downloader. The 4719 audit-policy event names the computer account, so I describe it as a **temporal association**, not a directly proven user action.

The available EVTX files do not prove live C2 communication, scheduled-task execution, successful collection by the detected tool, exfiltration or the effect of the PowerShell hash command. There is no packet capture, Task Scheduler Operational log, Sysmon log from the incident window or full process tree in the supplied set. The custom firewall rule's label is an investigator lead, not proof of its advertised purpose.

## Detection opportunities and takeaways

- Correlate 4624 interactive logons with 2004 firewall additions and 4698 scheduled-task creation by SID, not account-name spelling alone.
- Alert on unusual outbound firewall rules, especially those naming remote ports, and review their `ModifyingUser` and `ModifyingApplication` fields.
- Pair Defender 1116 and 1117 by threat and timestamp so detection and remediation are reported together.
- Watch for 4719 audit-policy changes and 104 log clears, but distinguish the event subject from a user inferred only by proximity.
- Apply a tight incident window before triaging matches. Here, older malware alerts and older clears were the main false leads.

## References

- [Hack The Box LogJammer Sherlock](https://app.hackthebox.com/sherlocks/LogJammer) and [How to Play Sherlocks](https://help.hackthebox.com/en/articles/8570249-how-to-play-sherlocks)
- [Microsoft: Security event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft: Security event 4719](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719) and [audit subcategory GUID table](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
- [Microsoft: Security event 4698](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)
- [Microsoft: Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Microsoft: PowerShell script-block logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging)
- [Microsoft: event-log clear example](https://learn.microsoft.com/en-us/answers/questions/2550635/event-viewer-application-error)
- [python-evtx project](https://github.com/williballenthin/python-evtx)
