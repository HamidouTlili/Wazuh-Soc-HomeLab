# Wazuh SOC Home Lab: Threat Detection and Attack Simulation

A small SOC lab built on VirtualBox: a Wazuh SIEM/XDR server, a Windows 10 endpoint with Sysmon, custom detection rules mapped to MITRE ATT&CK, and three Atomic Red Team simulations that I triggered myself and watched Wazuh detect.

## Summary

| Item | Value |
|---|---|
| Wazuh version | 4.9.2 (indexer, manager, dashboard on one VM) |
| Endpoint | Windows 10 (build 19045) with Sysmon64 and Wazuh agent 4.9.2 |
| Manager OS | Ubuntu Server 22.04.5 |
| Telemetry | Sysmon (process creation, registry events) + Windows event channels |
| Custom rules | 2 (`100100`, `100101`) |
| Techniques tested | T1059.001, T1547.001, T1003 (Atomic Red Team test T1003-7) |
| Detections | 3 of 3 techniques alerted; 2 of 3 needed my own rule or tuning |
| Not included | Part 2 extras (Suricata, YARA/ClamAV, osquery, Caldera) |

## Architecture

```
 Windows 10 VM                         Ubuntu Server VM
 Sysmon + Wazuh agent  --1514/TCP-->   Wazuh manager + indexer + dashboard
 (Atomic Red Team tests)               (custom rules in local_rules.xml)
          \_____ VirtualBox host-only network _____/
```

Both VMs sit on a host-only network, and nothing is exposed to the internet.

## 1. Setup: agent connected and Sysmon telemetry flowing

The Wazuh agent on the Windows VM reports to the manager and shows as **active**.

![Agent active in the Wazuh Endpoints summary][shot-4]

After adding the `Microsoft-Windows-Sysmon/Operational` channel to the agent config, Sysmon events arrive in Threat Hunting (28 hits in the first window).

![Sysmon events arriving in Wazuh][shot-7]

Wazuh's default ruleset already fires on that telemetry (discovery commands, PowerShell dropping executables).

![Default rules firing on Sysmon events][shot-8]

## 2. Simulation 1: PowerShell encoded commands (T1059.001)

**Version 0 (no alert).** My first rule hooked into `sysmon_event1`. A manual encoded command produced no `100100` alert, because Wazuh's built-in rule 92057 (level 12) matched the same event first, and only one rule wins per event.

![No results for rule 100100 on the first version][shot-35]

**Version 1.** I rebuilt it as a child of 92057 at level 13, and the same manual encoded command (`powershell.exe -EncodedCommand ...`) fired it.

![Rule 100100 firing on a manual encoded PowerShell command][shot-11]

The alert carries the MITRE mapping (T1059.001, tactic Execution, technique PowerShell).

![Alert details with MITRE ATT&CK fields][shot-13]

**Atomic Red Team test 15** runs PowerShell with three spellings of the encoded-command switch: `-E`, `-EncodedCommand` and `-Enc`.

![Atomic Red Team test T1059.001-15, three variants][shot-15]

**Finding: version 1 missed all three.** Atomic Red Team starts PowerShell through WMI, so the events follow a different rule chain. Wazuh's built-in rule `92071` (level 12) alerted instead, and my custom rule never ran.

![Only default rule 92071 fired, rule 100100 is absent][shot-18]

The default rule's own pattern shows why it handled every spelling: it matches `powershell.exe` followed by `-e` or its longer forms (`-ea`, `-ec`, `-en`, `-enco`, `-encode`, `-encodeda`, `-encodedcommand`).

![Details of default rule 92071][shot-36]

**Fix (version 2).** The rule now hooks into both parent rules (`if_sid` 92057 and 92071) and its regex covers the abbreviated switches followed by a base64-looking payload.

![Rule 100100 after the fix][shot-19]

**Result.** Re-running the test produced six alerts from rule `100100` at level 13 (two runs of the three variants).

![Six alerts from rule 100100 after the fix][shot-20]

## 3. Simulation 2: Registry Run key persistence (T1547.001)

Atomic test 1 (`Reg Key Run`) adds a value to `HKCU\...\CurrentVersion\Run` with `reg.exe`, then it is cleaned up with the test's cleanup command.

![Atomic test T1547.001-1 definition and cleanup command][shot-22]

Running it adds the value `Atomic Red Team` to the Run key, and the cleanup command removes it again.

![Test run: Run key added, then removed by the cleanup][shot-30]

Wazuh's default rules caught it with no custom rule: `92302` (registry entry executed on next logon modified by `reg.exe`, level 6), `92041` (Base64-like value added to a registry key, level 10) and `92052` (command prompt started by an abnormal process, level 4).

![Default rule 92302 detail][shot-23]

The three alerts appear in Threat Hunting right after the run (16:15:57 in this screenshot, from a re-run on Nov 17; the original run on Nov 14 produced the same three alerts).

![Alerts 92052, 92041 and 92302 after the Run key test][shot-32]

## 4. Simulation 3: NTLM authentication forced with rpcping (T1003)

Atomic test T1003-7 runs `rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM` against localhost only; nothing is dumped or downloaded.

![Atomic test T1003-7 definition][shot-27]

**Finding: Sysmon logged the process, but Wazuh created no alert.** No default rule matches `rpcping` with NTLM options. Each run produces two Sysmon process-creation events (ID 1): the PowerShell wrapper that launches the command, and `RpcPing.exe` itself with `-u NTLM` (screenshot from the Nov 17 re-run).

![Sysmon process-creation events for rpcping][shot-33]

**Fix.** Custom rule `100101` (level 10) matches `rpcping.exe` with `-u NTLM`.

![Custom rule 100101][shot-29]

After the rule was loaded, the test alerted at level 10 (first on Nov 15, then again on a Nov 17 re-run). In the table below, the `100101` row at 16:21:31 sits next to `92057` and `92213`, which come from the PowerShell session that launched the test.

![Rule 100101 alert at level 10][shot-32]

## Results

| # | Technique | Atomic test | Default Wazuh detection | Result |
|---|---|---|---|---|
| 1 | T1059.001 PowerShell | T1059.001-15 (EncodedCommand variants) | Rule 92071, level 12 | Custom rule 100100 needed two fixes (shadowed by a default rule, then missed the WMI launch path); then 6/6 alerts at level 13 |
| 2 | T1547.001 Run key persistence | T1547.001-1 | Rules 92302 (level 6), 92041 (level 10), 92052 (level 4) | Detected by default rules |
| 3 | T1003 NTLM forced with rpcping | T1003-7 | None (Sysmon logged it, Wazuh did not alert) | Gap closed with custom rule 100101, level 10 |

Full write-ups with alert details: [`simulations/atomic-tests-log.md`](simulations/atomic-tests-log.md).
Custom rules: [`rules/local_rules.xml`](rules/local_rules.xml).

## What I learned

- **Only one rule wins per event.** My first PowerShell rule never fired because a built-in rule matched the same event first. When a custom rule stays silent, check which rule actually fired before assuming the rule is broken.
- **A custom rule that hangs off one parent rule only sees what that parent sees.** Version 1 worked for a manual test but missed Atomic Red Team, which starts PowerShell through WMI. Testing several launch methods exposed the gap.
- **Default rules are strong on well-known behaviour** (encoded PowerShell, Run key writes) and silent on niche tools (`rpcping` with NTLM). Sysmon having the event is not the same as Wazuh alerting on it.
- **Operations matter.** The Wazuh manager's vulnerability-detection updater filled a 40 GB disk with temporary downloads (about 21 GB in `/var/ossec/queue/vd_updater/tmp`), which crashed the indexer and manager. I cleaned the temp folder, disabled vulnerability detection for this lab, and added a longer service start timeout.
- Wazuh leaves a stale lock (`/var/ossec/var/start-script-lock`) after an unclean shutdown. Shut VMs down cleanly.

## Reproduce it

1. Create an Ubuntu Server 22.04 VM (4 GB RAM or more, 40 GB disk) and install Wazuh with the official all-in-one installer (`wazuh-install.sh -a`).
2. Install the Wazuh agent on the Windows VM and add the Sysmon `localfile` block (`Microsoft-Windows-Sysmon/Operational`, `eventchannel`) to `ossec.conf`.
3. Copy the rules from `rules/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`, run `wazuh-analysisd -t`, and restart the manager.
4. On the Windows VM, add a Defender exclusion for the Atomic Red Team folder, install Invoke-AtomicRedTeam, and run the tests listed above. Remove the registry value after test T1547.001-1 with `-Cleanup`.


## Limitations

- Simulations are single, safe test cases on one endpoint; they show detection of the behaviour, not resilience against a real attacker.
- Rule `100101` matches one specific tool and switch and is meant as a learning example.
- Part 2 (network IDS, file scanning, host queries, adversary emulation) is not part of this project.

*Lab only. Tests were run on virtual machines I own, on an isolated network.*

<!-- Embedded screenshots (base64) -->