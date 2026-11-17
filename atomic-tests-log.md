# Atomic Red Team simulation log

Lab: Wazuh 4.9.2 (all-in-one, Ubuntu Server 22.04) + Windows 10 endpoint (Sysmon64, Wazuh agent 4.9.2).
All times are local time as shown in the Wazuh dashboard. Every test was run with Atomic Red Team on my own isolated host-only VM lab.

---

## Simulation 1: PowerShell encoded commands

```
TECHNIQUE: T1059.001 - Command and Scripting Interpreter: PowerShell
SIMULATED VIA: Invoke-AtomicTest T1059.001 -TestNumbers 15
               (ATHPowerShellCommandLineParameter -EncodedCommand parameter variations)
               Variants run: -E, -EncodedCommand, -Enc (each with -NoProfile)
DETECTION BEFORE TUNING: Wazuh default rule 92071 (level 12) - 3 of 3 variants alerted.
                         Custom rule 100100 (version 1) did NOT fire (0 of 3).
DETECTION AFTER TUNING: Custom rule 100100 (version 2, level 13) - 6 alerts (two runs of the 3 variants)
ALERT (after): rule.id 100100, level 13, agent win10-sysmon,
               description "Custom: encoded PowerShell command execution on endpoint (T1059.001)",
               rule.mitre.id T1059.001, tactic Execution
MITRE MAPPING: T1059.001
VERDICT: True positive (simulated)
RECOMMENDATION: Alert on any encoded PowerShell, whether PowerShell was started by a user,
                by another PowerShell, or by WMI. Match all abbreviated switch forms, not only -enc.
```

What happened:

1. My first version of rule 100100 hooked into `sysmon_event1` and never fired on a manual encoded command: built-in rule 92057 (level 12) matched the same event first, and only one rule wins per event (Nov 5).
2. I rebuilt the rule as a child of 92057 (level 13). The manual test then fired it.
3. The Atomic test starts PowerShell through WMI. Those events follow a different rule chain (92070 -> 92071), so the built-in rule 92071 alerted at level 12 and my version 1 rule never ran (Nov 11). That was a gap in my rule, not in the default ruleset.
4. Fix: `<if_sid>92057,92071</if_sid>` and a regex that covers the abbreviated switches `-e`, `-ec`, `-ea`, `-en`, `-enc`, `-enco`, `-encode`, `-encodeda` and `-encodedcommand`, followed by a base64-looking payload of 20+ characters.
5. After the fix, all three variants fired rule 100100 at level 13 (Nov 14, two runs).

Lessons: when a custom rule stays silent, check which rule actually fired. And a rule that depends on one parent rule only covers the process-creation paths that parent covers, so test with more than one launch method.

---

## Simulation 2: Registry Run key persistence

```
TECHNIQUE: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
SIMULATED VIA: Invoke-AtomicTest T1547.001 -TestNumbers 1 (Reg Key Run)
               Command: REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" ...
DETECTION: Wazuh default rules (no custom rule needed)
ALERT: Nov 14, 21:43:23 (the same three alerts fired again on a Nov 17 re-run at 16:15:57)
       92052 level 4  - Windows command prompt started by an abnormal process
       92041 level 10 - Value added to registry key has Base64-like pattern
       92302 level 6  - Registry entry to be executed on next logon was modified
                         using command line application reg.exe  (Sysmon event 13)
MITRE MAPPING: T1547.001 (Persistence)
VERDICT: True positive (simulated)
RECOMMENDATION: The key persistence alert (92302) is only level 6. Raise it for Run keys that point to
                user-writable paths, and review any Run key written by reg.exe.
CLEANUP: Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup; verified with
         reg query HKCU\...\Run (entry removed).
```

---

## Simulation 3: NTLM authentication forced with rpcping

```
TECHNIQUE: T1003 - OS Credential Dumping (as labelled by Atomic Red Team test T1003-7)
SIMULATED VIA: Invoke-AtomicTest T1003 -TestNumbers 7 (Send NTLM Hash with RPC Test Connection)
               Command: rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM
               (runs against localhost only; nothing is dumped or downloaded)
TELEMETRY: Sysmon logged the process creation (event ID 1) and four registry events (event ID 13)
           on Nov 14 at 21:57. Wazuh created NO alert from it: no default rule matches rpcping.
           Each run logs two event ID 1 entries: the powershell.exe wrapper and RpcPing.exe itself
           (rule 100101 matches the RpcPing.exe event).
DETECTION: Custom rule 100101 (level 10), added after the gap was found
ALERT (after): Nov 15, 21:55:43 - rule.id 100101, level 10, agent win10-sysmon,
               "Custom: rpcping forcing NTLM authentication (possible hash capture, T1003)"
               (fired again on a Nov 17 re-run at 16:21:31)
MITRE MAPPING: T1003
VERDICT: True positive (simulated) - detection gap found and closed
RECOMMENDATION: Alert on rpcping.exe with -u NTLM, and monitor unusual NTLM authentication in general.
                The rule is narrow (it matches only this tool and switch), so it needs broader NTLM
                monitoring to be useful in production.
```

Honest limits:

- The test targets localhost, so it shows that the behaviour is detectable, not that credentials were captured.
- Rule 100101 is tuned to this exact test and is a starting point, not a production rule.
