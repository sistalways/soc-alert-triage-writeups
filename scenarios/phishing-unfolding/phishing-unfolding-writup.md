# Phishing Unfolding

**Difficulty:** Medium · **Recommended Time limit:** 40 mins · **Result:** Passed - security breach prevented

## Scenario Overview

A live phishing attack unfolds inside a corporate network while routine alerts keep arriving. The goal is to separate real attacker activity from noise, reconstruct the attack chain as it happens (PowerShell execution, reverse shell, suspicious DNS), and write case reports explaining the full scope of the breach.

---

## Results

| Metric | Value |
|---|---|
| Total Time Taken | ~120 min |
| Total alerts | 36 |
| Actual true positives | 15 |
| Actual false positives | 21 |
| Marked TP | 19 (15 correct, 4 incorrect) |
| Marked FP | 17 (17 correct, 0 incorrect) |
| True positive identification rate | **100%** - every malicious alert caught |
| False positive identification rate | **81%** - 4 benign alerts escalated unnecessarily |

### Alert Breakdown

| Alert Rule | Count | Actual Verdict | Notes |
|---|---|---|---|
| Suspicious email from external domain | 10 | FP | Hat-themed spam; rule fires on TLD alone (and even on gmail.com) |
| Suspicious Attachment found in email | 1 | **TP** | The phishing email that started the incident |
| Suspicious Parent Child Relationship (benign) | 11 | FP | taskhostw, rdpclip, WUDFHost, TrustedInstaller, svchost |
| Suspicious Parent Child Relationship (nslookup) | 10 | **TP** | DNS exfiltration chunks |
| Suspicious Parent Child Relationship (Robocopy) | 1 | **TP** | Data collection from the finance share |
| Powershell Script in Downloads Folder | 1 | **TP** | PowerView dropped |
| Network drive mapped to a local drive | 1 | **TP** | Finance share mapped |
| Network drive disconnected from a local drive | 1 | **TP** | Attacker cleanup |

---

## Attack Chain

| Stage             | Activity                                                                                                            | Alert(s)  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------- | --------- |
| Initial Access    | Phishing email from `john@hatmakereurope.xyz` ("FINAL NOTICE: Overdue Payment") with `ImportantInvoice-Febrary.zip` | 1005      |
| Execution         | User opens `invioce.pdf.lnk` (double extension) -> PowerShell downloads powercat from GitHub                        | -         |
| Command & Control | powercat reverse shell to `2.tcp.ngrok.io:19282`                                                                    | -         |
| Discovery         | `systeminfo`, `whoami`, `whoami /priv`, `net user`, `net localgroup`                                                | -         |
| Discovery         | `PowerView.ps1` written to Downloads and executed                                                                   | 1020      |
| Collection        | `net use Z: \\FILESRV-01\SSF-FinancialRecords`                                                                      | 1022      |
| Collection        | Robocopy copies `InvestorPresentation2023.pptx` and `ClientPortfolioSummary.xlsx` into a staging folder             | 1023      |
| Defense Evasion   | `net use Z: /delete`                                                                                                | 1024      |
| Collection        | Files compressed into `exfilt8me.zip`                                                                               | -         |
| Exfiltration      | ZIP Base64-encoded and sent as subdomains via `nslookup` to `haz4rdw4re.io`                                         | 1025–1032 |
| Exfiltration      | Second encoded string sent over DNS                                                                                 | 1033–1034 |

Affected assets: host `win-3450`, user `michael.ascot`, share `\\FILESRV-01\SSF-FinancialRecords`.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | ZIP attachment in invoice-themed email |
| Execution | T1204.002 User Execution: Malicious File | User opened `invioce.pdf.lnk` |
| Execution | T1059.001 PowerShell | `IEX(...DownloadString(...))` |
| Defense Evasion | T1036.007 Double File Extension | `.pdf.lnk` |
| Command & Control | T1105 Ingress Tool Transfer | powercat and PowerView downloaded |
| Command & Control | T1572 Protocol Tunneling | ngrok tunnel |
| Discovery | T1082, T1033, T1087.001, T1069.001 | systeminfo, whoami, net user, net localgroup |
| Discovery | T1087.002 Domain Account Discovery | PowerView |
| Collection | T1039 Data from Network Shared Drive | Robocopy from `Z:\` |
| Collection | T1074.001 Local Data Staging | `Downloads\exfiltration\` folder |
| Collection | T1560.001 Archive Collected Data | `exfilt8me.zip` |
| Defense Evasion | T1070 Indicator Removal | `net use Z: /delete` |
| Exfiltration | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | Base64 chunks in DNS queries |

## Indicators of Compromise

| Type         | Indicator                                                            |
| ------------ | -------------------------------------------------------------------- |
| Sender       | `john@hatmakereurope.xyz`                                            |
| Attachment   | `ImportantInvoice-Febrary.zip` -> `invioce.pdf.lnk`                  |
| URL          | `raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1` |
| C2           | `2.tcp.ngrok.io:19282`                                               |
| Exfil domain | `haz4rdw4re.io`                                                      |
| Files        | `PowerView.ps1`, `exfilt8me.zip`, `Downloads\exfiltration\`          |

## Key Splunk Queries

Full host timeline (this query surfaced the whole attack):

```spl
index=* host.name="win-3450"
| table timestamp event.code process.name process.parent.name process.command_line file.path dns.question.name
| sort timestamp
```

Baseline a "suspicious" parent-child pair across the environment:

```spl
index=* process.name="taskhostw.exe"
| stats count, values(host.name) as hosts by process.parent.name, process.command_line, process.working_directory
```

Check a user's full inbox for related emails:

```spl
index=* datasource=email recipient="michael.ascot@tryhatme.com"
| table timestamp sender recipient subject attachment
```

Check whether attacker indicators spread to other hosts:

```spl
index=* "PowerView" OR "ngrok" OR "powercat"
| stats count by host.name
```

## Decoding the DNS Exfiltration

Each `nslookup` subdomain was a 30-character slice of one Base64 string. Decoding chunks in CyberChef confirmed what was stolen:

- `UEsDBBQ...` -> `PK`, the ZIP file signature
- `...Q2xpZW50UG9ydGZvbGlv...` + `U3VtbWFyeS54bHN4...` -> `ClientPortfolio` + `Summary.xlsx`
- `...ludmVzdG9yUHJlc2Vu` + `dGF0aW9uMjAyMy5wcHR4...` -> `InvestorPresen` + `tation2023.pptx`

Because 30 isn't a multiple of 4, some chunks don't start on a Base64 boundary. Trimming 1-3 leading characters made them readable.

## Triage Notes on False Positives

- **taskhostw.exe** `KEYROAMING` **/** `NGCKeyPregen` from svchost.exe: built-in scheduled tasks.
- **rdpclip.exe** from svchost.exe: RDP clipboard monitor, launched at the start of any RDP session.
- **WUDFHost.exe** from services.exe: User-Mode Driver Framework host.
- **TrustedInstaller.exe** from services.exe in `C:\Windows\servicing\`: Windows Modules Installer.
- **svchost.exe -k wsappx** from services.exe: services.exe is the *expected* parent of every svchost.
- **External-domain emails:** hat-themed spam with no attachments or links. The handover notes warned about "Hat of the Month" campaign noise, and the real phishing email used a hat-themed domain to hide in it.

---

## What I Did Well

- **100% true positive rate.** Every malicious alert was identified and escalated.
- **Reconstructed the full attack chain** from email delivery to DNS exfiltration by pivoting from the host timeline rather than working alerts in isolation.
- **Proved what was stolen** by decoding the Base64 DNS subdomains back to the exfiltrated filenames.
- **Baselined benign alerts in Splunk** (same behavior across hosts, recurring tasks) instead of closing them on assumption.
- **Consistent, self-contained reports** using the 5 Ws, with related alerts cross-referenced. The simulator's feedback called them exceptionally well-structured.

## What I Need to Improve

- **4 benign alerts escalated as TPs** (1000, 1001, 1003, 1006). Early in the run, before I had a baseline, I leaned toward escalating. For 1006, I changed the verdict after the host was later compromised, but the rdpclip activity itself was still legitimate. The handover note asks to *update the report* with the incident link, not to flip the verdict.
- **Slow on early alerts.** The first few took 8-10 minutes each, compared with under 5 minutes once I had a rhythm. Most of that time went to repeating the same Splunk checks.
- **Phishing alerts took longer to close** than process alerts.
- **Header fields in my first report** didn't match the structure I used in later reports.

## Plan for Next Run

- Judge each alert on **its own evidence**. A host being compromised later doesn't make earlier benign activity malicious.
- Run a quick **environment baseline in the first few minutes** (common parent-child pairs, email senders) so early benign alerts close quickly.
- Use a **fixed email checklist**: attachment? link? sender impersonation? urgency or financial lure? Zero hits means spam, not phishing.
- Keep a **report template ready** with consistent header fields from alert one.