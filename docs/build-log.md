# Build Log

A running record of the problems I hit while building this lab and how I solved them.

## Environment decisions

| Decision | Why |
|---|---|
| Didn't run the lab on my school-issued laptop | It's a managed device. Attack-simulation tools could trigger the school's endpoint security alerts and would likely break the acceptable-use policy. |
| Didn't run a local VM on my MacBook Air | Apple M1 with 8 GB RAM and only ~7.6 GB free disk. A Windows VM needs 40–60 GB of disk, and 8 GB RAM would leave too little for macOS. |
| Built the lab in Azure (Azure for Students, $100 credit) | No local disk or RAM cost, x64 Windows (no ARM compatibility issues), and disk snapshots give me a rewind point. |
| Used Windows Server 2022 Datacenter instead of Windows 11 | Windows 11 images in Azure require confirming a license with multi-tenant hosting rights, which I don't have. Server 2022 includes its license and still ships all eight LOLBins I'm testing. |
| Added ARM64 support to the setup script anyway | While planning a local VM on Apple Silicon, I found Windows on ARM needs `Sysmon64a.exe` instead of `Sysmon64.exe`. The script now picks the right binary. |

## Problems and fixes

### Repo setup

**`git` not recognized on Windows**
- *Symptom:* `'git' is not recognized as an internal or external command`, even though `winget` said Git was already installed.
- *Cause:* Git was installed, but the open terminal had an old PATH that didn't include it.
- *Fix:* Confirmed the binary existed with `"C:\Program Files\Git\cmd\git.exe" --version`, then added it to PATH for the session with `set PATH=%PATH%;C:\Program Files\Git\cmd`. A reboot fixes it permanently.

**A stray file got committed**
- *Symptom:* The first commit included `.Rhistory`, an RStudio history file that has nothing to do with the project.
- *Fix:* `git rm --cached .Rhistory` and added it to `.gitignore`.
- *Lesson:* Review `git status` before the first commit.

### Azure VM deployment

**VM size not available**
- *Symptom:* `This size is currently unavailable in eastus for this subscription: NotAvailableForSubscription` for the default size (Standard_D2s_v3).
- *Cause:* Student subscriptions only get access to a limited set of VM sizes, which varies by region.

**Deployment blocked by policy**
- *Symptom:* Every resource (VM, NIC, NSG, public IP, VNet) failed with `RequestDisallowedByAzure`.
- *Cause:* Azure for Students applies a built-in "allowed regions" policy, and East US wasn't on it.
- *Fix:* Found the allowed list under **Policy → Assignments → Allowed resource deployment regions**: `norwayeast`, `belgiumcentral`, `canadacentral`, `westus`, `mexicocentral`.

**No usable sizes in Canada Central**
- Every size in the closest allowed region was unavailable for my subscription, so I moved on to the next region.

**Wrong region by one character**
- *Symptom:* `RequestDisallowedByAzure` again, this time on `vnet-westus2-1`.
- *Cause:* I selected **West US 2**, but the policy allows **West US** (`westus`). They're different regions next to each other in the dropdown.
- *Lesson:* Check the region code in the error message, not just the friendly name.

**Found a working combination**
- **Mexico Central + Standard_B2as_v2** (2 vCPU, 8 GB, ~$67/month if left on 24/7, about $0.09/hour).
- In the size picker, greyed-out sizes with an ⓘ icon were the unavailable ones.

**Auto-shutdown not supported in Mexico Central**
- *Fix:* Compensated with a $20 budget with email alerts at $5 and $10, the Azure mobile app to stop the VM remotely, and a habit of clicking **Stop** after every session.
- *Lesson:* Shutting down Windows from inside the VM does **not** stop billing. Only stopping from Azure deallocates the VM.

**OS disk deployed as Premium SSD**
- *Symptom:* The Disks page showed Premium SSD LRS even though I meant to choose Standard SSD.
- *Why it matters:* Disks are billed even while the VM is stopped, and Premium costs roughly twice as much.
- *Fix:* Stopped (deallocated) the VM, then changed the disk to Standard SSD under **Size + performance**.

**Accidental empty data disk**
- A blank "create and attach new disk" row appeared on the Disks page. I discarded it without saving.

### Lab tooling

**Sysmon config download returned 404**
- *Symptom:* `Invoke-WebRequest : 404: Not Found` when the setup script fetched `sysmonconfig.xml` from the sysmon-modular repo.
- *Cause:* The sysmon-modular project stopped storing its prebuilt configs in the repository and now publishes them as GitHub Release assets.
- *Fix:* Pointed the script at `https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml`.
- *Lesson:* Hardcoded URLs to third-party projects break. Pull from release assets, or pin a specific version.

**Atomic Red Team install looked frozen**
- *Symptom:* The setup script sat at "Installing Atomic Red Team" with no output.
- *Cause:* It was waiting on a NuGet provider prompt that hadn't rendered yet. A fresh Windows Server has no NuGet provider, and PowerShellGet needs it to pull modules from the PowerShell Gallery.
- *Fix:* Answered `Y`. The script now runs `Install-PackageProvider -Name NuGet -Force` up front, so the prompt never appears.
- *Lesson:* Unattended scripts on fresh machines need their dependencies installed explicitly. Silent progress output can hide an interactive prompt.

**Choosing which atomic tests to run**
- *Problem:* Each technique has many atomic tests (T1105 alone has 30+). Some test unrelated tools (curl, scp), some download real offensive tools (Mimikatz, BloodHound), and some wait for a password and would hang an unattended run.
- *Fix:* Rewrote `Run-Atomics.ps1` to run a hand-picked list of test numbers per technique, chosen to exercise the LOLBin behaviour each rule targets. I avoided tests that pull in third-party offensive tooling.

### Day-to-day operations

**RDP stopped working the next day (error 0x704)**
- *Symptom:* Windows App reported "Unable to connect", error code 0x704, even though the VM showed as Running in Azure.
- *Cause:* My public IP had changed since I locked the RDP rule to "My IP address", so the network security group was dropping my connection.
- *Fix:* Updated the RDP inbound rule's source to my current IP.
- *Lesson:* Restricting by source IP is a real security win, but it breaks whenever your IP changes. In production this is usually solved with a VPN, a bastion host (Azure Bastion), or just-in-time VM access instead of exposing RDP at all.

**VM size ended up as D2s_v4, not B2as_v2**
- The deployed VM is Standard_D2s_v4 (~$0.20/hour) instead of the cheaper B2as_v2 (~$0.09/hour) I'd planned. VM sizes can be changed after deployment, but only while the VM is stopped (deallocated).

### Hardening

- Restricted the RDP (3389) inbound rule to **my IP address only**, instead of the default "Any", right after deployment.
- Shared only a dedicated `lab-transfer` folder with the VM, not my whole repo or home folder.
- Took an incremental disk snapshot named `clean` as a restore point.
