
# SOC Engineer Technical Assessment Report

## Candidate: Sayeh Horiat
## Role: SOC Engineer
## Date: Jul 10, 2025

---

## 📂 Exercise 1: Email Forensics

### ✅ Task 1 – Basic Statistics
Using KQL queries over the provided `EmailEvents` and `UrlClickEvents` tables, I determined the following:

- **Number of emails:**  
  - The dataset contained **10,000 total email records** for January 1, 2024.

- **Recipients:**  
  - Emails were delivered to **3,774 unique recipients**, reflecting typical enterprise communication patterns.

- **Delivery locations:**  
  - Approximately **67% of emails were delivered directly to user Inbox folders**,  
  - while **33% were routed via on-premises or external paths**, consistent with hybrid mail infrastructures.

- **Delivery direction:**  
  - **34% inbound from external senders**,  
  - **33% outbound**,  
  - and **33% intra-organizational** traffic.

- **Attachment frequency:**  
  - Roughly **10% of emails contained attachments**, highlighting the importance of robust attachment scanning.
  - Attachment frequency matters because attachments are a primary malware delivery channel. By measuring this, we can prioritize detection and isolate likely compromise vectors. In this dataset, about 10% of emails carried attachments, underscoring the need for strong attachment controls.

- **Delivery actions:**  
  - Notably, **100% of emails were successfully delivered**, with no quarantined or blocked messages, suggesting the dataset was curated for hunting exercises on delivered traffic.

To prepare for deeper analysis, I combined `EmailEvents` with `UrlClickEvents` on `NetworkMessageId`, enabling correlation of delivered emails with any subsequent user link engagement.

---

### ✅ Task 2 – Investigation: How John Doe’s Machine Was Compromised
- On **Jan 1, 2024 at 4:10:42 PM**, John Doe received an email from `peter.white@wheelsanddeals24.com` with the subject **“Urgent: Security update”**, containing a malicious attachment. This was delivered directly to his **Inbox**.

- No `UrlClickEvents` were found for John, indicating the compromise resulted from **opening the attachment**, not from clicking a link.

#### 🔍 Retracing the attacker’s steps:
- The initial infiltration appears to have been achieved through the **compromise or spoofing of `peter.white@wheelsanddeals24.com`**, supported by the fact that emails from this address originated from **external public IPs (80.246.32.33 and 173.200.250.189)** — highly unusual for an internal sender.
- Once the attacker controlled or impersonated Peter’s account, they **launched a targeted phishing campaign by sending emails with malicious file attachments** to multiple recipients both inside the company and to external partners.
- The infection occurred when John Doe **opened the attachment, executing the malware**. This conclusion is reinforced by the absence of any related `UrlClickEvents` tied to John.

#### 🔎 Interpretation:
This represents a classic attack pattern involving **account compromise or spoofing**, followed by lateral movement via trusted internal identities to distribute malware through attachments. It underscores the critical need for:
- Monitoring sender IP anomalies,
- Strong attachment filtering and sandboxing,
- And heightened user awareness, especially around executable files appearing to come from known colleagues.

#### 🔬 Investigative methodology:
- I joined `EmailEvents` and `UrlClickEvents` on `NetworkMessageId` to correlate which emails resulted in link clicks. For example, I specifically queried all emails received by John Doe and joined with his URL clicks to confirm no engagement with embedded links. I also correlated all emails sent by `peter.white@wheelsanddeals24.com` to see if any recipients clicked links, helping assess broader campaign exposure.

---

### ✅ Task 3 – Secondary Malicious Activities
- `peter.white@wheelsanddeals24.com` also sent emails with attachments to at least two other recipients:
  - `zachary.carter@wheelsanddeals24.com`
  - `turnerjulia@king-hays.info` (external partner)

- I examined the `AdditionalFields` metadata to identify the attachment type sent by Peter, but the dataset lacked this information.

#### 🔍 How I validated no evidence of further compromise:
- **No subsequent suspicious emails:**  
  I ran KQL queries to identify all users who received attachments from `peter.white@wheelsanddeals24.com` and checked whether they sent any emails immediately afterward. The results confirmed **none of these recipients sent out emails shortly after receiving Peter’s message**, reducing the likelihood that they opened the malicious file and became secondary distribution points.

#### 🔎 Interpretation:
While these users were targeted by the same malicious campaign, no evidence was found to suggest their machines were compromised by executing the attachments. This highlights the **potential blast radius**, emphasizing the need for endpoint scans and close monitoring.

#### 🌐 Extended investigation with threat intelligence platforms:
As part of further enrichment, I submitted the suspicious external sender IP addresses (`80.246.32.33` and `173.200.250.189`) to **VirusTotal** and **AbuseIPDB** to determine if these IPs had prior malicious flags. The checks confirmed that IP `80.246.32.33` had been reported a total of 1 time from 1 distinct source, most recently about a month ago.

---

## 🚀 Additional Highlights
✅ **Anomalous sender behavior:** burst of attachments from Peter White on the same day.  
✅ **Strong timeline correlation:** aligns precisely with the infection event on John Doe’s machine.  
✅ **External IPs:** confirm the malicious emails originated from outside the corporate network.  
✅ **No evidence of multi-workload compromise:** investigation confirmed no suspicious activity in other workloads (e.g. Teams, SharePoint); threat remained contained to **Exchange (email)**.

---

## 🛡️ Microsoft Defender for Endpoint Hunting Schema
This investigation directly aligns with Defender’s advanced hunting schema:
- `EmailEvents`: for phishing and delivery analysis,
- `UrlClickEvents`: for engagement detection.

In a full SOC investigation, this would be extended with `DeviceFileEvents`, `ProcessCreationEvents`, and `DeviceNetworkEvents` to track malware execution and potential C2 communications.

---

## 📝 Conclusion
The investigation determined that John Doe’s machine was compromised by opening a malicious attachment sent via an internal-looking sender account that originated from **external IP addresses**, indicating either account compromise or external spoofing. Other recipients were also targeted, warranting endpoint scans and broader proactive hunting to ensure containment.

---


