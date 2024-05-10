https://redsiege.com/tools-techniques/2020/10/detecting-kerberoasting/

Kerberos Authentication:

Client
   |
   | AS_REQ : The client requests an authentication ticket from the Authentication Server.
   v
Authentication Server (AS)
   |
   | AS_REP : The Authentication Server replies with a Ticket Granting Ticket (TGT)
   v
Client
   |
   | TGS_REQ : The client requests a service ticket from the Ticket Granting Server using the TGT.
   v
Ticket Granting Server (TGS)
   |
   | TGS_REP : The Ticket Granting Server replies with a service ticket
   v
Client
   |
   | AP_REQ : The client requests access to the service from the Service Server using the service ticket
   v
Service Server (SS)
   |
   | AP_REP (optional) : The Service Server replies to the client, confirming the service (this step is optional and is used for mutual authentication).
   v
Client

Certainly! Here's a detailed explanation of the Kerberos authentication process, including the encryption and decryption details for each step:

1. **AS_REQ (Authentication Service Request)**:
   - **Client** sends a plaintext message to the **Authentication Server (AS)** containing the user's ID and the ID of the requested service.
   - **Encryption**: None at this stage.

2. **AS_REP (Authentication Service Reply)**:
   - **AS** verifies the user's ID in the Kerberos database and creates a **Ticket Granting Ticket (TGT)**, which includes the client ID, client network address, ticket validity period, and the client/TGS session key.
   - **TGT** is encrypted using the **TGS's secret key**.
   - **AS** also sends a separate message to the client containing the client/TGS session key, encrypted with the client's secret key (derived from the user's password).
   - **Encryption**: TGT with TGS's secret key, session key with client's secret key.
   - **Decryption**: Client uses its secret key to decrypt the session key.

3. **TGS_REQ (Ticket Granting Service Request)**:
   - **Client** sends a new request to the **Ticket Granting Server (TGS)**, including the encrypted **TGT** received from the AS and an **Authenticator**, which contains the client ID and timestamp, encrypted with the client/TGS session key.
   - **Encryption**: Authenticator with client/TGS session key.
   - **Decryption**: TGS decrypts TGT with its secret key and Authenticator with the session key.

4. **TGS_REP (Ticket Granting Service Reply)**:
   - **TGS** verifies the Authenticator and TGT, creates a **Service Ticket (ST)**, which includes the client ID, client network address, validity period, and the client/SS session key.
   - **ST** is encrypted using the **service's secret key**.
   - **TGS** sends the ST and a new session key for the client and service to use, encrypted with the client/TGS session key.
   - **Encryption**: ST with service's secret key, session key with client/TGS session key.
   - **Decryption**: Client uses the client/TGS session key to decrypt the new session key.

5. **AP_REQ (Application Request)**:
   - **Client** sends the **ST** and a new **Authenticator** to the **Service Server (SS)**, which includes the client ID and timestamp, encrypted with the client/SS session key.
   - **Encryption**: Authenticator with client/SS session key.
   - **Decryption**: SS decrypts ST with its secret key and Authenticator with the session key.

6. **AP_REP (Application Reply)** (optional):
   - **SS** may send a message back to the client, encrypted with the client/SS session key, to confirm its identity and establish mutual authentication.
   - **Encryption**: Message with client/SS session key.
   - **Decryption**: Client uses the client/SS session key to decrypt the message.

This process ensures that sensitive information, such as passwords, is never sent over the network in plaintext. Instead, Kerberos relies on symmetric key cryptography and the use of secret keys known only to the AS, TGS, and SS to protect the authentication process¹²³⁴⁵.

Please note that the actual Kerberos protocol is more complex and includes additional steps and measures to prevent replay attacks and ensure the integrity and confidentiality of the exchanges. The explanation provided here focuses on the main transactions and the use of encryption and decryption at each step.


_____________________________________________________________________________________________________________________________________________________________________________________________________________
KERBEROASTING:
A **Kerberoasting attack** is a type of cyber attack that targets the Kerberos authentication protocol, which is commonly used in Windows networks. The attack is designed to extract service account credentials from Active Directory. Here's what you need to know to understand the attack:

1. **Service Principal Name (SPN)**: An SPN is an identifier given to a service instance to associate it with a service account. Kerberos uses SPNs to associate a service instance with a service account in Active Directory.

2. **Kerberos Tickets**: These are encrypted tickets used by Kerberos for authenticating users and services. They contain a variety of information, including a timestamp and the user's group memberships.

3. **Ticket Granting Service (TGS)**: Part of the Kerberos Key Distribution Center (KDC) that issues service tickets after initial authentication.

4. **Encryption**: Kerberos tickets are encrypted with the hash of the service account's password.

The **step-by-step procedure** of a Kerberoasting attack is as follows:

1. An attacker compromises a domain user account.
2. Using the compromised account, the attacker requests a Kerberos service ticket for a service associated with an SPN.
3. The KDC issues a service ticket, which is encrypted with the hash of the service account's password.
4. The attacker captures this ticket and takes it offline.
5. The attacker then uses brute force or other techniques to crack the password hash.
6. Once the password is obtained, the attacker can impersonate the service account and access resources or escalate privileges².

**Detection** by a SOC analyst involves:

Here are the details to look for in Event ID 4769 to spot a potential Kerberoasting attack:

- **Service Name (SPN)**: The service name should be validated to ensure it's not being abused to request service tickets for Kerberoasting.
- **Ticket Encryption Type**: Kerberoasting often involves requesting tickets encrypted with the RC4 algorithm, which corresponds to an encryption type of **0x17**.
- **Ticket Options**: Certain flags in the ticket options field can indicate a Kerberoasting attempt, such as **0x40810000**.
- **Client IP**: The source IP address from where the ticket request is made can be investigated for suspicious activity.

SOC analysts should also consider setting up alerts for multiple service ticket requests within a short time frame, especially if they are for different services. This could indicate an attacker is trying to request multiple service tickets for offline cracking.

Additionally, implementing account lockout policies, monitoring for unusual login times, and analyzing login locations can help in detecting potential attacks. Regularly reviewing and updating service account passwords with complex, hard-to-crack passwords will also reduce the risk of successful Kerberoasting attack. If you need further assistance or have more questions, feel free to ask!

_____________________________________________________________________________________________________________________________________________________________________________________________________________

SILVER TICKET

A **Silver Ticket attack** is a type of cybersecurity threat that exploits the Kerberos authentication protocol, specifically targeting service accounts within an Active Directory environment. Here's a detailed explanation of the attack and how it can be detected:

### Understanding Silver Ticket Attack
- **Service Principal Name (SPN)**: An SPN is a unique identifier for a service instance on a network, linked to a service account in Active Directory.
- **Kerberos Tickets**: These are encrypted tickets issued by the Key Distribution Center (KDC) to authenticate users and services.
- **Ticket Granting Service (TGS)**: A component of the KDC that issues service tickets after a user is initially authenticated.

Certainly, let me clarify the steps involved in a Silver Ticket attack:

[Attacker] --(Gathers Information)--> [Domain SID & Service DNS Name]
[Attacker] --(Obtains NTLM Hash)--> [Service Account]
[Attacker] --(Extracts Password)--> [NTLM Hash]
[Attacker] --(Forges TGS)--> [Silver Ticket]
[Attacker] --(Exploits Service)--> [Targeted Service]
[Attacker] --(Maintains Access)--> [Compromised Service]
[Attacker] --(Covers Tracks)--> [Log Manipulation]

1. **Information Gathering**:
   - The attacker identifies the target domain and the specific local service they intend to compromise.
   - They gather the domain security identifier (SID) and the DNS name of the service¹.

2. **NTLM Hash Acquisition**:
   - Using tools like Mimikatz, the attacker obtains the NTLM hash (password hash) of the service account associated with the service they want to access¹.

3. **Password Extraction**:
   - The attacker uses techniques such as Kerberoasting to extract the unencrypted password from the NTLM hash¹.

4. **Ticket Forgery**:
   - With the unencrypted password, the attacker forges a Kerberos Ticket Granting Service (TGS) ticket, also known as a Silver Ticket.
   - This forged ticket allows the attacker to authenticate as if they were the targeted service¹.

5. **Exploitation**:
   - The attacker uses the forged Silver Ticket to access resources, elevate privileges, or move laterally within the network¹.
   - They can execute code as the targeted local system, potentially leading to further system compromise or financial gain¹.

The Silver Ticket attack is particularly dangerous because it allows the attacker to maintain persistence in the network by continually generating valid service tickets without the need for further authentication. It's crucial for security teams to monitor for signs of such attacks and to implement strong security measures to protect against them. I


### Detection and SOC Analysis
SOC analysts can detect Silver Ticket attacks by monitoring specific event IDs in the Windows Event Log:
- **Event ID 4769**: Indicates a Kerberos service ticket was requested. Look for new or unusual usernames and service ticket requests with RC4 encryption (encryption type 0x17)⁴.
- **Event ID 4624, 4634, 4672**: Monitor for logon/logoff events with malformed or blank fields, which could indicate manipulation⁶.
- **Event ID 4770**: Serves as an indicator of a Kerberos ticket renewal, which could be suspicious if occurring frequently or in unusual patterns.

SOC analysts should also:
- **Monitor LSASS**: Watch for unexpected processes interacting with the Local Security Authority Subsystem Service (LSASS), which handles password changes and Kerberos ticket generation⁴.
- **Correlation Rules**: Create rules to match suspicious patterns, such as RC4 encryption combined with frequent logins or new usernames⁴.

### Preventive Measures
- **Strong Passwords**: Ensure that service accounts use strong, unique passwords to resist offline cracking attempts.
- **Least Privilege**: Implement a least-privilege model to restrict user and domain administrator access.
- **Kerberos Configuration**: Use AES encryption for Kerberos where possible and enable Privilege Attribute Certificate (PAC) validation⁴.

_____________________________________________________________________________________________________________________________________________________________________________________________________________


### Golden Ticket Attack

A **Golden Ticket attack** is a type of cybersecurity threat that targets the Kerberos authentication protocol used within Windows Active Directory environments. The attack allows a threat actor to gain almost unlimited access to an organization's domain, including devices, files, and domain controllers¹. Here's how the attack works and how it can be detected:

### Golden Ticket Attack

The **Golden Ticket attack** is a sophisticated and severe security threat that targets the Kerberos authentication protocol within Windows Active Directory environments. Here's an expanded step-by-step explanation of how the attack is performed:

[Attacker] --(Initial Access)--> [Domain Controller]
[Attacker] --(Domain Information)--> [Domain SID]
[Attacker] --(KRBTGT Account Compromise)--> [KRBTGT Hash]
[Attacker] --(Extraction of KRBTGT Hash)--> [Mimikatz]
[Attacker] --(Golden Ticket Creation)--> [Forged TGT]
[Attacker] --(Exploitation)--> [Domain Resources]
[Attacker] --(Maintaining Persistence)--> [Network]
[Attacker] --(Covering Tracks)--> [Log Manipulation]


1. **Initial Access**:
   - The attacker first needs to gain administrative privileges on the network, often by compromising a domain administrator's credentials. This can be achieved through various means, such as phishing, exploiting vulnerabilities, or using malware¹.

2. **KRBTGT Account Compromise**:
   - The KRBTGT account in Active Directory is a service account that issues and signs all Ticket Granting Tickets (TGTs) within the domain. The attacker targets this account to obtain its NTLM hash, which is the encrypted version of the account's password².

3. **Extraction of KRBTGT Hash**:
   - With administrative access to a domain controller, the attacker uses tools like Mimikatz to extract the NTLM hash of the KRBTGT account. This step is crucial as the hash is used to create the Golden Ticket².

4. **Golden Ticket Creation**:
   - Using the extracted NTLM hash, the attacker creates a Golden Ticket. This ticket is a forged TGT that provides authentication as any user within the domain. The Golden Ticket is crafted to have extensive privileges and a long validity period, often set to the maximum allowed by the system².

5. **Exploitation**:
   - With the Golden Ticket, the attacker can access resources across the domain without the need for further authentication. They can create new accounts, modify existing accounts, access confidential data, and move laterally within the network¹.

6. **Maintaining Persistence**:
   - The Golden Ticket allows the attacker to maintain persistence within the network, as it can be used to authenticate even if the original compromised credentials are changed or if the user accounts are disabled¹.

7. **Covering Tracks**:
   - Attackers using a Golden Ticket can often cover their tracks by manipulating logs or using the ticket discreetly to avoid detection¹.

#### Detection and Mitigation

Detecting a Golden Ticket attack involves monitoring for anomalies in Kerberos ticket usage, such as tickets with unusually long lifetimes or tickets granting access to high-value targets without corresponding authentication events. Security teams should also look for signs of lateral movement or privilege escalation that do not align with typical user behavior.

To mitigate the risk of a Golden Ticket attack, organizations should:
- Regularly change the KRBTGT account password, which requires two changes to fully invalidate existing tickets.
- Implement strict access controls and monitor administrative accounts for unusual activity.
- Use advanced threat detection systems that can identify irregular patterns in Kerberos ticket usage¹².


#### Detection and SOC Analysis
SOC analysts can detect Golden Ticket attacks by monitoring specific event IDs in the Windows Event Log:
- **Event ID 4769**: Indicates a Kerberos service ticket was requested. Look for anomalies such as encryption types or ticket options that are unusual for your environment⁵.
- **Event ID 4674 & 4688**: These events may lack details like origin IP addresses but can provide account names for further investigation⁷.
- **Event ID 4771**: Failed Kerberos pre-authentication events can sometimes indicate brute force attacks on the KRBTGT account⁵.

Analysts should also look for:
- **Anomalous Ticket Lifetimes**: Tickets with unusually long lifetimes could indicate a Golden Ticket.
- **Irregular Access Patterns**: Access to resources that do not align with the normal behavior of the user or service account.
- **Encryption Key Types**: Verify that the encryption key type used on a Kerberos ticket does not utilize the insecure RC4 algorithm, which could indicate a Golden Ticket attack⁹.




