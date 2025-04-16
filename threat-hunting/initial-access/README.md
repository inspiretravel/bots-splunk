OSINT look for src_ip
Hunting an APT with Splunk - Initial Access

Hunting an APT with Splunk is a hands-on workshop designed to provide a deeper dive into a "fictional nation-state" Advanced Persistent Threat. This workshop leverages Splunk and Enterprise Security and uses the Lockheed Martin Kill Chain and MITRE ATT&CK to contextualize a hunt. Initial access of the victim's system is the primary focus in this workshop. All hunts in this workshop series leverage the popular Boss of the SOC (BOTS) dataset. Users will leave with a better understanding of how Splunk can be used to hunt for threats within their enterprise.


Access the Splunk Server to answer questions throughout this workshop, using the below shown server and credentials:

SplunkServer: https://apthunting.splunk.show

User ID: user001-splk

Password: Splunk.5

<h2>Notes:</h2>

metadata command

| metadata type=sourcetypes index=botsv2
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| eval recentTime=strftime(recentTime,"%Y-%m-%d %H:%M:%S")
| sort - totalCount

project create time and last seen time

Menu: 

Apps > Enterprise Security > Security Domains > Identoty > Asset Center (show dashboard)

Apps >Frothly Environment (show the network diagram)

<h1>T1566.001 Phishing - spearphishing attachment</h1>

Look for mail traffic attack

index=botsv2 sourcetype=stream:smtp attach_filename {}=invoie.zip

Find additional info about the phish: Originating sender, sneder name, receipients, attachment name, size, date/time, body, subject, others

Look for attach_type{}

Use OSINT look for src_ip location and use whi is searching the sender address

<h2>Common sender investigation</h2>

index=botsv2 sourcetype=stream:smtp sender="Jim Smith <jsmith@urinalysis.com>"
|table +time receipient subject attach_filename{} attach_size{} attach_content_decoded_md5_hash{}


Copy base64 filehas to cyberchef

Comparing emails content:
index=botsv2 sourcetype=stream: smtp snder="Jim Smith <jsmith@urinalysis.com>"
|table _time receipient subject content_body{}
|sort receipient

Look for attachment hash value

input has file into virusTotal

<h2>lesson learn</h2>
Identify receipients received emails from same sender, Identical Metadata in both attacks, sent from a commercial service, OSINT did not provide additional corroboration

Recommedation: Apply watchlisting of domain to monitor, apply alerting to sender IP, automate analysis of hash values, develop analytics to alert on attachment

<h1>T1204.0021 User Execution: Malicious file</h1>

Check any execution action:

index=botsv2 invoice.zip sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"

Additional Events after Execution

Use time picker to narrow down the event

index=botsv2 invoice.zip sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" | reverse

Use cyberchef decode the powershell/file hash code

<h2>lesson learn</h2>

User did have encoded powershell code after opening the attachment from spearphishing email

Recommedation: Prohibit use of macro file, monitor their execution, apply EDR solution to analyze and log and block the execution, Alert when sysmon or windows events code 4688 appears with powershell running




