
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

<h2>T1566.001 Phishing - spearphishing attachment</h2>

Look for mail traffic attack

index=botsv2 sourcetype=stream:smtp attach_filename {}=invoie.zip

Find additional info about the phish: Originating sender, sneder name, receipients, attachment name, size, date/time, body, subject, others

Look for attach_type{}






