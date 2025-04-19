# Scenario 1: Web site defacement 

Web site defacement
Today is Alice's first day at the Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprises' IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.



|info|link|
|---------------|--------------|
|Splunk server:|https://gettingstarted.splunk.show|
|Credentials:|user001-splk , Splunk.5|
|Bots v1 sourcetype summary:|https://botscontent.netlify.app/v1/bots_sourcetypes.html|
|Splunk quick reference guide:|https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf|
|Gcpd poison ivy memo:|https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html|
|Alices journal:|https://botscontent.netlify.app/v1/alice-journal.html|
|Mission document:|https://botscontent.netlify.app/v1/mission_document.html|

Source from: Sysmon, windows events, windows registry, IIS, Splunk Stream (wire data), Suricata, Fortigate

## Question 1:
What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?


## Question 2 :
What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.


## Queston 3: 
What content management system is imreallynotbatman.com likely using?



## Question 4:
What is the name of the file that defaced the imreallynotbatman.com website?(Come to this question after finding password and parentprocess in further questions)

## Question 5:
This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

## Question 6:
What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

## Question 7:
What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

## Question 8:
What is the name of the executable uploaded by Po1s0n1vy?

## Question 9:
What is the MD5 hash of the executable uploaded?

## Question 10:
GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

## Question 11:
What special hex code is associated with the customized malware discussed in question 10?

## Question 12:
What was the first brute force password used?

## Question 13:
One of the passwords in the brute force attack is James Brodsky’s favorite Coldplay song. We are looking for a six character word on this one. Which is it?

## Question 14:
What was the correct password for admin access to the content management system running “imreallynotbatman.com”?

## Question 15:
What was the average password length used in the password brute forcing attempt?

## Question 16:
How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

## Question 17:
How many unique passwords were attempted in the brute force attempt?

# Scenario 2: Ransomware

After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...

Ransomware screen shot: https://botscontent.netlify.app/v1/cerber-sshot.png

Ransomware warning: https://botscontent.netlify.app/v1/cerber-sample-voice.mp3

Bots v1 sourcetype summary: https://botscontent.netlify.app/v1/bots_sourcetypes.html

Splunk quick reference guide: https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf

Alices journal: https://botscontent.netlify.app/v1/alice-journal.html

Mission document: https://botscontent.netlify.app/v1/mission_document.html


## Question 1:
What was the most likely IPv4 address of we8105desk on 24AUG2016?

## Question 2:
Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times?

## Question 3: 
What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

## Question 4:
What was the first suspicious domain visited by we8105desk on 24AUG2016?

## Question 5:
During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

## Question 6:
What is the name of the USB key inserted by Bob Smith?

## Question 7: 
Bob Smith’s workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

## Question 8:
How many distinct PDFs did the ransomware encrypt on the remote file server?

## Question 9: 
The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

## Question 10: 
The Cerber ransomware encrypts files located in Bob Smith’s Windows profile. How many .txt files does it encrypt?

## Question 11:
The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

## Question 12:
Now that you know the name of the ransomware’s encryptor file, what obfuscation technique does it likely use?

