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

## Question 101:
What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

First come to our mind, sorucetype is highly assocatied with http. We can start to narrow down the data.
```
index=botsv1 imreallynotbatman.com sourcetype="stream:http"
```

Look for interesting fields > source ip or dest ip. Find one field called c_ip that look like what we can answer this question.
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q100%20.jpg?raw=true)

Ans: 40.80.148.42

## Question 102 :
What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

This question is asked for the scanner. See to input the wildcard with scan for getting some hints. 

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http" c_ip="40.80.148.42" "*scan*"
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q102.jpg?raw=true)

Look at the dest_header. We found the hint related to joomla. Keep looking down the data. Here it goes. It captures the scanner info.

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q102a.jpg?raw=true)

Ans: Acunetix

## Queston 103: 
What content management system is imreallynotbatman.com likely using?

Based on previous question, we know the joomla is one of CMS system.

Ans: joomla

## Question 104:
What is the name of the file that defaced the imreallynotbatman.com website?(Come to this question after finding password and parentprocess in further questions)

After solving Q108, go back this question. Look at firewall data and think Defaced may relate to some sort of image file. Got stuck for 20 mins. Removed the search keyword imreallynotbatman. 

```
index=botsv1 sourcetype="fgt_utm" NOT dest=192.168.250.70
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q104.jpg?raw=true)

There is category field and click on Malicious Websites. Find one particular file

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q104a.jpg?raw=true)

Ans: Poisonivy-is-coming-for-you-batman.jpeg

## Question 105:
This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

Look at Q104 URL file path. prankglassinebracket.jumpingcrab.com is the domain of this attack.

Ans: Prankglassinebracket.jumpingcrab.com

## Question 106:
What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

Look for something in http log if people attack using malware file from malicious IP
```
index=botsv1 imreallynotbatman.com dest_ip=192.168.250.70 sourcetype=stream:http http_method=POST
```

There is 2 src IP address. Look at another one. 

The question is identify the attack from Po1s0n1vy.

Term: Po1s0n1vy is an Advanced Persistent Threat (APT) group identified for targeting organizations with custom malware and spear phishing tactics, often involving initial compromise through emails with malicious attachments. The group has been associated with specific TTPs (Tactics, Techniques, Procedures) and infrastructure

Got the hints from request field using POST involving email.
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q106.jpg?raw=true)

Ans: 23.22.63.114

## Question 108:
What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

Browse around and look for some clues. 
```
index=botsv1 imreallynotbatman.com dest_ip="192.168.250.70" sourcetype="stream:http"
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q107.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q107a.jpg?raw=true)

There is source IP 40.80.148.42 outside the company. Look supicious but seem no luck. Think about the http method for entering userid and password.

```
index=botsv1 imreallynotbatman.com dest_ip="192.168.250.70" sourcetype="stream:http" http_method=POST
```

Drill down more. Form_date field shows us this IP address 23.22.63.114 doing some logon transaction attempt 
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q107b.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/Q107b.jpg?raw=true)

Ans: 23.22.63.114

## Question 109:
What is the name of the executable uploaded by Po1s0n1vy?

THe source most likley coulkd capture tin IDS/IPS system for this type of attack. So, we can look for the soruce from suricata. 

Term: Suricata is a free and open-source network intrusion detection and prevention system (IDS/IPS) developed by the Open Information Security Foundation (OISF). It's used to identify, stop, and assess network threats. Suricata can also function as a network security monitoring (NSM) engine and analyze PCAP files

```
index=botsv1 sourcetype=suricata dest=imreallynotbatman.com http.http_method=POST
```

Look at the dest ip pointing to the local machine that capture many times
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/109.jpg?raw=true)

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/109a.jpg?raw=true)

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/109b.jpg?raw=true)

Eventually, found the 2 exe filenames. 3719.exe is the one. 

Ans: 3791.exe

## Question 110:
What is the MD5 hash of the executable uploaded?

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/110.jpg?raw=true)

```index=botsv1 "3791.exe" CommandLine=3791.exe```
Look at the field MD5 . And it should have commandline once this file is executed sorting out the MD5 value. The answer is AAE3F5A29935E6ABCC2C2754D12A9AF0.

## Question 111:
GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

Use the Q110 info to find the info in any.run, virus total and google. 
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/111.jpg?raw=true)

Ans: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

## Question 112:
What special hex code is associated with the customized malware discussed in question 111?
```
ans: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21
```

## Question 114:
What was the first brute force password used?

```
index=botsv1 imreallynotbatman.com dest_ip=192.168.250.70 sourcetype=stream:http http_method=POST form_data=*username*passwd* | table form_data
```
Use the rex function to extract the info from form_data field and sort it out by ascend sequence. 
```
index=botsv1 sourcetype=stream:http http_method=POST imreallynotbatman.com dest_ip=192.168.250.70 form_data=*username*passwd*
|rex field=form_data passwd=(?<Pass>\w+)
|table Pass src
|reverse
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/114.jpg?raw=true)

Answer: 12345678

## Question 115: need to be reviewed
One of the passwords in the brute force attack is James Brodsky’s favorite Coldplay song. We are looking for a six character word on this one. Which is it?

This is the most difficulty question for me. Found the query from the web but try to explain this query:

```
index=botsv1 sourcetype=”stream:http” http_method=POST form_data=”*username*passwd*”
|rex field=form_data “passwd=(?<Pass>\w+)”
|eval lenpword=len(Pass)
|search lenpword=6
|eval pass1=lower(Pass)
|lookup coldplay.csv song as pass OUTPUTNEW song
|search song=*
|table song
```
Ans: Yellow

## Question 116:
What was the correct password for admin access to the content management system running “imreallynotbatman.com”?

```
index=botsv1 sourcetype=stream:http http_method=POST form_data=*username*passwd*
|rex field=form_data passwd=(?<Pass>\w+)
|stats count values(src) by Pass
|sort — count desc
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/116.jpg?raw=true)

Ans: batman

## Question 117:
What was the average password length used in the password brute forcing attempt?

```
index=botsv1 sourcetype=stream:http http_method=POST form_data=*username*passwd*
|rex field=form_data passwd=(?<Pass>\w+)
|search Pass=*
|eval pwdlen=len(Pass)
|stats avg(pwdlen) as avg_len_http
|eval avg_len_http=round(avg_len_http,0)
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/117.jpg?raw=true)

Ans: 6


## Question 118:
How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

```
index=botsv1 sourcetype=stream:http 
|rex field=form_data passwd=(?<Pass>\w+)
|search Pass=batman
|transaction Pass
|table duration
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/118.jpg?raw=true)

Answer: 92.17

## Question 119:
How many unique passwords were attempted in the brute force attempt?
```
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
|rex field=form_data passwd=(?<Pass>\w+)
|stats dc(Pass)
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s1/119.jpg?raw=true)

Answer: 412

--------------------------------
# Scenario 2: Ransomware

After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...

Ransomware screen shot: https://botscontent.netlify.app/v1/cerber-sshot.png

Ransomware warning: https://botscontent.netlify.app/v1/cerber-sample-voice.mp3

Bots v1 sourcetype summary: https://botscontent.netlify.app/v1/bots_sourcetypes.html

Splunk quick reference guide: https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf

Alices journal: https://botscontent.netlify.app/v1/alice-journal.html

Mission document: https://botscontent.netlify.app/v1/mission_document.html


## Question 200:
What was the most likely IPv4 address of we8105desk on 24AUG2016?

Select the date range into 24AUG2016. Look for the winner.

```
index="botsv1" we8105desk | stats count by src_ip
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/200.jpg?raw=true)

Ans: 192.168.250.100

## Question 201:
Among the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times?

```
index=”botsv1" sourcetype=”suricata” *cerber* 
```
Get the hint from the field signautre id and keep looking.

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/202.jpg?raw=true)

Ans: 2816763

## Question 202: 
What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

domain info should capture into DNS data source.

```
index=botsv1 sourcetype=stream:dns src_ip=192.168.250.100
```

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/203.jpg?raw=true)
Search any suspicous domain.

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/203a.jpg?raw=true)

Ans: cerberhhyed5frqa.xmfir0.win


## Question 203:
What was the first suspicious domain visited by we8105desk on 24AUG2016?

```
index=botsv1 sourcetype=stream:dns src_ip=192.168.250.100 "query_type{}"=A  |table _time query{} | reverse
```
Look for the query info and use the reverse function in time to identify 

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/204.jpg?raw=true)

Ans: solidaritedeproximite.org

## Question 204:
During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

Ans: 4490

## Question 205:
What is the name of the USB key inserted by Bob Smith?

Go to google. Look for any USB key in windows registry.
```
index=botsv1 *USBSTOR* sourcetype=*regis*
```
find usbstor with reg_sz value . Let try it out.
```
index=botsv1 *USBSTOR* sourcetype=WinRegistry registry_value_type=REG_SZ *usbstor* | table key_path
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/205.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/205a.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/205b.jpg?raw=true)

friendly name

Ans: MIRANDA_PRI

## Question 206: 
Bob Smith’s workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

file server most likely five us the hint of SMB.

```
index=botsv1 sourcetype=stream:smb stc_ip=192.168.250.100
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/206.jpg?raw=true)

Click dest_ip, find the most count value

Ans: 192.168.250.20

## Question 207:
How many distinct PDFs did the ransomware encrypt on the remote file server?

Use windows log and pdf to narrow down our search.

```
index=botsv1 sourcetype=wineventlog* *.pdf
```

click host field. There is 2 values. we9041srv looks like as file server.
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/207.jpg?raw=true)

keep searching the fields. Relative_Target_name show all PDF value
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/207a.jpg?raw=true)

```
index=botsv1 sourcetype=wineventlog* *.pdf dest_nt_host="we9041srv.waynecorpinc.local" |table Relative_Target_Name
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/207b.jpg?raw=true)

Some value in Relative_Target_Name displays more than one. Therefore, use dedup to remove the extra one.
```
index=botsv1 sourcetype=wineventlog* *.pdf dest_nt_host="we9041srv.waynecorpinc.local" |table Relative_Target_Name | dedup Relative_Target_Name | stats count
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/207c.jpg?raw=true)

Look for the account name using by Bob
```
index=botsv1 sourcetype=wineventlog* *.pdf dest_nt_host="we9041srv.waynecorpinc.local" Account_Name="bob.smith" | table Relative_Target_Name | dedup Relative_Target_Name | stats count
```
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/207d.jpg?raw=true)
Answer: 257

## Question 208: 
The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

Look into sysmon log and input the tmp name and we know it triggered by command line. Then, sort it out from the beginning.
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/208.jpg?raw=true)

Ans: 3968

## Question 209: 
The Cerber ransomware encrypts files located in Bob Smith’s Windows profile. How many .txt files does it encrypt?

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/209.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/209a.jpg?raw=true)
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/209b.jpg?raw=true)

Ans: 406

## Question 210:
The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?


```
index=botsv1 sourcetype="stream:http" src_ip=192.168.250.100
```
Guess malware could connect somewhere. URL may be the fields to look for. 
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/210.jpg?raw=true)

In URL, one file /mhtr.jpg catch our eyes. Use suricata to reconfirm.

![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/210a.jpg?raw=true)

Ans: mhtr.jpg

## Question 211:
Now that you know the name of the ransomware’s encryptor file, what obfuscation technique does it likely use?


Search it in the internet
![Alt image](https://github.com/inspiretravel/bots-splunk/blob/main/BOTSv1/images_s2/211.jpg?raw=true)

Ans: steganography
