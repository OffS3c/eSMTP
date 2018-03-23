# eSMTP
A multithreadded tool to enumerate SMTP User/OS information from SMTP Servers

D:\ArchivalStorage\OSCP\pwk-labs>python eSMTP.py

[!] eSMTP   : A multithreadded tool to enumerate SMTP User/OS information from SMTP Servers (version 1.0b)
[A] Author  : OffS3c (https://offs3c.com)
[C] Company : Glaxosoft (https://glaxosoft.com)

[-] atleast 1 target is required

+------+------------+------------+------+-------------+
| Host | Connection | Is Windows | User | User Exists |
+------+------------+------------+------+-------------+
+------+------------+------------+------+-------------+

D:\ArchivalStorage\OSCP\pwk-labs>

# Usage
D:\ArchivalStorage\OSCP\pwk-labs>python eSMTP.py -h
usage: eSMTP.py [-h] [-b] [-U USERS] [-u USER] [-T TARGETS] [-t TARGET]
                [--threads THREADS] [--timeout TIMEOUT] [-d]

You need to provide some arguments for me to work

optional arguments:
  -h, --help            show this help message and exit
  -b, --banner          don't print banner
  -U USERS, --users USERS
                        path to the file containing target user(s) to test
  -u USER, --user USER  target user to test
  -T TARGETS, --targets TARGETS
                        path to the file containing target IP(s) to test
  -t TARGET, --target TARGET
                        target user to test
  --threads THREADS     threads or max connections at a time ( Default:1,
                        Max:50 )
  --timeout TIMEOUT     connection timeout in seconds ( Default:30, Max:240 )
  -d, --debug           be very very verbose

D:\ArchivalStorage\OSCP\pwk-labs>

# Tests

D:\ArchivalStorage\OSCP\pwk-labs>python eSMTP.py -d -U all-users.txt -T IPs.txt --timeout 15 --threads 10

+--------------+------------+------------+--------------+-------------+
|      Host    | Connection | Is Windows |     User     | User Exists |
+--------------+------------+------------+--------------+-------------+
|  13.15.01.22 | Successful |    Yes     |    AhmEd     |      No     |
|  13.16.10.72 | Successful |   Maybe    |    BOruY     |      Yes    |
+--------------+------------+------------+--------------+-------------+

D:\ArchivalStorage\OSCP\pwk-labs>
