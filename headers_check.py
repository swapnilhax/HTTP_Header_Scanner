#!/usr/bin python

import sys
import urllib2
import os
from colorama import Fore,Style


BLUE = '\33[94m'
LightBlue = '\033[94m'
RED = '\033[91m'
WHITE = '\33[97m'
YELLOW = '\33[93m'
GREEN = '\033[32m'
LightCyan    = "\033[96m"
END = '\033[0m'

if len(sys.argv) < 2:
    os.system("clear || cls")
    sys.stdout.write(RED + """  

_   _ _____ _____ ____    _   _                _           
| | | |_   _|_   _|  _ \  | | | | ___  __ _  __| | ___ _ __ 
| |_| | | |   | | | |_) | | |_| |/ _ \/ _` |/ _` |/ _ \ '__|
|  _  | | |   | | |  __/  |  _  |  __/ (_| | (_| |  __/ |   
|_| |_| |_|   |_| |_|     |_| |_|\___|\__,_|\__,_|\___|_|   
                                                            
 ____                                  
/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | (_| (_| | | | | | | |  __/ |   
|____/ \___\__,_|_| |_|_| |_|\___|_|   
                                       
                                                                                          
    """  + END+BLUE+'HTTP Header Vulnerability Scanner'.format(RED, END).center(69) +
    '\n' + '\tMade ^_^ by: {}Sw4pn1l'.format(YELLOW, RED, YELLOW, BLUE).center(76) +
    '\n' + '\tVersion: {}1.0{}\n'.format(YELLOW, END).center(80) + '\n')
else:
#    sys.exit('Usage: python headers_check.py')
    os.system("clear || cls")


if len(sys.argv) < 2:
#  print(Fore.RED + '\n\nHTTP Header Vulnerability Scanner Developed by Swapnil')
  print(Style.RESET_ALL)
  print('[+] Please provide a fully-qualified path!\n')
  print(Fore.YELLOW + '[+] Example: python filename.py http://www.google.com\n\n')
  print(Style.RESET_ALL)
 
  sys.exit()
else:
  response = urllib2.urlopen(sys.argv[1])
#  print(Fore.YELLOW + '\n\n[+] HTTP Header Vulnerability Scanner Developed by Swapnil')
#  print(Style.RESET_ALL)
  print('[+] HTTP Header Analysis for ' + sys.argv[1] + ':' + '\n\n')

# check x-xss-protection:
if response.info().getheader('x-xss-protection') == '1 mode=block':
  print(Fore.RED + 'NOT VULNERABLE')
  print(Style.RESET_ALL)
  print('(X-XSS-Protection) Cross-Site Scripting Protection is enforced.(NOT VULNERABLE)')
else:
   print(Fore.RED +'Vulnerability')
   print(Style.RESET_ALL)
   print('- Server does not enforce Cross-Site Scripting Protection.\nThe X-XSS-Protection Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting Attacks.\n\n')
  

# check x-frame-options:
if response.info().getheader('x-frame-options') == 'deny' or 'sameorigin':
  print(Fore.RED + 'NOT VULNERABLE')
  print(Style.RESET_ALL)
  print('(X-Frame-Options) Cross-Frame Scripting Protection is enforced. [VALUE: %s]\n\n' % response.info().getheader('x-frame-options'))
else:
  print(Fore.RED +'Vulnerability ')
  print(Style.RESET_ALL)
  print('- Server does not enforce Cross-Frame Scripting Protection.\nThe X-Frame-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Click-Jacking Attacks. \n\n')

# check x-content-type-options:
if response.info().getheader('x-content-type-options') == 'nosniff':
  print(Fore.RED + 'NOT VULNERABLE')
  print(Style.RESET_ALL)
  print('(X-Content-Type-Options) MIME-Sniffing Protection is enforced. [VALUE: %s]\n\n' % response.info().getheader('x-content-type-options'))
else:
  print(Fore.RED +'Vulnerability ')
  print(Style.RESET_ALL)
  print('- Server does not enforce MIME-Sniffing Protection.\nThe X-Content-Type-Options Header setting is either inadequate or missing.\nClient may be vulnerable to MIME-Sniffing Attacks. \n\n')

# check strict-transport-security:
if response.info().getheader('strict-transport-security'):
  print(Fore.RED + 'NOT VULNERABLE')
  print(Style.RESET_ALL)
  print('(Strict-Transport-Security) HTTP over TLS/SSL is enforced. [VALUE: %s]\n\n' % response.info().getheader('strict-transport-security'))
else:
  print(Fore.RED +'Vulnerability ')
  print(Style.RESET_ALL)
  print('- Server does not enforce HTTP over TLS/SSL Connections.\nThe Strict-Transport-Security Header setting is either inadequate or missing.\nClient may be vulnerable to Session Information Leakage.\n\n')

# check content-security-policy:
#if response.info().getheader('content-security-policy'):
#  print('(Content-Security-Policy) Content Security Policy is enforced. [VALUE: %s]\n\n' % response.info().getheader('content-security-policy'))
#else:
#  print('Vulnerability ')
#  print('- Server does not enforce a Content Security Policy.\nThe Content-Security-Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting and Injection Attacks. [VALUE: %s]\n\n' % (response.info().getheader('content-security-policy') if response.info().getheader('content-security-policy') else 'MISSING'))

# check x-content-security-policy:
#if response.info().getheader('x-content-security-policy'):
#  print('Deprecated ')
#  if not response.info().getheader('content-security-policy'):
#    print('(X-Content-Security-Policy) Content Security Policy is enforced. (SWITCH TO STANDARD HTTP HEADER: \'Content-Security-Policy\')\n\n')
#  else:
#    print('(X-Content-Security-Policy) Content Security Policy is enforced. (DROP DEPRECATED HEADER: \'X-Content-Security-Policy\')\n\n')

# check x-webkit-csp:
#if response.info().getheader('x-webkit-csp'):
#  print('Deprecated ')
#  if not response.info().getheader('content-security-policy'):
#    print('(X-Webkit-CSP) Content Security Policy is enforced. (SWITCH TO STANDARD HTTP HEADER: \'Content-Security-Policy\')\n\n', WHITE)
#  else:
#    print('(X-Webkit-CSP) Content Security Policy is enforced. (DROP DEPRECATED HEADER: \'X-Webkit-CSP\')\n\n')

# check access-control-allow-origin:
#if response.info().getheader('access-control-allow-origin'):
#  print('(Access-Control-Allow-Origin) Access Control Policies are enforced. [VALUE: %s]\n\n' % response.info().getheader('access-control-allow-origin'))
#else:
#  print('Vulnerability ')
#  print('- Server does not enforce an Access Control Policy.\nThe Access-Control-Allow-Origin Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Domain Scripting Attacks. [VALUE: %s]\n\n' % (response.info().getheader('access-control-allow-origin') if response.info().getheader('access-control-allow-origin') else 'MISSING'))

# check x-download-options:
#if response.info().getheader('x-download-options') == 'noopen':
#  print('(X-Download-Options) File Download and Open Restriction Policies are enforced. [VALUE: %s]\n\n' % response.info().getheader('x-download-options'))
#else:
#  print('Vulnerability ')
#  print('- Server does not enforce a File Download and Open Policy.\nThe X-Download-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Browser File Execution Attacks. [VALUE: %s]\n\n' % (response.info().getheader('x-download-options') if response.info().getheader('x-download-options') else 'MISSING'))

# check cache-control:
#if response.info().getheader('cache-control') and (response.info().getheader('cache-control').startswith('private') or response.info().getheader('cache-control').startswith('no-cache')):
#  print('(Cache-control) Private Caching or No-Cache is enforced. [VALUE: %s]\n\n' % response.info().getheader('cache-control'))
#else:
#  print('Vulnerability ')
#  print('- Server does not enforce a Content Caching Policy.\nThe Cache-control Header setting is either inadequate or missing.\nClient may be vulnerable to Content Caching Attacks. [VALUE: %s]\n\n' % (response.info().getheader('cache-control') if response.info().getheader('cache-control') else 'MISSING'))

# check x-permitted-cross-domain-policies:
#if response.info().getheader('X-Permitted-Cross-Domain-Policies') == 'master-only' or response.info().getheader('X-Permitted-Cross-Domain-Policies') == 'none':
#  print('(X-Permitted-Cross-Domain-Policies) X-Permitted-Cross-Domain-Policies are enforced. [VALUE: %s]\n\n' % response.info().getheader('X-Permitted-Cross-Domain-Policies'))
#else:
#  print('Vulnerability ')
#print('- Server does not enforce a X-Permitted-Cross-Domain-Policies.\nThe Cross-Domain Meta Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Protocol-Scripting Attacks. [VALUE: %s]\n\n' % (response.info().getheader('X-Permitted-Cross-Domain-Policies') if response.info().getheader('X-Permitted-Cross-Domain-Policies') else 'MISSING'))
