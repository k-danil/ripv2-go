# ripv2-go
Simple ripv2 deaemon implimented again RFC2453, RFC4822.

---
Incoming signals:

SIGHUP - reinit config

SIGUSR1 - print adj table to log

SIGTERM - gracefull stop

---
Basic config in toml:
<pre><code>
[local]
metric = 120
msgSize = 25
log = 4

[timers]
updateTimer = 30
timeoutTimer = 180
garbageTimer = 120

[interfaces]
 [interfaces.br0]
 auth = true
   [interfaces.br0.keychain]
   authType = 3
   authKey = "123"
 [interfaces.lo]
 passive = true
</code> </pre>

**metric** - metric in linux local table

**authType** - "2" Plain "3" md5

**log** - log level 0 -> 5

---
TODO:
* Test suit
* Neighbor list
* Unicast neighbors