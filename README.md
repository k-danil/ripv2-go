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

---
TODO:
* Check local address using subscriptions
* Add debug logging support
* Support startup flags
* Limit route entry count for outgoing pdu +-
* Local metric configuration +-
* Test suit
