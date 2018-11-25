# dns-blocker

Experimental DNS server to block domains using a blacklist. The ideia is to block TCP/UDP communication to specific domains/subdomains by manipulating DNS answers. This program enables you to use wildcards and you don't have to know all subdomains a priori, as you would if using ``iptables``.


For every query of type ``A`` (i.e. returns an IPv4 address for the given domain name), the server will do the following:

* Return the IP address ``127.0.0.2`` if the domain **is** in the blacklist; this way the program trying to connect with that domain will fail to communicate properly;
* Return a ``Server Failure`` error if the domain **is not** in the blacklist; the DNS client will try another DNS server and propably succeed the second time.

Any query with a type different than ``A`` receives a ``Server Failure`` error.

## Building

```
mkdir build && cd build
cmake ..
make && sudo make install
```

## Rules

Before starting the DNS server, you need a text file containing rules. Rules are domain names you want to block, one per line. It's possible to use an asterisk (*) to match any subdomains and two asterisks (**) to match any subdomains and the domain itself.

```
google.com
*.microsoft.com
**.bing.com
```

In the example above, the first rule blocks the domain ``google.com``; the second rule blocks every subdomain of ``microsoft.com``, but not ``microsoft.com`` itself; and the third rule blocks ``bing.com`` and any of its subdomains. The third rule is equivalent to:

```
bing.com
*.bing.com
```

Domain names can contain the following characters: ASCII letters, numbers, dashes (-) and periods (.). Asterisks must appear only at the beginning of the rule and must be followed by a periods.

## Running

Once you have a file with rules, just run ``dnsblocker``:

```
# dnsblocker 192.168.0.1 53 rules.txt
```

The first argument is the IP address the server should bind with; the second argument is the UDP port to be used (53 is the standard DNS port); and the third argument is the path to the file containing the rules.

The program will run as a daemon and output information in a log file at ``/var/log/dnsblocker.log``. To stop the program, send ``SIGTERM`` signal with the command ``kill`` or ``pkill``. You can also send ``SIGUSR1`` signal to reload the rules.

## Limitations

* This is a prototype code and many exceptional conditions are not properly handled.
* Only the required parts of DNS protocol as implemented.
