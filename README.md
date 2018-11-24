# dns-blocker

Experimental DNS server to block domains using a blacklist. The ideia is to block TCP/UDP communication to specific domains/subdomains by manipulating DNS answers. This program enables you to use wildcards and you don't have to know all subdomains a priori, as you would if using ``iptables``.


For every query of type ``A`` (i.e. returns an IPv4 address for the given domain name), the server will do the following:

* Return the IP address ``127.0.0.2`` if the domain **is** in the blacklist; this way the program trying to connect with that domain will fail to communicate properly;
* Answer with the ``Server Failure`` error if the domain **is not** in the blacklist; the DNS client will try another DNS server and propably succeed the second time.

Any query with a type different than ``A`` receives an ``Server Failure`` error.

# Building

```
mkdir build && cd build
cmake ..
make
```

# Run

Before starting the DNS server, you need a text file containing rules. Rules are domain names you want to block, one per line. It's possible to use wildcards to match any subdomains.

```
google.com
*.microsoft.com
```

The first line blocks the domain ``google.com`` and the second line blocks every subdomain of ``microsoft.com``, but not ``microsoft.com`` itself.

With the file created, just run the program with a command like:

```
./dnsblocker 192.168.0.1 53 rules.txt
```

The first argument is the IP address the server should bind with; the second argument is the UDP port to be used (53 is the standard DNS port); and the third argument is the path to the file containing the rules.

The program will run as a daemon and a log file will be generated at ``/var/log/dnsblocker.log``. To stop the program, send a SIGTERM signal with the command ``kill``.

# Limitations

* Domain names can contain the following characters: letters, numbers, dashes (-) and dots (.). You can use an asterisk as the first character to enable wildcard matching.
* This is a prototype code and many exceptional conditions are not properly handled.


