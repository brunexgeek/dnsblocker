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

## Configuration

To configure parameters of `dnsblocker` you use pairs of key-value stored in a JSON file.

* **blacklist** &ndash; Path to the blacklist file.
* **binding** &ndash; Specify the IPv4 address and port for the program to bind with.
* **external_dns** &ndash; Specify external DNS servers to be used by recursive queries. The last entry without targets will be the default DNS server. Entries with targets will be used only if the domain name being queried match one of the expressions.

```json
{
    "blacklist" : "blacklist.txt",
    "binding" : {
        "address": "127.0.0.2",
        "port" : 53
    },
    "external_dns" : [
        { "address" : "8.8.4.4" },
        { "address" : "192.168.0.20", "targets" : [ "**.example.com" ] }
    ]
}
```

## Blacklist

The blacklist file contain rules to define blocked domains. Rules are expressions and each line of the blacklist define a singel rule. It's possible to use an asterisk (*) to match any subdomains and two asterisks (**) to match any subdomains and the domain itself.

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

Domain names can contain the following characters: ASCII letters, numbers, dashes (-) and periods (.). Asterisks must appear only as the first characters of the rule and must be followed by a periods.

## Running

Once you have the configuration file and the blacklist, just run ``dnsblocker``:

```
# dnsblocker config.json /var/log/
```

The first argument is the path to the configuration file and the second argument is the path where the log file must be written. The second argument is optional.

To stop the program, send ``SIGTERM`` signal with the command ``kill`` or ``pkill``.

## Console

You can use the `dig` or `nslookup` to send the following special *commands* to `nsblocker`. These commands will be executed only if the request comes from the same IP address as the binding address.

* **reload@dnsblocker** &ndash; Reload the blacklist.
* **dump@dnsblocker** &ndash; Dump the cache entries to the file `dnsblocker.cache` in the same location of the log file.

Example:

```
# dig reload@dnsblocker
```

## Limitations

* This is a prototype code and many exceptional conditions are not properly handled.
* Only the required parts of DNS protocol are implemented.
