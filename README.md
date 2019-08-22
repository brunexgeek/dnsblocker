# dns-blocker

Simple DNS server to filter domains using blacklist. The ideia is to block TCP/UDP communication to specific domains/subdomains by manipulating DNS answers. This program enables you to use wildcards and you don't have to know all subdomains a priori, as you would when using ``iptables`` or *hosts* file. This program is compatible with GNU/Linux and Windows.

For every query of type ``A`` (i.e. returns an IPv4 address for a given domain name), the server will do the following:

* Return the IP address ``127.0.0.2`` if the domain **is** in the blacklist; this way the program trying to connect with that domain will fail to communicate properly;
* Recursively resolve the domain using one of the configured external name servers if the domain **is not** in the blacklist; the correct IPv4 address will be returned.

Any query with type different than ``A`` receives ``Server Failure`` error. Every DNS answer contains only one entry with the resolved IPv4.

## Building

```
mkdir build && cd build
cmake ..
make && sudo make install
```

## Configuration

To configure `dnsblocker` you use pairs of key-value stored in a JSON file.

* **blacklist** &ndash; Array of blacklist file names, relative to the configuration file path.
* **binding** &ndash; Specify the address and port for the program to bind with.
  * **address** &ndash; IPv4 address. The default value is `127.0.0.2`.
  * **port** &ndash; Port number (0-65535). The default value is `53`.
* **external_dns** &ndash; Array of objects containing external DNS servers to be used by recursive queries. Each object has the following fields:
  * **address** &ndash; Required IPv4 address of the external name server.
  * **targets** &ndash; Optional array of expressions (same syntax as blacklists). When the requested domain matches with one of those expressions, this name server will be used. If the name server is unavaiable, the default name server will be used instead. If this option is omited, this entry will be set as default external name server.
* **monitoring** &ndash; `allowed` to show allowed requests; `denied` to show blocked requests; `all` to show everything; `none` or any other value to disable monitoring.
* **cache** &ndash; Cache configuration.
  * **ttl** &ndash; TTL (time to live) for DNS responses. The default value is 10 minutes.
  * **limit** &ndash; Maximum number of entries in the cache. The default value is 1000.

```json
{
    "blacklist" : [ "blacklist.txt" ],
    "binding" : {
        "address": "127.0.0.2",
        "port" : 53
    },
    "external_dns" : [
        { "address" : "8.8.4.4" },
        { "address" : "192.168.0.20", "targets" : [ "**.example.com" ] }
    ],
    "monitoring" : "allowed"
}
```

## Blacklist

The blacklist file contain rules to define blocked domains. Rules are expressions and each line of the blacklist define a single rule. It's possible to use an asterisk (*) to match any subdomains and two asterisks (**) to match any subdomains and the domain itself.

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

The first argument is the path to the configuration file and the second argument is the path where the log file must be written. The second argument is optional, in which case the logs will be printed on screen.

To stop the program, send ``SIGTERM`` signal with the command ``kill`` or ``pkill``.

## Console

You can use the `dig` or `nslookup` to send the following special *commands* to `dnsblocker`. These commands will be executed only if the request comes from the same IP address as the binding address.

* **reload@dnsblocker** &ndash; Reload the blacklist.
* **dump@dnsblocker** &ndash; Dump the cache entries to the file `dnsblocker.cache` in the same location of the log file.

Example:

```
# dig reload@dnsblocker
```

## Limitations

* This is a prototype code and many exceptional conditions are not properly handled.
* Only the required parts of DNS protocol are implemented.
