# dns-blocker  [![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbrunexgeek%2Fdns-blocker%2Fbadge%3Fref%3Dmaster&label=build&logo=none)](https://actions-badge.atrox.dev/brunexgeek/dns-blocker/goto?ref=master)

Simple DNS server to filter domains using blacklist. The ideia is to block TCP/UDP communication to specific domains/subdomains by manipulating DNS answers. This program enables you to use wildcards and you don't have to know all subdomains a priori, as you would when using ``iptables`` or *hosts* file. This program is compatible with GNU/Linux and Windows.

For every query of type ``A`` (or ``AAAA`` if IPv6 is enabled), the server will do the following:

* Return the IP address ``127.0.0.2`` or ``::2`` if the domain **is** in the blacklist; this way the program trying to connect with that domain will fail to communicate;
* Recursively resolve the domain using one of the configured external name servers if the domain **is not** in the blacklist; the correct IP address will be returned.

Any query with type different than ``A`` (and ``AAAA`` if IPv6 is enabled) receives ``Server Failure`` error. Every DNS answer contains only one entry with the resolved IP (usually the first).

## Building

```
mkdir build && cd build
cmake ..
make && sudo make install
```

## Configuration

To configure `dnsblocker` you use pairs of key-value stored in a JSON file.

* **blacklist** &ndash; Array of strings with blacklist file names, relative to the configuration file path.
* **binding** &ndash; Specify the address and port for the program to bind with.
  * **address** &ndash; IPv4 address. The default value is `127.0.0.2`.
  * **port** &ndash; Port number (0-65535). The default value is `53`.
* **external_dns** &ndash; Array of objects containing external DNS servers to be used by recursive queries. Each object has the following fields:
  * **name** &ndash; entry name.
  * **address** &ndash; Required IPv4 address of the external name server.
  * **targets** &ndash; Optional array of expressions (same syntax as blacklists). When the requested domain matches with one of those expressions, this name server will be used. If the name server is unavaiable, the default name server will be used instead. If this option is omited, this entry will be set as default external name server.
* **monitoring** &ndash; `allowed` to show allowed requests; `denied` to show blocked requests; `all` to show everything; `none` or any other value to disable monitoring.
* **cache** &ndash; Cache configuration.
  * **ttl** &ndash; TTL (time to live) in seconds for DNS responses. The default value is 10 minutes.
  * **limit** &ndash; Maximum number of entries in the cache. The default value is 1000.

```json
{
    "blacklist" : [ "blacklist.txt" ],
    "binding" : { "address": "127.0.0.2", "port" : 53 },
    "external_dns" : [
        { "address" : "8.8.4.4", "name" : "default" },
        { "address" : "192.168.0.20", "targets" : [ "**.example.com" ], "name" : "enterprise" }
    ],
    "monitoring" : "allowed",
    "cache" : { "ttl" : 600, "limit" : 1000 }
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

Domain names can contain the following characters: ASCII letters, numbers, dashes (-) and periods (.). Asterisks must appear only as the first characters of the rule and must be followed by a period.

## Running on GNU/Linux

Once you have the configuration file and the blacklist, just run ``dnsblocker``:

```
# dnsblocker config.json /var/log/
```

The first argument is the path to the configuration file and the second argument is the path where the log file must be written. The second argument is optional, in which case the logs will be printed on screen.

To stop the program, send ``SIGTERM`` signal with the command ``kill`` or ``pkill``.

## Running on Windows

On Windows `dnsblocker` is a service and must be installed:

```
# sc create dnsblocker binPath= "<path to executable> <config file> <log path>" start= "auto"
```

If any path contains spaces, you must use additional escaped quotes between the arguments. Its recomended to use absolute paths. Also is useful to make sure the service is configured with automatic startup and restart at failure (you can change this options in `services.msc`).


## Console

Console functionality is enable by default using the macro `ENABLE_DNS_CONSOLE` at `defs.hh.in`.

You can use the `dig` or `nslookup` to send the following special *commands* to `dnsblocker`. These commands will be executed only if the request comes from the same IP address as the binding address or from 127.0.0.1 in case of binding to `0.0.0.0` (any address).

* **reload@dnsblocker** &ndash; Reload the blacklist.
* **dump@dnsblocker** &ndash; Dump the cache entries to the file `dnsblocker.cache` in the same location of the log file.

Example:

```
# dig reload@dnsblocker
```

## Limitations

* Only the required parts of DNS protocol are implemented.
