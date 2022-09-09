# dnsblocker  [![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbrunexgeek%2Fdnsblocker%2Fbadge%3Fref%3Dmaster&label=build&logo=none)](https://actions-badge.atrox.dev/brunexgeek/dnsblocker/goto?ref=master) ![Version](https://img.shields.io/badge/version-0.20-blue)

Simple DNS server that act as a proxy for DNS protocol and filter queries using pattern matching. The ideia is to block TCP/UDP communication to specific domains/subdomains by manipulating DNS answers. This program enables you to use patterns and you don't have to know all subdomains a priori, as you would be if using ``iptables`` or *hosts* file. This program is compatible with GNU/Linux and Windows.

For each query of type ``A`` and ``AAAA`` the server will do the following:

* Return the IP address ``127.0.0.2`` or ``::2`` if the domain **is not** in the whitelist and `use_heuristics` is enabled and the domain looks like random;
* Return the IP address ``127.0.0.2`` or ``::2`` if the domain **is not** in the whitelist and **is** in the blacklist;
* Otherwise, recursively resolve the domain using one of the configured external name servers.

Any query other than ``A`` and ``AAAA`` are recursively resolved without filtering.

## Building

```
mkdir build && cd build
cmake ..
make && sudo make install
```

## Configuration

To configure `dnsblocker` you use pairs of key-value stored in a JSON file.

* **blacklist** &ndash; Array of strings with blacklist file names, relative to the configuration file path.
* **whitelist** &ndash; Array of strings with whitelist file names, relative to the configuration file path.
* **binding** &ndash; Specify the address and port for the program to bind with.
  * **address** &ndash; IPv4 address. The default value is `127.0.0.2`.
  * **port** &ndash; Port number (0-65535). The default value is `53`.
* **external_dns** &ndash; Array of objects containing external DNS servers to be used by recursive queries. Each object has the following fields:
  * **name** &ndash; Entry name.
  * **address** &ndash; Required IPv4 address of the external name server.
  * **targets** &ndash; Optional array of expressions (see _List of rules_ section below). When the requested domain matches with one of those expressions, this name server will be used. If the name server is unavaiable, the default name server will be used instead. If this option is omited, this entry will be set as default external name server.
* **use_heuristics** &ndash; Enable (`true`) or disable (`false`) heuristics to detect random domains (used by some tracking and advertising APIs)
* **monitoring** &ndash; Array of strings indicating the types of entries that should be logged. If no value is specified, the monitoring is disabled. Possible values are zero or more of:
  * `all` - show everything
  * `allowed` - show allowed requests (combine `recursive`, `cache`, `failure` and `nxdomain`)
  * `denied` - show blocked requests
  * `recursive` - show requests handled by external DNS servers
  * `cache` - show requests handled by internal cache
  * `failure` - show requests that failed
  * `nxdomain` - show requests for unknown domains
* **cache** &ndash; Cache configuration.
  * **ttl** &ndash; TTL (time to live) in seconds for DNS entries in the cache. The default value is 10 minutes (600 seconds).
  * **limit** &ndash; Maximum number of entries in the cache. The default value is 5000.
* **use_ipv6** &ndash; Enable IPv6 queries. Make sure the binary is compiled with IPv6 support.
* **threads** &ndash; Especify the amount of threads the program should spawn to handle requests concurrently. The default value is 1.

```json
{
    "blacklist" : [ "blacklist.txt", "ads.txt" ],
    "whitelist" : [ "whitelist.txt" ],
    "binding" : {
        "address": "127.0.0.2",
        "port" : 53
    },
    "external_dns" : [
        { "address" : "8.8.4.4", "name" : "default" },
        { "address" : "192.168.0.20", "targets" : [ "**.example.com" ], "name" : "enterprise" }
    ],
    "monitoring" : ["denied", "recursive"],
    "cache" : {
        "ttl" : 600,
        "limit" : 1000
    }
}
```

## List of rules

The blacklist and whitelist files contain rules to define denied and allowed domains, respectively. Rules are expressions and each line of the list define a single rule. It's possible to use an asterisk (*) to match any subdomains and two asterisks (**) to match any subdomains and the domain itself.

```
google.com
*.microsoft.com
**.bing.com
```

In the example above, the first rule matches the domain ``google.com``; the second rule matches every subdomain of ``microsoft.com``, but not ``microsoft.com`` itself; and the third rule matches ``bing.com`` and any of its subdomains. The third rule is equivalent to:

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

The first argument is the path to the configuration file and the second argument is the directory where the log file must be written. The second argument can be omitted, in which case the logs will be printed on `stdout`.

To stop the program, send ``SIGTERM`` signal. You can use the commands ``kill`` or ``pkill`` to send the signal.

## Running on Windows

On Windows `dnsblocker` is a service and must be installed:

```
# sc create dnsblocker binPath= "<path to executable> <config file> <log path>" start= "auto"
```

If any path contains spaces, you must use additional escaped quotes between the arguments. Its recomended to use absolute paths. Also is useful to make sure the service is configured with automatic startup and restart at failure (you can change this options in `services.msc`).


## Console

Console functionality is enable by default using the CMake option `ENABLE_DNS_CONSOLE`. When the console is enabled, `dnsblocker` will expose a set of HTTP REST endpoints at http://127.0.0.2:53022.

* **GET /console/reload** &ndash; Reload blacklists and whitelists.
* **GET /console/cache** &ndash; Returns the cache content as JSON.
* **GET /console/cache/reset** &ndash; Clean the cache.
* **GET /console/monitor** &ndash; Monitoring page showing the latest DNS queries.
* **GET /console/monitor/events** &ndash; Returns the latest DNS queries as a JSON array.
* **GET /console/allow/\<rule\>** &ndash; Temporarily add a rule to the whitelist.
* **GET /console/filter/on** &ndash; Enable DNS filtering.
* **GET /console/filter/off** &ndash; Disable DNS filtering. The blacklist will be ignored.
* **GET /console/heuristic/on** &ndash; Enable heuristics to detect random domains.
* **GET /console/heuristic/off** &ndash; Disable heuristics to detect random domains.

Example:

```
# curl http://127.0.0.2:53022/console/reload
```

## Limitations

* Only the required parts of DNS protocol are implemented.
