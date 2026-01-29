# Support for peer to peer in picoquic

It would be too bad if the QUIC stack implemented in picoquic only supported
client to server applications. On the other hand, P2P application require
multiple functions: name resolution, and generally the discovery of
peers; management of certificates, public keys and other credentials; and
the ability to interoperate through NAT and firewalls. That's quite a bit of
work. Hopefully, some of that work can be delegated to the application, or to
other packages used by the application. For example, there would be little
point in developing yet another distributed hash table, applications can just
use existing packages and API for that.

The first priority is probably the traversal of firewalls and NAT, because
this is the closest to the transport service provided by QUIC.
That can be split into multiple components: some kind of proxy or relay
system, so applications behind NAT or firewalls can receive data even
before holes have been punched; STUN like servers so application can
learn how their IP addresses appear out of the NAT; services like
UPNP, NAT PMP or PCP to open ports in the local firewall; and automated
protocols like ICE to establish a path between two endpoints.

## Masque

Among firewall traversal services, the most interesting is probably Masque,
and in particular
Masque UDP, as it allows opening a dedicated port on the Masque proxy,
That's definitely on the TODO list. The Masque protocol itself is
straightforward, but it cannot be deployed without some form of
access control -- leaving a relay completely open on the Internet
is somewhat dangerous. Masque suggests using OAuth, but that could be
a big development.

## Address Discovery

The next most useful tool is something like STUN, i.e., a server that
can return the IP address of the client. We have a 
[specification in progress](https://github.com/marten-seemann/draft-seemann-quic-address-discovery),
and an implementation in progress, with two goals:

* enable any picoquic server to provide the address discovery service,
* enable P2P developers to gather the IP addresses used by their endpoint.

The service is negotiated using a transport parameter, "address_discovery_mode",
that could be 


