# Pico Web Transport

Implementation of the web transport protocol on top of picoquic and h3zero implementation of HTTP3.

## Pico Web Transport architecture

The web transport implementation runs on top of the "h3zero" implementation of HTTP3,
which itself runs on top of Quic/picoquic. The application interfaces with the web transport
API, and receives data through a callback. 

~~~
+-----------------------+                    +-----------------------+
| client app            |                    | server app            |
| H3zero API / Callback |                    | H3zero API / Callback |
|   |             ^     |                    |   |             ^     |
+---|-------------|-----+                    +---|-------------|-----+
    |             |                              |             |
+---|-------------|-----+                    +---|-------------|-----+
|   v             |     |                    |   v             |     |
|H3zero/WebTransport    |                    |H3zero/WebTransport    |
|Picoquic API / Callback|                    |Picoquic API / Callback|
|   |             ^     |                    |   |             ^     |
+---|-------------|-----+                    +---|-------------|-----+ 
    |             |                              |             |
+---|-------------|-----+                    +---|-------------|-----+
|   v             |     |                    |   v             |     |
|      Picoquic         |                    |      Picoquic         |
+-----------------------+                    +-----------------------+
~~~

The web transport server is actually an HTTP server, augmented with support for
web transport primitives. Establishing a web transport connection requires
first establishing an HTTP3 connection, handled by the H3zero server code,
then using the "Connect Web transport" method on the client to "upgrade" the
HTTP3 connection to a web transport connection. The connect request is sent
over a QUIC/HTTP3 stream. That stream needs to remain open for the
duration of the session -- closing it closes the session.

Client and server can then open QUIC streams, over which they run the protocol
of their choice. The QUIC streams opened by web transport start with a "stream
prefix", which differentiate them from regular HTTP3 streams. For web transport,
the stream prefix is set to the identifier of the "control stream", i.e., the
stream over which the connect request was sent. The HTTP3 server processes the
incoming streams. It will direct these streams to a web transport session if it
recognizes their prefix, or treat them as regular HTTP traffic otherwise.

There is state attached to sessions, such as remembering open streams. In the picoquic
Web Transport implementation, the session state is an object of type
`picowt_session_ctx-t`, which is allocated by the application
on the client side when starting the connect call, and created by the server on the server
side when processing that call. The allocation is recorded in
the table of stream prefixes in the H3Zero connection context. The table is keyed
by the ID of the control stream for the session.

### Preparing an H3 server to accept Web Transport sessions

To support web transport, a server must be ready to accept H3 connections, and then
configured to accept web transport connections over that. There is an example of such
code in the `quic__server` function of `picoquic_demo.c`. To simplify, the
requirements are:

 * Prepare a picoquic context ready to accept HTTP3 requests. In `picoquicdemo`, 
   this is done by setting the callback to `picoquic_demo_server_callback`,
   defined in `demoserver.c`. That callback provides support for 4 different
   protocols: HTTP3, HTTP/0.9, SIDUCK and QUICPERF. If you only want to support
   HTTP3, you can set the callback function to `h3zero_callback`, defined in `

 * Configure the HTTP3 server to accept and process Web Transport requests by
   configuring a "path table". Each path specifies a local URL, a path callback
   function, and a path callback context, per `picohttp_server_path_item_t`
   in `h3zero_common.h`.

 * Run the server socket loop connected to the picoquic context.

### Setting Web Transport sessions on a client

To set up a web transport connection, the client needs to first create a
connection to the target web server, then attach a web transport session
to that connection. In picoquic, this requires:

 * Creating a client side quic context

 * Creating a connection with the ALPN set to "H3" and the callback
   set to `h3zero_callback` defined in `h3zero_common.h`.

 * Create a stream in the connection.
 
 * Call the API `picowt_connect` defined in `pico_webtransport.h`
 
 * Run the server socket loop connected to the picoquic context.

The function `wt_baton_client` in `baton_app_.c` provides an example of a
web transport client.

## Web transport API

The web transport application will interact with the web transport and the
QUIC stack in three ways:

 * Setting up the Web Transport context by calling `picowt_connect` on the
   client,

 * Opening and closing streams,

 * Responding to "path" callbacks from the web stack.

### Setting up a web transport session on the client

The web transport connection is set in four phases:
 
 1- Create an h3zero stream context for the control stream, using
    the API picowt_set_control_stream.
 
 2- Prepare the application state before the connection. This may
    include documenting the control stream context.
 
 3- Call the picowt_connect API to prepare and queue the web transport
    connect message. The API takes the following parameters:
 
  - `cnx`: QUIC connection context
  - `stream_ctx`: the stream context returned by `picowt_set_control_stream`
  - `path`: the path parameter for the connect request
  - `wt_callback`: the path callback used for the application
  - `wt_ctx`: the web transport application context associated with the path callback
 
 4- Make sure that the application is ready to process incoming streams.

The function `wt_baton_connect` in `wt_baton.c` provides an example
of setting the web transport session on the client._

### Web transport callback

The web transport callback API is defined as `picohttp_post_data_cb_fn`
in `h3zero_common.h`. The enumeration `picohttp_call_back_event_t`
defines the following callback events:

~~~
        picohttp_callback_get, /* Received a get command */
        picohttp_callback_post, /* Received a post command */
        picohttp_callback_connecting, /* Sending out a connect command */
        picohttp_callback_connect, /* Received a connect command */
        picohttp_callback_connect_refused, /* Connection request was refused by peer */
        picohttp_callback_connect_accepted, /* Connection request was accepted by peer */
        picohttp_callback_post_data, /* Data received from peer on stream N */
        picohttp_callback_post_fin, /* All posted data have been received on this stream */
        picohttp_callback_provide_data, /* Stack is ready to send chunk of data on stream N */
        picohttp_callback_post_datagram, /* Datagram received on this context */
        picohttp_callback_provide_datagram, /* Ready to send datagram in this context */
        picohttp_callback_reset, /* Stream has been abandoned by peer. */
        picohttp_callback_deregister, /* Context has been deregistered */
        picohttp_callback_free
~~~

The callback definition is generic -- it is used for any kind of web server
extension defined by connecting an URL path with a processor. Apart from
web transport, it is currently used to process HTTP Post requests. That's
why the list includes the `get` and `post` events, which are not used by
web transport.

An example of callback implementation is provided in `wt_baton_callback`
in `wt_baton.c`._

### Creating streams

Once the session is created, client and server will be able to open "local"
streams, i.e., client initiated streams on the client or server initiated
on the servers.

These streams should be called by calling the function `picowt_create_local_stream`
with parameters:

  - `cnx`: QUIC connection context
  - `h3_ctx`: the h3zero context for the connection
  - `control_stream_id`: the stream_id of the control stream for the web transport session.

Once streams are created, data can be sent pretty much like for plain QUIC applications.

### Sending datagrams

Once the session is created or accepted by both peers, an application may send and
receive datagrams. An application signals its desire to send datagrams by calling the
function `h3zero_set_datagram_ready` defined in `h3zero_common.h` with two parameters:

 - `cnx`: QUIC connection context,
 - `stream_id`: Stream ID of the control stream for the web transport session.
 
When the stack is ready to send a datagram, it will issue a callback that is
relayed to the web transport user as `picohttp_callback_provide_datagram`.
The process for sending datagrams is very similar to the process with raw QUIC,
but to acquire a datagram buffer it uses the function `h3zero_provide_datagram_buffer`
with parameters:

 - `context`: must be set to the value of the argument `bytes` of the 
   `picohttp_callback_provide_datagram` callback.
 - `length`: the length of the datagram prepared by the application, which must be
   lower than or equal to the value of the argument `length` of the 
   `picohttp_callback_provide_datagram` callback.
 - `ready_to_send`: whether the application is ready to send more datagrams.

An example of sending datagrams can be found in the function `wt_baton_provide_datagram`
in `wt_baton.c`.

When a datagram is ready, the application will receive a callback
`picohttp_callback_post_datagram` in which the arguments `bytes`
and `length` provide the value and length of the received datagram.

The raw QUIC callbacks `picoquic_callback_datagram_acked`,
`picoquic_callback_datagram_lost`, and `picoquic_callback_datagram_spurious`
are not propagated to the Web Transport application. (Not impossible, but nobody
has asked for them yet.)

## Running a web transport and a raw QUIC server in the same process

It is possible to create a server that handles both "raw" QUIC connections
and "web transport" connections. All these connections will share a single
QUIC context and a single UDP port. The requirements are:

 - develop an ALPN selection function of type `picoquic_alpn_select_fn`,
   as specified in `picoquic.h`, then call `picoquic_set_alpn_select_fn`
   to attach the ALPN selection function to the QUIC context.
 - develop two callback functions, one of type `picoquic_stream_data_cb_fn`
   for the "raw" connections, and another of type `picohttp_post_data_cb_fn`
   for the "web transport" sessions.
 - develop a third callback function that will only be set as default callback
   for the QUIC context. This function will only be used for the first
   callback for an incoming connection. The function should retrieve the
   ALPN of the incoming connection using the API `picoquic_tls_get_negotiated_alpn`,
   and then relay the call to the appropriate callback, `h3zero_callback` if this
   is an HTTP3 connection, or the raw callback of the application if this
   is a call to the ALPN of the application protocol.

There is an example of this process in `demoserver.c`, with the ALPN selection
function `picoquic_demo_server_callback_select_alpn` and the redirection
callback `picoquic_demo_server_callback`.


