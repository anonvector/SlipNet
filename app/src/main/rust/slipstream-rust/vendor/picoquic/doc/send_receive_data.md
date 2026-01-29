# Sending and Receiving Data

Application data can be sent using streams and also datagrams if
the datagram option is negotiated.
Picoquic provides two APIs for sending data on stream,
and also two APIs for sending datagram frames: queuing APIs
and "just in time" APIs. Receiving is always "just in time",
using the "callback" API.

## Opening streams

QUIC streams come in four classes:

- bidirectional streams opened by the client,
- bidirectional streams opened by the server,
- unidirectional streams opened by the client,
- unidirectional streams opened by the server.

Bidirectional streams enable data in both directions, while unidirectional
streams enable sending data from the endpoint that create them to its peer.

Streams are identified by a 64 bit stream ID. The type of stream is encoded
in the 2 least significant bits of the stream ID. Streams numbers should be
opened in sequence in the specified class.

Before using any of the stream APIs, the application must either learn the
stream ID of a remote stream when receiving a callback related to that stream,
or select a local bidirectional or unidirectional stream ID, using the
`picoquic_get_next_local_stream_id` API:
~~~
/* Obtain the next available stream ID in the local category */
uint64_t picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidir);
~~~
That API should be used when creating a local stream. 

Streams in picoquic are created implicitly, either when the application
starts using them or when the first data for the stream are received
from the peer.

## Sending Data on Streams

Picoquic provides a "queuing" API to add data to a stream, and an alternative
"just in time" API. When sending "just in time", picoquic does not build
an internal data queue. Instead, the application is called when the stack is
ready to send a stream frame for the specified stream, gets access to the packet
that is being formatted, and writes the application data directly into that
packet just before the packet is sent on the network.

Using the just in time API is a bit more complex than just queuing data, but
avoiding copying data in queues reduces memory and CPU consumption. For
example, when serving an image on a web page, the HTTP stack can compose
stream data frames directly from the image file, instead of loading the image in
memory and copying it in the stream queue.

For "real time" applications, the just in time API also has the advantage of
sending the most up to date data. Suppose for example an application that
provides the time over the network. With the "just in time" API, it can read
the clock immediately before sending the packet, providing more accurate time to
the receiver.

### Queuing stream data

Applications can "add" data to a stream by calling either `picoquic_add_to_stream`
or `picoquic_add_to_stream_with_ctx`.

~~~
int picoquic_add_to_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, const uint8_t* data, size_t length, int set_fin);

int picoquic_add_to_stream_with_ctx(picoquic_cnx_t * cnx,
    uint64_t stream_id, const uint8_t * data, size_t length, int set_fin,
    void * app_stream_ctx);
~~~

These two functions are identical, except for the `app_stream_ctx` parameter,
which is actually not used in the sending process but in only in the receive
callbacks.

When using these API, the data to be sent is copied and added to an internal
queue per stream. It will be sent on the network as soon as flow control,
congestion control and scheduling priorities permit.

### Just in time stream data

With the just in time API, the application:

- marks a stream as `active` using the API "picoquic_mark_active_stream".

- receives the callback `picohttp_callback_provide_data` when the stack is ready
to send data on the stream.

- services the callback by reserving a buffer using the
API "picoquic_provide_stream_data_buffer", and copying the
application data in that buffer.

The APIs are documented in "picoquic.h":
~~~
/* Mark stream as active, or not.
 * If a stream is active, it will be polled for data when the transport
 * is ready to send. The polling will only start after all currently
 * queued data has been sent.
 */
int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void* v_stream_ctx);

/* If a stream is marked active, the application will receive a callback with
 * event type "picoquic_callback_prepare_to_send" when the transport is ready to
 * send data on a stream. The "length" argument in the call back indicates the
 * largest amount of data that can be sent, and the "bytes" argument points
 * to an opaque context structure. In order to prepare data, the application
 * needs to call "picoquic_provide_stream_data_buffer" with that context
 * pointer, with the number of bytes that it wants to write, with an indication
 * of whether or not the fin of the stream was reached, and also an indication
 * of whether or not the stream is still active. The function
 * returns the pointer to a memory address where to write the byte -- or
 * a NULL pointer in case of error. The application then copies the specified
 * number of bytes at the provided address, and provide a return code 0 from
 * the callback in case of success, or non zero in case of error.
 */

uint8_t* picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);
~~~

### Reneging on the application writing promise

Nobody is perfect. An application may "think" that it is ready to send data
and set the "active" flag using `picoquic_mark_active_stream`, only to
receive a callback and find out that it does not have anything more to
send.

The application can in that case state that it has nothing to send by
calling `picoquic_provide_stream_data_buffer` and setting the number
of bytes to zero, e.g.:

~~~
    /* Not sending here! */
    (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
~~~

In this example, the `fin` flag is set to 0, and the `still active` flag set to 0.
The application might call the API "picoquic_mark_active_stream" later,
and mark the stream as active again.

The application could combine `nb_bytes_ = 0` (no data to send now) and `fin = 1`,
if finished sending that stream. The stack will then send a stream data frame with
no content but the `FIN` bit set, marking the end of the stream.

The application could also set `is_still_active=1`, or call `picoquic_mark_active_stream`
from within the call back, which is equivalent. But that's a bit of a gamble.
The stack will try to fill the current packet with some other content,
but will immediately repeat the callback when ready to send another packet.
That kind of "hyper active polling" may not be the best for performance, except in the
case when the application message does not fit in the length of the buffer, maybe
because some other data was already written in the outgoing packet. The next callback
should provide a larger buffer.

### Mixing Queueing and Just in time

An application may use the "queuing" and "just in time" API on the same stream.
For example, the HTTP implementation uses the queuing API to write HTTP frame
headers to the stream, and then uses the "just in time" API to write the actual
page data. The rule is simple: picoquic will always write all the queued data
before issuing the callback `picohttp_callback_provide_data`.

### Pinning streams to paths

In multipath environments, it is sometimes desirable to "pin" a QUIC stream to
a specific path. Applications that want to pin path to streams must first
monitor the state of paths, which is provided by callbacks such as:
~~~
/* A new path is available, or a suspended path is available again */
picoquic_callback_path_available, 
/* An available path is suspended */
picoquic_callback_path_suspended, 
/* An existing path has been deleted */
picoquic_callback_path_deleted, 
/* Some path quality parameters have changed */
picoquic_callback_path_quality_changed 
~~~
In these API, each path is identified by a 64 bit `unique_path_id`. This identifier
can be used to set the "affinity" between a stream and a path:
~~~
int picoquic_set_stream_path_affinity(picoquic_cnx_t* cnx, 
    uint64_t stream_id, uint64_t unique_path_id);
~~~
When the affinity is set, picoquic will wait until the path is ready
to send queued data for that stream, or to issue the callback
`picoquic_callback_prepare_to_send` for that stream.

## Receiving stream data

When stream data are received, the contents are queued temporarily until
it can be delivered in order. At that point, the application will
receive a callback `picoquic_callback_stream_data` or, if this is
the last data for a stream, `picoquic_callback_stream_data`.

The callback will indicate the stream ID. The `stream_ctx` argument
will be set to the value associated with the stream in the last call
to one of:
~~~
int picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* app_stream_ctx);
int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void* v_stream_ctx);
int picoquic_add_to_stream_with_ctx(picoquic_cnx_t * cnx, uint64_t stream_id,
    const uint8_t * data, size_t length, int set_fin, void * app_stream_ctx);
~~~

If an application discards a stream context, it should be careful to
remove the memory association to this context in the stack. It can do
that by setting the `stream_ctx` argument to NULL in one of the previous
API, or by calling:
~~~
/* Remove association between stream and context */
void picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id);
~~~

## Closing streams

When an application has finished sending data on a stream, it should set the
FIN bit in its last call to `picoquic_add_to_stream_with_ctx` or to
`picoquic_provide_stream_data_buffer`.

When the peer has set the FIN bit and the last stream frame has been received
in order, the application receives the callback `picoquic_callback_stream_fin`,
which may also deliver the last data bytes for the stream.

Application can also abruptly close the stream using the RESET mechanism,
by calling the API:
~~~
int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error);
~~~
If a stream is reset by the peer, the application will receive the callback
`picoquic_callback_stream_reset`.

The RESET mechanism only works for the sending direction. If a stream is
bidirectional, the application may well continue to receive data from
the peer until the peer's side of the stream is closed or reset. An
application that receives the callback `picoquic_callback_stream_reset`
may continue to send data on the stream until it decides to close
or reset it.

If an application resets a stream, Picoquic will immediately stop
sending on that stream. This includes not just new data, but also
previous data that would need to be repeated because of packet loss.

Picoquic considers that a bidirectional stream is closed if it is closed
or reset in both directions -- the application has sent the FIN of
the stream or reset the stream, and received the FIN or reset callback.
All resource associated with the stream are freed after that.
For unidirectional streams, picoquic considers a local stream closed if the
application has sent the FIN of the stream, and a remote stream close if the
application has received the FIN callback.

## Sending Datagrams

An application may send QUIC datagrams if the datagram extension has been
negotiated during the QUIC handshake. Like for streams, datagrams can
be either queued or sent "just in time". Just like for streams, sending
datagrams "just in time" saves CPU and memory, and allows real time
applications to fill datagram with up to date data.

In addition, the queuing API limits the size of the datagrams to 1200
bytes (`PICOQUIC_DATAGRAM_QUEUE_MAX_LENGTH`), so they can 
fit in the minimum packet length supported by QUIC. With the
just in time API, datagram sizes are only limited by the packet size
and also by the maximum size negotiated during the handshake.

### Queuing datagrams

Datagrams can be queued using the API:
~~~
int picoquic_queue_datagram_frame(picoquic_cnx_t* cnx, size_t length, const uint8_t* bytes);
~~~
Trying to queue datagram larger than `PICOQUIC_DATAGRAM_QUEUE_MAX_LENGTH` will result
in an error `PICOQUIC_ERROR_DATAGRAM_TOO_LONG`.

### Sending Datagrams just in time

With the just in time API, the application:

- indicates its readiness to send datagrams marks a stream as `active` using
  the API `picoquic_set_datagram_ready`.

- receives the callback `picoquic_callback_prepare_datagram` when the stack is ready
to send datagrams in a packet.

- services the callback by reserving a buffer using the
API `picoquic_provide_datagram_buffer` or `picoquic_provide_datagram_buffer_ex`,
and copying the application data in that buffer.

The APIs are defined in `picoquic.h`:
~~~
int picoquic_mark_datagram_ready(picoquic_cnx_t* cnx, int is_ready);

uint8_t* picoquic_provide_datagram_buffer(void* context, size_t length);
uint8_t* picoquic_provide_datagram_buffer_ex(void* context, size_t length,
         picoquic_datagram_active_enum is_active);
~~~

The old API `picoquic_provide_datagram_buffer` does not have the
`is_active` argument, which makes the "reneging" and "multipath" scenarios
harder to handle. It was kept so as to not require changes in old
applications, but new applications should preferably use the "extended'
API.

### Reneging on sending datagrams

There may be circumstances when an application indicates that it is
ready to send datagrams, but cannot send data when it receives the callback.

If the application marked the context ready by mistake, it should use
the extended API `picoquic_provide_datagram_buffer_ex` to signal
that it has no data to send. This is a way of saying "oops". The
stack will stop polling for datagrams, until there is a new call to
`picoquic_mark_datagram_ready`.

If the application does have data to send but the available
length indicated in the callback is too small, it should set the "length"
argument to 0, and the "is_active" argument to picoquic_datagram_active_any_path.
The stack will try to immediately reissue the callback in the next packet, hopefully with
more space available.

### Specifying the outgoing path for datagrams

In a multipath environment, it is sometimes useful to specify on which
path datagrams should be sent. For example, if sending realtime Voice
over IP, the application may want to send all the voice datagrams
on the same path, to minimize delay jitter. It may also want to choose
a path with a low latency and low packet loss.

In a multipath connection, the API `picoquic_mark_datagram_ready` signals
application readiness to send datagrams on any available path. The application can
use the API `picoquic_mark_datagram_ready_path` to request sending on a specific path:
~~~
int picoquic_mark_datagram_ready_path(picoquic_cnx_t* cnx,
    uint64_t unique_path_id, int is_path_ready);
~~~
If the generic API is used, the application will receive a callback
`picoquic_callback_prepare_datagram` each time a datagram can be sent
on any outgoing packet. If it uses the path specific API, it will only
receive the callback when a datagram can be sent on one of the
paths marked "ready".

The application using multipath should use the "extended" variant of the
datagram buffer API:

~~~
uint8_t* picoquic_provide_datagram_buffer_ex(void* context, size_t length,
         picoquic_datagram_active_enum is_active);
~~~

In that variant, the `is_active` enum provides options to describe whether
the application wants to continue sending datagrams on this path, or on
all paths, as stated in `picoquic.h`:

~~~
/*
 * In multipath environments, the application can use the API 
 * `picoquic_mark_datagram_ready_path` to signal that is is ready to send
 * datagrams on a specific path. The picoquic_provide_datagram_path_ex
 * API allows the application to mark 4 different level of activity:
 * 
 * - picoquic_datagram_not_active: not active on this path or any other.
 * - picoquic_datagram_active_any_path: active, but not specifically on this path.
 * - picoquic_datagram_active_this_path_only: ready to send datagrams on this
 *   path, but not on other paths unless they were specifically marked.
 * - picoquic_datagram_active_this_path_and_others: has traffic ready to
 *   send on this path, and some different traffic ready for any other path.
 */
 typedef enum {
    picoquic_datagram_not_active = 0,
    picoquic_datagram_active_any_path = 1,
    picoquic_datagram_active_this_path_only = 2,
    picoquic_datagram_active_this_path_and_others = 3
} picoquic_datagram_active_enum;
~~~

### Checking whether datagrams are received

The QUIC specifications make no guarantee that datagram frames will be received in order,
or at all. Picoquic allows applications some degree of control with three callbacks:

~~~
/* Ack for packet carrying datagram-frame received from peer */
picoquic_callback_datagram_acked,
/* Packet carrying datagram-frame probably lost */
picoquic_callback_datagram_lost,
/* Packet carrying datagram-frame was not really lost */
picoquic_callback_datagram_spurious,
~~~

The `bytes` and `length` arguments point to the datagram frame that
was sent. The application is freed to undertake any corrective action,
but it should be aware that this is a "best effort" API, based on
the acknowledgements of the carrying packets. Some implementations
of QUIC may well acknowledge these packets before the data is
actually processed by the application. In particular, some Web Transport
stacks are known to place the datagrams in a queue for delivery to
the application, and to delete them if the queue overflows.

## Receiving datagram data

The application will receive the callback `picoquic_callback_datagram` when a
datagram is received.