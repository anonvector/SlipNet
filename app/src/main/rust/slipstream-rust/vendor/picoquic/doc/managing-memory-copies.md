# Managing Memory Copies

Picoquic is designed to limit the number of memory copies and
related memory allocations when sending and receiving data.

## Memory copies when sending data

Application data is sent as either data frames or stream frames.
The sending process will format packets, send them, and
also keep them in memory for possible repetitions.

The typical flow would be:

1. The application makes the data available, either by calling the API `picoquic_add_to_stream`
   which allocates memory and keep a copy, or by signalling that data is available on a stream
   using `picoquic_mark_active_stream`, or by signalling that datagrams are ready to send
   using `picoquic_mark_datagram_ready`.
2. The socket loop wakes up and calls the API `picoquic_prepare_next_packet_ex`
   to ask the stack to prepare the next packet in the QUIC context. It provides
   a data buffer in which the packet will be copied before being sent.
3. The QUIC context selects the next avalaible connection, and will
   call the function `picoquic_prepare_packet_ex` to prepare the next packet for that connection.
4. That function allocates a packet container of type `picoquic_packet_t`, which will
   contain the formatted packet.
5. The formatting happens in the functions called from there, which will copy
   a set of QUIC frames in the packet, including datagram or stream data frames.
6. The content of the stream frames is either copied from data previously queued
   using the `picoquic_add_to_stream` API, or copied directly from the application
   memory using a callback `picoquic_callback_prepare_to_send` for streams, or
   `picoquic_callback_prepare_datagram` for datagrams.
7. When the packet is ready, the stack encrypt it. The clear text in the `packet` structure
   is left untouched, and the encrypted bytes are copied into the "send" buffer
   passed in `picoquic_prepare_next_packet_ex` call. That buffer will be sent to
   the peer through a socket call.
8. The clear text packet is attached to the retransmission queue, waiting for acknowledgement.

### Handling packet losses

In most cases, the clear text packet will be detached from the retransmission queue when the
acknowledgement is received. In some cases, the acknowledgement is not received, and
the data will have to be resent. For stream data, this will involve copying the stream data
from the old copy into a new packet.

### Recycling packets

When packets are acknowledged, the `picoquic_packet_t` element is "recycled". It is added
to a queue of empty packets managed in the Quic context, unless that queue has already
reached its maximum size, in which case the packets are freed. New packet structures are
only allocated when no recycled packet is available.

## Memory copies when receiving data.

The picoquic stack receives encrypted packets from the network, and delivers
decrypted data to the application.

The typical flow would be:

1. A new network packet is received from the socket, and is passed to the
   stack through a call to `picoquic_incoming_packet`.
2. The stack allocates a data node container of type `picoquic_stream_data_node_t`.
3. The header is analyzed and the packet is decrypted, with the clear text data
   is stored into the data node.
4. The decrypted packet is parsed, and the frames that it contained are processed. 
   The content of datagram frames is passed to the application through the
   callback `picoquic_callback_datagram`. The processing of stream data frames varies,
   because stream data must be delivered in order.
5. If the stream data is arriving in order, the data is delivered immediately,
   through the callback `picoquic_callback_stream_data` or `picoquic_callback_stream_fin`.
6. If the data cannot be delivered immediately, it needs to be kept in memory
   until the holes in the stream have been filled. The processing varies
   depending on the number of frames in the packet.
7. If the stream data frame is the last frame in the packet, the data node
   structured in queued to the stream. Else, a new data node is allocated,
   the stream data frame is copied to it, and that new data node is queued
   to the stream.
8. At the end of this process, if the data node was not queued to a stream it
   is recycled.

### Managing out of order delivery

When stream data frames arrive out of order, one data node is queued for
each incoming frame. When a hole filling frame arrives, the data is delivered
through the callback `picoquic_callback_stream_data` and the data node
is recycled. The data nodes will also be recycled if the stream is reset
or the connection is closed.

  