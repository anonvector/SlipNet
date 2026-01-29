# Memory management

Picoquic was initially designed for performance, with a choice to allocate
as much memory as necessary for maximal use of network resource. This
is a fine strategy in many cases, but it breaks when the supporting device
as limited resource. For example, we see
[deployment issues](https://github.com/private-octopus/picoquic/issues/1499)
with the application allocating hundreds of megabytes to ongoing connections
when doing connections at gigabit per seconds, which is a problem if the
supporting device has limited resource. The memory allocation on the
sender is largely a function of the bandwidth-delay product (BDP), but
occurence of packet losses can increase the requirements. The situation is
different on senders and receivers. The current version provides 2 APIs
to manage memory usage per connection at the sender and the receiver:
`picoquic_set_cwin_max` and `picoquic_set_max_data_control`.

## Sender side memory use and management

The sender consumes memory for a variety of tasks, but in common applications
the bulk of the memory is used for packet management. The life of a packet
goes through a series of steps:

* when ready to send, the code prepares an empty packet, then tries to fill it
  with a variety of frames, such as acknowledgement, stream data, or various
  control frames.
* if there is nothing to send, the packet memory is released. Otherwise,
  an encrypted version of the packet is passed to the network for
  transmission, and the clear text version is kept in a queue of packets
  waiting for acknowledgement.
* if a timely acknowledgement is received, the frames in the packet are
  marked as processed. For example, if the packet contained stream data,
  the corresponding bytes are marked as received. The code updates
  RTT measurements and congestion control state, and the packet memory
  is released.
* If the packet is not acknowledged in time, it is marked lost. The frames
  in the packet are extracted and if necessary queued for transmission. If
  the packet contained data frames, it is queued for data frame retransmission.
  Then, the packet is moved to the "loss confirmation" queue. (The packet may
  be present in both the stream data retransmission and the loss confirmation
  queue, but it is not duplicated.)
* In some cases, the acknowledgement of a packet arrives late, after
  it was considered lost. If the packet is in the "loss confirmation"
  queue, the frames in the packet are examined and marked as received,
  RTT and congestion control state are updated. Then, the packet memory
  is released.
* When the code finally decides that no acknowledgement will arrive, and
  the stream frame have been repeated in other packets, the
  packet memory is released.

If the packet loss rate is small, the bulk of the memory is dedicated to
the list of packets that have benn sent and are neither acknowledged or
declared lost. These packets are considered "in transit", and the size of
the data in transit is limited by the congestion window.

If many packets are lost, we will see many packets in the "loss confirmation"
queue. We will also see packets stay in the "not yet acknowledged"
queue until they are declared lost. This will tend to increase the memory
used by these two queues. 

The value of the congestion window is determined by the selected congestion
control algorithm, such as for example Cubic or BBR. In general that's fine,
but there can be bugs or unforeseen circumstances causing the window to become
really large. The solution is to set a cap to the maximum window size, so
that even if the congestion control is too optimistic, the memory size will
still be limited. The API to do that is:
~~~
void picoquic_set_cwin_max(picoquic_quic_t* quic, uint64_t cwin_max);
~~~
The cap will apply to all the connection managed in the specified QUIC context,
because all these connections share the same memory pool. 

## Receiver side memory management

In normal circumstances, a QUIC receiver only need a small amount of memory
to receive packets, process them, and submit them to the application. But QUIC
guarantees that stream data will be delivered in sequence to the application,
which leads to "head of line blocking". In the worse case scenario, all data
is sent to a single stream. In case of packet loss, all data received on that
stream must be buffered until the loss is corrected, which typically requires
one round trip but might require two or more in the rare cases where the
repeated packet is itself lost, and maybe the repeat of that, etc.

QUIC includes flow control mechanisms so receivers can limit how many streams
the peer opens, how much data can be sent on individual streams, and how much
data can be sent on all the streams. By default, picoquic enforces the number
of streams limit, limit the number of concurrent streams that the peer can open
to the initial value set in the transport parameters `initial_max_stream_id_bidir`
or `initial_max_stream_id_unidir`. In contrast, picoquic by default automatically
increases the amount of data that can be sent per stream or globally, because
flow control tends to limit performance. This has a cost: if the peer sends
to much data, head of queue blocking can force the receiver to allocate
excessive amounts of memory.

Implementations that want to control that maximum amount of memory can use this API:
~~~
void picoquic_set_max_data_control(picoquic_quic_t* quic, uint64_t max_data);
~~~
Note that, per the QUIC protocol, endpoints that grant flow control credits cannot
withdraw them. If the application sets the maximum flow control limit upon
initialization, it will be applied to all connections. If the application sets
it after connections have started and have granted flow control credits, the
limit will only be applied once these credits have been consumed.

The memory allocated can exceed the flow control limit, because the memory
is allocated for each QUIC packet that the application receives. This was
done to avoid copying the data twice, once upon decrypting the packet, and
another when queuing the packet for later delivery on a stream. Instead,
the code keeps a copy of the received packet in memory until the stream data
has been delivered. If the peer sends packets in small data frames, the
amount of memory used will be significantly higher than the flow control
limit. (OK, arguably this is a bug, or a bad trade-off between performance
and memory allocation. We may need to fix that.)

## No global limit yet

In theory, we could devise an algorithm that automatically sets the sender or
receiver cap based
on the overall amount of memory available. For example, an algorithm could
monitor the total number of packets allocated across all connections,
lower the cap if the packets queue are too large, and progressively lift
it when conditions stabilize. But in practice this will require some work...


