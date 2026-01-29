# The picoquic code sample

The picoquic sample code in the "sample" folder builds a single executable, `picoquic_sample`.
This is a simple file transfer program that can be 
instantiated in client or server mode. The program can be instantiated
as either:
~~~
picoquic_sample client server_name port folder *queried_file
~~~
or:
~~~
picoquic_sample server port cert_file private_key_file folder
~~~
The client opens a quic connection to the server, and then fetches 
the listed files. The client opens one bidir client stream for each
file, writes the requested file name in the stream data, and then
marks the stream as finished. The server reads the file name, and
if the named file is present in the server's folder, sends the file
content on the same stream, marking the fin of the stream when all
bytes are sent. If the file is not available, the server resets the
stream. If the client receives the file, it writes its content in the
client's folder.

Server or client close the connection if it remains inactive for
more than 10 seconds.

The purpose of the sample is not to provide example of using the
picoquic API to build a simple application. The current code is
limited: it does not use the "configuration" API to set parameters
of the picoquic endpoint, and it does not demonstrate how to run
picoquic in a background thread.