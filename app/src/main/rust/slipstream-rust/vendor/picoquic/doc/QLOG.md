# How To Produce QLOG files with picoquic

picoquic can produce [QLOG](https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/) compatible files.

To create QLOG files picoquic requires binary logging to be enabled while serving the connection for which a QLOG should be created. Once the connection is closed, the binary log files from client and server can be converted into the QLOG format with the picolog utility.

## Create Binary Log File

### Command line

Binary logging can be enabled on the command line with the `-b` parameter. `-b` expects a path to the binary log file.

Binary logging can be used for clients and for servers.


```
picoquicdemo -b <path_to_binary_log> [...]
```

### C Interface

Binary logging can be enabled in the C interface by calling `picoquic_set_binlog(quic, path)` by providing the quic context that should start logging and the path to the binary log file.

## Convert Binary Log Files to QLOG

Once the log file has been created, it can be converted using the `picolog` utility.

Calling

```
picolog -f qlog <path_to_binary_log>
```

would create a QLOG file for each connection found in the binary log. If only one connection should be converted, the connection id of that connection must be specified with command line parameter `-c`.

```
picolog -f qlog -c <connection_id> <path_to_binary_log>
```

For more information about `picolog` call

```
picolog -h
```

