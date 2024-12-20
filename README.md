# An Experimental TCP Tunnel over QUIC

## Build
Clone the repo and compile with ```cargo build --release```

## Run

### On your remote server:
```
sirang [OPTIONS] remote [OPTIONS] --key <PATH> --cert <PATH> --forwardaddr <ADDRESS>
```
Here, ```--key``` and ```--cert``` and your tls key and tls certificate respectively.
```--forwardaddr``` is the remote tcp_address you're forwarding your traffic to.

By default, the remote quic server starts on address `0.0.0.0:4433`.
To change this, you can specify the optional argument ```--addr``` to start the quic server on your preferred address.

### On your local machine:
```
sirang [OPTIONS] local [OPTIONS] --cert <PATH> --remoteaddr <ADDRESS>
```
Here, ```--cert``` is the tls certificate of the remote server and ```--remoteaddr``` is the address of the remote quic server created with ```sirang remote```.

By default, the local tcp server starts on `127.0.0.1:8080`.
To change this, you can specify the optional argument ```--localaddr``` to start the tcp server on your preferred address.

### General

To turn on debug logging, use ```--debug``` before either command. <br/>
To set the buffer size, use ```--buffersize``` before either command.

## Progress

- [x] Functionality
- [x] Debug Logging
- [ ] Testing
- [ ] Benchmarking
