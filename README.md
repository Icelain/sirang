# An Experimental TCP Tunnel over QUIC

## Install
Install through cargo with ```cargo install sirang``` <br>
### OR <br>

Install from the [Github Releases](https://github.com/Icelain/sirang/releases) page

### OR <br>
Clone the repo and compile with ```cargo build --release```

## Running a Forward Tunnel

### On your remote server:
```
sirang forward [GENERAL_OPTIONS] remote [OPTIONS] --key <PATH> --cert <PATH> --forwardaddr <ADDRESS>
```
Here, ```--key``` and ```--cert``` and your tls key and tls certificate respectively.
```--forwardaddr``` is the remote tcp_address you're forwarding your traffic to.

By default, the remote quic server starts on address `0.0.0.0:4433`.
To change this, you can specify the optional argument ```--quicaddr``` to start the quic server on your preferred address.

### On your local machine:
```
sirang forward [GENERAL_OPTIONS] local [OPTIONS] --cert <PATH> --remoteaddr <ADDRESS>
```
Here, ```--cert``` is the tls certificate of the remote server and ```--remoteaddr``` is the address of the remote quic server created with ```sirang forward remote```.

By default, the local tcp server starts on `127.0.0.1:8080`.
To change this, you can specify the optional argument ```--localaddr``` to start the tcp server on your preferred address.

## Running a Reverse Tunnel

### On your remote server:
```
sirang reverse [GENERAL_OPTIONS] remote [OPTIONS] --key <PATH> --cert <PATH>
```
Here, ```--key``` and ```--cert``` and your tls key and tls certificate respectively.

By default, the remote quic server starts on address `0.0.0.0:4433` and the default tcp server starts on address `0.0.0.0:5000`.
To change this, you can respectively specify the optional arguments ```--quicaddr``` and ```--tcpaddr``` to start the quic and tcp servers on your preferred addresses.

### On your local machine:
```
sirang reverse [GENERAL_OPTIONS] local --cert <PATH> --localaddr <ADDRESS> --remoteaddr <ADDRESS>
```
Here, ```--cert``` is the tls certificate of the remote server and ```--remoteaddr``` is the address of the remote quic server created with ```sirang reverse remote```.

The argument ```--localaddr``` specifies the local tcp server you want to tunnel to.

## General Options:

To turn on debug logging, use ```--debug``` before either command. <br/>
To set the buffer size(in bytes), use ```--buffersize``` before either command. The default buffer size is 32KB.

## Progress

- [x] Functionality
- [x] Debug Logging
- [x] Testing
