# auto-mtls-client-server-cli

This is a cross-platform go tool to demonstrate the implementation of mTLS (Mutual TLS) and how useful it can help
to setup authorization on top of TLS certificate - known as Certificate Bound Token. This program could be run into
client or server mode through the mention of flag --client or --server respectively. Only the server mode generates
both Root/server and Client CA certificates. These are saved to a fixed location on disk and deleted once server exits.



## Table of contents
* [Technologies](#technologies)
* [Setup](#setup)
* [Usage](#usage)
* [License](#license)


## Technologies

This project is developed with:
* Golang version: > 1.16
* Native libraries only


## Setup

On Windows, Linux macOS, and FreeBSD you will be able to download the pre-built binaries once available.
If your system has [Go >= 1.16](https://golang.org/dl/) you can pull the codebase and build from the source.

```
# build the auto-mtls-client-server-cli program on windows
git clone https://github.com/jeamon/auto-self-signed-mtls-with-certs-bound-token.git && cd auto-self-signed-mtls-with-certs-bound-token
go build -o mtls-client-server-cli.exe mtls-client-server-cli.go

# build the auto-mtls-client-server-cli program on linux and others
git clone https://github.com/jeamon/auto-self-signed-mtls-with-certs-bound-token.git && cd auto-self-signed-mtls-with-certs-bound-token
go build -o mtls-client-server-cli mtls-client-server-cli.go
```


## Usage


```Usage:
    
    mtls-client-server-cli [--client] [--server] [--help] [--version] [--certs <path-to-ca-certificates>] 


Options:

    -client   Specify to run the program into client mode.
    -server   Specify to run the program into server mode.
    -version  Display the current version of this program.
    -help     Display the help - how to use this program.
    -port     Specify the port where the server should listen.
    -ip       Specify the ip address where to bind the server.


Arguments:

    <path-to-ca-certificates>  path to both root & clients CA certificates folder.


You can run this tool into two different modes (client or server) by specifying the flags --client or
--server. In both mode, you can define the server's ip address and/or port number. By default --ip 
address is localhost (127.0.0.1) and --port is 8443. When these values are mentionned into client mode,
it means the address where the client should connect. Also, in client mode, you can specify the path of 
the parent folder (with --certs flag) from where to load the root/server CA certificate (to authenticate
the server) and client CA certificate (to sign the client auto-generated certificate). If not provided
the client will expect to find them from a folder named certificates inside the same working directory.
Only into server mode that both CA certificates are generated, this means you must run the server before.
Finally, you can display the instructions with the --help flag and the version with --version flag.


Examples:

    $ mtls-client-server-cli --version
    $ mtls-client-server-cli --help
    $ mtls-client-server-cli --client
    $ mtls-client-server-cli --server
    $ mtls-client-server-cli --client --ip 127.0.0.1 --port 8443 --certs certificates
    $ mtls-client-server-cli --client --ip 127.0.0.1 --port 8443
    $ mtls-client-server-cli --server --ip 127.0.0.1 --port 8443
	
```


## License

please check & read [the license details](https://github.com/jeamon/auto-self-signed-mtls-with-certs-bound-token/blob/master/LICENSE) or [reach out to me](https://blog.cloudmentor-scale.com/contact) before any action.