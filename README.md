## RPCAPd

#### build instructions for macOS

* `brew install cmake openssl libpcap`
* `cmake . -DPCAP_ROOT_DIR=/usr/local/opt/libpcap -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@3`
* `make`
