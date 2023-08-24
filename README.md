In this repository you can find example UDP server which uses BPF to distribute traffic between two threads. It was implemented using official documentation but sadly it does not work as expected.

Sadly attempt to launch second thread in reuse port group fails:
```
./reuseport 
Netflow plugin will listen on 0.0.0.0:2056 udp port
Netflow plugin will listen on 0.0.0.0:2056 udp port
Setting reuse port
Loading BPF to implement random UDP traffic distribution over available threads
Successfully loaded reuse port BPF
Setting reuse port
Loading BPF to implement random UDP traffic distribution over available threads
Successful bind
Started capture
Successfully loaded reuse port BPF
Can't bind on port: 2056 on host 0.0.0.0 errno:98 error: Address already in use
```

How to build

```
make
```

Platform information: Ubuntu 22.04 6.2.0-26-generic.
