# DNS Cache Poisoning

An exercise in exploiting the DNS Cache poisoning attack, that was demonstrated by Dan Kaminsky in 2008. 

An illustration of the attack can be found [Here](http://unixwiz.net/techtips/iguide-kaminsky-dns-vuln.html)

This project has two parts building up to the attack - in the first, I build a simple DNS proxy (`dnsproxy.py`) that can be used to spoof DNS replies. The second, `poison.py` is an extension of this idea, leading to the Kaminsky attack - poisoning an entire server by spoofing replies.

## Setup

We will be using the popular BIND (Berkeley Internet Name Domain) program for getting and resolving DNS queries. Also, the user will need Python's Scapy library to run the files (specifically, version 2.3.3).

### 1. Configuring BIND

(Note: The BIND server has been patched so that one doesn't need to spoof IP address of the sent packet such that the IP address matches that of the remote name server. This is because this needs sudo access, which is not always available. In an actual attack scenario, this is required.)

#### Configuration Files

In `etc/`, you will find two files: `named.conf` and `rndc.conf`. You will need to pick random port numbers, <ins>greater than 1024</ins> (unless you have root access), and modify the following parameters in the above-mentioned files:

<ins>rndc.conf</ins>

```txt
options {
  default-key “rndc-key”; 
  default-server 127.0.0.1; 
  default-port <RNDC port number>;
};
```

<ins>named.conf</ins>

```txt
options {
    ...
    query-source port <query port>;
    ...
    listen-on-port <NAMED port number> { any; };
};
...
controls {
    inet 127.0.0.1 port <RNDC port number>
    allow { 127.0.0.1; } keys { “rndc-key”; };
};
```

- `query-source port` specifies the port number BIND will use to send its outgoing queries to external DNS servers.
- `listen-on port` specifies the port number BIND will use to listen for DNS queries.

#### Running

To run the BIND server, run the script `./run_bind sh`
To enable logging of queries received by BIND, do `./bin/rndc -c etc/rndc.conf querylog`

### 2. Installing Scapy

`pip install scapy==2.3.3 --user`

Verify successful installation by opening the interpeter:

```python
>>> import scapy
>>> exit()
```

Importing the scapy module should not raise any errors.

During the installation and actualy running of scapy, the following warnings and errors can be safely ignored: `SNIMissingWarning`,`InsecurePlatformWarning` and `Exception RuntimeError: 'maximum recursion depth exceeded while calling a Python object' in <type 'exceptions.AttributeError'> ignored`.

## Running the Code

- DNS Proxy Spoofer: open 3 terminals.
  - Terminal 1: `./run_bind.sh`
  - Terminal 2: `python dnsproxy --port <Proxy Port #> --dns_port <named..conf listen-on port> --spoof_response <include if you want to spoof>`
  - Terminal 3 : `dig @127.0.0.1 example.com -p <Proxy Port #>` (if you are spoofing, stick to example.com for demo purposes)
- Cache Poisoning Exploit: 
  - Terminal 1 : `./run_bind.sh`
  - Terminal 2 : `python poison.py --ip <BIND ip> --port <named..conf listen-on port> --query_port <named.conf query-source port>`

If you want to run the attack multiple times, you need to kill and restart the server because the cache got poisoned, what did you expect ;)
