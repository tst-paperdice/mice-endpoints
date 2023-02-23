# mice-endpoints

Repo for measurement client and server codebases (e.g. packet generation, censorship signal detection, etc.) including the censorlab submodule.

## Running on a single host
You can run both endpoints (client and server) as well as the censorlab as docker containers all on a single host just by running:
$ sudo run.sh

This is tested to work on galileo - will almost certainly only work in linux environments because it is doing some networking stack fanciness.

When it is finished you can see the host-level capture of traffic in mice-pktgen.pcap and the view from the server container in server-mount/server.pcap.

### Options:
-b will skip rebuilding the images. Handy for retesting things; however, because the endpoints generate traffic based on a docker COPY'd config.json they must be rebuilt to change traffic patterns.

-c will skip running the censorlab. Handy for testing just the base endpoint connectivity is working.

## Running on separate hosts (has not been verified in a while)
The two endpoints can be run on different hosts (if you want to still use the censorlab, it will need to be run on the host alongside the endpoint-server and verifying it is still properly intercepting traffic from external systems bound to the endpoint-server has not been done).


Replace the values in ./docker/endpoint/build_env with the correct server and client IPs and Ports, and the amount of time you would like the traffic to be generated for (in float seconds, 0.0 for just sending the trigger traffic once).

### On the client host:
$ docker build --target client -t endpoint-client:latest docker/.
$ docker run \
    --ip 123.123.123.2 \
    -p 123.123.123.2:12345:12345/tcp \
    --env-file docker/endpoint/build_env \
    --name=endpoint-client --rm \
    endpoint-client:latest

Replace 123.123.123.2 and 12345 with the correct IP for the client and the port to send from.


### On the server host:
$ docker build --target server -t endpoint-server:latest docker/.
$ docker run \
    --ip 123.123.123.2 \
    -p 123.123.123.2:12345:12345/tcp \
    --env-file docker/endpoint/build_env \
    --name=endpoint-server --rm \
    endpoint-server:latest

Replace 123.123.123.2 and 12345 with the correct IP for the client and the port to receive to.

## Running Outside Docker
Synopsis: Install dependencies on the client and server hosts and then run the main.py script with the proper arguments.

$ cd ./docker/endpoint/
$ pip3 install -r requirements.txt

# Client:
$ python3 main.py \
     --src ${CLIENT_HOST} \
    --sport ${CLIENT_PORT} \
    --dst ${SERVER_HOST} \
    --dport ${SERVER_PORT} \
    --replay-for ${PLAY_TIME}

# Server:
python3 main.py \
    --src ${SERVER_HOST} \
    --sport ${SERVER_PORT} \
    --dst ${CLIENT_HOST} \
    --dport ${CLIENT_PORT} \
    --replay-for ${PLAY_TIME} \
    --server

## Outstanding Issues

### TCP Flushing
Because we using a normal TCP socket (as opposed to a raw socket) we don't directly control when the actual packets are sent, just when we provide data to send. Thus, if we set delays too short between consecutive packets from the same source, the TCP stack may merge both messages into a single packet. There is likely something we can do here, like the equivalent of a "flush" action that forces the TCP stack to send what it has now, rather than "implicitly flushing" by having a long enough delay.

### Raw TCP Support
A significant problem with our endpoint TCP code is that we don't control ACKs because we are not using raw TCP sockets (thus the system's TCP stack automatically sends an ACK back). We should extend the endpoint code to use raw TCP sockets so that we can control ACK packets (e.g. in a real bidirectional application you likely get fewer ACK-only packets because the other side has data to send back along with the ACK).

Raw TCP sockets generally result in RST packets being sent by the OS of the receiver because it does not recognize the socket as "actually opened." A standard way to get around this is to add an iptables rules to drop outgoing RST packets; NOTE a very important thing to _not_ do is block _incoming_ RST packets since that will break testing the censor sending RSTs as a censorship action.

Once Raw TCP is supported the traffic Scripts will need to specify flags for packets (such as ACK and SYN).

