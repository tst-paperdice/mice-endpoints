#!/bin/bash

# Copyright 2023 Two Six Technologies

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Usage: sudo bash run.sh

# Create the dummy network interface tap0.
# Ref: https://superuser.com/a/750412
# Ref: https://linuxconfig.org/configuring-virtual-network-interfaces-in-linux

USE_CENSOR=true
BUILD=true
TAG=main
MODEL_BASE=model
POISON_BASE=config
while getopts "hcbt:m:p:" arg; do
    case $arg in
        h)
            echo "$0 usage:" && grep " .)\ #" $0; exit 0;
            ;;
        c) # Do NOT run the censor
            USE_CENSOR=false
            echo "Not Running Censor"
            ;;
        b) # SKIP rebuilding containers
            BUILD=false
            echo "Skipping Build"
            ;;
        t) # Tag for images to use (and build unless -b)
            TAG=$OPTARG
            echo "Using tag: ${TAG}"
            ;;
        m) # Model file basename (.json and .onnx.ml are attached)
            MODEL_BASE=$OPTARG
            echo "Using model ${MODEL_BASE}.json ${MODEL_BASE}.onnx.ml"
            ;;
        p) # Poison script basename (.json is attached)
            POISON_BASE=$OPTARG
            echo "Using script ${POISON_BASE}.json"
            ;;
    esac
done

CLIENT_IP=123.123.123.2
SERVER_IP=123.123.123.3
sudo modprobe dummy
sudo ip link add mice-dummy type dummy
sudo ip link set dev mice-dummy address AA:AA:AA:AA:AA:AA
sudo ip addr add 123.123.123.0/24 brd + dev mice-dummy
sudo ip link set dev mice-dummy up
echo "The dummy network interface mice-dummy is now available."

# Create the Docker network mice-net that inherits from tap0.
docker network create \
    --driver macvlan \
    --subnet 123.123.123.0/24 \
    --gateway 123.123.123.254 \
    --opt parent=mice-dummy \
    mice-net
echo "The Docker network mice-net is now up."

# Sniff network traffic from tap0
touch mice-pktgen.pcap
chmod 777 mice-pktgen.pcap
tshark -i mice-dummy -w mice-pktgen.pcap &

# Run pktgens using the mice-net networks.

# Optional: build the images:

if [ "$BUILD" = true ]; then
    docker build --target client -t endpoint-client:${TAG} docker/.
    docker build --target server -t endpoint-server:${TAG} docker/.
    if [ "$USE_CENSOR" = true ]; then
        docker build --target censorlab  -t censorlab:${TAG} docker/.
    fi
fi

echo "Running endpoint-server"
docker run \
    --rm \
    --network mice-net \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --ip ${SERVER_IP} \
    -p ${CLIENT_IP}:12345:12345/tcp \
    --env PAYLOAD_PATH=${POISON_BASE}.json \
    --env-file docker/endpoint/build_env \
    --name=endpoint-server --rm \
    --volume $(pwd)/server-mount/:/logging/ \
    --volume $(pwd)/docker/endpoint:/app/endpoint \
    endpoint-server:${TAG} &


sleep 10

echo "Running tcpdump on server"
docker exec endpoint-server tcpdump -i eth0 -w /logging/server.pcap &

if [ "$USE_CENSOR" = true ]; then
   echo "Running censorlab"
   docker exec endpoint-server iptables -t raw -A PREROUTING -s 123.123.123.0/24 -j NFQUEUE --queue-num 0
   docker run \
        --rm \
        --net=container:endpoint-server \
        --env-file docker/endpoint/build_env \
        --volume $(pwd)/docker/endpoint/:/model-volume/ \
        --name=censorlab --rm --cap-add=NET_ADMIN censorlab:${TAG} &
   sleep 5
   
   echo "Model load command sent"
   CENSORLAB_ID=$(docker ps | grep censorlab | cut -d' ' -f1 | tail -n-1)
   docker exec $CENSORLAB_ID cargo run --bin ipc_client send-model  \
          Tcp \
          /model-volume/${MODEL_BASE}.onnx.ml \
          /model-volume/${MODEL_BASE}.json
   
   sleep 10
fi

echo "Running endpoint-client"
docker run \
    --rm \
    --network mice-net \
    --ip ${CLIENT_IP} \
    -p ${CLIENT_IP}:12345:12345/tcp \
    --env-file docker/endpoint/build_env \
    --env PAYLOAD_PATH=${POISON_BASE}.json \
    --name=endpoint-client \
    --volume $(pwd)/client-mount/:/logging/ \
    --volume $(pwd)/docker/endpoint:/app/endpoint \
    endpoint-client:${TAG} 

# Shut down the censor
if [ $(docker ps -f name=censorlab -q) ]; then
    docker kill censorlab
fi

if [ $(docker ps -f name=endpoint-client -q) ]; then
    docker kill endpoint-client
fi

if [ $(docker ps -f name=endpoint-server -q) ]; then
    docker kill endpoint-server
fi


# Tear down network interfaces.
docker network rm mice-net
echo "The Docker network mice-net has been deleted."


ip addr del 123.123.123.0/24 brd + dev mice-dummy
ip link delete mice-dummy type dummy
echo "The dummy network interface mice-dummy has been deleted."

rmmod dummy
