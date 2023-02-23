FROM --platform=linux/amd64 mice-base as base

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

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    libpcap0.8 \
    iputils-ping \
    net-tools \
    netcat \
    tcpdump \
    iptables \
    texlive && \
    apt-get clean
WORKDIR /app/
COPY endpoint/requirements.txt .
RUN pip3 install -r requirements.txt

COPY endpoint /app/endpoint

WORKDIR /app/endpoint/

ENV NUM_RUNS=1
ENV SOCKET_PROTOCOL="tcp"
ENV LOG_DIR="./"
ENV EVENT_PATH="/logging/events.txt"

FROM rust:1.61 as censorlab
WORKDIR /usr/src/myapp
COPY censorlab ./censorlab
ENV ORT_STRATEGY download
WORKDIR ./censorlab
RUN cargo build
RUN apt update && apt install -y python3 python3-pip && pip install onnxruntime
CMD cargo run --bin censorlab -- nfq 123.123.123.2

FROM base as client
CMD python3 main.py \
    --src ${CLIENT_HOST} \
    --sport ${CLIENT_PORT} \
    --dst ${SERVER_HOST} \
    --dport ${SERVER_PORT} \
    --replay-for ${PLAY_TIME} \
    --num-runs ${NUM_RUNS} \
    --save-payloads ${PAYLOAD_PATH} \
    --config ${PAYLOAD_PATH} \
    --protocol ${SOCKET_PROTOCOL} \
    --log-dir ${LOG_DIR} \
    --event-log-path ${EVENT_PATH}

FROM base as server
CMD python3 main.py \
    --src ${SERVER_HOST} \
    --sport ${SERVER_PORT} \
    --dst ${CLIENT_HOST} \
    --dport ${CLIENT_PORT} \
    --replay-for ${PLAY_TIME} \
    --num-runs ${NUM_RUNS} \
    --save-payloads ${PAYLOAD_PATH} \
    --config ${PAYLOAD_PATH} \
    --protocol ${SOCKET_PROTOCOL} \
    --server \
    --log-dir ${LOG_DIR} \
    --event-log-path ${EVENT_PATH}
