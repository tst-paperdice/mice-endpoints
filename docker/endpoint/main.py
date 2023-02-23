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

import argparse
from collections import deque
import json
import math
import multiprocessing as mp
import socket
import time
import traceback
from base64 import b64decode, b64encode
from enum import Enum
from pprint import pprint
from telnetlib import IP
from typing import Any, Dict, List, NamedTuple, Optional, Tuple
import logging

import numpy as np
from scapy.all import *
from scipy import stats

from ScriptEntry import ScriptEntry
from PacketBuilder import PacketBuilder

def fg_mp_helper(cfg: ScriptEntry, mode: str, epsilon: float, pb: PacketBuilder):
    return cfg.id, pb.make_packet(cfg.size, cfg.entropy, epsilon=epsilon)


class TCPFlowGenerator:

    SOCKET_TIMEOUT = 5.0

    def __init__(self, args: argparse.Namespace, logger: logging.Logger):
        self.logger = logger
        self.config = ScriptEntry.load_file(args.config)
        self.args = args
        self.packet_builder = PacketBuilder(seed=self.args.seed)
        protocol = self.config[0].protocol
        if not all(el.protocol == protocol for el in self.config):
            self.logger.error(f'All protocols must match in config json file: {args.config}')
            raise RuntimeError(f'All protocols must match in config json file: {args.config}')
        self.args.protocol = protocol
        if args.server:
            self.mode = "server"
        else:
            self.mode = "client"
        self.logger.info("Initializing payloads. This may take a while...")
        self.messages = self.make_message_dict(self.mode)
        self.logger.info(f"Payload generation complete. Generated {len(self.messages)} payloads.")
        if args.save_payloads:
            self.logger.info(f"Saving script with payloads to {args.save_payloads}")
            with open(args.save_payloads, 'w') as f:
                json.dump([obj.to_json() for obj in self.config], f, indent=4)
        self.event_log = open(f"{self.args.event_log_path}", "w", buffering=1)
        self.censor_queue = deque()

    def run_capture(self):
        # source = SniffSource(iface=conf.iface, filter=f"not src host {self.args.src}")
        source = SniffSource(iface=conf.iface)
        capture_sink = WrpcapSink(f"{self.args.capture_path}")

        class ResetCheck(Sink):
            def __init__(self, event_log, censor_queue):
                Sink.__init__(self)
                self.event_log = event_log
                self.closing = False
                self.censor_queue = censor_queue
            def push(self, pkt):
                if pkt and TCP in pkt:
                    if "F" in pkt[TCP].flags:
                        self.closing = True
                    if "FA" in pkt[TCP].flags:
                        self.closing = False
                    if "R" in pkt[TCP].flags and not self.closing:
                        self.event_log.write(pkt.sprintf(
                            "%.time% %-20s,IP.src%%IP.sport% -> %-20s,IP.dst%%IP.dport% %IP.chksum% "
                            "%03xr,IP.proto%, possible censorship, unexpected RESET\n"
                        ))
                        self.censor_queue.append("RESET")

            def high_push(self, pkt):
                self.push(pkt)

        class ProbeCheck(Sink):
            def __init__(self, event_log, expected_addr, expected_port, self_addr):
                Sink.__init__(self)
                self.event_log = event_log
                self.expected_addr = expected_addr
                self.expected_port = expected_port
                self.self_addr = self_addr

            def push(self, pkt):
                if IP in pkt:
                    if pkt[IP].src == self.self_addr:
                        return
                    if pkt[IP].src != self.expected_addr:
                        if pkt[IP].dport != self.expected_port:
                            self.event_log.write(
                                pkt.sprintf(
                                    "%.time% %-20s,IP.src%%IP.sport% -> %-20s,IP.dst%%IP.dport% %IP.chksum% "
                                    "%03xr,IP.proto%, PROBE WRONGPORT\n"
                                )
                            )
                        else:
                            self.event_log.write(
                                pkt.sprintf(
                                    "%.time% %-20s,IP.src%%IP.sport% -> %-20s,IP.dst%%IP.dport% %IP.chksum% "
                                    "%03xr,IP.proto%, PROBE RIGHTPORT\n"
                                )
                            )

            def high_push(self, pkt):
                self.push(pkt)

        source > capture_sink
        # TODO: can I remove probe and reset checks for now? Is David working on this out of band?
        source > ProbeCheck(
            self.event_log, self.args.dst, self.args.sport, self.args.src
        )
        source > ResetCheck(self.event_log, self.censor_queue)

        self.cap_pipeline = PipeEngine(source)
        self.cap_pipeline.start()
        time.sleep(1)  # give time for sniff to start

    def stop_capture(self):
        self.cap_pipeline.stop()
        self.event_log.close()

    def run_session(self):
        if self.args.protocol == "tcp":
            sock_type = socket.SOCK_STREAM
        elif self.args.protocol == "udp":
            sock_type = socket.SOCK_DGRAM

        with socket.socket(socket.AF_INET, sock_type) as sock:
            if self.args.server:
                self.logger.info(f"binding to {self.args.src}:{self.args.sport} ...")

                # TODO: changed this to work with cloud infra. May need to re-enable src.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", self.args.sport))
                # sock.bind((self.args.src, self.args.sport))
                self.logger.debug("bind complete")

                # del self.args.dport

                if self.args.protocol == "tcp":
                    self.logger.debug("listening...")
                    sock.listen()

                    self.logger.debug("waiting to accept...")
                    conn, addr = sock.accept()
                    self.logger.debug(f"accepted by {addr}")

                    conn.settimeout(self.SOCKET_TIMEOUT)
                    return self._comm_loop(conn)
                elif self.args.protocol == "udp":
                    return self._comm_loop(sock)
                else:
                    raise Exception(f"invalid protocol: {self.args.protocol}")
            else:
                if self.args.protocol == "tcp":
                    start = time.time()
                    while True:
                        if time.time() > start + 30:
                            self.logger.warning(
                                f"timed out trying to connect to {self.args.dst}:{self.args.dport}"
                            )
                            return
                        try:
                            self.logger.debug(
                                f"connecting to {self.args.dst}:{self.args.dport} ..."
                            )
                            sock.connect((self.args.dst, self.args.dport))
                            break
                        except ConnectionRefusedError:
                            self.logger.warning("connection refused. retrying...")
                            time.sleep(1)
                            continue
                    self.logger.debug("connected")
                    sock.settimeout(self.SOCKET_TIMEOUT)
                elif self.args.protocol == 'udp':
                    sock.bind((self.args.src, self.args.sport))
                return self._comm_loop(sock)

    def make_message_dict(self, mode: str) -> Dict[str, Dict[str, Any]]:
        # use multiprocessing to speed things up
        # the function evaluated and the arguments must be picklable,
        # so pack things neatly
        # Only need to generate if there was no sample already provided
        pool_input = [
            (elt, mode, self.args.epsilon, self.packet_builder)
            for elt in self.config
            if (len(elt.sample) == 0 and elt.size != 0)
        ]
        self.logger.info(f"Have to dynamically generate payloads for {len(pool_input)} packets")

        res = []
        if len(pool_input):
            with mp.Pool(mp.cpu_count()) as pool:
                res = pool.starmap(fg_mp_helper, pool_input)
                pool.close()
                pool.join()

        self.logger.debug("pool complete")

        # package things into a neat dict so we don't need to think
        # about how the tuple is structured lately
        ret = {
            elt.id: {"payload": list(b64decode(elt.sample)), "entropy": elt.entropy}
            for elt in self.config
        }

        for elt in res:
            if elt == None:
                continue
            d = {"payload": elt[1][0], "entropy": elt[1][1]}
            ret[elt[0]] = d

        # overwrite our initially loaded packet script with these generate payloads
        self.config = [
            ScriptEntry(
                *elt[:-1],
                sample=b64encode(bytes(ret[elt.id]["payload"])).decode("ascii"),
            )
            for elt in self.config
        ]

        return ret

    def _comm_loop(self, sock: socket.SocketType) -> None:
        done = False
        next_msg = None

        # first message is the only one with no dependence
        start_msg = [msg for msg in self.config if msg.dependence == ""][0]

        config_as_dict = ScriptEntry.make_dict(self.config)
        stop_time = time.time() + self.args.replay_for
        start_time = math.inf # Keep track of the timestamp when conversation most recently started

        while not done:
            if next_msg is None:
                next_msg = start_msg

            if self.censor_queue:
                # TODO: handle behavior change
                pass

            if self.mode == next_msg.origin:
                if next_msg.delay != 0:
                    time.sleep(next_msg.delay)
                self.logger.debug(f"sending {next_msg.id=}, {self.args.dst=}")
                payload = bytes(self.messages[next_msg.id]["payload"])
                if self.args.protocol == "tcp":
                    try:
                        sock.send(payload)
                    except BrokenPipeError as e:
                        logger.warning(e)
                        done = True
                elif self.args.protocol == "udp":
                    sock.sendto(payload, (self.args.dst, int(self.args.dport)))

            else:
                self.logger.debug(f"receiving {next_msg.id=}")
                if next_msg.delay != 0:
                    time.sleep(next_msg.delay)
                if self.args.protocol == 'tcp':
                    try:
                        payload = sock.recv(next_msg.size)
                    except ConnectionResetError as err:
                        self.logger.error(f"connection reset while waiting to receive {next_msg.id=}: {str(err)}")
                        self.censor_queue.append("CONNECTION RESET")
                        payload = b'' # Mark as empty payload, to be caught for possible censorship
                    except socket.timeout as err:
                        self.logger.error(f"connection timed out while waiting to receive {next_msg.id=}: {str(err)}")
                        self.event_log.write(f"{time.time()} possible censorship, connection timed out waiting to receive {next_msg.id}: {str(err)}")
                        self.censor_queue("CONNECTION TIMEOUT")
                        payload = b'' # Mark as empty payload, to be caught for possible censorship
                        done = True # If there's a timeout, just break out
                elif self.args.protocol == 'udp':
                    try:
                        payload = sock.recvfrom(next_msg.size)[0]
                    except socket.timeout:
                        # Testing with run.sh, end time discrepancy between client and server has been 
                        # less than 0.4 seconds, arbitrarily chose 1.0 for some wiggle room
                        if abs(stop_time - start_time) <= 1.0:
                            self.logger.warning('UDP corner case socket timeout, gracefully closing')
                            done = True
                            continue
                        else:
                            payload = b'' # Mark as empty payload, to be caught for possible censorship

                # Keep track of time from when the first message is received
                if start_time == math.inf:
                    stop_time = time.time() + self.args.replay_for
                    if self.args.protocol == 'udp':
                        sock.settimeout(self.SOCKET_TIMEOUT) # Once conversation has started, can add the timeout
                self.logger.debug(f"{len(payload)=}")

                expected_tcp_payload = bytes(self.messages[next_msg.id]["payload"])
                if expected_tcp_payload != payload and len(expected_tcp_payload) > 0:
                    self.event_log.write(f"{time.time()} possible censorship, UNEXPECTED PAYLOAD received '{payload.hex()}' "
                                         f"expected '{expected_tcp_payload.hex()}'\n")
                    self.censor_queue.append("UNEXPECTED PAYLOAD")

            # If there is no next message then we jump back to the start
            if next_msg.id in config_as_dict:
                next_msg = config_as_dict[next_msg.id]
            else:
                if time.time() < stop_time:  # replay the script again
                    next_msg = start_msg
                    start_time = time.time() # Keep track of most recent loop start time for UDP
                else: # time to stop
                    done = True

        return len(self.censor_queue)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate network flows with fixed entropy."
    )
    parser.add_argument(
        "--dst", help="specify remote IP address.", required=True, type=str
    )
    parser.add_argument("--src", help="specify source IP address.", type=str)
    parser.add_argument(
        "--server",
        help="flag to specify that this instance is the server.",
        action="store_true",
    )
    parser.add_argument(
        "--sport", help="specify source port to use.", required=True, type=int
    )
    parser.add_argument(
        "--dport", help="specify destination port to use.", required=True, type=int
    )
    parser.add_argument(
        "--config", help="specify flow config file.", type=str, default="config.json"
    )
    parser.add_argument(
        "--epsilon",
        help="specify epsilon for entropy generation.",
        default=0.01,
        type=float,
    )
    parser.add_argument(
        "--replay-for",
        help="Repeat trigger for this many seconds",
        type=float,
        default=2.0,
    )
    parser.add_argument(
        "--num-runs",
        help="Number of times to run the script",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--save-payloads",
        help="Save the generated payloads as a new packet script at this file",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--capture-path",
        help="Path to write the full packet capture to",
        type=str,
        default="full_capture.pcap",
    )
    parser.add_argument(
        "--event-log-path",
        help="Path to save a log of events (resets, probes, etc.) to",
        type=str,
        default="events.txt",
    )
    parser.add_argument(
        "--seed",
        help="Seed for randomness",
        type=int,
        default=0,
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        help="Which communication protocol sockets will use, default is tcp",
        default="tcp",
    )
    parser.add_argument(
        "--log-dir",
        help="Path to save a logs",
        type=str,
        default="./",
    )

    args = parser.parse_args()
    return args


if __name__ == "__main__":

    args = parse_args()

    mode = 'server' if args.server else 'client'
    logging.basicConfig(filename=f'{args.log_dir}/{mode}_log.log', filemode='w')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    logger.info(
        f"Configuration:\n"
        f"\tConfig: {args.config}\n"
        f"\tSource: {args.src}\n"
        f"\tSource Port: {args.sport}\n"
        f"\tDestination: {args.dst}\n"
        f"\tDestination Port: {args.dport}\n"
        f"\tServer: {args.server}\n"
        f"\tEpsilon: {args.epsilon}\n"
        f"\tReplay For: {args.replay_for}\n"
    )

    fg = TCPFlowGenerator(args, logger)
    fg.run_capture()  # Start scapy packet sniffing
    for run_num in range(args.num_runs):
        logger.info(f"RUN {run_num} STARTING...")
        num_censorship_events = fg.run_session()  # Start sending/receiving packets
        logger.info(f"RUN {run_num} FINISHED, {num_censorship_events} censorship events detected.")

    logger.info("SESSION FINISHED") 
    fg.stop_capture()  # Stop scapy packet sniffing
