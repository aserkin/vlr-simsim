#!/usr/bin/env python3
"""Minimal SGsAP VLR simulator for MME interoperability testing.

The simulator listens for SCTP connections from an MME and responds to a small
subset of SGsAP procedures that are useful when testing voice-centric UEs and
CS Fallback without a real VLR.

Implemented request handling:
- SGsAP-LOCATION-UPDATE-REQUEST -> ACCEPT or REJECT
- SGsAP-EPS-DETACH-INDICATION -> ACK
- SGsAP-IMSI-DETACH-INDICATION -> ACK
- SGsAP-RESET-INDICATION -> ACK

All other SGsAP messages are ignored.
"""

from __future__ import annotations

import argparse
import logging
import selectors
import signal
import socket
import sys
import types
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger("vlr-simsim")
sel = selectors.DefaultSelector()


IE_IMSI = 1
IE_VLR_NAME = 2
IE_LAI = 4
IE_SGS_CAUSE = 8
IE_MME_NAME = 9
IE_GLOBAL_CN_ID = 11
IE_REJECT_CAUSE = 15

MSG_LOCATION_UPDATE_REQUEST = 9
MSG_LOCATION_UPDATE_ACCEPT = 10
MSG_LOCATION_UPDATE_REJECT = 11
MSG_EPS_DETACH_INDICATION = 17
MSG_EPS_DETACH_ACK = 18
MSG_IMSI_DETACH_INDICATION = 19
MSG_IMSI_DETACH_ACK = 20
MSG_RESET_INDICATION = 21
MSG_RESET_ACK = 22

DEFAULT_REJECT_CAUSE = 8
DEFAULT_VLR_NAME = b"vlr-simsim"

IE_NAMES = {
    1: "IMSI",
    2: "VLR name",
    3: "TMSI",
    4: "LAI",
    5: "Channel needed",
    6: "eMLPP priority",
    7: "TMSI status",
    8: "SGs cause",
    9: "MME name",
    10: "EPS LU type",
    11: "Global CN-ID",
    14: "Mobile identity",
    15: "Reject cause",
    16: "IMSI detach from EPS",
    17: "IMSI detach from non-EPS",
    21: "IMEISV",
    22: "NAS message container",
    23: "MM info",
    27: "Erroneous message",
    28: "CLI",
    29: "LCS client identity",
    30: "LCS indicator",
    31: "SS code",
    32: "Service indicator",
    33: "UE time zone",
    34: "Mobile station classmark 2",
    35: "Tracking Area Identity",
    36: "E-UTRAN Cell Global Identity",
    37: "UE EMM mode",
}


@dataclass
class Config:
    host: str
    port: int
    vlr_name: bytes = DEFAULT_VLR_NAME
    reject_cause: int = DEFAULT_REJECT_CAUSE


@dataclass
class Stats:
    location_update_requests: int = 0
    eps_detach_indications: int = 0
    imsi_detach_indications: int = 0
    reset_indications: int = 0
    other_messages: int = 0


stats = Stats()


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(handler)


def parse_args(argv: list[str]) -> Config:
    parser = argparse.ArgumentParser(
        description="Minimal SGsAP VLR simulator for MME testing"
    )
    parser.add_argument("host", help="Local IP address to listen on")
    parser.add_argument(
        "port",
        type=int,
        help="Local SCTP port to listen on, usually 29118 for SGsAP",
    )
    parser.add_argument(
        "--vlr-name",
        default=DEFAULT_VLR_NAME.decode("ascii"),
        help="VLR name returned in RESET ACK messages",
    )
    parser.add_argument(
        "--reject-cause",
        type=int,
        default=DEFAULT_REJECT_CAUSE,
        help="Reject cause used in LOCATION UPDATE REJECT when mandatory IEs are missing",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    args = parser.parse_args(argv)

    configure_logging(args.log_level)
    return Config(
        host=args.host,
        port=args.port,
        vlr_name=args.vlr_name.encode("ascii", errors="strict"),
        reject_cause=args.reject_cause,
    )


def parse_ies(message: bytes) -> tuple[list[tuple[int, bytes]], bool]:
    """Parse SGsAP TLV-style IEs from a message after the message type octet."""
    ies: list[tuple[int, bytes]] = []
    offset = 1

    while offset < len(message):
        if offset + 1 >= len(message):
            logger.warning("truncated IE header at byte offset %s", offset)
            return ies, False

        ie_type = message[offset]
        ie_length = message[offset + 1]
        ie_end = offset + 2 + ie_length

        if ie_end > len(message):
            logger.warning(
                "truncated IE %s (type=%s length=%s offset=%s)",
                IE_NAMES.get(ie_type, "unknown"),
                ie_type,
                ie_length,
                offset,
            )
            return ies, False

        ies.append((ie_type, message[offset:ie_end]))
        offset = ie_end

    return ies, True


def first_ie(ies: list[tuple[int, bytes]], ie_type: int) -> bytes | None:
    for current_type, raw_ie in ies:
        if current_type == ie_type:
            return raw_ie
    return None


def location_update_reject(config: Config) -> bytes:
    return bytes(
        [
            MSG_LOCATION_UPDATE_REJECT,
            IE_MME_NAME,
            0,
            IE_GLOBAL_CN_ID,
            1,
            config.reject_cause,
            IE_REJECT_CAUSE,
            1,
            config.reject_cause,
        ]
    )


def handle_location_update(message: bytes, config: Config) -> bytes:
    stats.location_update_requests += 1
    logger.info("SGsAP LOCATION UPDATE REQUEST received")

    ies, valid = parse_ies(message)
    imsi_ie = first_ie(ies, IE_IMSI)
    lai_ie = first_ie(ies, IE_LAI)

    if not valid or imsi_ie is None or lai_ie is None:
        logger.warning("rejecting LOCATION UPDATE REQUEST: missing or malformed mandatory IEs")
        return location_update_reject(config)

    logger.info("accepting LOCATION UPDATE REQUEST")
    return bytes([MSG_LOCATION_UPDATE_ACCEPT]) + imsi_ie + lai_ie


def handle_eps_detach(message: bytes, _config: Config) -> bytes:
    stats.eps_detach_indications += 1
    logger.info("SGsAP EPS DETACH INDICATION received")

    ies, _ = parse_ies(message)
    imsi_ie = first_ie(ies, IE_IMSI)
    if imsi_ie is None:
        logger.warning("EPS DETACH INDICATION missing IMSI IE, sending bare ACK")
        return bytes([MSG_EPS_DETACH_ACK])

    logger.info("sending EPS DETACH ACK")
    return bytes([MSG_EPS_DETACH_ACK]) + imsi_ie


def handle_imsi_detach(message: bytes, _config: Config) -> bytes:
    stats.imsi_detach_indications += 1
    logger.info("SGsAP IMSI DETACH INDICATION received")

    ies, _ = parse_ies(message)
    imsi_ie = first_ie(ies, IE_IMSI)
    if imsi_ie is None:
        logger.warning("IMSI DETACH INDICATION missing IMSI IE, sending bare ACK")
        return bytes([MSG_IMSI_DETACH_ACK])

    logger.info("sending IMSI DETACH ACK")
    return bytes([MSG_IMSI_DETACH_ACK]) + imsi_ie


def handle_reset(_message: bytes, config: Config) -> bytes:
    stats.reset_indications += 1
    logger.info("SGsAP RESET INDICATION received")
    return bytes([MSG_RESET_ACK, IE_VLR_NAME, len(config.vlr_name)]) + config.vlr_name


def handle_other(message: bytes, _config: Config) -> bytes:
    stats.other_messages += 1
    msg_type = message[0] if message else None
    logger.info("ignoring unsupported SGsAP message type %s", msg_type)
    return b""


DISPATCH = {
    MSG_LOCATION_UPDATE_REQUEST: handle_location_update,
    MSG_EPS_DETACH_INDICATION: handle_eps_detach,
    MSG_IMSI_DETACH_INDICATION: handle_imsi_detach,
    MSG_RESET_INDICATION: handle_reset,
}


def dump_stats() -> None:
    logger.warning("SGs statistics")
    logger.warning("Location Update Requests: %s", stats.location_update_requests)
    logger.warning("EPS Detach Indications: %s", stats.eps_detach_indications)
    logger.warning("IMSI Detach Indications: %s", stats.imsi_detach_indications)
    logger.warning("Reset Indications: %s", stats.reset_indications)
    logger.warning("Other Messages: %s", stats.other_messages)


def register_signals() -> None:
    def receive_signal(signal_number: int, _frame: object) -> None:
        if signal_number == signal.SIGUSR1:
            dump_stats()
            return
        if signal_number in (signal.SIGINT, signal.SIGTERM):
            logger.warning("received signal %s, shutting down", signal_number)
            sel.close()
            sys.exit(0)
        logger.warning("received signal %s", signal_number)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGUSR1):
        signal.signal(signum, receive_signal)


def accept_wrapper(sock: Any) -> None:
    conn, addr = sock.accept()
    logger.warning("accepted connection from %s", addr)
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, outb=b"")
    sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)


def service_connection(key: selectors.SelectorKey, mask: int, config: Config) -> None:
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(4096)
        if recv_data:
            data.outb += recv_data
        else:
            logger.warning("closing connection to %s", data.addr)
            sel.unregister(sock)
            sock.close()
            return

    if mask & selectors.EVENT_WRITE and data.outb:
        message = bytes(data.outb)
        msg_type = message[0]
        handler = DISPATCH.get(msg_type, handle_other)
        response = handler(message, config)
        data.outb = b""
        if response:
            sock.send(response)


def main(argv: list[str]) -> int:
    config = parse_args(argv)
    register_signals()

    try:
        from sctp import sctpsocket_tcp
    except ImportError as exc:
        logger.error("python sctp module is required to run this simulator: %s", exc)
        return 1

    lsock = sctpsocket_tcp(socket.AF_INET)
    lsock.bind((config.host, config.port))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    logger.warning("listening on %s:%s", config.host, config.port)

    while True:
        for key, mask in sel.select(timeout=None):
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask, config)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
