#!/usr/bin/env python3
"""
Read the total energy production from an SMA Sunny Boy SB 5000TL-20 over Bluetooth.

The SB xxxxTL-20 series has no network interface; it talks the SMA Bluetooth
protocol (RFCOMM channel 1). This script implements the minimal part of that
protocol needed to log on and read the yield counters. No third-party packages
are required (Python 3.9+ on Windows, or Linux with BlueZ).

Usage:
    py sma_total_yield.py 00:80:25:XX:XX:XX
    py sma_total_yield.py 00:80:25:XX:XX:XX --password 0000 --json
    py sma_total_yield.py 00:80:25:XX:XX:XX --signal   (signal strength only)
    python3 sma_total_yield.py 00:80:25:XX:XX:XX --adapter 11:22:33:44:55:66
        (use a specific local Bluetooth adapter, e.g. a USB dongle)

Bluetooth signal strength is reported by the inverter (how well it receives
this PC), shown as a percentage. Failed connections are retried (--retries).
The inverter's Bluetooth address can be found in Windows Bluetooth settings
(device name starts with "SMA") or set via the SMA_BT_ADDRESS environment variable.
"""

import argparse
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime

# Outer (Bluetooth level) frame types
OTYPE_PPP = 0x01
OTYPE_HELLO = 0x02
OTYPE_GETVAR = 0x03
OTYPE_VARVAL = 0x04
OTYPE_PPP2 = 0x08  # partial PPP frame, more follows
OUTER_HLEN = 18
VAR_SIGNAL = 0x05

SMA_PROTOCOL_ID = 0x6560
ZERO_ADDR = "00:00:00:00:00:00"
BROADCAST_ADDR = "ff:ff:ff:ff:ff:ff"

LOCAL_ADDR2 = bytes.fromhex("78003f10fb39")  # our "application" SUSyID/serial
BROADCAST2 = b"\xff" * 6

# Data object identifiers (LRI)
LRI_TOTAL_YIELD = 0x2601   # Metering_TotWhOut  (Wh)
LRI_DAY_YIELD = 0x2622     # Metering_DyWhOut   (Wh)
LRI_AC_POWER = 0x263F      # GridMs_TotW        (W)

NAN_S32 = 0x80000000
NAN_U64 = 0xFFFFFFFFFFFFFFFF
NAN_S64 = 0x8000000000000000


class SMAError(Exception):
    pass


def _crc16_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC_TABLE = _crc16_table()


def crc16(data, crc=0xFFFF):
    """PPP FCS-16 (CRC-16/X-25)."""
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFF


def ba2bytes(addr):
    """Bluetooth address string -> 6 bytes as used on the wire (reversed)."""
    parts = addr.split(":")
    if len(parts) != 6:
        raise ValueError("Invalid Bluetooth address: %r" % addr)
    return bytes(int(p, 16) for p in reversed(parts))


def bytes2ba(data):
    return ":".join("%02X" % b for b in reversed(data))


class SMABluetooth:
    def __init__(self, address, timeout=10.0, adapter=None):
        self.remote_addr = address
        self.adapter = adapter
        self.timeout = timeout
        self.local_addr = ZERO_ADDR
        self.sock = None
        self.rxbuf = bytearray()
        self.pppbuf = bytearray()
        self.tag = 0

    # ----- connection --------------------------------------------------------
    def connect(self):
        if not hasattr(socket, "AF_BLUETOOTH"):
            raise SMAError("This Python build has no Bluetooth socket support")
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM,
                                  socket.BTPROTO_RFCOMM)
        self.sock.settimeout(self.timeout)
        if self.adapter:
            self.sock.bind((self.adapter, 0))
        self.sock.connect((self.remote_addr, 1))
        try:
            self.local_addr = self.sock.getsockname()[0]
        except OSError:
            self.local_addr = ZERO_ADDR

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # ----- outer (Bluetooth) frames -----------------------------------------
    def _recv_exact(self, n):
        while len(self.rxbuf) < n:
            chunk = self.sock.recv(1024)
            if not chunk:
                raise SMAError("Connection closed by inverter")
            self.rxbuf.extend(chunk)
        data = bytes(self.rxbuf[:n])
        del self.rxbuf[:n]
        return data

    def tx_outer(self, from_, to_, type_, payload):
        pktlen = len(payload) + OUTER_HLEN
        hdr = bytes([0x7E, pktlen & 0xFF, pktlen >> 8])
        pkt = hdr + bytes([hdr[0] ^ hdr[1] ^ hdr[2]])
        pkt += ba2bytes(from_) + ba2bytes(to_) + struct.pack("<H", type_)
        self.sock.sendall(pkt + payload)

    def rx_outer(self):
        hdr = self._recv_exact(4)
        if hdr[0] != 0x7E:
            raise SMAError("Bad start byte in Bluetooth frame")
        if hdr[0] ^ hdr[1] ^ hdr[2] != hdr[3]:
            raise SMAError("Bad header checksum in Bluetooth frame")
        pktlen = hdr[1] | (hdr[2] << 8)
        rest = self._recv_exact(pktlen - 4)
        from_ = bytes2ba(rest[0:6])
        to_ = bytes2ba(rest[6:12])
        type_ = struct.unpack("<H", rest[12:14])[0]
        return from_, to_, type_, rest[14:]

    def wait_outer(self, wanted_type, deadline):
        while time.monotonic() < deadline:
            from_, to_, type_, payload = self.rx_outer()
            if type_ == wanted_type:
                return payload
        raise SMAError("Timeout waiting for frame type 0x%02X" % wanted_type)

    # ----- PPP framing -------------------------------------------------------
    def tx_ppp(self, payload):
        frame = b"\xff\x03" + struct.pack("<H", SMA_PROTOCOL_ID) + payload
        frame += struct.pack("<H", crc16(frame))
        raw = bytearray([0x7E])
        for b in frame:
            if b in (0x7E, 0x7D, 0x11, 0x12, 0x13):
                raw += bytes([0x7D, b ^ 0x20])
            else:
                raw.append(b)
        raw.append(0x7E)
        self.tx_outer(self.local_addr, BROADCAST_ADDR, OTYPE_PPP, bytes(raw))

    def _decode_ppp(self, raw):
        raw = raw[1:-1]
        frame = bytearray()
        i = 0
        while i < len(raw):
            b = raw[i]
            if b == 0x7D:
                i += 1
                b = raw[i] ^ 0x20
            frame.append(b)
            i += 1
        if frame[0:2] != b"\xff\x03":
            raise SMAError("Bad PPP header")
        if struct.unpack("<H", frame[-2:])[0] != crc16(frame[:-2]):
            raise SMAError("Bad PPP checksum")
        protocol = struct.unpack("<H", frame[2:4])[0]
        return protocol, bytes(frame[4:-2])

    def rx_ppp(self, deadline):
        """Return the next complete PPP payload with the SMA protocol id."""
        while time.monotonic() < deadline:
            _, _, type_, payload = self.rx_outer()
            if type_ not in (OTYPE_PPP, OTYPE_PPP2):
                continue
            self.pppbuf.extend(payload)
            end = self.pppbuf.find(b"\x7e", 1)
            if end < 0:
                continue
            raw = bytes(self.pppbuf[:end + 1])
            del self.pppbuf[:end + 1]
            if raw[0] != 0x7E:
                continue
            protocol, data = self._decode_ppp(raw)
            if protocol == SMA_PROTOCOL_ID:
                return data
        raise SMAError("Timeout waiting for inverter response")

    # ----- SMA 6560 (inner) packets -----------------------------------------
    def _next_tag(self):
        self.tag = (self.tag + 1) & 0x7FFF
        return self.tag

    def tx_6560(self, ctrl, c1, c2, type_, subtype, arg1, arg2, extra=b""):
        tag = self._next_tag()
        payload = bytearray()
        payload.append(len(extra) // 4 + 9)
        payload.append(ctrl)
        payload += BROADCAST2
        payload += bytes([0x00, c1])
        payload += LOCAL_ADDR2
        payload += bytes([0x00, c2])
        payload += struct.pack("<HHHHHII", 0, 0, tag | 0x8000, type_, subtype,
                               arg1, arg2)
        payload += extra
        self.tx_ppp(bytes(payload))
        return tag

    @staticmethod
    def parse_6560(p):
        if p[0] * 4 != len(p):
            raise SMAError("Inner length mismatch")
        error, pktcount, tag, type_, subtype, arg1, arg2 = \
            struct.unpack("<HHHHHII", p[18:36])
        return {
            "from": p[10:16],
            "error": error,
            "pktcount": pktcount,
            "tag": tag & 0x7FFF,
            "type": type_ & ~1,
            "response": bool(type_ & 1),
            "subtype": subtype,
            "arg1": arg1,
            "arg2": arg2,
            "extra": p[36:],
        }

    def wait_6560(self, tag):
        deadline = time.monotonic() + self.timeout
        while True:
            pkt = self.parse_6560(self.rx_ppp(deadline))
            if pkt["response"] and pkt["tag"] == tag:
                return pkt

    # ----- high-level operations --------------------------------------------
    def hello(self):
        deadline = time.monotonic() + self.timeout
        hellopkt = self.wait_outer(OTYPE_HELLO, deadline)
        # Echo the inverter's announcement (contains its NetID) to establish link
        self.tx_outer(ZERO_ADDR, self.remote_addr, OTYPE_HELLO, hellopkt)
        self.wait_outer(0x05, deadline)

    def signal_strength(self):
        """Bluetooth signal strength (in %) as received by the inverter."""
        deadline = time.monotonic() + self.timeout
        self.tx_outer(ZERO_ADDR, self.remote_addr, OTYPE_GETVAR,
                      struct.pack("<H", VAR_SIGNAL))
        while True:
            payload = self.wait_outer(OTYPE_VARVAL, deadline)
            if len(payload) >= 5 and \
                    struct.unpack("<H", payload[0:2])[0] == VAR_SIGNAL:
                return payload[4] * 100.0 / 255.0

    def logon(self, password="0000", timeout=900):
        pw = password.encode("ascii")
        if len(pw) > 12:
            raise ValueError("Password too long (max 12 characters)")
        pw += b"\x00" * (12 - len(pw))
        extra = b"\xaa\xaa\xbb\xbb\x00\x00\x00\x00"
        extra += bytes((c + 0x88) & 0xFF for c in pw)  # user group encoding
        tag = self.tx_6560(0xA0, 0x01, 0x01, 0x040C, 0xFFFD, 7, timeout, extra)
        pkt = self.wait_6560(tag)
        if pkt["error"] != 0:
            raise SMAError("Logon failed (error 0x%04X) - wrong password?"
                           % pkt["error"])
        susyid, serial = struct.unpack("<HI", pkt["from"])
        return susyid, serial

    def logoff(self):
        tag = self._next_tag()
        payload = bytearray([0x08, 0xA0]) + BROADCAST2 + b"\x00\x03" + \
            LOCAL_ADDR2 + b"\x00\x03"
        payload += struct.pack("<HHHHHI", 0, 0, tag | 0x8000, 0x010E, 0xFFFD,
                               0xFFFFFFFF)
        self.tx_ppp(bytes(payload))

    def query(self, subtype, first_lri, last_lri, recsize):
        """Read data records; returns {lri: (timestamp, raw_value_bytes)}."""
        tag = self.tx_6560(0xA0, 0x00, 0x00, 0x0200, subtype,
                           (first_lri << 8), (last_lri << 8) | 0xFF)
        pkt = self.wait_6560(tag)
        if pkt["error"] != 0:
            raise SMAError("Query 0x%04X failed (error 0x%04X)"
                           % (subtype, pkt["error"]))
        records = {}
        extra = pkt["extra"]
        # Response arg1/arg2 are first/last record index -> derive record size
        nrec = pkt["arg2"] - pkt["arg1"] + 1
        if 0 < nrec <= len(extra) and len(extra) % nrec == 0:
            recsize = len(extra) // nrec
        for off in range(0, len(extra) - recsize + 1, recsize):
            rec = extra[off:off + recsize]
            lri = struct.unpack("<H", rec[1:3])[0]
            ts = struct.unpack("<I", rec[4:8])[0]
            records[lri] = (ts, rec[8:])
        return records

    def energy(self):
        recs = self.query(0x5400, LRI_TOTAL_YIELD, LRI_DAY_YIELD, 16)
        result = {}
        for lri, key in ((LRI_TOTAL_YIELD, "total_wh"),
                         (LRI_DAY_YIELD, "today_wh")):
            if lri in recs:
                ts, raw = recs[lri]
                val = struct.unpack("<Q", raw[:8])[0]
                result[key] = None if val in (NAN_U64, NAN_S64) else val
                result[key + "_time"] = ts
        return result

    def ac_power(self):
        recs = self.query(0x5100, LRI_AC_POWER, LRI_AC_POWER, 28)
        if LRI_AC_POWER not in recs:
            return None
        val = struct.unpack("<I", recs[LRI_AC_POWER][1][:4])[0]
        return 0 if val == NAN_S32 else struct.unpack("<i", struct.pack("<I", val))[0]


def read_inverter(args):
    result = {}
    with SMABluetooth(args.address, args.timeout, args.adapter) as sma:
        sma.hello()
        try:
            result["signal"] = sma.signal_strength()
        except (OSError, SMAError):
            result["signal"] = None
        if args.signal:
            return result
        result["susyid"], result["serial"] = sma.logon(args.password)
        result["data"] = sma.energy()
        try:
            result["power"] = sma.ac_power()
        except SMAError:
            result["power"] = None
        sma.logoff()
    return result


def describe_error(e):
    errno_ = getattr(e, "errno", None)
    if getattr(e, "winerror", None) == 10060 or isinstance(e, socket.timeout) \
            or errno_ in (110, 112):  # ETIMEDOUT / EHOSTDOWN (Linux page timeout)
        return ("Bluetooth connection timed out - inverter out of range or "
                "busy (%s)" % e)
    if errno_ == 113:  # EHOSTUNREACH: Linux found no usable local adapter
        return ("No usable Bluetooth adapter on this machine (adapter missing, "
                "powered off, or not Bluetooth Classic capable) (%s)" % e)
    return str(e)


def main():
    ap = argparse.ArgumentParser(
        description="Read total energy production from an SMA SB 5000TL-20 (Bluetooth).")
    ap.add_argument("address", nargs="?", default=os.environ.get("SMA_BT_ADDRESS"),
                    help="Inverter Bluetooth address, e.g. 00:80:25:12:34:56 "
                         "(or set SMA_BT_ADDRESS)")
    ap.add_argument("--password", default="0000", help="User password (default 0000)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds")
    ap.add_argument("--retries", type=int, default=3,
                    help="Connection attempts before giving up (default 3)")
    ap.add_argument("--adapter", default=os.environ.get("SMA_BT_ADAPTER"),
                    help="Bluetooth address of the local adapter to use, when "
                         "the machine has more than one (e.g. a USB dongle)")
    ap.add_argument("--signal", action="store_true",
                    help="Only show Bluetooth signal strength (no logon)")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args()

    if not args.address:
        ap.error("Bluetooth address required (argument or SMA_BT_ADDRESS)")

    attempts = max(1, args.retries)
    for attempt in range(1, attempts + 1):
        try:
            result = read_inverter(args)
            break
        except ValueError as e:
            print("Error: %s" % e, file=sys.stderr)
            return 1
        except (OSError, SMAError) as e:
            if attempt == attempts:
                print("Error: %s" % describe_error(e), file=sys.stderr)
                return 1
            print("Attempt %d/%d failed: %s - retrying..."
                  % (attempt, attempts, describe_error(e)), file=sys.stderr)
            time.sleep(3)

    signal = result["signal"]
    if args.signal:
        if args.json:
            print(json.dumps({"bt_signal_pct": signal}))
        elif signal is None:
            print("Bluetooth signal: unknown (inverter did not report it)")
        else:
            print("Bluetooth signal: %.1f %%" % signal)
        return 0

    data, power, serial, susyid = (result["data"], result["power"],
                                   result["serial"], result["susyid"])
    if data.get("total_wh") is None:
        print("Error: inverter did not return a total yield value", file=sys.stderr)
        return 1

    if args.json:
        out = {"serial": serial, "susyid": susyid,
               "total_kwh": data["total_wh"] / 1000.0,
               "today_kwh": (data["today_wh"] / 1000.0
                             if data.get("today_wh") is not None else None),
               "ac_power_w": power,
               "bt_signal_pct": (round(signal, 1)
                                 if signal is not None else None),
               "timestamp": data["total_wh_time"]}
        print(json.dumps(out))
    else:
        ts = datetime.fromtimestamp(data["total_wh_time"])
        print("Inverter serial : %d" % serial)
        print("Total yield     : %.3f kWh" % (data["total_wh"] / 1000.0))
        if data.get("today_wh") is not None:
            print("Today's yield   : %.3f kWh" % (data["today_wh"] / 1000.0))
        if power is not None:
            print("Current AC power: %d W" % power)
        if signal is not None:
            print("Bluetooth signal: %.1f %%" % signal)
        print("Inverter time   : %s" % ts.strftime("%Y-%m-%d %H:%M:%S"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
