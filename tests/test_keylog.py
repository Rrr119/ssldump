"""Regression checks for SSLKEYLOGFILE decryption on TLS 1.2 and TLS 1.3."""

import json
import os
import struct
import subprocess
import sys
import tempfile


def run_ssldump(ssldump, pcap, keylog):
    result = subprocess.run(
        [ssldump, "-n", "-j", "-N", "-l", keylog, "-r", pcap],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="surrogateescape",
        timeout=60,
    )
    records = [
        json.loads(line)
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    return records, result.stderr


def handshake_types(records):
    return [
        record["handshake_type"]
        for record in records
        if record.get("handshake_type")
    ]


def application_data(records):
    return [
        record["msg_data"]
        for record in records
        if record.get("msg_type") == "application data"
    ]


def check_output_errors(output):
    lowered = output.lower()
    if "bad mac" in lowered:
        raise AssertionError("decryption reported a bad MAC")
    if "unknown record type" in lowered:
        raise AssertionError("decryption produced an unknown record type")


def check_tls12(ssldump, samples):
    records, output = run_ssldump(
        ssldump,
        os.path.join(samples, "tls1.2_aes256.pcap"),
        os.path.join(samples, "log.txt"),
    )
    types = handshake_types(records)
    for expected in ("ClientHello", "ServerHello", "ClientKeyExchange"):
        if expected not in types:
            raise AssertionError("TLS 1.2 pcap is missing {}".format(expected))
    apps = application_data(records)
    for expected in ("hello tls12\n", "bye\n"):
        if expected not in apps:
            raise AssertionError(
                "TLS 1.2 application data {!r} was not decrypted".format(expected)
            )
    if not any(record.get("cert_chain") for record in records):
        raise AssertionError("TLS 1.2 certificate chain was not decoded")
    check_output_errors(output)


def check_tls13(ssldump, samples):
    records, output = run_ssldump(
        ssldump,
        os.path.join(samples, "tls1.3_aes128.pcap"),
        os.path.join(samples, "log.txt"),
    )
    types = handshake_types(records)
    for expected in (
        "EncryptedExtensions",
        "Certificate",
        "CertificateVerify",
        "Finished",
    ):
        if expected not in types:
            raise AssertionError("TLS 1.3 pcap is missing {}".format(expected))
    if types.count("Finished") != 2:
        raise AssertionError("TLS 1.3 pcap did not decode both Finished messages")
    apps = application_data(records)
    for expected in ("hello\n", "bye\n", "kill\n"):
        if expected not in apps:
            raise AssertionError(
                "TLS 1.3 application data {!r} was not decrypted".format(expected)
            )
    if not any(record.get("cert_chain") for record in records):
        raise AssertionError("TLS 1.3 certificate chain was not decoded")
    check_output_errors(output)


def read_pcap_packets(path):
    with open(path, "rb") as source:
        data = source.read()
    if len(data) < 24:
        raise AssertionError("{} is not a pcap file".format(path))

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise AssertionError("{} uses an unsupported pcap format".format(path))
    scale = 1000000000 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1000000

    header = data[:24]
    packets = []
    offset = 24
    base = None
    index = 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise AssertionError("{} has a truncated packet header".format(path))
        ts_sec, ts_frac, captured_len, _ = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        if offset + captured_len > len(data):
            raise AssertionError("{} has a truncated packet".format(path))
        packet = data[offset : offset + captured_len]
        offset += captured_len

        timestamp = ts_sec + (ts_frac / scale)
        if base is None:
            base = timestamp
        packets.append((timestamp - base, index, packet))
        index += 1
    return header, endian, scale, packets


def merge_pcaps(paths):
    merged = []
    header = None
    endian = None
    scale = None

    for file_index, path in enumerate(paths):
        current_header, current_endian, current_scale, packets = read_pcap_packets(
            path
        )
        if header is None:
            header = current_header
            endian = current_endian
            scale = current_scale
        elif (
            current_header[4:] != header[4:]
            or current_endian != endian
            or current_scale != scale
        ):
            raise AssertionError("sample pcaps use incompatible capture formats")
        merged.extend(
            (timestamp, file_index, packet_index, packet)
            for timestamp, packet_index, packet in packets
        )

    merged.sort(key=lambda item: (item[0], item[1], item[2]))
    return header, endian, scale, [(item[0], item[3]) for item in merged]


def write_merged_pcap(path, header, endian, scale, packets):
    with open(path, "wb") as destination:
        destination.write(header)
        for timestamp, packet in packets:
            timestamp_units = int(round(timestamp * scale))
            ts_sec, ts_frac = divmod(timestamp_units, scale)
            destination.write(
                struct.pack(
                    endian + "IIII", ts_sec, ts_frac, len(packet), len(packet)
                )
            )
            destination.write(packet)


def check_multiflow(ssldump, samples):
    source_pcaps = [
        os.path.join(samples, "tls1.2_aes256.pcap"),
        os.path.join(samples, "tls1.3_aes128.pcap"),
        os.path.join(samples, "tls1.3_keyupdates_aes256.pcap"),
    ]
    header, endian, scale, packets = merge_pcaps(source_pcaps)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as destination:
        merged_path = destination.name
    try:
        write_merged_pcap(merged_path, header, endian, scale, packets)
        records, output = run_ssldump(
            ssldump, merged_path, os.path.join(samples, "log.txt")
        )
    finally:
        os.unlink(merged_path)

    client_ports = {
        record.get("src_port")
        for record in records
        if record.get("handshake_type") == "ClientHello"
    }
    apps_by_client = {port: [] for port in client_ports}
    types_by_client = {port: [] for port in client_ports}
    for record in records:
        port = record.get("src_port")
        if port not in client_ports:
            continue
        if record.get("handshake_type"):
            types_by_client[port].append(record["handshake_type"])
        if record.get("msg_type") == "application data":
            apps_by_client[port].append(record.get("msg_data"))

    if len(client_ports) != 3:
        raise AssertionError("expected three independent TLS flows")

    tls12_ports = [
        port
        for port in client_ports
        if "ClientKeyExchange" in types_by_client[port]
    ]
    keyupdate_ports = [
        port for port in client_ports if "KeyUpdate" in types_by_client[port]
    ]
    tls13_ports = client_ports - set(tls12_ports) - set(keyupdate_ports)
    if len(tls12_ports) != 1 or len(keyupdate_ports) != 1 or len(tls13_ports) != 1:
        raise AssertionError("could not identify all three flow types")

    expected = {
        tls12_ports[0]: ["hello tls12\n", "bye\n"],
        tls13_ports.pop(): ["hello\n", "bye\n", "kill\n"],
        keyupdate_ports[0]: ["hello\n", "keyupdate\n", "hello\n", "bye\n", "kill\n"],
    }
    for port, expected_data in expected.items():
        if apps_by_client[port] != expected_data:
            raise AssertionError(
                "flow {} was not independently decrypted: {}".format(
                    port, apps_by_client[port]
                )
            )
    if handshake_types(records).count("KeyUpdate") != 2:
        raise AssertionError("multi-flow capture did not expose both KeyUpdate messages")
    check_output_errors(output)


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: test_keylog.py <ssldump> <samples-dir> "
            "<tls12|tls13|multiflow>"
        )

    ssldump, samples, mode = sys.argv[1:]
    checks = {
        "tls12": check_tls12,
        "tls13": check_tls13,
        "multiflow": check_multiflow,
    }
    if mode not in checks:
        raise SystemExit("unknown test mode: {}".format(mode))
    checks[mode](ssldump, samples)
    print("Verified keylog decryption: {}".format(mode))


if __name__ == "__main__":
    main()
