"""Regression checks for TLS 1.3 handshake decoding with an SSLKEYLOGFILE."""

import json
import os
import subprocess
import sys
import tempfile


def run_ssldump(ssldump, pcap, keylog=None):
    command = [ssldump, "-n", "-j", "-N", "-r", pcap]
    if keylog:
        command.extend(["-l", keylog])

    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="surrogateescape",
        timeout=60,
    )

    records = []
    for line in result.stdout.splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records, result.stdout + result.stderr


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


def check_cipher_suites(ssldump, samples, keylog):
    pcaps = {
        "tls1.3_aes128.pcap": "hello\n",
        "tls1.3_aes256gcm.pcap": "hello\n",
        "tls1.3_chacha.pcap": "hello\n",
        "tls1.3_ccm.pcap": "heelo\n",
        "tls1.3_ccm8.pcap": "hello\n",
    }
    required = [
        "ClientHello",
        "ServerHello",
        "EncryptedExtensions",
        "Certificate",
        "CertificateVerify",
        "Finished",
    ]

    for pcap_name, expected_data in pcaps.items():
        records, output = run_ssldump(
            ssldump, os.path.join(samples, pcap_name), keylog
        )
        types = handshake_types(records)
        for handshake_type in required:
            if handshake_type not in types:
                raise AssertionError(
                    "{}: missing {}".format(pcap_name, handshake_type)
                )
        if types.count("Finished") != 2:
            raise AssertionError("{}: expected two Finished messages".format(pcap_name))
        if not any(record.get("cert_chain") for record in records):
            raise AssertionError("{}: missing decoded certificate chain".format(pcap_name))
        if expected_data not in application_data(records):
            raise AssertionError("{}: missing decrypted application data".format(pcap_name))
        if "unknown record type" in output or "bad MAC" in output:
            raise AssertionError("{}: TLS 1.3 record decoding error".format(pcap_name))


def check_key_update(ssldump, samples, keylog):
    pcap = os.path.join(samples, "tls1.3_keyupdates_aes256.pcap")
    records, output = run_ssldump(ssldump, pcap, keylog)
    types = handshake_types(records)
    if types.count("KeyUpdate") != 2:
        raise AssertionError("Expected two decrypted KeyUpdate messages")
    apps = application_data(records)
    if "keyupdate\n" not in apps or "hello\n" not in apps:
        raise AssertionError("Application data failed across TLS 1.3 key updates")
    if "bad MAC" in output:
        raise AssertionError("TLS 1.3 key update produced a bad MAC")


def check_multi_message_record(ssldump, samples, keylog):
    pcap = os.path.join(samples, "tls1.3_curl_google.pcap")
    records, output = run_ssldump(ssldump, pcap, keylog)
    if not any(record.get("cert_chain") for record in records):
        raise AssertionError("Google TLS 1.3 certificate chain was not decoded")
    if not any(
        data.startswith("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        for data in application_data(records)
    ):
        raise AssertionError("TLS 1.3 HTTP/2 application data was not decrypted")
    if "bad MAC" in output or "short certificate" in output:
        raise AssertionError("TLS 1.3 multi-message record was decoded incorrectly")


def check_crlf_keylog(ssldump, samples, keylog):
    with open(keylog, "r", encoding="ascii") as source:
        lines = source.read().splitlines()

    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", newline="", suffix=".keylog", delete=False
    ) as destination:
        for line in lines:
            destination.write(line + "\r\n")
        crlf_keylog = destination.name

    try:
        records, output = run_ssldump(
            ssldump, os.path.join(samples, "tls1.3_aes128.pcap"), crlf_keylog
        )
    finally:
        os.unlink(crlf_keylog)

    if "hello\n" not in application_data(records):
        raise AssertionError("CRLF key log did not decrypt TLS 1.3 application data")
    if "bad MAC" in output:
        raise AssertionError("CRLF key log produced a bad MAC")


def check_missing_keylog(ssldump, samples):
    records, _ = run_ssldump(
        ssldump, os.path.join(samples, "tls1.3_aes128.pcap")
    )
    types = handshake_types(records)
    if "ClientHello" not in types or "ServerHello" not in types:
        raise AssertionError("Plaintext TLS 1.3 hello messages were not decoded")
    leaked_types = {
        "EncryptedExtensions",
        "Certificate",
        "CertificateVerify",
        "Finished",
    }.intersection(types)
    if leaked_types:
        raise AssertionError(
            "Decrypted TLS 1.3 messages decoded without a key log: {}".format(
                ", ".join(sorted(leaked_types))
            )
        )


def main():
    ssldump = sys.argv[1]
    samples = sys.argv[2]
    keylog = os.path.join(samples, "log.txt")

    check_cipher_suites(ssldump, samples, keylog)
    check_key_update(ssldump, samples, keylog)
    check_multi_message_record(ssldump, samples, keylog)
    check_crlf_keylog(ssldump, samples, keylog)
    check_missing_keylog(ssldump, samples)
    print("Verified TLS 1.3 handshake and key log decoding")


if __name__ == "__main__":
    main()
