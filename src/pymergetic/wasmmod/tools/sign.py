
# This file is part of wasmmod, https://github.com/pymergetic-wasmmod/wasmmod
#
# The MIT License (MIT)
#
# Copyright (c) 2026 Rouven Raudzus <raudzus@pymergetic.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
Sign .wasm / .aot / .elf for MICROPY_WASM_VERIFY (ECDSA-P256 + SHA-256).

Embed-only: writes `wasmmod.sig` (MPWS: sig + chain) into the artifact.
Digest = artifact bytes without that section (same for .wasm, .aot, and .elf).

  tools/wasmmod.py sign gen-pki -o .keys
  tools/wasmmod.py sign sign --key .keys/sign/leaf.key.pem \\
      --chain .keys/sign/chain.der packs/hello.wasm
  tools/wasmmod.py sign info packs/hello.aot
  tools/wasmmod.py sign verify --trust .keys/trust/root.crt.der packs/hello.aot

Requires openssl.
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

SIG_SECTION = "wasmmod.sig"
# Embedded: magic + sig + optional cert chain (leaf first).
MPWS_MAGIC = b"MPWS"
MPWS_VER = 1

AOT_SECTION_TYPE_CUSTOM = 100
AOT_CUSTOM_SECTION_RAW = 0


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.check_call(cmd)


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def write_file(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data)


def openssl_sign(key: Path, data: Path, sig_out: Path) -> None:
    run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(sig_out), str(data)])


def openssl_sign_bytes(key: Path, data: bytes, sig_out: Path) -> None:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tf.write(data)
        tmp = Path(tf.name)
    try:
        openssl_sign(key, tmp, sig_out)
    finally:
        tmp.unlink(missing_ok=True)


def pem_to_der_cert(pem: Path, der: Path) -> None:
    run(["openssl", "x509", "-in", str(pem), "-outform", "DER", "-out", str(der)])


def cmd_gen_key(out_prefix: Path) -> None:
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    pem = out_prefix.with_suffix(".pem")
    pub = Path(str(out_prefix) + ".pub.der")
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(pem)])
    run(["openssl", "ec", "-in", str(pem), "-pubout", "-outform", "DER", "-out", str(pub)])
    print(pem)
    print(pub)


def _ec_key(path: Path) -> None:
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(path)])


def _req(key: Path, subject: str, out_csr: Path) -> None:
    run(["openssl", "req", "-new", "-key", str(key), "-subj", subject, "-out", str(out_csr)])


def _sign_cert(
    csr: Path,
    ca_crt: Path,
    ca_key: Path,
    out_crt: Path,
    *,
    days: int,
    extfile: Path,
    serial: int,
) -> None:
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-set_serial",
            str(serial),
            "-days",
            str(days),
            "-sha256",
            "-extfile",
            str(extfile),
            "-out",
            str(out_crt),
        ]
    )


def cmd_gen_pki(out_dir: Path, with_sub_ca: bool, days: int) -> None:
    """Write trust/ (host CA) and sign/ (pack leaf + chain) under out_dir."""
    trust = out_dir / "trust"
    sign = out_dir / "sign"
    trust.mkdir(parents=True, exist_ok=True)
    sign.mkdir(parents=True, exist_ok=True)

    root_key = trust / "root.key.pem"
    root_crt = trust / "root.crt.pem"
    root_der = trust / "root.crt.der"
    leaf_key = sign / "leaf.key.pem"
    leaf_crt = sign / "leaf.crt.pem"
    leaf_der = sign / "leaf.crt.der"
    chain_der = sign / "chain.der"

    # Root CA (self-signed). OpenSSL 3 req uses -config/-extensions, not -extfile.
    _ec_key(root_key)
    root_cfg = trust / "root.cnf"
    write_file(
        root_cfg,
        textwrap.dedent(
            """\
            [req]
            distinguished_name = req_dn
            x509_extensions = v3_ca
            prompt = no
            [req_dn]
            CN = wasmmod-root
            [v3_ca]
            basicConstraints = critical,CA:TRUE,pathlen:2
            keyUsage = critical,keyCertSign,cRLSign
            subjectKeyIdentifier = hash
            """
        ),
    )
    run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(root_key),
            "-config",
            str(root_cfg),
            "-days",
            str(days),
            "-sha256",
            "-out",
            str(root_crt),
        ]
    )
    pem_to_der_cert(root_crt, root_der)

    signer_crt = root_crt
    signer_key = root_key
    serial = 2
    intermediates: list[Path] = []

    if with_sub_ca:
        sub_key = sign / "sub.key.pem"
        sub_csr = sign / "sub.csr.pem"
        sub_crt = sign / "sub.crt.pem"
        sub_der = sign / "sub.crt.der"
        sub_ext = sign / "sub.ext"
        _ec_key(sub_key)
        _req(sub_key, "/CN=wasmmod-sub", sub_csr)
        write_file(
            sub_ext,
            textwrap.dedent(
                """\
                basicConstraints=critical,CA:TRUE,pathlen:0
                keyUsage=critical,keyCertSign,cRLSign
                subjectKeyIdentifier=hash
                authorityKeyIdentifier=keyid,issuer
                """
            ),
        )
        _sign_cert(sub_csr, root_crt, root_key, sub_crt, days=days, extfile=sub_ext, serial=serial)
        serial += 1
        pem_to_der_cert(sub_crt, sub_der)
        signer_crt, signer_key = sub_crt, sub_key
        intermediates.append(sub_der)

    # Leaf signing cert (digitalSignature only — not a CA).
    leaf_csr = sign / "leaf.csr.pem"
    leaf_ext = sign / "leaf.ext"
    _ec_key(leaf_key)
    _req(leaf_key, "/CN=wasmmod-pack-signer", leaf_csr)
    write_file(
        leaf_ext,
        textwrap.dedent(
            """\
            basicConstraints=critical,CA:FALSE
            keyUsage=critical,digitalSignature
            extendedKeyUsage=codeSigning
            subjectKeyIdentifier=hash
            authorityKeyIdentifier=keyid,issuer
            """
        ),
    )
    _sign_cert(leaf_csr, signer_crt, signer_key, leaf_crt, days=days, extfile=leaf_ext, serial=serial)
    pem_to_der_cert(leaf_crt, leaf_der)

    # chain.der = leaf || intermediates (root stays in trust/ only).
    chain = leaf_der.read_bytes() + b"".join(p.read_bytes() for p in intermediates)
    write_file(chain_der, chain)

    for p in (root_der, leaf_key, leaf_der, chain_der):
        print(p)
    if with_sub_ca:
        print(sign / "sub.crt.der")


def pack_mpws(sig: bytes, chain: bytes) -> bytes:
    if len(sig) > 0xFFFF or len(chain) > 0xFFFF:
        raise SystemExit("sig/chain too large for MPWS")
    return (
        MPWS_MAGIC
        + bytes([MPWS_VER, 0])
        + len(sig).to_bytes(2, "big")
        + sig
        + len(chain).to_bytes(2, "big")
        + chain
    )


def _aot_align4(buf: bytes) -> bytes:
    """Pad with zeros so len % 4 == 0 (WAMR read_uint32 uses align_ptr on headers)."""
    pad = (-len(buf)) % 4
    return buf if pad == 0 else buf + bytes(pad)


def without_sig_section(buf: bytes) -> bytes:
    """Artifact bytes that ECDSA covers for embedded wasmmod.sig (.wasm / .aot / .elf)."""
    if len(buf) < 8:
        raise SystemExit("artifact too small")
    want = SIG_SECTION.encode()
    if buf[:4] == b"\x00asm":
        out = bytearray(buf[:8])
        i = 8
        while i < len(buf):
            sec_start = i
            sid = buf[i]
            i += 1
            size, i = _read_uleb(buf, i)
            sec_end = i + size
            if sec_end > len(buf):
                raise SystemExit("truncated wasm while stripping wasmmod.sig")
            skip = False
            if sid == 0:
                nlen, j = _read_uleb(buf, i)
                if j + nlen <= sec_end and buf[j : j + nlen] == want:
                    skip = True
            if not skip:
                out.extend(buf[sec_start:sec_end])
            i = sec_end
        return bytes(out)

    if buf[:4] == b"\x00aot":
        # Section headers are 4-aligned (WAMR align_ptr). Copy kept sections plus
        # the align pad that follows each body up to the next header. Stop before
        # a trailing 1..3-byte pad that is not a full header (would break load).
        out = bytearray(buf[:8])
        p = 8
        while p + 8 <= len(buf):
            typ, size = struct.unpack_from("<II", buf, p)
            content = p + 8
            end = content + size
            if end > len(buf) or size > 0x10000000:
                raise SystemExit("truncated aot while stripping wasmmod.sig")
            aligned = (end + 3) & ~3
            if aligned <= len(buf) and (aligned == len(buf) or aligned + 8 <= len(buf)):
                next_p = aligned
            else:
                # Body ends with only a short trailing pad left — keep through end.
                next_p = min(end, len(buf))
            skip = False
            if typ == AOT_SECTION_TYPE_CUSTOM and size >= 6:
                sub = struct.unpack_from("<I", buf, content)[0]
                if sub == AOT_CUSTOM_SECTION_RAW:
                    slen = struct.unpack_from("<H", buf, content + 4)[0]
                    name_off = content + 6
                    if name_off + slen <= end:
                        name_bytes = buf[name_off : name_off + slen]
                        bare = name_bytes[:-1] if name_bytes.endswith(b"\x00") else name_bytes
                        if bare == want:
                            skip = True
            if not skip:
                out.extend(buf[p:next_p])
            p = next_p
            if skip:
                # Drop trailing pad after sig (not part of the signed body).
                break
        return bytes(out)

    if buf[:4] == b"\x7fELF":
        from .elf import strip_section

        return strip_section(buf, SIG_SECTION)

    raise SystemExit("not a .wasm/.aot/.elf (need \\0asm / \\0aot / \\x7fELF magic)")


def append_sig_section(buf: bytes, payload: bytes) -> bytes:
    """Append wasmmod.sig to a sig-free .wasm / .aot / .elf (same embed model)."""
    if len(buf) < 8:
        raise SystemExit("artifact too small")
    if buf[:4] == b"\x00asm":
        name = SIG_SECTION.encode()
        body = uleb(len(name)) + name + payload
        section = bytes([0]) + uleb(len(body)) + body
        return buf + section

    if buf[:4] == b"\x00aot":
        # Caller must pass 4-aligned bytes so the sig header is align_ptr-ready.
        # Do NOT pad after the sig section — trailing zeros look like a truncated
        # next section and WAMR fails with "unexpected end".
        if len(buf) % 4:
            raise SystemExit("internal: AOT embed buffer not 4-aligned")
        name = SIG_SECTION.encode() + b"\x00"
        body = (
            struct.pack("<I", AOT_CUSTOM_SECTION_RAW)
            + struct.pack("<H", len(name))
            + name
            + payload
        )
        return buf + struct.pack("<II", AOT_SECTION_TYPE_CUSTOM, len(body)) + body

    if buf[:4] == b"\x7fELF":
        from .elf import append_section

        return append_section(buf, SIG_SECTION, payload)

    raise SystemExit("not a .wasm/.aot/.elf (need \\0asm / \\0aot / \\x7fELF magic)")


def _read_uleb(buf: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, i
        shift += 7
        if shift > 35:
            raise SystemExit("invalid uleb")
    raise SystemExit("truncated uleb")


def parse_mpws(payload: bytes) -> dict:
    """Parse wasmmod.sig payload → {is_mpws, sig, chain}."""
    if (
        len(payload) >= 8
        and payload[:4] == MPWS_MAGIC
        and payload[4] == MPWS_VER
    ):
        sl = int.from_bytes(payload[6:8], "big")
        if 8 + sl > len(payload) or sl == 0:
            raise SystemExit("bad MPWS sig length")
        rest = payload[8 + sl :]
        chain = b""
        if len(rest) >= 2:
            cl = int.from_bytes(rest[0:2], "big")
            if 2 + cl > len(rest):
                raise SystemExit("bad MPWS chain length")
            chain = rest[2 : 2 + cl]
        return {"is_mpws": True, "sig": payload[8 : 8 + sl], "chain": chain}
    if not payload:
        raise SystemExit("empty wasmmod.sig payload")
    return {"is_mpws": False, "sig": payload, "chain": b""}


def inspect_sig(buf: bytes) -> dict | None:
    """Return sig meta for a .wasm/.aot/.elf, or None if no wasmmod.sig."""
    from .source import extract_custom_section

    payload = extract_custom_section(buf, SIG_SECTION)
    if payload is None:
        return None
    parsed = parse_mpws(payload)
    stripped = without_sig_section(buf)
    return {
        "section": SIG_SECTION,
        "is_mpws": parsed["is_mpws"],
        "sig_len": len(parsed["sig"]),
        "chain_len": len(parsed["chain"]),
        "signed_len": len(stripped),
        "sig": parsed["sig"],
        "chain": parsed["chain"],
    }


def der_certs(blob: bytes) -> list[bytes]:
    """Split concatenated DER X.509 certs (leaf first)."""
    out: list[bytes] = []
    i = 0
    while i < len(blob):
        if blob[i] != 0x30:
            raise SystemExit(f"bad DER cert at offset {i}")
        if i + 1 >= len(blob):
            raise SystemExit("truncated DER cert")
        length = blob[i + 1]
        hdr = 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or i + 2 + n > len(blob):
                raise SystemExit("bad DER length")
            length = int.from_bytes(blob[i + 2 : i + 2 + n], "big")
            hdr = 2 + n
        end = i + hdr + length
        if end > len(blob):
            raise SystemExit("truncated DER cert")
        out.append(blob[i:end])
        i = end
    return out


def _openssl_pubkey_from_cert_der(cert_der: bytes, out_pub: Path) -> None:
    with tempfile.NamedTemporaryFile(suffix=".crt.der", delete=False) as tf:
        tf.write(cert_der)
        crt = Path(tf.name)
    try:
        run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-in",
                str(crt),
                "-pubkey",
                "-noout",
                "-out",
                str(out_pub),
            ]
        )
    finally:
        crt.unlink(missing_ok=True)


def _openssl_pem_from_der(der: Path, pem: Path) -> None:
    run(["openssl", "x509", "-inform", "DER", "-in", str(der), "-out", str(pem)])


def verify_sig(buf: bytes, *, trust: Path | None = None, pubkey: Path | None = None) -> None:
    """
    Verify embedded wasmmod.sig (raises SystemExit on failure).
    PKI: --trust root.crt.der (+ chain inside MPWS).
    Pinned: --pubkey leaf.pub.der (SPKI) or PEM.
    """
    info = inspect_sig(buf)
    if info is None:
        raise SystemExit(f"no {SIG_SECTION}")
    stripped = without_sig_section(buf)
    if stripped[:4] == b"\x00aot":
        stripped = _aot_align4(stripped)

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        data_path = td_path / "payload.bin"
        sig_path = td_path / "sig.der"
        data_path.write_bytes(stripped)
        sig_path.write_bytes(info["sig"])

        pub_path = td_path / "leaf.pub.pem"
        if pubkey is not None:
            if not pubkey.is_file():
                raise SystemExit(f"missing pubkey {pubkey}")
            # Accept PEM or DER SPKI.
            raw = pubkey.read_bytes()
            if b"BEGIN" in raw:
                pub_path.write_bytes(raw)
            else:
                run(
                    [
                        "openssl",
                        "pkey",
                        "-pubin",
                        "-inform",
                        "DER",
                        "-in",
                        str(pubkey),
                        "-out",
                        str(pub_path),
                    ]
                )
        elif info["chain"]:
            certs = der_certs(info["chain"])
            leaf = certs[0]
            _openssl_pubkey_from_cert_der(leaf, pub_path)
            if trust is not None:
                if not trust.is_file():
                    raise SystemExit(f"missing trust {trust}")
                ca_pem = td_path / "ca.pem"
                if trust.read_bytes()[:1] == b"0":  # DER SEQUENCE
                    _openssl_pem_from_der(trust, ca_pem)
                else:
                    ca_pem.write_bytes(trust.read_bytes())
                leaf_pem = td_path / "leaf.pem"
                with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tf:
                    tf.write(leaf)
                    leaf_der = Path(tf.name)
                try:
                    _openssl_pem_from_der(leaf_der, leaf_pem)
                finally:
                    leaf_der.unlink(missing_ok=True)
                untrusted = td_path / "untrusted.pem"
                untrusted.write_bytes(b"")
                for c in certs[1:]:
                    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tf:
                        tf.write(c)
                        mid = Path(tf.name)
                    try:
                        mid_pem = td_path / f"mid-{mid.name}.pem"
                        _openssl_pem_from_der(mid, mid_pem)
                        untrusted.write_bytes(untrusted.read_bytes() + mid_pem.read_bytes())
                    finally:
                        mid.unlink(missing_ok=True)
                cmd = ["openssl", "verify", "-CAfile", str(ca_pem)]
                if untrusted.stat().st_size:
                    cmd += ["-untrusted", str(untrusted)]
                cmd.append(str(leaf_pem))
                run(cmd)
        else:
            raise SystemExit("need --trust (with MPWS chain) or --pubkey")

        run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(pub_path),
                "-signature",
                str(sig_path),
                str(data_path),
            ]
        )


def cmd_info(target: Path) -> None:
    if not target.is_file():
        raise SystemExit(f"missing {target}")
    info = inspect_sig(target.read_bytes())
    if info is None:
        raise SystemExit(f"{target}: no {SIG_SECTION}")
    print(f"section={info['section']}")
    print(f"mpws={int(info['is_mpws'])}")
    print(f"sig_len={info['sig_len']}")
    print(f"chain_len={info['chain_len']}")
    print(f"signed_len={info['signed_len']}")


def cmd_verify(target: Path, *, trust: Path | None, pubkey: Path | None) -> None:
    if not target.is_file():
        raise SystemExit(f"missing {target}")
    if trust is None and pubkey is None:
        raise SystemExit("verify needs --trust ROOT.crt.der and/or --pubkey leaf.pub")
    verify_sig(target.read_bytes(), trust=trust, pubkey=pubkey)
    print(f"{target}: OK")


def cmd_sign(
    key: Path,
    target: Path,
    *,
    cert: Path | None,
    chain: Path | None,
) -> None:
    if not key.is_file():
        raise SystemExit(f"missing key {key} (try: tools/wasmmod.py sign gen-pki -o .keys)")
    if not target.is_file():
        raise SystemExit(f"missing {target}")
    if chain is not None and not chain.is_file():
        raise SystemExit(f"missing chain {chain}")
    if cert is not None and not cert.is_file():
        raise SystemExit(f"missing cert {cert}")

    chain_bytes = b""
    if chain is not None:
        chain_bytes = chain.read_bytes()
    elif cert is not None:
        chain_bytes = cert.read_bytes()

    data = target.read_bytes()
    to_sign = without_sig_section(data)
    if to_sign[:4] == b"\x00aot":
        to_sign = _aot_align4(to_sign)

    with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as tf:
        sig_path = Path(tf.name)
    try:
        openssl_sign_bytes(key, to_sign, sig_path)
        sig = sig_path.read_bytes()
    finally:
        sig_path.unlink(missing_ok=True)

    payload = pack_mpws(sig, chain_bytes) if chain_bytes else sig
    target.write_bytes(append_sig_section(to_sign, payload))
    print(f"{target} (+{SIG_SECTION})", file=sys.stderr)
    print(target)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key", help="raw ECDSA keypair (no X.509)")
    g.add_argument("-o", "--output", type=Path, required=True, help="key prefix")

    p = sub.add_parser("gen-pki", help="write trust/ (root CA) + sign/ (leaf + chain)")
    p.add_argument("-o", "--output", type=Path, required=True, help="keys root (creates trust/ and sign/)")
    p.add_argument("--sub-ca", action="store_true", help="insert intermediate CA under root")
    p.add_argument("--days", type=int, default=3650, help="cert lifetime (default 10y)")

    s = sub.add_parser("sign", help="embed wasmmod.sig (MPWS) into .wasm / .aot / .elf")
    s.add_argument("--key", type=Path, required=True, help="private key PEM (leaf or raw)")
    s.add_argument("--cert", type=Path, help="leaf cert DER → MPWS chain (prefer --chain)")
    s.add_argument(
        "--chain",
        type=Path,
        help="full chain DER (leaf first, then intermediates) embedded in wasmmod.sig",
    )
    s.add_argument(
        "--embed",
        action="store_true",
        help=argparse.SUPPRESS,  # legacy no-op; embed is the only mode
    )
    s.add_argument("target", type=Path, help=".wasm / .aot / .elf path")

    i = sub.add_parser("info", help="inspect embedded wasmmod.sig")
    i.add_argument("target", type=Path, help=".wasm / .aot / .elf path")

    v = sub.add_parser("verify", help="verify embedded wasmmod.sig (openssl)")
    v.add_argument("--trust", type=Path, help="root CA DER/PEM (PKI; uses MPWS chain)")
    v.add_argument("--pubkey", type=Path, help="pinned leaf SPKI DER or PEM (skip chain)")
    v.add_argument("target", type=Path, help=".wasm / .aot / .elf path")

    args = ap.parse_args()
    if args.cmd == "gen-key":
        cmd_gen_key(args.output)
    elif args.cmd == "gen-pki":
        cmd_gen_pki(args.output, args.sub_ca, args.days)
    elif args.cmd == "info":
        cmd_info(args.target)
    elif args.cmd == "verify":
        cmd_verify(args.target, trust=args.trust, pubkey=args.pubkey)
    else:
        cmd_sign(args.key, args.target, cert=args.cert, chain=args.chain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
