"""Local TLS material for the explicit development network."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True, slots=True)
class TLSMaterial:
    ca_certificate: Path
    certificate: Path
    private_key: Path


def generate_local_tls(
    directory: str | Path,
    *,
    hostname: str = "localhost",
) -> TLSMaterial:
    """Create a short-lived local CA and leaf certificate without overwriting."""

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    ca_path = target / "agent-web-local-ca.pem"
    cert_path = target / "localhost-cert.pem"
    key_path = target / "localhost-key.pem"
    for path in (ca_path, cert_path, key_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite TLS file: {path}")

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Agent Web Local Development CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    san_entries: list[x509.GeneralName] = [x509.DNSName(hostname)]
    if hostname == "localhost":
        san_entries.extend(
            [
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]
        )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    created: list[Path] = []
    try:
        _exclusive_write(
            ca_path,
            ca_cert.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        created.append(ca_path)
        _exclusive_write(
            cert_path,
            leaf_cert.public_bytes(serialization.Encoding.PEM),
            0o644,
        )
        created.append(cert_path)
        _exclusive_write(
            key_path,
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        created.append(key_path)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return TLSMaterial(ca_path, cert_path, key_path)


def _exclusive_write(path: Path, content: bytes, mode: int) -> None:
    """Create one TLS file atomically enough to prevent permissive key modes."""

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
