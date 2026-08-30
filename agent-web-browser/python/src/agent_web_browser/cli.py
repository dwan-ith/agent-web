from __future__ import annotations

import argparse
from urllib.parse import urlsplit

import uvicorn
from libagentweb import LocalEd25519Signer, load_ed25519_private_key

from .daemon import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Agent Web Browser")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--base-url", default="https://localhost:7443")
    parser.add_argument("--identity-directory")
    parser.add_argument("--did-document")
    parser.add_argument("--private-key")
    parser.add_argument(
        "--web-caller-key",
        help="Ed25519 PEM key for Web-native authenticated HTTP actions",
    )
    parser.add_argument("--tls-certificate", required=True)
    parser.add_argument("--tls-private-key", required=True)
    parser.add_argument(
        "--session-token",
        help="pin the daemon session token instead of generating one "
        "(scripted launches); auto-generated and printed otherwise",
    )
    parser.add_argument("--allow-private-network", action="store_true")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("--host must remain loopback")
    parsed = urlsplit(args.base_url)
    if parsed.scheme != "https" or parsed.hostname not in {"localhost", "127.0.0.1"}:
        parser.error("--base-url must be an HTTPS loopback URL")
    identity = None
    did_document = None
    private_key = None
    if args.identity_directory or args.did_document or args.private_key:
        try:
            from agent_web_server import PublisherIdentity, active_identity_paths
        except ModuleNotFoundError as exc:
            parser.error(
                "identity options require the optional browser ANP compatibility extra"
            )
        if args.identity_directory:
            if args.did_document or args.private_key:
                parser.error(
                    "--identity-directory cannot be combined with direct identity files"
                )
            did_document, private_key = active_identity_paths(
                args.identity_directory
            )
            identity = PublisherIdentity.from_files(did_document, private_key)
        else:
            if not args.did_document or not args.private_key:
                parser.error(
                    "provide both --did-document and --private-key"
                )
            did_document = args.did_document
            private_key = args.private_key
            identity = PublisherIdentity.from_files(did_document, private_key)
    caller_controller = None
    caller_signer = None
    if args.web_caller_key:
        caller_controller = f"{args.base_url.rstrip('/')}/.well-known/agent-web-caller"
        caller_signer = LocalEd25519Signer(
            load_ed25519_private_key(args.web_caller_key),
            key_id=f"{caller_controller}#key-1",
        )
    app = create_app(
        identity=identity,
        did_document_path=did_document,
        private_key_path=private_key,
        base_url=args.base_url,
        allow_private_networks=args.allow_private_network,
        caller_controller=caller_controller,
        caller_signer=caller_signer,
        session_token=args.session_token,
    )
    print(
        "Agent Web Browser ready:", f"{args.base_url.rstrip('/')}?token={app.state.daemon_token}"
    )
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=args.tls_certificate,
        ssl_keyfile=args.tls_private_key,
    )


if __name__ == "__main__":
    main()
