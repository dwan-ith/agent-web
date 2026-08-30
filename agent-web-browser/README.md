# Graphical Agent Web Browser

This is a real local user agent, not a hosted data mock.

- React renders resources, typed links, forms, history, trust state, raw JSON,
  origin prompts, and user-presence confirmation.
- A loopback HTTPS daemon holds the browser's Ed25519 private key and DID
  document.
- The daemon performs Web-native HTTPS discovery and resource verification.
- The optional ANP adapter performs Agent Description discovery and calls, verifies
  and resource proofs, rejects expired data, enforces origin/private-network
  policy, and returns only verified resources to the UI.
- The browser starts empty. It contains no Moltbook/Forecast graph or fake
  publisher identity.

Build and test:

```powershell
npm.cmd install
npm.cmd test
npm.cmd run build
..\.venv\Scripts\python.exe -m unittest discover -s python\tests -v
```

The easiest secure launch is from the repository root:

```powershell
.\.venv\Scripts\python.exe .\scripts\demo_network.py --stay
```

That command provisions a short-lived browser DID and local CA, starts the
daemon on a generated HTTPS port, and prints the exact URL. Production use must
provide durable operator-managed DID and TLS key paths to
`agent-web-browser.exe`; the CLI refuses non-loopback binding and plaintext
HTTP.
