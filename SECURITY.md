# Security

## Reporting a vulnerability

Please report security issues through the disclosure process at
**https://security.omitly.app/disclosure/** rather than opening a public issue.

We would rather hear about a problem early and imperfectly described than not at
all. If you are unsure whether something is a security issue, report it anyway.

## What this repository contains

This repository holds the Omitly MCP server and the compiled wasm detection
bundle. The redaction engine, the tamper-evidence seal and the licensing
implementation are developed privately and are not part of this repository —
this code calls the engine, it does not contain it.

That means a vulnerability you find here is most likely in one of:

- the MCP tool surface (argument handling, path resolution, schema enforcement)
- the free-tier metering in `src/usage.ts`
- the Claude Desktop bundle under `mcpb/`

Findings in the engine itself are equally welcome — report them the same way.

## Verifying the wasm bundle

`wasm/leakcheck_wasm_bg.wasm.sha256` records the SHA-256 of the committed
bundle. It is the same artifact published in the `omitly-mcp` npm package, so
you can compare all three — this repository, the npm tarball, and your installed
copy:

```bash
shasum -a 256 wasm/leakcheck_wasm_bg.wasm
cat wasm/leakcheck_wasm_bg.wasm.sha256
```

If those ever disagree, treat it as a security issue and report it.

## Network behaviour

The MCP server does not send document content anywhere. Detection and redaction
run on your machine, and the free-tier usage counter is a local file under
`OMITLY_STATE_DIR` (default `~/.omitly`) — nothing in that path touches the
network.

If you observe this server making a network request you did not ask for, that is
a bug and a security issue. Please report it.

## Further reading

Omitly publishes its threat model, a summary of its cryptographic bill of
materials, and its post-quantum transition plan:

- Threat model — https://security.omitly.app/threat-model/
- Cryptography — https://security.omitly.app/crypto/
- Post-quantum plan — https://security.omitly.app/pqc/
