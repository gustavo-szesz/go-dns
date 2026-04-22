# go-dns

Small Go project that builds DNS queries manually (RFC 1035 style) and resolves records over UDP, with emphasis on **MX** (mail exchange) lookup.

## What it does

- Encodes and decodes DNS messages (`dns` package)
- Sends DNS queries over UDP (`network` package)
- CLI commands:
  - `A` -> resolve IPv4
  - `MX` -> resolve mail exchangers (priority + host)
  - `MAIL` -> mail-oriented analysis (MX, Null MX, fallback to A, SPF, DMARC)

## Requirements

- Go `1.26.1` (as defined in `go.mod`)

## Run

```bash
go run . <domain> [A|MX|MAIL]
```

Examples:

```bash
go run . gmail.com A
go run . gmail.com MX
go run . gmail.com MAIL
```

## Example output (MX)

```text
gmail.com MX -> 5 gmail-smtp-in.l.google.com
gmail.com MX -> 10 alt1.gmail-smtp-in.l.google.com
...
```

## Project structure

```text
.
├── main.go          # CLI entrypoint
├── dns/             # DNS message model, encoding/decoding, RR parsing
└── network/         # UDP client + high-level resolvers (A, MX, TXT, MAIL)
```

## MX-focused improvement sketch

Current flow is already functional, but this is a practical next step to make MX lookups more robust:

```text
[Input Domain]
     |
     v
[Normalize domain]
     |
     v
[Query MX]
  | success                    | no MX/NODATA
  v                            v
[Sort by preference]      [Try fallback A]
  |                            |
  v                            v
[Resolve A/AAAA for each MX] [Mark fallback path]
     |
     v
[Return structured result + status code]
```

Suggested enhancements:

1. Use random DNS transaction IDs instead of fixed `0x1234`.
2. Distinguish `NXDOMAIN`, `NODATA`, timeout, and parse errors in return values.
3. Add retry with 2+ resolvers (for example: `8.8.8.8`, `1.1.1.1`).
4. Add table/json output mode for easier automation.
5. Add tests for compressed names and MX edge cases (including `Null MX` = `.`).

