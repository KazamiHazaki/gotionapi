# GoTionAPI

Notion AI → OpenAI-compatible API server. Single Go binary, zero runtime dependencies.

Uses [uTLS](https://github.com/refraction-networking/utls) Chrome JA3 fingerprint impersonation to bypass Notion's bot detection — same technique as the Python `cloudscraper` approach, but compiled into a standalone binary.

## Quick Start

```bash
# Linux/macOS
chmod +x gotionapi-linux-amd64
./gotionapi-linux-amd64

# Windows
gotionapi-windows-amd64.exe
```

On first run, paste your `NOTION_ACCOUNTS` JSON when prompted:

```
Input your key :
{
  "token_v2": "v03:your_token_here",
  "space_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "user_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "space_view_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "user_name": "Your Name",
  "user_email": "you@example.com"
}
```

Server starts on `http://localhost:8000`.

## Usage

```bash
# List models
curl http://localhost:8000/v1/models

# Chat completion (non-stream)
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet4.6",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Chat completion (stream)
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "kimi-2.6",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'

# Health check
curl http://localhost:8000/health
```

## Models

| Friendly Name | Notion Internal ID |
|---|---|
| `claude-opus4.6` | avocado-froyo-medium |
| `claude-opus4.7` | apricot-sorbet-high |
| `claude-opus4.8` | ambrosia-tart-high |
| `claude-sonnet4.6` | almond-croissant-low |
| `gemini-2.5flash` | vertex-gemini-2.5-flash |
| `gemini-3.1pro` | galette-medium-thinking |
| `gpt-5.2` | oatmeal-cookie |
| `gpt-5.4` | oval-kumquat-medium |
| `gpt-5.5` | opal-quince-medium |
| `kimi-2.6` | fireworks-kimi-k2.6 |

Default model: `claude-sonnet4.6`

## Modes

Set via `APP_MODE` environment variable:

| Mode | Description |
|---|---|
| `lite` | Minimal — single-turn, no history, lowest resource usage |
| `standard` | Full context in each request, no persistent storage |
| `heavy` (default) | Multi-turn conversations with SQLite persistence |

### Heavy Mode

Pass `conversation_id` in the request body to continue a conversation:

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet4.6",
    "messages": [{"role": "user", "content": "What did I just say?"}],
    "conversation_id": "abc-123"
  }'
```

Conversations are stored in SQLite (`DB_PATH`, default `./data/conversations.db`).

## Configuration

All via environment variables or `.env` file:

| Variable | Default | Description |
|---|---|---|
| `APP_MODE` | `heavy` | `lite`, `standard`, or `heavy` |
| `PORT` | `8000` | Server listen port |
| `NOTION_ACCOUNTS` | — | JSON account config (fallback if no `accounts.json`) |
| `DB_PATH` | `./data/conversations.db` | SQLite path (heavy mode only) |
| `NOTION2API_DEBUG` | — | Set `1` for verbose logging |

### Account Loading Priority

1. `accounts.json` file
2. `NOTION_ACCOUNTS` environment variable
3. `.env` file
4. Interactive prompt (first run)

## Build from Source

Requires Go 1.21+:

```bash
cd notion2api-go-mvp
go build -o gotionapi .
```

## Releases

Pre-built binaries available on the [Releases](https://github.com/KazamiHazaki/gotionapi/releases) page:

- `gotionapi-linux-amd64`
- `gotionapi-linux-arm64`
- `gotionapi-darwin-amd64`
- `gotionapi-darwin-arm64`
- `gotionapi-windows-amd64.exe`

## Architecture

```
Client (OpenAI SDK / curl)
  │
  ▼
GoTionAPI Server (Go binary)
  │  ┌─────────────────────┐
  │  │ uTLS Chrome JA3     │ ← impersonates Chrome TLS fingerprint
  │  │ HTTP/1.1             │
  │  └─────────┬───────────┘
  ▼            ▼
Notion API  ─  /api/v3/runInferenceTranscript
```

Key technical decisions:
- **uTLS** (`github.com/refraction-networking/utls v1.6.7`) for Chrome JA3 TLS fingerprint impersonation
- **HTTP/1.1 only** — strips `h2` from ALPN because `*utls.UConn` breaks Go's h2 transport detection
- **Fresh TLS spec per connection** — `UTLSIdToSpec(HelloChrome_Auto)` + `ApplyPreset(HelloCustom)`
- **Pure Go SQLite** (`modernc.org/sqlite`) — no CGO required

## License

MIT
