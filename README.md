# GoTionAPI

Notion AI → OpenAI-compatible API server. Single Go binary, zero runtime dependencies.

Uses [uTLS](https://github.com/refraction-networking/utls) Chrome JA3 fingerprint impersonation to bypass Notion's bot detection — same technique as the Python `cloudscraper` approach, but compiled into a standalone binary.

**v3.2.1** — Response filter (7-step), input filter (framework injection strip), bookend detection, broadened reasoning patterns.

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

An API key is auto-generated and displayed:

```
✓ Account saved to accounts.json
🔑 API Key: sk-xxx...xxxx
   (saved to .apikey — use this as Bearer token)
```

Server starts on `http://localhost:8000`.

## Features

### API Endpoints (OpenAI-compatible)

| Endpoint | Auth | Description |
|---|---|---|
| `GET /` | - | Root info page |
| `GET /health` | - | Health check (accounts, mode, status) |
| `GET /v1/models` | Bearer | List all registered models |
| `POST /v1/chat/completions` | Bearer | Chat completion (stream + non-stream) |

### Models (10 registered)

| Friendly Name | Notion Workflow ID | Default |
|---|---|---|
| `claude-sonnet4.6` | almond-croissant-low | ✅ |
| `claude-opus4.6` | avocado-froyo-medium | |
| `claude-opus4.7` | apricot-sorbet-high | |
| `claude-opus4.8` | ambrosia-tart-high | |
| `gemini-2.5flash` | vertex-gemini-2.5-flash | |
| `gemini-3.1pro` | galette-medium-thinking | |
| `gpt-5.2` | oatmeal-cookie | |
| `gpt-5.4` | oval-kumquat-medium | |
| `gpt-5.5` | opal-quince-medium | |
| `kimi-2.6` | fireworks-kimi-k2.6 | |

### 3 Operating Modes

Set via `APP_MODE` environment variable:

| Mode | Description |
|---|---|
| `lite` | Minimal — single-turn, no history, lowest resource usage |
| `standard` | Full context in each request, no persistent storage |
| `heavy` (default) | Multi-turn conversations with SQLite persistence |

### Auth & Account Management

- **API key**: `API_KEY` env > `.apikey` file > auto-generate (if accounts exist)
- **Account loading**: `accounts.json` > `NOTION_ACCOUNTS` env > `.env` > interactive prompt
- **CLI commands**: `apikey-reset`, `apikey-regenerate` (via `os.Args[1]`)
- **Multi-account**: load balancing across Notion accounts

### Security & Anti-Detection

- **uTLS fingerprinting** — Chrome JA3/TLS fingerprint impersonation (bypass Cloudflare)
- **Warm-up cookies** — auto-collect `__cf_bm`, `_cfuvid`, `notion_browser_id`, `device_id` from notion.so→notion.com redirect chain
- **Multi-domain cookie strategy** — visits 5 domains for full cookie set
- **Auth middleware** — `requireAuth()` wrapper on all `/v1/*` endpoints

### Response Filter (7 steps)

Notion AI responses often contain internal artifacts that leak into the output. GoTionAPI automatically cleans these through a 7-step pipeline:

| Step | What | Example | Method |
|---|---|---|---|
| 1 | Notion markup | `<lang primary="en-US">`, `<br>`, attribute tails | Regex cleanup |
| 1.5 | Bookend detection | `Simple greeting, no tools needed.` at start + end | Regex match + strip both |
| 2 | Reasoning prefix | `General knowledge question.`, `Simple greeting in Indonesian.` | 10+ regex patterns |
| 3 | Content duplication | Same response appears twice (artifacted + clean) | Paragraph-level dedup |
| 4 | Trailing fragment | Reasoning meta-text in last paragraph | Pattern strip |
| 5 | Trailing line prefix | Reasoning text on last line | Line-level strip |
| 6 | Inline suffix | `...😊Simple greeting in Indonesian.` | Search last 80 chars |

Applied to all response paths: non-stream (heavy + standard), stream chunks (heavy + standard), and record-map extraction.

### Input Filter

Framework injection blocks are stripped from user messages before sending to Notion:

| Block | Pattern | Purpose |
|---|---|---|
| `memory-context` | `` | Hermes memory injection |
| `hermes-memory` | `<hermes-memory>...</hermes-memory>` | Hermes memory block |
| `honcho-context` | `<honcho-context>...</honcho-context>` | Honcho context block |

### Heavy Mode (SQLite Persistence)

Pass `conversation_id` in the request body to continue a conversation:

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ***" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet4.6",
    "messages": [{"role": "user", "content": "What did I just say?"}],
    "conversation_id": "abc-123"
  }'
```

Conversations are stored in SQLite (`DB_PATH`, default `./data/conversations.db`).

## API Key Authentication

All `/v1/*` endpoints require Bearer token authentication. Public endpoints (`/health`, `/`) are unauthenticated.

```bash
# Include the API key in requests
curl http://localhost:8000/v1/models \
  -H "Authorization: Bearer sk-xxx...xxxx"

curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx...xxxx" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-sonnet4.6", "messages": [{"role": "user", "content": "Hello!"}]}'
```

### CLI Commands

```bash
# Regenerate API key
./gotionapi apikey-reset

# Same as above (alias)
./gotionapi apikey-regenerate
```

### Key Loading Priority

1. `API_KEY` environment variable
2. `.apikey` file
3. Auto-generated on first run (if accounts exist)

## Usage

```bash
# List models
curl http://localhost:8000/v1/models \
  -H "Authorization: Bearer sk-xxx...xxxx"

# Chat completion (non-stream)
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx...xxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet4.6",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Chat completion (stream)
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx...xxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "kimi-2.6",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'

# Health check (no auth required)
curl http://localhost:8000/health
```

## Configuration

All via environment variables or `.env` file:

| Variable | Default | Description |
|---|---|---|
| `APP_MODE` | `heavy` | `lite`, `standard`, or `heavy` |
| `PORT` | `8000` | Server listen port |
| `API_KEY` | auto-generated | Bearer token for auth (set to override) |
| `NOTION_ACCOUNTS` | — | JSON account config (fallback if no `accounts.json`) |
| `DB_PATH` | `./data/conversations.db` | SQLite path (heavy mode only) |
| `NOTION2API_DEBUG` | — | Set `1` for verbose logging |

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
  │  ┌──────────────────────┐
  │  │ Bearer Auth (API Key) │ ← auto-generated sk-* key
  │  │ uTLS Chrome JA3       │ ← impersonates Chrome TLS fingerprint
  │  │ HTTP/1.1               │
  │  └──────────┬─────────────┘
  ▼             ▼
Input Filter ← strips memory-context, hermes-memory, honcho-context
  │
  ▼
Notion API  ─  /api/v3/runInferenceTranscript
  │
  ▼
Response Filter (7 steps) ← markup, bookend, prefix, dedup, trailing, suffix
  │
  ▼
Client (clean OpenAI-compatible response)
```

## Technical Details

- **uTLS** (`github.com/refraction-networking/utls v1.6.7`) for Chrome JA3 TLS fingerprint impersonation
- **HTTP/1.1 only** — strips `h2` from ALPN because `*utls.UConn` breaks Go's h2 transport detection
- **Fresh TLS spec per connection** — `UTLSIdToSpec(HelloChrome_Auto)` + `ApplyPreset(HelloCustom)`
- **Pure Go SQLite** (`modernc.org/sqlite`) — no CGO required
- **API Key auth** — auto-generated on first run, stored in `.apikey`, configurable via `API_KEY` env var
- **Response filter** — 7-step pipeline: markup cleanup, bookend detection, reasoning prefix strip, deduplication, trailing fragment/line strip, inline suffix detection
- **Input filter** — strips `` and `<hermes-memory>` / `<honcho-context>` blocks before forwarding to Notion
- **Warm-up** — visits notion.so→notion.com redirect chain to collect Cloudflare cookies (`__cf_bm`, `_cfuvid`, `notion_browser_id`, `device_id`)
- **Multi-account** — round-robin across registered Notion accounts

## Hermes Integration

GoTionAPI can be used as a custom provider in [Hermes Agent](https://hermes-agent.nousresearch.com):

```yaml
# ~/.hermes/config.yaml
custom_providers:
  local-notion:
    base_url: http://localhost:8000/v1
    api_key: sk-xxx...xxxx
```

## License

MIT
