# resqd-mcp

Model Context Protocol server for RESQD. Lets Claude (Desktop, Code, or any MCP client) read and write your zero-knowledge vault as a set of tools.

## Install

From this repo:

```bash
cd resqd/mcp
cargo install --path .
```

This puts `resqd-mcp` at `~/.cargo/bin/resqd-mcp`.

## Configure

You need three environment variables:

| var | where it comes from |
| --- | --- |
| `RESQD_API_URL` | your RESQD API base URL (e.g. `https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com` for alpha, or `https://api.resqd.ai` once on custom domain) |
| `RESQD_API_TOKEN` | mint one at `https://resqd-app.pages.dev/settings/` — only shown once |
| `RESQD_MASTER_KEY_B64` | your passkey-derived master key, also shown on `/settings/`. **Treat this like a root password — anyone who holds it can read your vault.** |

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "resqd": {
      "command": "resqd-mcp",
      "env": {
        "RESQD_API_URL": "https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com",
        "RESQD_API_TOKEN": "rsqd_your_token_here",
        "RESQD_MASTER_KEY_B64": "your_master_key_base64"
      }
    }
  }
}
```

Restart Claude Desktop. You should see the `resqd` MCP server connected and four tools available: `upload_file`, `list_vault`, `fetch_file`, `delete_file`.

## Claude Code

```bash
claude mcp add resqd resqd-mcp \
  -e RESQD_API_URL=https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com \
  -e RESQD_API_TOKEN=rsqd_your_token_here \
  -e RESQD_MASTER_KEY_B64=your_master_key_base64
```

## Tools

### `upload_file`
Encrypt a file on disk and store it in your vault.

**args:** `{ path: string, name?: string }`
**returns:** `{ asset_id, name, mime, size, canary_sequence, anchored_on_chain }`

Example prompt to Claude: *"Upload `~/Documents/tax_return_2026.pdf` to my RESQD vault."*

### `list_vault`
List your vault assets with decrypted filenames.

**args:** `{}`
**returns:** `{ count, assets: [{ asset_id, name, mime, created_at }] }`

### `fetch_file`
Download an asset, decrypt it, write it to disk. Triggers a canary rotation and on-chain anchor.

**args:** `{ asset_id: string, save_to: string }`
**returns:** `{ path, name, mime, size }`

### `delete_file`
Permanent removal. On-chain canary history is preserved (Base L2 is append-only).

**args:** `{ asset_id: string }`
**returns:** `{ asset_id, deleted }`

## Zero-knowledge caveat

The MCP server has a copy of your master key. That's how it can encrypt/decrypt locally without the RESQD server ever seeing plaintext. It's a real key delegation — treat the MCP host like you'd treat a Mac with your password on it.

A v2 design would use proxy re-encryption so each agent gets a delegated key scoped to specific assets, but that's future work.

## Debugging

Set `RUST_LOG=debug` to see verbose logs on stderr. `stdout` is reserved for MCP protocol — never log to it.
