# Supermemory MCP Setup

Supermemory provides Tier 3 (cloud-based) memory that survives session resets, machine changes, and everything else.

## 1. Create a Supermemory Account

Sign up at [supermemory.ai](https://supermemory.ai) and get your API key.

## 2. Add to MCP Configuration

Add the following to your `~/.mcp.json` file:

```json
{
  "mcpServers": {
    "mcp-supermemory-ai": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-supermemory"],
      "env": {
        "SUPERMEMORY_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

**Note:** The exact package name and configuration may vary. Check the Supermemory documentation for the latest MCP server setup instructions.

## 3. Verify

Restart Claude Code and test:

```
Save a test memory: "This is a test memory for team blueprint setup"
```

Then in a new session:

```
Recall: "team blueprint setup"
```

You should see the test memory returned.

## 4. Project Scoping

Use `containerTag` to scope memories per project:

- **Save with tag:** Memories are saved with a project identifier
- **Recall with tag:** Only returns memories from that project
- **No tag:** Cross-project memories (patterns, learnings)

## Available Tools

Once configured, these MCP tools are available:

| Tool | Purpose |
|---|---|
| `mcp__mcp-supermemory-ai__memory` | Save or forget memories |
| `mcp__mcp-supermemory-ai__recall` | Search memories semantically |
| `mcp__mcp-supermemory-ai__listProjects` | List available project scopes |
| `mcp__mcp-supermemory-ai__whoAmI` | Check current user info |

## Security

- Store your API key securely (the `~/.mcp.json` file should be `chmod 600`)
- Never commit API keys to git
- Each team member needs their own Supermemory account and API key
