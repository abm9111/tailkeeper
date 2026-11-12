@AGENTS.md

## Claude MCP smoke test

- After `make install`, test the MCP server end to end in a headless session. Write a config file with `{"mcpServers": {"tailkeeper": {"type": "stdio", "command": "<absolute path to the installed binary>", "args": ["mcp"]}}}`, then run `claude -p --strict-mcp-config --mcp-config <file> --allowedTools mcp__tailkeeper --disallowedTools Bash --output-format json "<a read-only question>"`. Confirm the call in `tailkeeper audit tail -n 5` and run `tailkeeper audit verify`.
