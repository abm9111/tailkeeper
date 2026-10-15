# 1Password

Uses the 1Password CLI, `op run`: it reads secret references from an environment file, resolves them, and runs a command with the values in its environment. The options are those of 1Password's documentation of `op run`; check them against `op run --help` for your version.

1. Store the OAuth client ID and secret (and the privacy key) as fields of one item, say `tailkeeper` in vault `Private`.
2. Write an environment file of references, mode 0600, for example `~/.config/tailkeeper/op.env`:

   ```
   TAILKEEPER_READ_CLIENT_ID=op://Private/tailkeeper/client-id
   TAILKEEPER_READ_CLIENT_SECRET=op://Private/tailkeeper/client-secret
   TAILKEEPER_PRIVACY_KEY=op://Private/tailkeeper/privacy-key
   ```

   It holds references, not values.
3. Point the configuration's `exec` provider at `op run` (use the absolute path `command -v op` prints):

   ```hujson
   "read": {
     "provider": "exec",
     "command": ["/opt/homebrew/bin/op", "run", "--env-file", "/Users/you/.config/tailkeeper/op.env", "--"]
   }
   ```

   `op run` conceals any value it loaded if the program prints it; leave that on. An MCP host starts tailkeeper without a terminal, so `op` must be able to unlock without one: use the 1Password app's integration with the CLI, which asks the app for approval, as 1Password's documentation describes.
4. Run `tailkeeper doctor`. It should report the read credential and the privacy key as loaded.
