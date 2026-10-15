# Proton Pass

Uses the Proton Pass CLI, `pass-cli run`: it reads secret references from an environment file, resolves them, and runs a command with the values in its environment. The options below are those of `pass-cli run --help` in version 2.4.2; check them against `pass-cli run --help` for your version.

1. Store the OAuth client ID and secret (and the privacy key) as fields of one item, say `tailkeeper` in vault `Personal`.
2. Write an environment file of references, mode 0600, for example `~/.config/tailkeeper/pass.env`:

   ```
   TAILKEEPER_READ_CLIENT_ID=pass://Personal/tailkeeper/TAILKEEPER_READ_CLIENT_ID
   TAILKEEPER_READ_CLIENT_SECRET=pass://Personal/tailkeeper/TAILKEEPER_READ_CLIENT_SECRET
   TAILKEEPER_PRIVACY_KEY=pass://Personal/tailkeeper/TAILKEEPER_PRIVACY_KEY
   ```

   It holds references, not values. A reference names the vault, the item and the field, as in Proton's documentation (`pass://vault/item/field`); `pass-cli item view --help` shows that the share ID and item ID work in their place. Check the form against `pass-cli run --help` and Proton's documentation for your version.
3. Point the configuration's `exec` provider at `pass-cli run` (use the absolute path `command -v pass-cli` prints):

   ```hujson
   "read": {
     "provider": "exec",
     "command": ["/opt/homebrew/bin/pass-cli", "run", "--env-file", "/Users/you/.config/tailkeeper/pass.env", "--"]
   }
   ```

   `pass-cli run` masks secrets in the child's output by default; leave that on. An MCP host starts tailkeeper without a terminal, so `pass-cli` must already be logged in.
4. Run `tailkeeper doctor`. It should report the read credential and the privacy key as loaded.
