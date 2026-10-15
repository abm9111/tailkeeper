# Credential recipes

tailkeeper's `exec` credential provider re-runs tailkeeper under a wrapper command you name in the configuration. The wrapper must put `TAILKEEPER_READ_CLIENT_ID` and `TAILKEEPER_READ_CLIENT_SECRET` (and, if you use one, `TAILKEEPER_PRIVACY_KEY`) in the environment of the command it runs, then run it. It must not print them. The secret then reaches tailkeeper's process only, never your shell.

- `1password.md`: with the 1Password CLI (`op run`).
- `proton-pass.md`: with the Proton Pass CLI (`pass-cli run`).

Any secret manager with an equivalent "run with secrets in the environment" command works the same way.

## What every recipe follows

- The configuration's `command` holds the wrapper and its options, never a value. Arguments are visible to every process of your user, and the configuration file is a file.
- The file the wrapper reads lists references to the secrets, never the secrets. Keep it mode 0600 anyway: it shows which vault and item hold them.
- The wrapper is an absolute path, because tailkeeper refuses a relative one and MCP hosts start servers with a minimal `PATH`. The `command` list ends with `--`, so that the wrapper takes the rest as the command to run. That is the convention of these recipes (a test checks it), not a rule tailkeeper enforces: it checks only that the list is not empty and that its first element is an absolute path, then runs the list followed by its own binary and arguments.
- Nothing is exported in a shell profile or an agent host's settings. A variable set there reaches every program the shell or host starts.
- While tailkeeper runs, the values sit in its environment, and the wrapper holds them in memory. Another process of your user can read them there. That is the limit of personal mode that the README and `SECURITY.md` state: run your agent in a sandbox that cannot reach these processes.
- Check a recipe with `tailkeeper doctor`, which reports the read credential (the first four characters of its client ID only) and whether the privacy key loaded. It never prints a secret.
