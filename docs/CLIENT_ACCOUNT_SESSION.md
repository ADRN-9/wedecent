# Client account session foundation

`wd account` provides the local authenticated-session layer that later `wd connect`
automatic grant acquisition will use.

## Commands

```text
wd account login
wd account status
wd account logout
```

The login command requires the Supabase project URL, publishable key and account
email. The project URL and publishable key are public client configuration, not
server secrets. They may be supplied once through flags or environment variables:

```text
WEDECENT_SUPABASE_URL
WEDECENT_SUPABASE_PUBLISHABLE_KEY
WEDECENT_ACCOUNT_EMAIL
```

The account password is never accepted from an environment variable or a command
line argument. `wd` reads it interactively from a terminal and immediately drops
the Go string after the login request completes.

## Stored session

The session is stored under the existing client state directory as:

```text
account-session.json
```

With the default application-directory behavior this lives beside the client
identity and trust store. `WEDECENT_HOME` continues to override the state root.

The session file contains the Supabase access token and refresh token and must be
treated as a credential. On Unix-like systems the client creates the state
directory with mode `0700`, creates the session file with mode `0600`, and refuses
to load a session file that is readable or writable by group/other users. Writes
use a protected temporary file and rename so a partially written credential file
is not installed.

Windows builds now disable console echo while reading passwords. Windows ACL- or
credential-vault-backed storage remains a separate hardening milestone; POSIX
mode bits alone are not a complete Windows secret-storage design.

## Refresh behavior

`wd account status` refreshes the Supabase access token when it has less than two
minutes of validity remaining, persists the rotated access/refresh tokens, and
then verifies the session with `/auth/v1/user`. It never prints either token.

`wd account logout` requests Supabase `scope=local`, so it terminates only this CLI
session rather than every session for the account, and always removes the local
session file. If the network or remote logout fails, the command warns that only
the local credential was removed.

## Security boundary

The publishable key is intentionally client-safe. The following values are not:

- account password
- access token
- refresh token
- connection-grant JWT
- device private identity key
- connection-grant signing private key

None of those secret credentials should be committed, logged, copied into issue
reports, or supplied as normal command-line arguments.

## Automatic relay grants

When `wd connect` selects a `wsrelay://` locator and no diagnostic
`--connection-grant-file` override is supplied, the client now loads the local
account session, refreshes it when necessary, persists any rotated refresh token,
and calls `/functions/v1/connection-grant` with this client's cryptographic
device ID and the requested target device ID.

The returned `terminal.connect` grant is kept only in process memory and is
passed directly to the WebSocket relay transport. It is not written to disk,
printed, or passed through a command-line argument. The existing
`--connection-grant-file` option remains an explicit diagnostic override for
relay authorization tests.

Direct TCP and legacy TCP-relay locators do not load the account session or
request a Supabase connection grant. If a WebSocket relay connection is selected
without a local account session, `wd` fails before dialing and instructs the user
to run `wd account login`.
