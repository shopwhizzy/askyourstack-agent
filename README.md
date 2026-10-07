# AskYourStack agent

This is the program that [AskYourStack](https://askyourstack.com) installs on a customer's Linux server. It is the only part of AskYourStack that runs on your machine, as the Linux user you choose (an ordinary user that owns your sites, or root for the whole server), so here is its source: read it, build it, and check that the binary we serve is the one this code makes.

The rest of AskYourStack (the MCP server your AI talks to, the risk classification, the approval gate, the dashboard) runs at askyourstack.com and is not in this repository.

## What it does

The agent is one static Go binary with no dependencies outside Go's standard library (`go.mod` lists none). It:

- **dials out** to `https://askyourstack.com` and asks for work. It opens no port and runs no server. Each request waits up to 25 seconds for a job, then asks again (`loop` in `main.go`).
- **runs the operations** the hub sends and posts the results back. The full list is the `switch` in `handle()` in `main.go`: facts about the machine, run a command, read and write a file, snapshots and rollback, background jobs, list the sites it finds, a health report, log and traffic reports, database queries with the site's own credentials, the site's console (bin/magento, wp-cli, bin/console, artisan, drush), server-to-server copies for migrations, database dumps and restores, image conversion, a whole-site crawl and the malware scan.
- **updates itself** from a signed manifest (`selfUpdate` in `main.go`): the manifest's ed25519 signature is checked against `releaseKey`, the public key built into the binary (the same key as `release-key.pem` here), the download's SHA-256 is checked against the manifest, and the new binary must start and name the expected version before it replaces the old one, which is kept as `.prev`.

The agent does not judge commands. The classification into read, change, destructive and blocked, the server's safety mode and the approvals happen at askyourstack.com before a job reaches the agent. In other words, whoever controls the hub, or your private MCP address within the mode you set, controls what the agent runs. Two things the hub cannot override are on this machine: disconnecting, and the lock below.

## What it talks to

Three endpoints, all outbound HTTPS to the hub, with the agent's own token as a bearer header:

| Call | When | What is sent |
|---|---|---|
| `POST /agent/enroll` | once, at install | the one-time install token, hostname, agent version, the Unix user it runs as, whether that is root |
| `GET /agent/poll` | continuously | the version header, `X-Agent-Locked: 1` when locked; the answer is a job or nothing |
| `POST /agent/result` | after each job | the job's result, which is what the tool returns to the AI |

Nothing else leaves the server unless a job reads it (a file your AI asked for, a command's output, a report). Database passwords are read from the site's own configuration and handed to the database client in a private file (`sites.go`); they are never part of a result. Server-to-server copies for a migration go straight between the two servers over rsync and SSH with a throwaway key (`transfer.go`); the files never pass through the hub.

To see it yourself on a server: `ss -tnp | grep sudowhizzy-agent`.

## Where it keeps things

As root (a system service): configuration in `/etc/sudowhizzy/agent.json` (the hub address and the agent's token, mode 0600), state in `/var/lib/sudowhizzy` (jobs, snapshots, dumps, audits, deleted after 7 to 90 days), the binary in `/usr/local/bin`. As an ordinary user (shared hosting, no root): `~/.config/sudowhizzy`, `~/.local/share/sudowhizzy` and `~/.local/bin`, and it manages only that user's own sites and files (`mode.go`). Root is optional: run the same install line as a jailed Linux user and the operating system, not the agent, is what keeps it inside that user's home.

## The lock

```
sudowhizzy-agent lock
```

While the lock is set, the agent answers only the operations that read (`readOps` in `lock.go`: facts, files, logs, the health, traffic and crawl reports, snapshots and dumps it takes itself, read-only database queries) and refuses every other job, whatever the hub sends and whatever safety mode the server has in the dashboard. Shell commands (`run`, `job_start`) are refused entirely: the agent cannot tell a reading command from a writing one. Only someone with a shell on the server can lift it, with `sudowhizzy-agent unlock`. It is the one check that does not depend on the hub. Signed agent updates still apply while locked.

## Disconnect

In the dashboard, Disconnect revokes the agent's token: the agent exits with code 3 and systemd leaves it stopped. On the server:

```
systemctl disable --now sudowhizzy-agent
```

## Check a release against this source

Every release is built from a commit of this repository, with Go and flags that make the build reproducible: the same commit and the same Go version give byte-for-byte the same binary. The release manifest at <https://askyourstack.com/dl/manifest.json> names the version, the SHA-256 of each binary, the commit and the Go version, and <https://askyourstack.com/dl/manifest.sig> is its signature.

```sh
git clone https://github.com/shopwhizzy/askyourstack-agent.git
cd askyourstack-agent
sh verify.sh                                   # the release served right now
sh verify.sh /usr/local/bin/sudowhizzy-agent   # and the binary installed on this machine
```

`verify.sh` checks the manifest's signature with `release-key.pem`, checks out the commit the manifest names, builds with the same command and compares the hash. You need git, curl, openssl and the Go version the manifest names (a different Go version gives a different hash, which proves nothing either way). By hand:

```sh
curl -fsSL https://askyourstack.com/dl/manifest.json -o manifest.json
curl -fsSL https://askyourstack.com/dl/manifest.sig | base64 -d > manifest.sig
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in manifest.json -sigfile manifest.sig
git checkout <commit from manifest.json>
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.sourceCommit=$(git rev-parse HEAD)" -o sudowhizzy-agent .
sha256sum sudowhizzy-agent        # must equal files.amd64 in manifest.json
sudowhizzy-agent build            # an installed agent prints its version, commit and Go version
```

## The installer

`install.sh` is the script behind the one-line install. It downloads the binary for your CPU from `https://askyourstack.com/dl/`, enrols with your one-time token and installs a systemd unit (as root) or a user unit or cron watchdog (as a user). To read it before running it:

```sh
curl -fsSL https://askyourstack.com/install.sh -o install.sh
less install.sh
sh install.sh <your token>
```

## Build and test

```sh
go build .
go test ./...
./sudowhizzy-agent sites     # what list_sites would answer on this machine
```

## The malware scan's patterns

`scan.go` holds its detection patterns XOR-scrambled (`sig()`, the readable pattern is in the comment above each). That is not secrecy, the patterns are the usual web shell and skimmer signatures: antivirus programs flagged the agent itself as malware when the strings were readable in the binary. The larger rule set is sent by the hub with each scan and is not in this repository.

## Reporting a security problem

Write to <info@askyourstack.com> with "security" in the subject, or see <https://askyourstack.com/.well-known/security.txt>. We answer every report.

## Licence

Apache License 2.0, see `LICENSE`. Copyright Whizzy Digital Solutions Lda.
