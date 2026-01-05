# Karkinos

> A fork of [Thanatos](https://github.com/MythicAgents/thanatos) with enhanced capabilities

Karkinos is a Windows and Linux C2 agent written in Rust, built on the Thanatos foundation with additional offensive features.

## What's New in Karkinos

- **BOF/COFF Execution** - In-memory Beacon Object File execution using [coffeeldr](https://github.com/joaoviictorti/coffeeldr)
  - Cobalt Strike-compatible argument packing
  - Support for short, int, str, wstr, and binary argument types
  - Module stomping for enhanced evasion

## Installation

Requires [Mythic](https://github.com/its-a-feature/Mythic) to be set up.

```bash
sudo ./mythic-cli install github https://github.com/icryo/karkinos
sudo ./mythic-cli payload start karkinos
```

Karkinos supports the http C2 profile:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli c2 start http
```

## Features
  - Background job management
  - Built-in ssh client
    * Connect to a machine and download/upload files between that machine and Mythic
    * Get directory listings from machines using sftp
    * Spawn agents on machines using ssh
    * ssh-agent hijacking
  - Streaming portscan
  - Stand up TCP redirectors
  - **BOF/COFF execution (Windows)**

## General Commands

Command | Syntax | Description
------- | ------ | -----------
cat | `cat [file]` | Output the contents of a file.
cd | `cd [new directory]` | Change directory.
cp | `cp [source] [destination]` | Copy a file from [source] to [destination].
download | `download [path]` | Download a file from the target system (supports relative paths).
exit | `exit` | Exit the agent.
getenv | `getenv` | Get the current environment variables.
getprivs | `getprivs` | Get the privileges of the agent session.
jobkill | `jobkill [job id]` | Shutdown a running background job.
jobs | `jobs` | List currently running background jobs.
ls | `ls [directory]` | List files or directories (supports relative paths).
mkdir | `mkdir [directory]` | Make a new directory.
mv | `mv [source] [destination]` | Move a file from [source] to [destination] (supports relative paths).
portscan | `portscan [popup]` | Scan a list of IPs for open ports.
ps | `ps` | Get a list of currently running processes.
pwd | `pwd` | Print working directory.
redirect | `redirect [<bindhost>:<bindport>:<connecthost>:<connectport>]` | Setup a TCP redirector on the remote system.
rm | `rm [path]` | Remove a file or directory (supports relative paths).
setenv | `setenv [name] [value]` | Set environment variable [name] to [value].
shell | `shell [command]` | Run a shell command with `bash -c` on Linux or `cmd.exe /c` on Windows in a new thread.
sleep | `sleep [interval][units] [jitter]` | Set the sleep interval and jitter (supports unit suffixing).
ssh | `ssh [popup]` | Use ssh to execute commands, download/upload files or grab directory listings.
ssh-agent | `ssh-agent [-c <socket>] [-d] [-l]` | Connect to running ssh agent sockets on the host or list identities.
ssh-spawn | `ssh-spawn [popup]` | Spawn a Mythic agent on a remote host using ssh.
unsetenv | `unsetenv [var]` | Unset an environment variable.
upload | `upload [popup]` | Upload a file to the host machine.

### Windows-specific Commands
Command | Syntax | Description
------- | ------ | -----------
bof | `bof [popup]` | Execute a Beacon Object File in memory with arguments.
powershell | `powershell [command]` | Run a command using `powershell.exe /c` in a new thread.

## Credits

This project is a fork of [Thanatos](https://github.com/MythicAgents/thanatos) by the MythicAgents team. Original license applies.
