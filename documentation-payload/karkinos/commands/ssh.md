+++
title = "SSH"
chapter = false
weight = 103
hidden = true
+++

Karkinos features a built-in SSH client. This allows the agent to make remote connections
to machines using SSH without spawning any processes. The SSH client features various
mechanisms for authentication such as ssh keys, username/password combo and interacting
with running ssh agents. More information about ssh agent auth can be found in the
[ssh-agent](/agents/karkinos/commands/ssh-agent/) command documentation.  

The commands below do not depend on an SSH client being installed on the system. All SSH
connections are handled in the agent.

## Commands
 - [SSH download](/agents/karkinos/commands/ssh-download/)
 - [SSH exec](/agents/karkinos/commands/ssh-exec/)
 - [SSH ls](/agents/karkinos/commands/ssh-ls/)
 - [SSH rm](/agents/karkinos/commands/ssh-rm/)
 - [SSH spawn](/agents/karkinos/commands/ssh-spawn/)
 - [SSH upload](/agents/karkinos/commands/ssh-upload/)

