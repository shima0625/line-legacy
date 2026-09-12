# Security policy

## Supported use

Use this project only on devices, accounts, and networks you control. The gateway handles authentication material, messages, contacts, group metadata, and uploaded media at runtime. It is not designed for untrusted multi-user hosting.

## Required controls

- Keep `/etc/line-legacy/line-legacy.env`, certificates, tokens, logs, queues, caches, and media outside version control.
- Restrict the deployment directory and environment file to the service account.
- Bind to a private interface and firewall gateway, DNS, CDN, call, and helper ports.
- Do not reuse a personal production account for protocol experiments.
- Rotate account sessions and remove generated state after a suspected disclosure.

## Reporting

Do not include tokens, MIDs, message bodies, phone numbers, packet captures, private keys, or reproducible account data in public reports. Provide a minimal redacted description to the repository maintainer.
