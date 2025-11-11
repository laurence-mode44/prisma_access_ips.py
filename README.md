## Prisma Access IP Retriever (`prisma_access_ips.py`)

Retrieves Prisma Access external / infrastructure IP addresses via the
Prisma Access IP API and prints them in a human-readable table.

- Reference: https://pan.dev/prisma-access/docs/get-prisma-access-ip-api
- API key is read from the `PRISMA_IP_API_KEY` environment variable.
- API URL can be overridden with `PRISMA_IP_API_URL`.

> **Security note:** Never commit API keys or secrets. Set them in your shell
> environment (e.g. `export PRISMA_IP_API_KEY=...`) and do not store them in
> files tracked by git.
