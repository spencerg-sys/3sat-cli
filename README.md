# 3SAT CLI

Command line client for the 3SAT protocol.

The package installs a `3sat` command for users who want to search the answer database, create bounties, buy answer access, and download answer bundles without using the web UI.

## Install

For local development:

```bash
cd 3sat_CLI
python -m pip install -e .
```

After publishing to PyPI, the intended install command is:

```bash
pip install 3sat
```

## Security

Use a dedicated protocol wallet. Do not use your main wallet.

The CLI does not store private keys by default. Pass a private key with `--private-key`, or set:

```bash
export 3SAT_PRIVATE_KEY=0x...
```

On PowerShell:

```powershell
$env:3SAT_PRIVATE_KEY="0x..."
```

## Quickstart

Show current configuration:

```bash
3sat config show
```

Initialize the default public deployment configuration:

```bash
3sat config init
```

Search for an existing answer:

```bash
3sat search problem.cnf
```

Create a bounty. The command prepares and uploads the instance/metadata first. It broadcasts only when `--send` is provided:

```bash
3sat issue problem.cnf --reward 100 --token USDC --send
```

Buy answer access:

```bash
3sat buy-answer SAT-XXXX-XXXX-XXXX --send
```

Download an original finalized bounty bundle:

```bash
3sat download-answer SAT-XXXX-XXXX-XXXX -o answer.zip
```

Download a matched bundle rebuilt for the CNF you searched:

```bash
3sat download-answer SAT-XXXX-XXXX-XXXX --cnf my-query.cnf -o matched-answer.zip
```

## Commands

- `3sat config show`
- `3sat config init`
- `3sat config set KEY VALUE`
- `3sat standardize problem.cnf`
- `3sat search problem.cnf`
- `3sat marketplace`
- `3sat bounty SAT-...`
- `3sat issue problem.cnf --reward 100 --token USDC --send`
- `3sat buy-answer SAT-... --send`
- `3sat download-answer SAT-... --cnf query.cnf`
- `3sat balance --address 0x...`

## Configuration

The config file is stored at:

```text
~/.3sat/config.json
```

Supported environment variable overrides:

- `3SAT_API_URL`
- `3SAT_RPC_URL`
- `3SAT_CHAIN_ID`
- `3SAT_CHAIN_NAME`
- `3SAT_BOUNTY_MANAGER_ADDRESS`
- `3SAT_ARTIFACT_ACCESS_CONTROLLER_ADDRESS`
- `3SAT_USDC_ADDRESS`
- `3SAT_TOKEN_ADDRESS`
- `3SAT_PRIVATE_KEY`

## Notes

The CLI uses the public 3SAT API for artifact storage, search, metadata generation, and transaction preparation. Wallet signing and transaction broadcasting happen locally on the user's machine.

The solver and verifier automation clients remain separate because they bundle SAT solvers, proof checkers, and long-running polling loops.

