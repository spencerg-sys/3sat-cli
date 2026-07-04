# 3SAT CLI

Official command line client for the 3SAT protocol.

The package installs a `3sat` command for users who want to search the answer database, create bounties, buy answer access, and download answer bundles without using the web UI.

## Links

- Website: https://3sat.network/
- Web app: https://3sat.network/app
- Protocol docs: https://3sat.network/docs/api
- SAT Academy: https://3sat.network/docs/academy

## Install

```bash
pip install 3sat
```

Verify the installation:

```bash
3sat --help
3sat doctor
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

Check the configured API, RPC, contracts, tokens, and optional wallet balances:

```bash
3sat doctor --address 0xYourWallet
3sat tokens --onchain
```

Create a bounty. The command prepares and uploads the instance/metadata first. It broadcasts only when `--send` is provided:

```bash
3sat issue problem.cnf --reward 100 --token USDC --send
```

Run a true local dry run without uploading files:

```bash
3sat issue problem.cnf --reward 100 --token USDC --dry-run
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
- `3sat doctor`
- `3sat tokens`
- `3sat standardize problem.cnf`
- `3sat search problem.cnf`
- `3sat marketplace` (shows 20 bounties by default)
- `3sat marketplace --offset 20` (load the next page)
- `3sat bounty SAT-...`
- `3sat issue problem.cnf --reward 100 --token USDC --dry-run`
- `3sat issue problem.cnf --reward 100 --token USDC --send`
- `3sat buy-answer SAT-... --send`
- `3sat download-answer SAT-... --cnf query.cnf`
- `3sat balance --address 0x...`
- `3sat upload-solution answer.cnf --kind sat`
- `3sat upload-solution proof.frat --kind unsat --proof-format frat`
- `3sat prepare-commit SAT-... --solver 0x... --solution-ref r2://... --solution-digest 0x... -o reveal.json`
- `3sat commit SAT-... --solution-ref r2://... --solution-digest 0x... --private-key 0x... --send -o reveal.json`
- `3sat reveal --bundle reveal.json --submission-id 1 --private-key 0x... --send`

## Solver flow for advanced users

The fully automated solver clients are still the easiest way to solve bounties. Advanced users can also use the CLI.

Issuer task descriptions are limited to 200 characters. This keeps public metadata concise and prevents oversized bounty descriptions from being used as an abuse vector.

Upload a SAT answer:

```bash
3sat upload-solution answer.cnf --kind sat
```

Upload an UNSAT proof:

```bash
3sat upload-solution unsat-proof.frat --kind unsat --proof-format frat
```

Prepare a commit without broadcasting:

```bash
3sat prepare-commit SAT-XXXX-XXXX-XXXX \
  --solver 0xSolverWallet \
  --solution-ref r2://... \
  --solution-digest 0x... \
  -o reveal.json
```

Broadcast a commit:

```bash
3sat commit SAT-XXXX-XXXX-XXXX \
  --solution-ref r2://... \
  --solution-digest 0x... \
  --private-key 0x... \
  --send \
  -o reveal.json
```

Reveal after commit. Use the submission id assigned by the commit transaction:

```bash
3sat reveal --bundle reveal.json --submission-id 1 --private-key 0x... --send
```

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

## Development

Install from source when contributing to the CLI:

```bash
git clone https://github.com/spencerg-sys/3sat-cli.git
cd 3sat-cli
python -m pip install -e .
```
