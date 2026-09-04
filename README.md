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

The wheel embeds its own Python implementation of the
`3sat-dimacs-strict-v1` parser plus the shared conformance corpus. It does not
need the TypeScript core or Node.js at runtime. File-based CNF commands validate
bounded raw bytes locally before configuration, wallet, or network operations;
SAT artifacts must additionally be non-conflicting unit-clause assignments.

## Security

Use a dedicated protocol wallet. Do not use your main wallet.

The CLI does not store private keys by default. Pass a private key with `--private-key`, or set:

```bash
export THREESAT_PRIVATE_KEY=0x...
```

On PowerShell:

```powershell
$env:THREESAT_PRIVATE_KEY="0x..."
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

The bundled defaults target the production deployment on Arbitrum One (chain ID `42161`). Existing `~/.3sat/config.json` files are not overwritten by source-default changes; preserve intentional custom values, then replace every public deployment field with `3sat config set` before connecting to production.

Search for an existing answer:

```bash
3sat search problem.cnf
```

Check the configured API, RPC, contracts, tokens, and optional wallet balances:

```bash
3sat doctor --address 0xYourWallet
3sat tokens --onchain
```

Create a bounty. The command accepts a DIMACS CNF instance up to 4 MiB, leaving multipart headroom beneath Vercel's 4.5 MB request limit, then prepares and uploads the instance/metadata first. It broadcasts only when `--send` is provided:

```bash
3sat issue problem.cnf --reward 100 --token USDC --send
```

Before broadcasting, the CLI locally ABI-encodes the expected approval and bounty call, verifies the complete prepared transaction batch (`to`, `data`, and `value`), and signs only the locally reconstructed transactions. Commit and reveal broadcasts use the same fail-closed check.

The CLI currently processes one CNF per `issue` invocation and one artifact per `upload-solution` invocation. It does not provide a built-in batch manifest, directory/glob input, or atomic batch upload/issue command.

The default open, reveal, and verification windows are 1 hour each. Every window must be at least 1 hour. During the official-verifier launch phase, verifier quorum is fixed at 1; `--quorum` is retained for compatibility but rejects every value other than `1`.

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

Download a matched answer for a CNF you searched. SAT assignments may be rebuilt for an equivalent CNF. For a format-normalized or variable-renamed UNSAT match, the service converts the finalized proof in an isolated worker and returns the bundle only after the matching checker accepts the proof against the exact CNF you supplied:

```bash
3sat download-answer SAT-XXXX-XXXX-XXXX --cnf my-query.cnf -o matched-answer.zip
```

UNSAT conversion jobs are asynchronous. The CLI waits up to 60 minutes by default (override with `--transform-timeout-minutes`), requires a valid checker-bound ZIP digest and size, verifies both against the downloaded bytes, and fails without writing an answer when parsing, conversion, or target proof checking fails. Matched CNFs larger than 3.5 MiB use the direct target-CNF upload for both SAT and UNSAT answers instead of passing through the web function body. The PUT URL lasts up to 45 minutes and its idempotent reservation remains completable for 60 minutes.

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
- `3sat upload-solution answer.cnf --kind sat --private-key 0x...`
- `3sat upload-solution proof.frat --kind unsat --proof-format frat --private-key 0x...`
- `3sat prepare-commit SAT-... --solver 0x... --artifact-id artifact-... --solution-digest 0x... -o reveal.json`
- `3sat commit SAT-... --artifact-id artifact-... --solution-digest 0x... --private-key 0x... --send -o reveal.json`
- `3sat reveal --bundle reveal.json --submission-id 1 --private-key 0x... --send`

## Solver flow for advanced users

The fully automated solver clients are still the easiest way to solve bounties. Advanced users can also use the CLI.

Issuer task descriptions are limited to 200 characters. This keeps public metadata concise and prevents oversized bounty descriptions from being used as an abuse vector.

Upload a SAT answer:

```bash
3sat upload-solution answer.cnf --kind sat --private-key 0x...
```

Upload an UNSAT proof:

```bash
3sat upload-solution unsat-proof.frat --kind unsat --proof-format frat --private-key 0x...
```

UNSAT proof uploads are limited to 100 MiB. Every SAT assignment and UNSAT proof uses a wallet-authenticated, two-phase direct upload, so solution bytes do not pass through the Vercel request body and the server can bind the opaque artifact to its uploader. The CLI generates and signs an idempotent upload id/token binding before reserving, so a lost reservation response can be retried without consuming another slot. The private key may be supplied by `--private-key` or `THREESAT_PRIVATE_KEY`.

Successful solution uploads return an opaque `artifactId`, not an R2 object location. Keep the artifact id and digest for commit and reveal. The artifact id is used only by the API to bind the private upload to the solver; it is not placed on chain and is not included in the commitment hash.

The solver passed to `prepare-commit` must be the same wallet that signed `upload-solution`. A different wallet cannot claim or reveal that private artifact.

Prepare a commit without broadcasting:

```bash
3sat prepare-commit SAT-XXXX-XXXX-XXXX \
  --solver 0xSolverWallet \
  --artifact-id artifact-... \
  --solution-digest 0x... \
  -o reveal.json
```

Broadcast a commit:

```bash
3sat commit SAT-XXXX-XXXX-XXXX \
  --artifact-id artifact-... \
  --solution-digest 0x... \
  --private-key 0x... \
  --send \
  -o reveal.json
```

Before preparing or sending a commit, the CLI verifies the bounty's snapshotted solver bond directly on chain and rebuilds the approval with that value. A snapshot value of zero is rejected.

The commitment binds the chain id, BountyManager address, bounty id, solver, solution kind, proof format, solution digest, and salt. The opaque artifact id stays in the local reveal bundle so the API can recover and verify the private upload binding, but neither commit nor reveal stores it on chain.

For `commit --send`, the CLI writes the reveal bundle atomically before broadcasting any approval or commit. Without `-o`, it uses `data/reveal-bundles/bounty-<id>-commit-<hash>.json`; if that write fails, nothing is broadcast. The bundle contains the secret salt required to reveal, so keep it durable and private and do not delete, share, sync, upload, or include it in a ZIP until the submission has been revealed.

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

- `THREESAT_CONFIG`
- `THREESAT_CONFIG_DIR`
- `THREESAT_API_URL`
- `THREESAT_RPC_URL`
- `THREESAT_CHAIN_ID`
- `THREESAT_CHAIN_NAME`
- `THREESAT_BOUNTY_MANAGER_ADDRESS`
- `THREESAT_ARTIFACT_ACCESS_CONTROLLER_ADDRESS`
- `THREESAT_USDC_ADDRESS`
- `THREESAT_TOKEN_ADDRESS`
- `THREESAT_PRIVATE_KEY`

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
