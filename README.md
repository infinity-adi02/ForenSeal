# ForenSeal

ForenSeal is a digital forensics integrity and custody demonstration. It fingerprints evidence at collection, constructs deterministic Merkle commitments, and can anchor roots to a local EVM. Blockchain commitments alone do not establish authenticity or legal admissibility.

## Requirements

- Python 3.12 (recommended; 3.13 should also work)
- Node.js 22 and npm 10 or newer
- Git

The app uses SQLite by default; no separate database server or credentials are required for local development. A local Hardhat EVM is included for blockchain anchoring. You can run the web app without it, but chain-dependent features need the node and deployed contract running.

## Clone and configure

Clone the repository from its GitHub page. Replace `OWNER` and `REPOSITORY` below with the GitHub account and repository name, then run:

```sh
git clone https://github.com/OWNER/REPOSITORY.git
cd REPOSITORY
cp .env.example .env
```

Edit `.env` before starting the API:

- Set a long, unique `JWT_SECRET`.
- Set `BOOTSTRAP_ADMIN_USERNAME` and a unique `BOOTSTRAP_ADMIN_PASSWORD`. On the first API start, these values create the initial administrator. If you change them after the account is created, the existing account is not renamed or reset automatically.
- Set `FINGERPRINT_REVEAL_CODE` to a private value, or leave it empty to keep original SHA-256 fingerprints hidden.
- Keep `FRONTEND_ORIGIN=http://localhost:5173` unless you run Vite on a different origin; the API uses this value for CORS.
- Keep `BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545` when using the included Hardhat node.

The settings and their local-development defaults are documented beside the fields in [backend/app/config.py](backend/app/config.py); the copyable template is [.env.example](.env.example). Never commit `.env`, real credentials, investigation data, local databases, generated contract deployments, or uploaded evidence. The `.gitignore` excludes these local files. The SQLite database and evidence storage directory are created under `backend/` at runtime; this default database is local application data, not a shared or hosted database.

## Install dependencies

From the repository root, create a Python environment and install the API dependencies:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
```

Install JavaScript dependencies separately for the frontend and contract toolchain:

```sh
cd frontend && npm ci
cd ../contracts && npm ci
```

The committed npm lock files make `npm ci` reproducible. If you change a dependency intentionally, update the corresponding lock file with npm and commit both files.

## Run the application

For the complete local blockchain workflow, start the Hardhat node in terminal 1:

```sh
cd contracts
npm run node
```

In terminal 2, deploy `EvidenceLedger` to that running node:

```sh
cd contracts
npm run deploy:local
```

Deployment writes the local contract address, chain ID, and ABI to the ignored file `backend/app/contract_deployment.json`. The local node keeps chain data in memory. If it is stopped or reset, restart it and redeploy; the old deployment file alone does not mean the contract still exists on the chain.

Start the API in terminal 3 (from the `backend/` directory):

```sh
cd backend
../.venv/bin/uvicorn app.main:app --reload
```

Start Vite in terminal 4:

```sh
cd frontend
npm run dev
```

Open `http://localhost:5173`. The API is at `http://localhost:8000`, health check at `/api/health`, and interactive API documentation at `http://localhost:8000/docs`. If the UI uses a different host or port, update `FRONTEND_ORIGIN` in `.env` to match and restart the API.

The frontend uses Vite's `/api` proxy to reach the API at `http://localhost:8000`; change `frontend/vite.config.ts` if you need a different API address. There are no frontend-specific secrets or database settings. For a non-local database, configure `DATABASE_URL` in `.env` and install the matching SQLAlchemy database driver yourself; SQLite is the only database driver included in the default install and the documented local setup.

## Implemented capabilities

- SQLite persistence for users, cases, evidence, batches, custody events, simulations, benchmark runs, and audit records.
- JWT login with Argon2 password hashes and administrator, collector, investigator, and auditor role checks.
- Chunked evidence upload, random storage keys, size limit, immutable original SHA-256, protected download, and missing/tamper detection.
- Deterministic Merkle trees with domain-separated leaf and parent hashes, duplicate-last odd-node rule, stable empty root, and inclusion proofs.
- `EvidenceLedger` local Solidity contract for authorized batch commitments, individual hash anchoring, custody event logging, and recipient-only transfer resolution.
- Contract deployment scripts and Python web3 integration. Batch status is checked against the deployed contract; pending and unavailable states are explicit.
- Hash-linked audit history, custody timeline, controlled working-copy tampering and missing/RPC failure simulations.
- PDF integrity reports and real-receipt gas benchmark runner. 1000 and 10000-record benchmark sizes require an explicit opt-in because each performs that many individual EVM transactions.
- React/TypeScript/Vite dashboard with case, evidence, verification, batch, custody, report, and account screens.
- Dataset import, simulation, and benchmark APIs remain available, but their dashboard pages are currently removed.
- Authenticated fuzzy global search across cases, evidence, batches, custody and audit records, simulations, admin-visible users, benchmark runs, and dataset references.

## Tests and builds

```sh
cd backend
../.venv/bin/pytest -q

cd ../frontend
npm run build

cd ../contracts
npm test
```

Contract tests and end-to-end chain tests need the Hardhat compiler/toolchain. Gas figures are written only from actual local chain receipts. No gas price or currency rate is assumed.

## API highlights

- `POST /api/auth/login`, `GET /api/auth/me`
- `POST /api/cases`, `GET /api/cases`
- `POST /api/cases/{case_id}/evidence`, `GET /api/cases/{case_id}/evidence`
- `POST /api/evidence/{evidence_id}/verify`, `GET /api/evidence/{evidence_id}/download`
- `POST /api/cases/{case_id}/batches`, `POST /api/batches/{batch_id}/anchor`
- `GET /api/blockchain/status`, `GET /api/batches/{batch_id}/chain-check`
- `GET /api/blockchain/transactions/{tx_hash}`
- `GET /api/audit/verify`, `GET /api/audit/anchors`
- `GET/POST /api/evidence/{evidence_id}/custody`
- `POST /api/simulations`, `POST /api/benchmarks/run`
- `GET /api/reports/cases/{case_id}.pdf`, `GET /api/audit/verify`, `POST /api/audit/anchor`
- `GET/POST /api/users`, `PATCH /api/users/{user_id}/role` (administrator only)
- `GET /api/search?q=...` (ranked global search; user accounts are only searchable by administrators)

## Security and operational limitations

- This is a local demonstration, not a production evidence repository. Review access controls, retention, backups, secure deployment, and key custody before handling real investigations.
- Evidence files and the SQLite database are stored locally. The application does not encrypt files at rest.
- The audit chain and custody records reside in the same database. An administrator able to rewrite the database can rewrite that history until an independent external anchor is configured.
- The local demo contract uses Hardhat unlocked development accounts and is not configured for public-chain keys or wallet signatures.
- User identity is represented by the authenticated application account in the off-chain audit record. Contract operator addresses are not proof of a human identity.
- Original SHA-256 values are redacted from evidence and verification API responses by default and omitted from PDF manifests until the admin reveal code is verified. The top-bar **Reveal SHA-256** control unlocks them for the current browser session; **Hide SHA-256** clears the session gate. Set a private `FINGERPRINT_REVEAL_CODE` in your ignored `.env` file; the repository does not contain the reveal code.
- PDF reports are generated evidence summaries, not legal certification.
- The Hardhat 2 development toolchain has npm audit advisories in transitive development dependencies. `npm audit fix` could not clear them without a breaking Hardhat/toolbox major upgrade. `npm audit --omit=dev` reported no production dependencies with advisories; do not expose the local EVM or use these development packages as a public service.
- Generic file ingestion is supported; no parsing of Splunk BOTS or OTRF formats is done. Select local dataset files manually and upload them into a case.

## Dataset sources and acquisition

ForenSeal keeps source links as references; it does not download datasets during startup. The dataset registry and importer are available through the API; the Dataset sources dashboard page is currently removed. Imported evidence stores the declared source name and official URL, original filename, case ID, optional OTRF scenario details, and ingestion timestamp. Unattributed uploads remain `Unspecified local file`. A declaration records what the importer selected; it does not independently authenticate provenance.

- **Splunk BOTS v3** — The official release is a pre-indexed Splunk dataset. Obtain the release from [Splunk's BOTS v3 repository](https://github.com/splunk/botsv3), verify its published checksum, install its app/data package under `$SPLUNK_HOME/etc/apps`, restart Splunk, then search `index=botsv3 earliest=0`. Export only the events needed for the case (CSV, JSON, or another local export format) and import those exports through Dataset sources. The original Splunk dataset and each selected event export are distinct files/artifacts; importing an export does not import or preserve the entire source dataset.
- **OTRF Security-Datasets** — Browse the [official repository](https://github.com/OTRF/Security-Datasets), select a scenario under its dataset catalog, and acquire only the scenario files needed. Import those files into the case individually or together; use the optional scenario field to record a name, technique, or repository path. Generic binary ingestion does not require that every file be parsed.
- **Ethereum BigQuery example queries** — Google's [example query documentation](https://cloud.google.com/blockchain-analytics/docs/example-queries) demonstrates SQL over public Blockchain Analytics tables, including Ethereum mainnet transaction data and aggregations. Running queries is optional and requires a configured Google Cloud project with BigQuery access and any applicable billing setup. This is public-chain analytics. It is separate from gas/elapsed-time measurements against the local Hardhat EvidenceLedger; BigQuery does not query the local Hardhat chain. Locally exported query results can be imported as a declared research artifact.

The importer accepts selected local files as raw bytes (including CSV, JSON, JSONL, TXT, LOG, and other allowed file types); it computes SHA-256 over exactly the uploaded bytes and does not parse or rewrite them. BOTS/OTRF labels are stored only when explicitly selected at import. File size limits still apply. Chain anchoring commits hashes, not the files themselves.

## Measured blockchain benchmarks

The benchmark API can submit transactions to the configured deployed `EvidenceLedger`: one `anchorEvidence` transaction per file and one `anchorBatch` transaction for a Merkle root. The dashboard page is currently removed. The API supports sizes 1, 10, 100, 1000, and 10000. Each run constructs distinct generated evidence IDs and SHA-256 digests as benchmark inputs; all reported gas, transaction hashes, and success flags come from receipts for transactions actually submitted to the deployed contract. The 1000 and 10000 per-file runs require explicit opt-in. Failed or unavailable EVM runs are reported as failures; no sample transaction or fabricated gas value is substituted.

## Dataset workflow verification status

Automated tests use small synthetic byte fixtures with BOTS/OTRF declared source IDs to exercise import metadata and byte-preserving hashing. They are test fixtures, not files downloaded from either official dataset. A real dataset-derived import requires a user-acquired BOTS export or OTRF scenario file, Splunk is needed to produce a BOTS event export, and BigQuery requires configured Google Cloud access. The optional simulation API modifies a disposable working copy and compares it with the original commitment; case PDF reports include declared source metadata, current file verification results, custody events, batch transaction references, and commitments.

## Independently check a report

From `backend/`, compare a downloaded evidence file with the report's ingestion fingerprint:

```sh
../.venv/bin/python verify_report.py --file /path/to/evidence.bin --sha256 <reported-sha256>
```

To also query the deployed local contract for a batch ID and root copied from the PDF (with the same Hardhat node still running):

```sh
../.venv/bin/python verify_report.py --batch-id <reported-batch-uuid> --merkle-root <reported-root>
```

The command checks the connected chain ID against `app/contract_deployment.json`. A reset local chain has no prior state, even if the deployment file remains.
