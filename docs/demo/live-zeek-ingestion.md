# Live Zeek ingestion (authorised networks only)

This optional demo mode turns the project from a CSV replay into a local live-telemetry pipeline:

`authorised network interface → Zeek conn.log (JSON metadata) → Docker live adapter → FastAPI → 60-second features → LSTM forecast → dashboard`

The sensor reads **connection metadata only**: time, IP addresses, ports, protocol, packets, bytes, duration and connection state. It does not read or upload packet payloads. Use it only on an interface and network you own or are explicitly authorised to monitor.

## Fastest macOS setup: one terminal

Install Zeek once:

```bash
brew install zeek
```

Identify the interface you are authorised to monitor:

```bash
networksetup -listallhardwareports
```

Then from the project root, substitute the confirmed interface (often `en0` for a
personal Wi-Fi connection) and run:

```bash
WTH_ANALYST_PASSWORD='AnalystPass123!' bash deployment/scripts/start_live_demo.sh en0
```

The script starts host Zeek plus Docker Compose (database, backend, frontend and
the live adapter) and creates the local demo accounts. It asks for your macOS password
only to let Zeek observe the selected authorised interface. `Ctrl-C` stops the adapter
and Zeek; the regular Docker application remains available until `docker compose down`.

On macOS, a Docker container cannot directly observe the Mac's physical Wi-Fi interface,
so Zeek remains a host process while Docker runs everything else. This is why the one
terminal script is the correct local setup rather than a privileged packet-capture container.

## Manual setup (if you prefer separate processes)

From the project root:

```bash
docker compose up --build
```

Open `http://127.0.0.1:3000`, sign in as an analyst, and leave the stack running.

### 1. Start the application

On macOS:

```bash
networksetup -listallhardwareports
```

For a normal Wi-Fi-only personal demo this is commonly `en0`; verify the output before using it.

### 2. Start Zeek JSON connection logging

In a second terminal, create a dedicated log folder and start Zeek on the authorised interface:

```bash
mkdir -p ~/zeek-live
cd ~/zeek-live
sudo zeek -i en0 LogAscii::use_json=T
```

This writes `~/zeek-live/conn.log`. Browsing a site or running a DNS lookup on your own machine will generate connection events. Stop Zeek with `Ctrl-C`.

### 3. Start the Docker live adapter

In a third terminal, from the project root:

```bash
export WTH_ANALYST_PASSWORD='your analyst password'
export ZEEK_LOG_DIR="$HOME/zeek-live"
docker compose -f docker-compose.yml -f docker-compose.live.yml --profile live up --build live-adapter
```

The bridge logs in using the analyst account, tails only new JSON connection records, batches up to 100 events, and refreshes its access token automatically when necessary. It prints the source and job IDs after every accepted batch.

### 4. Open the live dashboard

In the web app choose **Live sensor** → **Refresh** → **Open dashboard**. The existing dashboard then displays live-built 60-second windows, the five-minute risk projection, MITRE-aligned stage category, and feature explanation.

The forecast needs the model artifact plus at least 10 completed 60-second windows. For a short demo, keep the sensor running long enough to collect them. This MVP rebuilds source windows after each batch; production deployment should use a durable queue and incremental aggregation instead.

## Train for your authorised environment

Live Zeek connection logs do **not** include ground-truth attacks, so they cannot be used to
retrain the model directly. Record an approved exercise/incident timeline separately, review
it, then convert only that authorised capture into the same normalized flow CSV the trainer
uses. Never mark unknown traffic as benign simply to produce a bigger dataset.

Create `labels.csv` with exactly `start,end,label` columns. Timestamps must include a timezone;
use supported canonical labels such as `BENIGN`, `PortScan`, `SSH-Patator`, `DDoS`, or the
labels in [the mapping reference](../research/mitre_stage_mapping.md).

```csv
start,end,label
2026-09-20T09:00:00Z,2026-09-20T09:30:00Z,BENIGN
2026-09-20T09:30:00Z,2026-09-20T09:35:00Z,SSH-Patator
```

Convert a saved JSON `conn.log`. The default is conservative: connections outside reviewed
intervals are excluded. Add `--assume-uncovered-benign` only when the capture gaps are known
to be normal traffic.

```bash
PYTHONPATH=.:backend python -m ai.datasets.label_zeek_capture \
  ~/zeek-live/conn.log labels.csv --out data/authorised-zeek-training.csv

PYTHONPATH=.:backend python -m ai.evaluation.preflight_dataset \
  data/authorised-zeek-training.csv --test-fraction 0.2
```

Preflight exits nonzero when chronological training or held-out partitions do not contain both
benign and attack windows. Fix the capture coverage rather than changing the score. Only after
preflight succeeds should you train and evaluate the same split:

```bash
PYTHONPATH=.:backend python -m ai.training.train_world_model \
  data/authorised-zeek-training.csv --out ai/models/world_model.pt --epochs 30 --test-fraction 0.2
PYTHONPATH=.:backend python -m ai.evaluation.evaluate_models \
  data/authorised-zeek-training.csv ai/models/world_model.pt --test-fraction 0.2
```

## Troubleshooting

- **“Waiting for Zeek to create conn.log”**: ensure the Zeek command is still running and that its working directory is `~/zeek-live`.
- **401 on startup**: verify the analyst email/password; the password must be provided through `WTH_ANALYST_PASSWORD`, not typed into the command.
- **No live source in the browser**: wait for a `Sent … flows` message, then press **Refresh** on `/live`.
- **No forecast yet**: collect at least 10 distinct minute windows and confirm `ai/models/world_model.pt` is available to the backend container.
