# Live demo script (7 minutes)

Goal: show that the system ingests traffic, forecasts attack risk **before** the attack
materialises, explains why, and helps an analyst act early. Use the prepared replay
dataset. Never depend on live packet capture on stage.

## Timeline

| Time | Beat | Say | Show |
| --- | --- | --- | --- |
| 0:00–0:30 | Problem | "Most systems detect attacks after suspicious behaviour is obvious. We warn analysts earlier from traffic patterns." | One slide: late alert vs early warning |
| 0:30–1:00 | Why existing tools fall short | "Rule-based alerts are reactive and noisy. Detection is not forecasting." | Diagram: current traffic → late alert vs ours → early warning |
| 1:00–1:30 | Our solution | "Rolling traffic windows, next-window risk forecast, explanation, prioritised alerts." | Architecture graphic (`docs/architecture/README.md`) |
| 1:30–5:00 | Live demo | See click flow below | The app |
| 5:00–6:00 | Impact | "Earlier warning, less analyst overload, better prioritisation. Same architecture scales to a SOC tool." | Impact slide, three points |
| 6:00–7:00 | Future and closing | "Today: public datasets. With real environment traffic and retraining, this becomes an operational early-warning layer." | Roadmap slide |

## Click flow

1. Open the login page; log in as `analyst`.
2. Dashboard in a low-risk state.
3. Start the traffic replay (or open the preloaded replay job).
4. Traffic trend chart moves; point at the risk score as it begins to rise.
5. High-risk forecast alert appears.
6. Click the alert → detail page: predicted attack type, risk score, forecast horizon,
   contributing factors, affected host, recommendation.
7. Show on the timeline that the warning came **before** the attack peak.
8. Mark the alert as acknowledged; show the audit trail / status change.

What to say while it runs: "We are replaying real benchmark traffic through our pipeline.
The system groups it into time windows, extracts behavioural features, and the model raises
risk when it sees precursor behaviour. This is a forecast for the next short horizon, not a
label on current packets. Here are the top reasons."

## Backup plan

- Pre-recorded screen capture of the full flow.
- Static screenshots of dashboard and alert detail.
- Seeded database with ready alerts (`database/seed/`).
- Offline build via `docker compose up` with no internet.

## Rehearsal checkpoints

1. Dry run with dummy data.
2. Run with the real pipeline.
3. Timed run with the speaker script.
4. Final run with the backup plan exercised once.

## Demo accounts

Created by `backend/scripts/seed_demo_users.py`. Change the passwords before any deployment.
