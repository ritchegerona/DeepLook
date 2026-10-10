# Scheduled Watchlist Monitoring

DeepLook's watchlist can run unattended to detect newly observed (or vanished)
related infrastructure for indicators you care about. Each run re-checks every
watched indicator, diffs the result against the previous run, and records a
JSON-lines run log you can grep, ship, or alert on.

## The runner

`deeplook watch check` is the runner. Relevant flags:

| Flag | Purpose |
|------|---------|
| `--report PATH` | Append a JSON-lines run record to `PATH` (one JSON object per run) |
| `--fail-on-change` | Exit with code **2** when any changes are detected (for alerting) |
| `--output-format json` | Print the full result to stdout |
| `-w NAME` | Target workspace |

Run record shape:

```json
{"checked_at": "2026-01-01T12:00:00+00:00", "workspace": "default", "changes": 1, "results": [ ... ]}
```

Exit codes: `0` no changes, `2` changes detected (only with `--fail-on-change`),
`1` on error.

## Manual run

```bash
# One-off check, log the run
deeplook watch check -w default --report ~/.deeplook/watch-runs.jsonl

# Check only watch id 3
deeplook watch check -w default 3

# Alerting: exit 2 if anything changed since last run
deeplook watch check -w default --fail-on-change
```

## macOS (launchd)

1. Copy the template and edit the paths/user:

   ```bash
   cp examples/deeplook-watch.plist ~/Library/LaunchAgents/com.deeplook.watch.plist
   # edit __USER__ / paths to match your environment, then:
   ```

2. Load it (runs every hour and once at load):

   ```bash
   launchctl load  ~/Library/LaunchAgents/com.deeplook.watch.plist
   launchctl start com.deeplook.watch
   ```

3. Inspect:

   ```bash
   tail -f ~/.deeplook/watch.log
   tail -f ~/.deeplook/watch-runs.jsonl
   ```

4. Unload:

   ```bash
   launchctl unload ~/Library/LaunchAgents/com.deeplook.watch.plist
   ```

## Linux / cron

```bash
crontab -e
```

```cron
# Every hour: check the watchlist and append to the run log
0 * * * * /path/to/DeepLook/.venv/bin/deeplook watch check -w default \
  --report "$HOME/.deeplook/watch-runs.jsonl" >> "$HOME/.deeplook/watch.cron.log" 2>&1
```

## systemd timer

`~/.config/systemd/user/deeplook-watch.service`:

```ini
[Unit]
Description=DeepLook watchlist check

[Service]
Type=oneshot
ExecStart=%h/DeepLook/.venv/bin/deeplook watch check -w default --report %h/.deeplook/watch-runs.jsonl
```

`~/.config/systemd/user/deeplook-watch.timer`:

```ini
[Unit]
Description=Run DeepLook watchlist check hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now deeplook-watch.timer
```

## Alerting ideas

- Cron + `--fail-on-change`: chain `&& notify-send "DeepLook: watchlist changed"`.
- Pipe the run log into a SIEM/Elasticfilebeat and alert on nonzero `changes`.
- `deeplook watch check --output-format json` piped to `jq '.results[].changes[]'`
  to extract just the deltas.

## Notes

- Changes are detected by diffing related entities (`added` / `removed`) against
  the snapshot stored on each watch item — no state file required.
- Each check also writes a Timeline entry to the workspace, so `deeplook timeline`
  shows monitoring history per indicator.
