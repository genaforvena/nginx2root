# Runtime pin and its local changes

This plant does not contain Mishe source. Its minds run from a pinned release
snapshot in `.mishe-tauftauf/releases/<sha>/` (gitignored, like all site
state), exactly as the main Mishe plant does: running code comes from a
committed snapshot, never from a live checkout.

## Provenance

- Base: commit `0d686bba` (`budget-json-contract: budget and budget-consistency
  resolve to steward`) of the upstream mishe-tauftauf repository, copied
  verbatim from that repository's own pinned release directory on 2026-11-20.
- The snapshot is a fork with exactly seven file changes, all recorded here so
  anyone can rebuild the pin from the base commit:

### 1. Unit marker (`src/mishe_tauftauf/units.py`)

```diff
-MARKER = "# mishe-generated: observation runtime (edit nothing here; run `mishe sync`)"
+MARKER = "# nginx2root-generated: nginx2root observation runtime (edit nothing here; run `mishe sync`)"
```

Why: systemd user units for all plants on this host share
`~/.config/systemd/user`. Mishe's sync and doctor treat every unit file
carrying their own marker as theirs: a foreign plant's units in the shared
directory would be reported RED ("stale generated unit") by the other plant's
doctor and deleted by its next sync (observed directly while planting: the
main plant's periodic repair pruned a foreign plant's stock-marker units
within minutes). A distinct marker makes each plant's scan blind to the
other's units, which is the separation this plant requires.

### 2. Duty manifest (`duties.json`)

Replaced wholesale: the base snapshot carries the upstream plant's 85-duty
manifest; this plant runs one duty (`dispatch`, resolved by `operator`). The
repository's own `duties.json` is kept identical to the snapshot's copy so
`runtime_source` (which prefers the runtime's manifest) and a reader of the
repository see the same set.

### 3. Started-unit names (`src/mishe_tauftauf/wake.py`, `src/mishe_tauftauf/arm.py`)

```diff
- "systemctl", "--user", "start", "--no-block", f"mishe-wake@{role}.service"]
+ "systemctl", "--user", "start", "--no-block", f"nginx2root-wake@{role}.service"]
-TIMER_UNIT = "mishe-next-due"
+TIMER_UNIT = "nginx2root-next-due"
```

Why: upstream assumes one plant per host and hardcodes its own unit-name
prefix when it *asks systemd to start* units. With a second plant present,
that literal asked systemd to instantiate the main plant's
`mishe-wake@.service` template with a foreign role — the main plant's
dispatcher correctly refused ("role not declared"), but the request still
started its units three times and wrote foreign keys (`phpsec`, `nginxsec`)
into its wake-start ledger. The plant prefix must appear here too, or the
plants are not actually separate. Both foreign ledger keys were removed from
the main plant's state after the incident; its doctor was GREEN throughout.

### 4. Promotion unit prefix (`src/mishe_tauftauf/release_promotion.py`)

```diff
-        unit_dir=Path.home()/".config/systemd/user", prefix="mishe", no_slices=False,
+        unit_dir=Path.home()/".config/systemd/user", prefix="nginx2root", no_slices=False,  # fork change 4
```

Why: `activate()` (called during promotion, not during a normal `mishe sync`)
hardcodes the unit-name prefix. Change 1 gives these units the `nginx2root-`
marker, but with `prefix="mishe"` promotion rendered *mishe-named* units
carrying the foreign marker into the shared `~/.config/systemd/user`. On
2026-11-20 03:54Z this rewrote 179 of the main plant's units and turned its
`doctor` RED ("179 missing, 0 stale") until its 04:05Z sync restored them.
The prefix must appear here too, or promotion re-clobbers the other plant.
The main plant's own sync now refuses foreign-marked paths (upstream commit
`92f11a14`), but that guard is defence in depth, not a substitute for this
fork change. Keep the `nginx2root-plants.slice` drop-ins; undo is the one-line
revert above plus a `daemon-reload`.

### 5. Operator view dialogue block (`src/mishe_tauftauf/plant_view.py`)

```diff
     if role == 'operator':
-        out += _dialogue_block(home)
+        pass  # fork change 5: no household dialogue in this plant
```

Why: `_dialogue_block` renders the host-level household conversation tails
from `~/.mesh/` (Ilya/Rozalia) on every plant's operator pane. On this host
that content belongs to the main plant; this plant's operator is a delegate
mind with no household channel, and the foreign, never-updating text made
the operator window read as hung. This plant's operator view is its wall,
signals, dispatch and mail, nothing else.

### 6. Per-role idle pace (`src/mishe_tauftauf/yielding.py`)

```diff
+FORK_ROLE_IDLE_SECONDS = {"nginxsec": 300, "witness": 1800, "operator": 1800}
 def idle_delay(home, role, now, idle_seconds) -> float:
+    if idle_seconds == DEFAULT_IDLE_SECONDS and role in FORK_ROLE_IDLE_SECONDS:
+        return FORK_ROLE_IDLE_SECONDS[role]
```

Why: the upstream default for a yield that schedules nothing is a 2-hour
idle initiative, and the 30-minute open-lane acceleration needs budget
evidence this plant deliberately does not run. The owner wants the research
back-to-back: an unscheduled nginxsec yield now returns in 5 minutes, so a
wake that forgets `--again` cannot stall the chain for hours. Witness and
operator keep slower idle paces; explicit `--again`/`--when` from any mind
still overrides these defaults.

### 7. Capped self-scheduled returns for the researcher (`src/mishe_tauftauf/yielding.py`)

```diff
+FORK_ROLE_AGAIN_CAP_SECONDS = {"nginxsec": 900}
     clamp_note = ""
     requested_again = again
+    if role in FORK_ROLE_AGAIN_CAP_SECONDS and requested_again is not None and requested_again > FORK_ROLE_AGAIN_CAP_SECONDS[role]:
+        requested_again = FORK_ROLE_AGAIN_CAP_SECONDS[role]
```

Why: change 6 governs yields that schedule nothing, but an explicit
`--again` overrides it — observed 2026-11-20 05:57Z, when the researcher
yielded with an ~86-minute scheduled return against the owner's
back-to-back directive, stalling the chain for the afternoon. The cap
bounds self-scheduled gaps for nginxsec at 15 minutes; a genuine wait for
evidence must be expressed as a `--when signal:NAME=VALUE` condition (the
designed mechanism, which pairs with a deadline), not as a long timer.
The clamp is recorded in the yield's own clamp note so the mind sees why.

## Consequences

- Upgrades mean: take a newer upstream release snapshot, re-apply the seven
  changes above, re-point `runtime/current`, run `mishe sync`, and check
  `mishe doctor` exits 0 before releasing the hold.
- Host containment still applies: the hand-written prefix drop-in
  `nginx2root-.service.d/host-containment.conf` mirrors the host guard's
  conditions for all `nginx2root-*.service` units (trip condition, guard
  admission, slices, memory and start limits).
- The site-local verified binaries (`bin/mishe-tape`, `mishe-records`,
  `mishe-signal-*`) are byte-identical copies of the upstream plant's
  installed framer binaries, with their `*.install.json` sha256 records intact.
