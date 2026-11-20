# Runtime pin and its two local changes

This plant does not contain Mishe source. Its minds run from a pinned release
snapshot in `.mishe-tauftauf/releases/<sha>/` (gitignored, like all site
state), exactly as the main Mishe plant does: running code comes from a
committed snapshot, never from a live checkout.

## Provenance

- Base: commit `0d686bba` (`budget-json-contract: budget and budget-consistency
  resolve to steward`) of the upstream mishe-tauftauf repository, copied
  verbatim from that repository's own pinned release directory on 2026-11-20.
- The snapshot is a fork with exactly two file changes, both recorded here so
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

## Consequences

- Upgrades mean: take a newer upstream release snapshot, re-apply the two
  changes above, re-point `runtime/current`, run `mishe sync`, and check
  `mishe doctor` exits 0 before releasing the hold.
- Host containment still applies: the hand-written prefix drop-in
  `nginx2root-.service.d/host-containment.conf` mirrors the host guard's
  conditions for all `nginx2root-*.service` units (trip condition, guard
  admission, slices, memory and start limits).
- The site-local verified binaries (`bin/mishe-tape`, `mishe-records`,
  `mishe-signal-*`) are byte-identical copies of the upstream plant's
  installed framer binaries, with their `*.install.json` sha256 records intact.
