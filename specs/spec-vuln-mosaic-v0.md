# Vuln Mosaic Plugin Specification

**Vuln Mosaic is a standalone, near-pure-Python collector that keeps local copies of public vulnerability data (CVE records, the CISA KEV catalog, EPSS scores, GitHub advisories, NVD and OSV records) in stores it owns, plus a small read function for other modules, so that a running TAP instance reads vulnerability facts from local files and makes no lookup at use time.**

## Plugin Identity

| Field | Value |
| --- | --- |
| Slug | `vuln_mosaic` |
| Display name | TAP Vuln Mosaic |
| Description | Fetches public vulnerability data into local stores, and serves it to tooling and other modules without any live lookup. |
| Kind | Leaf plugin that defines no TAP-managed types (not a `*_core` substrate). It imports no other plugin; grype-tap (later), CI-side SBOM enrichment and any module that needs a CVE record import it. |

This plugin ships no TAP-managed types, so there are no default dimensions to declare. The only graph objects it touches are tap_cares' own `collection_job` records and the `schedule` node it seeds.

## Philosophy

Every other vulnerability tool in the stack answers a question from a dataset it was handed. Grype matches against a database Anchore builds; Trivy and OSV-Scanner do the same with theirs. What none of them does is keep the *records* (the CNA text, the CISA-ADP decision tree, the references) where other modules can read them. This plugin exists to hold that data locally and to say, every time it is read, how old it is.

Three consequences shape v0:

1. **The data comes from the source, as received.** Records are stored in the form upstream published them. A projection chosen today goes stale and consumers differ, so parsing is a function in `vuln_mosaic.records` that runs at read time over the stored record, never a transformation applied on the way in.
2. **A running instance makes no lookup at use time, by default.** A read of a CVE that is not held returns *not fetched* and queues the id for the next scheduled run. Fetching on the spot exists, but it is an operator switch that is off by default, because a blocking network call inside another module's request is a latency and failure surface, and because some deployments allow no egress at all.
3. **Three states, never two.** A CVE that has not been fetched is *not fetched* (unobserved), never "no such CVE". A dataset past its limit is *stale*, never silently current. A source that could not be reached ends the run failed, never clean. Absence of a record is not a finding of absence.

**What it deliberately does not do.** It does not scan, match or write findings (grype-tap does that); it does not make vulnerability records into grid nodes; it ships no pages or panels in v0. Grype stays the source of KEV status for the vulnerabilities it matched; the KEV file here is a lookup for CVEs Grype never matched. It does not build or serve a vulnerability vocabulary (compliance_core owns that).

**Prior art, and what it changed.** Grype and Trivy ship a single database file plus a metadata file and refresh by staged swap; this plugin takes the staged swap, the validation before use, the age rule measured from the source's own time, and the operator mirror, and rejects shipping a prebuilt database because the upstream records are already per-record JSON. OSV-Scanner keeps per-ecosystem zip files in a cache directory and has an explicit offline mode; this plugin takes the per-ecosystem opt-in and the offline switch. Dependency-Track and dependency-check keep a persistent local copy of NVD data and refresh it from a modified-since feed; this plugin takes the persistent store and the incremental refresh. Every project that builds its own local copy of upstream records uses a database as the working store, which is why record sources are SQLite files here and only whole-file sources are plain files. The fetch-on-the-spot read has no precedent in the scanners surveyed, which all pre-fetch; that is why it is off by default.

**Provenance markers.** Claims marked *observed* were measured on 2026-10-16. Claims marked *documented* come from the named source's own documentation, not re-read in full. Everything else is *designed*.

*Observed:* cvelistV5's hourly delta zip is cumulative since 00:00Z (the 1500Z zip held 1,855 files and 1,855 of the 1,856 ids that `deltaLog.json` lists for 00:00 to 15:00Z). Three of those 1,855 records were `REJECTED`. A blobless, shallow, bare clone of cvelistV5 was 11 MB and listed 409,194 paths at HEAD; a fetch eight minutes later took 1.1 s, added 0.08 MiB, and `git diff --name-status` listed 13 changes. `deltaLog.json` held 2,356 entries reaching 30 days back. In that 1,855-record sample, 1,736 carried a CISA-ADP container with SSVC metrics, and CISA-ADP carried CVSS on 38 and CWE on 28, against the CNA container's 1,799 and 1,825. KEV was 1.7 MB; EPSS was a 2.7 MB gzip CSV; OSV all-zip sizes were Wolfi 300 MB, Chainguard 1.07 GB, Ubuntu 777 MB, Debian 76 MB, PyPI 36 MB.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Local And Offline | Every record, score and catalog this plugin serves is read from a store on the instance; reading never reaches the network unless the operator enables it. |
| 2 | Honest Age | Every read carries the dataset's own as-of time and whether it is stale; an unreachable or old source is never reported as current or complete. |
| 3 | Fetch Only What Is Wanted | By default the plugin fetches the CVE ids that consumers name, so disk and egress track use, with a full-corpus mode as an operator choice. |
| 4 | Fail Closed | Nothing upstream is applied before it is verified; a bad download or a malformed record leaves the previous copy serving. |
| 5 | Foundational | The plugin imports no other plugin's vocabulary; consumers depend on it through a plain file and a small read function. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-vuln-mosaic-settings | [Operator Settings](#operator-settings) | Implemented | One validated settings file on the operator's filesystem; per-source switches, mode and age limit |
| req-vuln-mosaic-store | [The Stores](#the-stores) | Implemented | One SQLite file per record source, plain files for whole-file sources, in a directory the plugin owns |
| req-vuln-mosaic-staleness | [Staleness Is Derived](#staleness-is-derived) | Implemented | As-of and checked-at per source; `stale` computed at read time against the limit |
| req-vuln-mosaic-cvelist | [CVE Records From cvelistV5](#cve-records-from-cvelistv5) | Implemented | Blobless shallow git fetch; incremental by tree diff; REJECTED kept as state |
| req-vuln-mosaic-wanted | [The Wanted-Ids Contract](#the-wanted-ids-contract) | Implemented | A file the consumer writes, a request spool, and the wanted and full modes |
| req-vuln-mosaic-lookup | [The Read Function](#the-read-function) | Implemented | `get_cve`: record, not fetched or rejected; deferred by default, immediate by operator switch |
| req-vuln-mosaic-records | [The Record Parser](#the-record-parser) | Implemented | `vuln_mosaic.records`: CVSS CNA-first, CWE, SSVC; stdlib only |
| req-vuln-mosaic-integrity | [Integrity, Fail Closed](#integrity-fail-closed) | Implemented | Verify before apply; quarantine a malformed record; nothing upstream is signed |
| req-vuln-mosaic-refresh | [The Refresh Collector](#the-refresh-collector) | Implemented | `vuln_mosaic:refresh`; seeded hourly schedule; zero GRIFT batches; per-source outcomes in the collection job |
| req-vuln-mosaic-kev | [CISA KEV Catalog](#cisa-kev-catalog) | Implemented | Whole-file source; a lookup for CVEs Grype never matched |
| req-vuln-mosaic-epss | [FIRST EPSS Scores](#first-epss-scores) | Implemented | Whole-file source; keeps the model version and score date |
| req-vuln-mosaic-nvd | [NVD API 2.0](#nvd-api-20) | Proposed | By CVE id and by last-modified window for wanted ids; gated on terms and limits not yet read |
| req-vuln-mosaic-osv | [OSV, Per Ecosystem](#osv-per-ecosystem) | Implemented | Opt-in per ecosystem; whole zip swapped; the large ecosystems named |
| req-vuln-mosaic-ghsa | [GitHub Security Advisories](#github-security-advisories) | Implemented | GHSA ids to their CVE aliases, with a CVSS v3 base score computed from the vector; off by default; no mirror yet |
| req-vuln-mosaic-mirror | [The Operator Mirror](#the-operator-mirror) | Implemented | No-egress fallback: an artifact copy plus a sha256 manifest, verified before use |
| req-vuln-mosaic-fips | [FIPS Declaration](#fips-declaration) | Implemented | `[fips]` table; stdlib crypto uses the image's OpenSSL; git's TLS path to be verified |
| req-vuln-mosaic-corpus | [The Corpus Proof](#the-corpus-proof) | Implemented | Tests from real committed records, an egress-blocked run and a negative test per fail-closed path |
| req-vuln-mosaic-panel-cve | [The CVE Panel](#the-cve-panel) | Implemented | One panel type showing a CVE's record, KEV entry and EPSS score from the local datasets, structured, no prose |
| req-vuln-mosaic-commands | [Operator Commands](#operator-commands) | Implemented | `vuln_mosaic_want` writes a consumer's wanted file; `vuln_mosaic_refresh` runs a refresh now |
| req-vuln-mosaic-nongoals | [Non-Goals](#non-goals) | Implemented | No scanning, matching or findings; no records as nodes; no pages in v0 |
| req-vuln-mosaic-osv-incremental | [OSV Increments](#osv-increments) | Backlog | Apply OSV's modified-id list instead of swapping whole zips |
| req-vuln-mosaic-data-home | [A Platform Data Directory](#a-platform-data-directory) | Backlog | A core convention for operator data directories, deferred |
| req-vuln-mosaic-status-panel | [A Dataset Status Panel](#a-dataset-status-panel) | Backlog | A page or panel showing each source's age and last outcome |
| req-vuln-mosaic-grift-bridge | [Records As Graph Nodes](#records-as-graph-nodes) | Backlog | The default ruling is no; recorded so the question has a home |

### Operator Settings

----
RID: `req-vuln-mosaic-settings`

Status: `Implemented`

All operator choices live in one file, `<home>/settings.json`, on the operator's filesystem. It is never read from the grid and no operator-only value sits on a grid node, so anyone who can write the file is the operator by construction. The file ships with a JSON Schema and the loader validates against it at load; an invalid or unparseable file fails loud and the run does not start.

#### Implementation

`<home>` is a fixed directory chosen at deployment. Its default is `~/.local/share/tap/vuln-mosaic`, that is under the runtime user's `HOME` (`/home/nonroot` in the tap-web image), overridable by an environment variable the deployment sets (`VULN_MOSAIC_HOME`). The first draft named `/var/lib/tap/vuln-mosaic`; *observed* 2026-10-19 in the tap-web image, that directory does not exist and `/var/lib` is root-owned, so the runtime user cannot create it, while `HOME` is declared in the Dockerfile and writable. The collector wrote and read under the new default when run through the real task body (*observed* 2026-10-19). Where `<home>` should live long term, and how a platform would own it, is deferred (`req-vuln-mosaic-data-home`).

`tap_plugin/vuln_mosaic/schemas/settings.schema.json` (with a description on the top level and on every property) defines:

- `sources`: an object keyed by source name (`cvelist`, `kev`, `epss`, `nvd`, `osv`, `ghsa`). Each entry has `enabled` (boolean), `max_age_days` (positive integer, default 3, the same default grype-tap uses), and for `cvelist` a `mode` of `wanted` (the default) or `full`; for `osv` an `ecosystems` array of ecosystem names, each of which must appear in the bucket's `ecosystems.txt` and match `^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$`; anything else is refused at settings validation (a name can never contain `/` or `..`, because it becomes a directory name).
- `immediate_fetch`: boolean, default `false` (`req-vuln-mosaic-lookup`).
- `mirror`: an object keyed by source name whose values are directory paths (`req-vuln-mosaic-mirror`).

Defaults when the file is absent: `cvelist` (wanted), `kev` and `epss` enabled; `nvd`, `osv` and `ghsa` disabled until the operator enables them. Code reads settings only through `tap_plugin/vuln_mosaic/settings.py`, which returns a frozen object.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-settings-1 | Schema Validated | Implemented | A settings file that violates the schema (unknown source, non-positive age, wrong type) stops the run before any fetch and names the offending key. | |
| req-vuln-mosaic-settings-2 | Defaults When Absent | Implemented | With no settings file the loader returns the documented defaults and the run proceeds. | |
| req-vuln-mosaic-settings-3 | Never From The Grid | Implemented | No setting is read from a node, a dimension or a tag; the loader has no grid import. | Asserted by an import test. |

### The Stores

----
RID: `req-vuln-mosaic-store`

Status: `Implemented`

Each record source is one SQLite file with a single writer, the refresh collector. Whole-file sources are plain files published by staged swap. Everything lives under `<home>`, in the container's own filesystem for now.

#### Implementation

Layout under `<home>`:

- `stores/<source>.sqlite` for `cvelist` and `nvd`. Table `records(id TEXT PRIMARY KEY, state TEXT NOT NULL, date_updated TEXT, record_gz BLOB NOT NULL)` holds each record exactly as received, gzipped. Table `meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)` holds the dataset facts of `req-vuln-mosaic-staleness`. Table `wanted(id TEXT PRIMARY KEY, first_wanted TEXT NOT NULL, origin TEXT NOT NULL)` holds spool-added ids (`req-vuln-mosaic-wanted`). Table `quarantine(id TEXT NOT NULL, seen_at TEXT NOT NULL, reason TEXT NOT NULL)` holds records refused by `req-vuln-mosaic-integrity`. WAL journal mode, a busy timeout, and the standard library `sqlite3` module only.
- `files/<source>/<build>/<artifact>` plus a symlink `files/<source>/current` for `kev`, `epss` and each `osv/<ecosystem>`. A refresh stages beside the live copy, validates, moves the staging directory into `<build>`, atomically repoints `current`, and keeps the two newest builds. A reader resolves `current` once and opens the artifact immediately, then reads through that descriptor; it never re-resolves a saved path later.
- `<home>/.lock`: the writer holds an exclusive `flock` for the whole refresh and never waits for readers. SQLite readers need no lock. The one other writer is an immediate lookup (`req-vuln-mosaic-lookup`), which takes the same lock without waiting past its 10 s budget; if the refresh holds it, the lookup answers *not fetched* and queues the id.

The data is lost when the container is recreated (the directory is in the container filesystem, not a volume); the first run afterwards bootstraps from upstream, and until then every read answers *not fetched*. Wanted-ids mode keeps that bootstrap small; full mode is about 0.7 GB (*inferred* from the 8.5 times expansion measured on the delta sample; the expanded baseline itself is NOT measured). Only code running in the collector's container can read the stores; the collector and grype-tap's scan both run in `tap-web`, where the scheduler process runs (maintainer ruling, 2026-10-16).

Whether SQLite WAL reads work between two processes in that container, and what the read-only open requires of the `-shm` file, was tested across two processes (`test_cross_process_reader_sees_consistent_data`: a reader process polled while the writer committed 300 transactions, with no inconsistent read), on Linux in the tap-web container (*ran* 2026-10-19). Read-only opens of a WAL database worked because the reader's user owns the directory.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-store-1 | Records Kept As Received | Implemented | A record read back from a store, once gunzipped, is byte-identical to the record fetched. | |
| req-vuln-mosaic-store-2 | Atomic Publish | Implemented | A reader that opens a whole-file source while a refresh swaps `current` sees either the old build or the new build in full, never a mixture, and a reader that has opened its file keeps reading it across two further publications. | Concurrency test; the reader holds an open descriptor, not a saved path. |
| req-vuln-mosaic-store-3 | Single Writer | Implemented | A second refresh started while one is running refuses to start and says so. | |
| req-vuln-mosaic-store-4 | Empty Store Reads Not Fetched | Implemented | With `<home>` empty, a read of any id returns *not fetched* and raises nothing. | Covers a recreated container. |

### Staleness Is Derived

----
RID: `req-vuln-mosaic-staleness`

Status: `Implemented`

Every dataset carries two times, and `stale` is computed from them at read time, never stored. A dataset past its limit reads stale; one with no time at all reads unobserved; none is ever reported as current or complete without that comparison.

#### Implementation

Dataset facts per source, kept in `meta` (record sources) or an `index.json` beside `current` (whole-file sources): `as_of` (the source's own build or release time: for `cvelist`, the committer time of the last-applied commit; for `kev`, `dateReleased`; for `epss`, `score_date`; for `osv`, the artifact's last-modified time), `checked_at` (the last time something vouched that the data matched upstream), `source_version` (the commit, `catalogVersion`, `model_version`, or build id), and `fetched_at`.

`checked_at` is the staleness clock, and it is the source's word, not the install's: for a live fetch it is the time of the successful fetch, including a fetch that found nothing new (so a catalog that legitimately did not change for several days is not reported stale); for an operator mirror import it is the artifact's own build time from its manifest, so a late import of an old artifact does not read fresh. `stale = now - checked_at > max_age_days`. If `checked_at` is absent, `stale` is `None` (unobserved), not `false`.

A run in which a source could not be reached, or whose newest data is past its limit, ends failed naming that source (`req-vuln-mosaic-refresh`); the previous data keeps serving, flagged stale once its age passes the limit.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-staleness-1 | Stale Is Computed | Implemented | The same stored dataset reads not stale before `max_age_days` and stale after it, with no write in between. | A clock-injected test; strictly greater than the limit is stale. |
| req-vuln-mosaic-staleness-2 | No-Change Fetch Refreshes The Clock | Implemented | A fetch that finds the source unchanged advances `checked_at` and leaves `as_of` untouched. | |
| req-vuln-mosaic-staleness-3 | Mirror Age From Build Time | Implemented | A mirror import of an artifact built five days ago reads stale at a three-day limit, however recent the import. | |
| req-vuln-mosaic-staleness-4 | Unobserved Is Not Fresh | Implemented | A dataset with no `checked_at` reads `stale = None`, and no code path renders `None` as current. | |

### CVE Records From cvelistV5

----
RID: `req-vuln-mosaic-cvelist`

Status: `Implemented`

The CVE records come from the CVE Program's cvelistV5 repository, fetched with git as a blobless, shallow, bare clone, then kept current by diffing trees. A tree diff gives the exact changed paths since any past point, deletions included, with one egress host and no 26 MB change log read per run.

#### Implementation

Constants: remote `https://github.com/CVEProject/cvelistV5.git`, branch `main`, bare repository at `<home>/git/cvelistV5.git`. The remote is a constant in code, never read from the grid or from a record. Every git call is an argument list with no shell, a scrubbed environment (`GIT_TERMINAL_PROMPT=0`, `GIT_ALLOW_PROTOCOL=https`, `GIT_CONFIG_NOSYSTEM=1`, a `HOME` under `<home>/git-home`, no hooks), `transfer.fsckObjects=true`, a timeout and an output cap.

- **Bootstrap:** `git fetch --depth 1 --filter=blob:none origin main` into the bare repository (*observed*: 2.7 s and 11 MB, 409,194 paths). The last-applied commit is kept under `refs/applied/last` so a later fetch cannot prune it.
- **Wanted mode (default):** records whose path is `cves/<year>/<bucket>xxx/CVE-<year>-<n>.json` for an id in the wanted set are read from the repository and written to the store. Blobs are fetched for many ids in one round trip: `git fetch` of object ids with `fetch.negotiationAlgorithm=noop` (*observed* against GitHub 2026-10-19, four blobs in 0.7 s; without `noop`, a local upstream refused a bare blob want once `refs/applied/last` existed, *ran* in the tests). Blob ids come from the trees, which a blobless clone holds, through `git cat-file --batch-check=%(objectname)`; incremental ids come from `git diff --raw --no-abbrev`. The collector runs `git gc --auto` after a run that stored many records.
- **Full mode (operator switch):** fetches without the blob filter and streams every record path into the store.
- **Incremental:** after `git fetch`, `git diff --name-status refs/applied/last FETCH_HEAD` lists added, modified and deleted paths since the last applied commit, whatever the gap (*observed*: 13 changes after eight minutes). Only paths matching the record pattern are considered, in wanted mode only wanted ids, and `cves/delta.json` and `cves/deltaLog.json` are ignored. After a successful apply `refs/applied/last` moves to the fetched commit and `meta` records it as `source_version`.
- **REJECTED:** a record whose `cveMetadata.state` is `REJECTED` is stored with that state and surfaced by `req-vuln-mosaic-lookup` as rejected, never as a live CVE (*observed*: 3 of 1,855 records in one day's changes).
- **Deleted upstream:** a path deleted upstream removes the row, and the read answers *not fetched*. Upstream deleting a record, as opposed to rejecting it, was NOT observed on the live repository; the deletion path is tested against a local upstream (*ran* 2026-10-19).

Egress host: `github.com` only.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-cvelist-1 | Bootstrap And Increment | Implemented | A bootstrap followed by a fetch applies exactly the paths `git diff --name-status` reports between the two commits. | Against a local fixture repository, no network. |
| req-vuln-mosaic-cvelist-2 | Catch-Up From Any Gap | Implemented | Applying after a gap of many commits yields the same store as applying each commit in turn. | |
| req-vuln-mosaic-cvelist-3 | Rejected Kept As State | Implemented | A rejected record is stored with state `REJECTED` and is never returned as a live record. | Fixture from a real REJECTED record. |
| req-vuln-mosaic-cvelist-4 | Non-Records Ignored | Implemented | Changes to `delta.json`, `deltaLog.json` and paths outside the record pattern never reach the store. | |
| req-vuln-mosaic-cvelist-5 | Subprocess Hygiene | Implemented | Git runs with an argument list, a scrubbed environment, `https` only, a timeout and an output cap; no grid or record text enters a command line. | |

### The Wanted-Ids Contract

----
RID: `req-vuln-mosaic-wanted`

Status: `Implemented`

Consumers tell the plugin which CVE ids matter by writing a plain file, and the plugin imports nothing from them. A request spool carries single ids asked for at read time. The default mode fetches only those ids; full mode, an operator switch, fetches everything.

#### Implementation

- **Batch path:** each consumer writes its own file `<home>/wanted/<consumer>.json`, one file per consumer so writers never race. `<consumer>` matches `^[a-z][a-z0-9_]{0,63}$` (a plugin slug); the collector ignores, and names in its run record, any file in `wanted/` whose name does not, and never builds a path from an unvalidated name. A `wanted/` entry that is a symlink is ignored and named; files are opened with `O_NOFOLLOW`. The file validates against `tap_plugin/vuln_mosaic/schemas/wanted.schema.json` (a top-level `description` string and an `ids` array of strings, each a CVE id matching `^CVE-[0-9]{4}-[0-9]{4,}$` or a GHSA id matching `^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$`, each with a described property; `cvelist` reads the CVE ids and `ghsa` the GHSA ids, and each ignores the other kind). A file that fails validation is ignored for that run and named in the run's results; it never aborts the run.
- **Spool path:** a read that misses (`req-vuln-mosaic-lookup`, `req-vuln-mosaic-ghsa-6`) creates `<home>/spool/<CVE-id or GHSA-id>` with `O_CREAT | O_EXCL`, so concurrent requests for one id are one file. The collector ingests each spool file into the `wanted` table of the store, fetches the record, and deletes the file. Ids added this way stay wanted and are refreshed with the rest; v0 does not prune the set (its size is bounded by the ids ever asked about).
- **Wanted set** for a run is the union of every valid `wanted/*.json` file, the `wanted` table, and every id already held in the store. A record once stored is therefore refreshed on every run until the operator prunes it, so a consumer dropping an id from its file cannot leave an old copy reading as fresh. Pruning is an operator act and removes the row from `records` as well.
- **Modes:** `wanted` (default) fetches and refreshes only the wanted set; `full` is `settings.sources.cvelist.mode = "full"` and fetches every record. The mode applies to `cvelist`; `nvd` is always wanted-ids.
- A consumer, such as grype-tap, writes its file and calls the read function; it does not import this plugin's internals, and this plugin does not import the consumer's vocabulary.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-wanted-1 | Only Wanted Ids Fetched | Implemented | In wanted mode, a run stores a record for each wanted id present upstream and for no other id. | |
| req-vuln-mosaic-wanted-2 | Bad File Does Not Abort | Implemented | A schema-invalid wanted file is skipped and named in the results; the other files and the run proceed. | |
| req-vuln-mosaic-wanted-3 | Spool Is Idempotent | Implemented | Two requests for one id leave one spool file, and a fetched id is deleted from the spool and added to `wanted`. | |
| req-vuln-mosaic-wanted-4 | No Consumer Vocabulary | Implemented | The package imports no other plugin; a test fails if `tap_plugin.*` other than its own is imported. | |
| req-vuln-mosaic-wanted-5 | Held Records Stay Fresh | Implemented | A record already stored is refreshed on a later run although no wanted file lists its id any more. | |
| req-vuln-mosaic-wanted-6 | Consumer Name Validated | Implemented | A file named `../x.json` or `A B.json` in `wanted/`, or a symlink there pointing outside it, is ignored and named in the run record, and no path outside `wanted/` is opened. | |

### The Read Function

----
RID: `req-vuln-mosaic-lookup`

Status: `Implemented`

`vuln_mosaic.lookup.get_cve` is how another module asks for a CVE. It is plain Python with no Django import. On a miss it queues the id and answers *not fetched*; only where the operator has enabled immediate fetch does it go to the network inside the call.

#### Implementation

```python
get_cve(cve_id: str, *, home: Path | None = None) -> LookupResult
```

`LookupResult` is a frozen dataclass: `state` (`"found"`, `"not-fetched"` or `"rejected"`), `record` (the parsed JSON object, or `None`), and `dataset` (the facts of `req-vuln-mosaic-staleness`: `as_of`, `checked_at`, `source_version`, `stale`).

- The id is validated against `^CVE-[0-9]{4}-[0-9]{4,}$` before anything else; a malformed id raises `ValueError`. Untrusted text never reaches a path or command.
- **Found:** the record, with the dataset facts and its `stale` flag. A stale dataset still returns its record, flagged.
- **Rejected:** state `REJECTED` returns `rejected` and no live record.
- **Miss, deferred (always available):** returns `not-fetched` and creates the spool file of `req-vuln-mosaic-wanted`.
- **Miss, immediate (only if `settings.immediate_fetch` is true):** calls the same fetch function the collector uses, with a timeout of 10 s, validates it (`req-vuln-mosaic-integrity`), takes `<home>/.lock` (see `req-vuln-mosaic-store`), stores it and returns it; on any failure, including the lock being held by a refresh, it returns `not-fetched` with the reason in the result and still queues the id. There is one fetch function, so the two paths cannot drift.
- A read that finds a record takes no lock and writes nothing. A miss writes only the spool file, or, in immediate mode, the one record under the writer lock.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-lookup-1 | Three Outcomes | Implemented | A held id returns found, a held REJECTED id returns rejected, an unheld id returns not-fetched; none returns an absent record as an empty one. | |
| req-vuln-mosaic-lookup-2 | Miss Queues | Implemented | With immediate fetch off, a miss makes no network connection and leaves one spool file. | Asserted with egress blocked. |
| req-vuln-mosaic-lookup-3 | Immediate Uses The Shared Fetch | Implemented | With immediate fetch on, a miss stores and returns the record through the collector's own fetch function; a failure returns not-fetched and queues the id. | |
| req-vuln-mosaic-lookup-4 | No Django | Implemented | Importing `vuln_mosaic.lookup` imports no Django module. | Import-blocked test. |
| req-vuln-mosaic-lookup-5 | Malformed Id Refused | Implemented | An id that does not match the pattern raises `ValueError` before any file or network access. | |
| req-vuln-mosaic-lookup-6 | Immediate Respects The Writer Lock | Implemented | With a refresh holding `.lock`, an immediate lookup does not write, answers not-fetched and queues the id. | A concurrency test. |

### The Record Parser

----
RID: `req-vuln-mosaic-records`

Status: `Implemented`

`vuln_mosaic.records` turns a stored CVE JSON 5 record into the facts consumers want. It is standard library only and lives here because this plugin owns the record format; CI-side enrichment can use the same module.

#### Implementation

`extract_record(record: dict) -> ParsedRecord` returns a frozen dataclass with: `cve_id`, `state`, `reference_details` (each reference's URL with its tags, such as `vendor-advisory`, `patch`, `exploit`, `mailing-list`; an empty tuple when the record gives none) and `affected_products` (vendor, product, package name, default status, CPEs, the version ranges as given, `fixed_versions`: a transition to unaffected inside a range, or the `lessThan` bound of an affected range unless another affected range of the product starts at exactly that version, wildcard package names excluded; the record's own bounds, not a remediation guarantee, since versions are not compared; and `unaffected_versions`: versions listed with status unaffected, which can predate the vulnerable range and are not claimed as fixes), the CVSS metrics found in the CNA container first and in the CISA-ADP container as a fallback (each with its source container, version, base score, severity and vector), CWE ids from the `problemTypes` of the CNA container then CISA-ADP, the SSVC decision points (exploitation, automatable, technical impact, with version and timestamp) from the CISA-ADP metrics entry of type `ssvc`, dates, the `affected` entries and reference URLs. The SSVC entry location (`metrics[].other.type == "ssvc"`) was *observed* on 1,736 of 1,855 sampled records; the exact shape of its options is *documented* and is confirmed against the corpus fixtures.

Absent data uses the three states: `None` is unobserved (the container or field is not in the record), an empty list or empty object is observed-empty. The CNA-first rule is evidence-backed: in the sample the CNA carried CVSS on 1,799 records and CWE on 1,825, and CISA-ADP carried CVSS on 38 and CWE on 28.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-records-1 | CNA First | Implemented | When both the CNA and CISA-ADP carry CVSS, both are returned and the CNA's is marked primary; when only CISA-ADP carries it, that is primary. | |
| req-vuln-mosaic-records-2 | SSVC From CISA-ADP | Implemented | A record with a CISA-ADP SSVC entry yields its three decision points, version and timestamp; one without yields `None`. | |
| req-vuln-mosaic-records-3 | Three States | Implemented | A record with no `problemTypes` yields `None` CWEs; one with an empty list yields an empty list. | |
| req-vuln-mosaic-records-4 | Standard Library Only | Implemented | The module imports nothing outside the standard library. | Import test. |
| req-vuln-mosaic-records-5 | Reference Tags Parsed | Implemented | Each reference is returned with its URL and its tags; a reference without tags has an empty tuple, a record without references has `None`. | Added 2026-10-19 at the maintainer's request, via rampart-pg-ui. |
| req-vuln-mosaic-records-6 | Fixed Versions Parsed | Implemented | `fixed_versions` lists the range-end versions a record names (change to unaffected, or `lessThan` bound not starting another affected range); explicit unaffected entries go to `unaffected_versions`; a record naming none gives empty tuples. | Checked on the Log4Shell and snipe-it corpus records. |

### Integrity, Fail Closed

----
RID: `req-vuln-mosaic-integrity`

Status: `Implemented`

Nothing fetched is applied until it has been verified, and a failure leaves what was already serving untouched. Nothing upstream is signed, so verification proves shape and transport integrity, not the publisher's identity.

#### Implementation

- **What cannot be verified.** cvelistV5 releases and commits are not signed by a key this plugin can check; git's content hashing and `transfer.fsckObjects` catch corruption, and the digest GitHub reports for a release asset proves the download matches GitHub's copy. None of these authenticates the publisher, and the spec does not claim otherwise.
- **Per record, cvelist:** the JSON parses and is under a size cap (8 MiB); `dataType` is `CVE_RECORD`; the major of `dataVersion` is 5; `cveMetadata.cveId` equals the file name and the requested key; `state` is one of `PUBLISHED` or `REJECTED`.
- **Per record, nvd:** NVD API 2.0 objects are not CVE Record v5, so the v5 checks do not apply. The JSON parses and is under the same size cap; `id` matches the CVE-id pattern and equals the requested key; `vulnStatus` is a string, and is stored as the row's `state`. The field names are *documented*, not yet *observed* against a response, and are confirmed against the recorded fixture of `req-vuln-mosaic-nvd-2` before that requirement moves.
- **A record that fails** either set goes to `quarantine` with the reason, the previous good copy stays, and the run ends failed naming the count.
- **Per download:** TLS verification on (the default context, never disabled), redirects followed only to HTTPS hosts on the source's allow-list, a timeout, a body size cap per source, and no decompression beyond a stated bound.
- **Zip** (`osv`): a member-count cap, a per-member size cap, member names matching `^[A-Za-z0-9_.-]+\.json$` (no absolute paths, no `..`), and every member parsed as JSON in a stream, one member in memory at a time, so a malformed member anywhere in the archive refuses the whole zip.
- **A failure never partially applies:** a bad whole-file download leaves `current` where it was; a bad record batch rolls back the transaction for that source.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-integrity-1 | Malformed Record Quarantined | Implemented | A record with a wrong `dataType`, a mismatched `cveId` or an unknown `state` is quarantined with a reason, the earlier copy keeps serving, and the run ends failed. | |
| req-vuln-mosaic-integrity-2 | Bad Download Leaves Current | Implemented | A truncated, oversized or invalid whole-file download leaves `current` and the previous build unchanged. | |
| req-vuln-mosaic-integrity-3 | Zip Limits | Implemented | A zip with too many members, an oversized member, a member name containing `..`, or one malformed JSON member at any position is refused. | |
| req-vuln-mosaic-integrity-4 | TLS And Redirect Allow-List | Implemented | A redirect to a host outside a source's allow-list, or to plain HTTP, is refused. | |
| req-vuln-mosaic-integrity-5 | NVD Record Validated By NVD Rules | Implemented | An NVD object with a missing or mismatched `id` is quarantined, and a well-formed NVD object is not rejected for lacking CVE Record v5 fields. | |

### The Refresh Collector

----
RID: `req-vuln-mosaic-refresh`

Status: `Implemented`

One collector, `vuln_mosaic:refresh`, runs every enabled source on a seeded hourly schedule. It writes the stores, lands no GRIFT batch, and records each source's outcome in the tap_cares collection job, which is the only thing the grid ever sees.

#### Implementation

`VulnMosaicRefreshCollector(CollectorBase)` in `tap_plugin/vuln_mosaic/collectors/refresh/collector.py`, registered in `apps.py` `ready()` with `register_collector(key="refresh", scope="vuln_mosaic", cls=..., name=..., description=...)`; the scope is the plugin slug, never inferred from the module path, because the derived entity id is a durable grid key and a hardcoded schedule target (the same reason zizmor-tap gives).

- **Schedule:** `tap_plugin/vuln_mosaic/grift/schedule.grift.json`, declared under `[grift]`, seeds one tap_cares `schedule` node targeting `vuln_mosaic:refresh`, default cron `41 * * * *` (off the hour; cvelistV5 commits roughly every ten minutes, *observed* 2026-10-16), user-editable, one active run; the `schedule-grift-targets` guard verifies the target.
- **`run()`:** takes the writer lock, ingests the spool, then for each enabled source in a fixed order fetches, verifies (`req-vuln-mosaic-integrity`) and applies. One source failing never skips the rest. Each source's outcome is recorded with `record_info`, `record_warn` or `record_error` carrying the source, the `source_version`, counts and, on failure, the reason; the run `summary` names the sources that failed and those that are stale. `submit_grift` is never called, and `declare_no_surfaces()` says on the record that no listing surface was read. A run in which any source failed or is stale ends as a failed collection job naming each such source, never clean.
- **`self_test`:** `<home>` is writable, the settings file validates, the `git` binary is present, and each enabled source's host is named; a reachability check is read-only.
- **Gate (resolved):** the tap_cares task body accepts a run that lands zero batches. *Ran* 2026-10-19 in a dev stack: the collector fired through `fire_collector_and_await` ended `SUCCESSFUL` with its results and summary recorded and no batch.
- **Actor:** the collector runs as the `tap_cares.collector` program actor that the task body binds (*read* in `tap_cares/tasks.py`) and writes no grid object itself; its only grid footprint is the job record.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-refresh-1 | Seeded Schedule Fires | Implemented | After seeding, the schedule node exists with the default cron and a tick at a matching slot runs the collector. | Verified by the `schedule-grift-targets` guard. |
| req-vuln-mosaic-refresh-2 | Zero Batches Accepted | Implemented | A run that submits no GRIFT batch reaches a terminal state with its results and summary recorded. | The gate above. |
| req-vuln-mosaic-refresh-3 | One Source Failing | Implemented | With one source failing and others healthy, the healthy sources are applied and the job fails naming the failed one. | |
| req-vuln-mosaic-refresh-4 | Stable Scope | Implemented | The collector's registry scope is the literal `vuln_mosaic`, independent of the module path. | |
| req-vuln-mosaic-refresh-5 | Self-Test Reports | Implemented | `self_test` fails when `<home>` is unwritable, the settings are invalid or `git` is absent, and names which. | |

### CISA KEV Catalog

----
RID: `req-vuln-mosaic-kev`

Status: `Implemented`

The CISA Known Exploited Vulnerabilities catalog is held as a whole file, as a lookup for CVEs Grype never matched. grype-tap remains the source of KEV status for the vulnerabilities Grype matched; this file does not replace or duplicate that, it covers ids no scan has touched.

#### Implementation

URL `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (*observed*: about 1.7 MB, `catalogVersion` such as `2026.10.15`, `dateReleased`, `count`). Staged, validated and swapped into `files/kev/<build>/known_exploited_vulnerabilities.json` with `current` repointed. Validation: a JSON object with `catalogVersion`, `dateReleased`, `count` and a `vulnerabilities` array whose length equals `count`; each entry's `cveID` matches the id pattern; `catalogVersion` is not lower than the installed one (compared as dotted integers) and `dateReleased` is not in the future. The catalog has no delta, so a refresh downloads the whole file and an unchanged `catalogVersion` advances only `checked_at`. Egress host: `www.cisa.gov`. Consumers read `files/kev/current/known_exploited_vulnerabilities.json` and the dataset facts beside it, or call `vuln_mosaic.lookup.get_kev(cve_id)`, which returns `listed`, `not-listed` or `not-fetched`, the catalog entry as published (dateAdded, dueDate, requiredAction, knownRansomwareCampaignUse and the rest) and the dataset facts.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-kev-1 | Swap On New Version | Implemented | A catalog with a higher `catalogVersion` becomes `current`; the same version only advances `checked_at`. | |
| req-vuln-mosaic-kev-2 | Rollback And Count Refused | Implemented | A lower `catalogVersion`, a future `dateReleased`, or a `count` that disagrees with the array is refused and `current` is unchanged. | |
| req-vuln-mosaic-kev-3 | Entry Readable By Id | Implemented | `get_kev` returns the published entry for a listed id, `not-listed` for an unlisted one, and `not-fetched` with `stale = None` before any catalog is held. | |

### FIRST EPSS Scores

----
RID: `req-vuln-mosaic-epss`

Status: `Implemented`

The FIRST EPSS daily scores are held as a whole file, keeping the model version and score date their header carries.

#### Implementation

URL `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, which redirects (same host) to a dated file `epss_scores-YYYY-MM-DD.csv.gz` (*observed*: 2.7 MB; first line `#model_version:v2026.06.15,score_date:2026-10-16T12:02:51Z`, then the header `cve,epss,percentile`). Staged, validated and swapped into `files/epss/<build>/` with `current`. Validation: gzip decompresses within a bound; the first line parses into `model_version` and `score_date`; the header row is exactly `cve,epss,percentile`; every row has a CVE id and two numbers in `[0, 1]` (the file is read in full, streamed); `score_date` is not earlier than the installed one and not in the future. `as_of` is `score_date`; `source_version` is `model_version`. Only the current day is held (no history). `vuln_mosaic.lookup.get_epss(cve_id)` returns `scored`, `not-scored` or `not-fetched`, the score, the percentile, the model version and the score date, and the dataset facts. Egress host: `epss.empiricalsecurity.com`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-epss-1 | Header Kept | Implemented | The stored dataset facts carry the file's `model_version` and `score_date`. | |
| req-vuln-mosaic-epss-2 | Invalid File Refused | Implemented | A file with a wrong header, an earlier `score_date`, or an out-of-range score on any row (first, last or middle) is refused and `current` is unchanged. | |
| req-vuln-mosaic-epss-3 | Score Readable By Id | Implemented | `get_epss` returns the current score and percentile for a scored id, `not-scored` for an absent one, and `not-fetched` before any file is held. | |

### NVD API 2.0

----
RID: `req-vuln-mosaic-nvd`

Status: `Proposed`

NVD records add what cvelistV5 lacks, chiefly CPE applicability and NVD-scored CVSS. They are fetched by CVE id for wanted ids and kept current by a last-modified window. This requirement is gated: NVD's terms, key policy and rate limits are NOT read, so it cannot move to Approved for Development until they are.

#### Implementation

Base URL `https://services.nvd.nist.gov/rest/json/cves/2.0`, queried with `cveId=` for a wanted id and with `lastModStartDate` and `lastModEndDate` for increments (*observed*: an unauthenticated one-hour window answered 200 with `totalResults` 2,048 and `resultsPerPage` 2,000, so pagination is required). Stored in `stores/nvd.sqlite` in the shape of `req-vuln-mosaic-store`, the vulnerability object as received. NVD's own documentation pages (`nvd.nist.gov/developers/start-here`, `/api-workflows`) render only through JavaScript and could not be read by a fetch tool on 2026-10-19, so the limits are NOT read from NVD. Secondary sources (the `nvd-api` and `nvdlib` client libraries) report 5 requests per rolling 30 seconds without a key (50 with one) and a 120-day cap on date ranges; the code uses one request per 6.5 s, windows under 120 days, no key, and backs off 30, 60 and 120 s on a 403 or 429. The code is written and tested against recorded shapes, and the source stays disabled by default and this requirement stays Proposed until a person reads NVD's terms and limits. If an API key is used, it is a TAP secret and its handling is reviewed under the `manage-secret` skill before this requirement is approved; no key is specified here. Egress host: `services.nvd.nist.gov`. Disabled unless the operator enables it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-nvd-1 | Terms And Limits Read | Proposed | The spec's Implementation names NVD's rate limits and terms, taken from NVD's own documentation, before the status moves. | The gate. |
| req-vuln-mosaic-nvd-2 | By Id And By Window | Proposed | A wanted id is fetched by `cveId`, and changed records by a last-modified window, with pagination followed to the end. | Against a recorded fixture. |
| req-vuln-mosaic-nvd-3 | Rate Limited | Proposed | A run never exceeds the documented request rate and backs off on a 429 or 403. | |

### OSV, Per Ecosystem

----
RID: `req-vuln-mosaic-osv`

Status: `Implemented`

OSV advisories are held per ecosystem as the whole zip OSV publishes, opt-in per ecosystem because they are large. Package-keyed advisories cover ecosystems and ids that have no CVE.

#### Implementation

URL `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` (ecosystem names URL-encoded; the list is `ecosystems.txt` at the bucket root). *Observed* sizes: Wolfi 300 MB, Chainguard 1.07 GB, Ubuntu 777 MB, Debian 76 MB, Red Hat 27.6 MB, PyPI 36 MB, Go 12 MB, Alpine 6.7 MB, Rocky Linux 5.2 MB, npm 218 MB. Each enabled ecosystem is staged, validated (`req-vuln-mosaic-integrity` zip rules) and swapped into `files/osv/<ecosystem>/<build>/all.zip` with `current`; the two kept builds mean the on-disk cost is about twice the sum of the enabled zips. Change detection uses the response's `Last-Modified` or `ETag` where present (a HEAD request returns no length on this bucket, *observed*, so size comes from a ranged GET's `Content-Range`); where neither is present the zip is downloaded. The data license is NOT read. Egress host: `osv-vulnerabilities.storage.googleapis.com`. Disabled unless the operator enables an ecosystem.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-osv-1 | Opt-In Per Ecosystem | Implemented | Only ecosystems listed in settings are fetched; a default install fetches none; a name such as `../x` is refused before any path is built. | |
| req-vuln-mosaic-osv-2 | Whole Zip Swapped | Implemented | A new zip becomes `current` only after validation; an unchanged one advances `checked_at`. | |
| req-vuln-mosaic-osv-3 | Disk Budget Stated | Implemented | The settings documentation states the two-build cost of each enabled ecosystem and names Wolfi, Chainguard and Ubuntu as the largest. | |

### GitHub Security Advisories

----
RID: `req-vuln-mosaic-ghsa`

Status: `Implemented`

A GHSA id is not a CVE id and does not appear in a CVE record, so an advisory GitHub has scored but whose id a consumer holds only as `GHSA-…` cannot be read through `get_cve`. This source holds GitHub's own advisory records for the GHSA ids consumers ask for, so a consumer can map a GHSA id to the CVE ids it aliases and read a CVSS base score without a live lookup. It was added at the maintainer's request on 2026-10-19 (relayed from rampart-pg-ui), for five demo vulnerabilities that carried no `cvss_score`.

#### Implementation

Remote `https://github.com/github/advisory-database.git`, branch `main`, bare repository at `<home>/git/advisory-database.git`, fetched exactly as `req-vuln-mosaic-cvelist` fetches: blobless, shallow, incremental by `git diff --raw --no-abbrev` from `refs/applied/last`, blobs fetched by object id in batches, the same scrubbed environment and bounds. Egress host: `github.com` only. Records are stored as received in `<home>/stores/ghsa.sqlite` (the same SQLite store, `state` being `PUBLISHED`, or `WITHDRAWN` when the advisory has a `withdrawn` date). Off by default.

*Observed* 2026-10-19: a blobless depth-1 clone was 48 MB in 5.6 s and listed 391,144 paths under `advisories/`, 36,910 of them under `github-reviewed/` and the rest under `unreviewed/`. The layout is `advisories/<github-reviewed|unreviewed>/<year>/<month>/<GHSA id>/<GHSA id>.json`, records are OSV-format (`schema_version` 1.4.0). All five ids in the originating request were in `unreviewed/`, so the source reads both trees. A real run against GitHub for those five ids stored five records and a second run took 13 s with nothing new to fetch (*ran*).

- **Path is found, not derived.** The year and month directories are the advisory's publication date, which the id does not carry. A wanted id's path is found by listing the tree at the fetched commit, which a blobless clone holds, and the blob id comes from that listing. If an id appears under both trees the `github-reviewed` copy wins. An advisory promoted from `unreviewed/` to `github-reviewed/` is a delete and an add of one id in one diff and is applied as an update, not a deletion.
- **Wanted ids.** GHSA ids come from the same consumer files, the same spool and the same held-ids rule as CVE ids (`req-vuln-mosaic-wanted`); the `ghsa` source reads the GHSA kind and `cvelist` the CVE kind.
- **Aliases feed cvelist.** The refresh runs `ghsa` before `cvelist` and adds every CVE id that a held advisory aliases to the `cvelist` wanted table (origin `ghsa-alias`), so the CNA record for the alias is held the same run. This is how a consumer goes from `GHSA-…` to the CVE record, KEV entry and EPSS score it already can read.
- **CVSS.** The advisory carries a vector string in `severity[].score` and no number (*observed*: `CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L` with no base score). `vuln_mosaic.cvss` computes the v3.0 and v3.1 base score from the vector with the FIRST specification's formulas, stdlib only. It does not compute v2 or v4 scores: such a vector is kept with `base_score = None`, and `best_cvss` never returns it as a v3 number. One of the five originating advisories (the Python `tarfile` link-extraction fallback) carries only a v4 vector (*observed*), so it reads as unscored here until v4 scoring exists or the alias's CVE record carries a number.
- **Read function.** `get_ghsa(ghsa_id, *, home=None, queue=True)` returns `found`, `withdrawn` or `not-fetched` with the parsed advisory (aliases, CVE ids, summary, details, GitHub's severity label, CWE ids, CVSS metrics, reference urls with their type, and affected packages with the range ends the advisory names), and the dataset facts. A malformed id raises `ValueError` before any I/O, and a CVE id is malformed for it as a GHSA id is for `get_cve`. A miss queues the id when the `ghsa` source is enabled; when it is not, nothing is queued and the reason says so, because no refresh would drain the entry and the spool is bounded and shared with CVE misses.
- **Licence.** The data licence is NOT read here; it must be read before a deployment redistributes the data. Egress is one host the plugin already uses for cvelistV5.
- **No mirror in this version.** `mirror.ghsa` is refused by the settings schema; an offline deployment cannot use this source yet.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-ghsa-1 | Path Found By Listing | Implemented | A wanted id is located by listing the tree at the fetched commit, whatever its year and month directory, and a reviewed copy wins over an unreviewed one. | Real advisories in a local upstream. |
| req-vuln-mosaic-ghsa-2 | Increment And Promotion | Implemented | A later fetch applies exactly the changes to held advisories; an advisory moved between trees is updated, not deleted; a changed or deleted copy is resolved against the tip so a reviewed copy still wins and a remaining copy is kept; a row goes only when no copy remains; an id absent upstream is counted, not a failure; a first refresh re-aligns every wanted id with the tip, including one held from an immediate lookup. | The same first-refresh alignment applies to cvelist. |
| req-vuln-mosaic-ghsa-3 | Verified Before Applied | Implemented | An advisory whose `id` differs from its key, whose `schema_version` is not major 1, or that lacks `modified` or has a non-list field is quarantined, the good records of the batch are kept, and the dataset facts and applied ref do not advance. | |
| req-vuln-mosaic-ghsa-4 | Score Computed, Never Guessed | Implemented | The v3.0 and v3.1 base scores equal the published scores for known vectors (including the five originating advisories' values as read from GitHub's API); an incomplete, duplicated, unknown or v2/v4 vector yields no score. | |
| req-vuln-mosaic-ghsa-5 | Wanted And Aliases | Implemented | A wanted file or spool entry holding a GHSA id is read by `ghsa` only; a malformed GHSA id invalidates its file; a held advisory's CVE aliases become wanted by `cvelist` in the same run, once. | |
| req-vuln-mosaic-ghsa-6 | Three States | Implemented | `get_ghsa` returns found, withdrawn (never as live) or not-fetched with unobserved staleness, queues a miss only when the source is enabled and `queue` is true, and refuses a CVE id. | |
| req-vuln-mosaic-ghsa-7 | Off By Default | Implemented | A default install does not fetch this source. | |

### The Operator Mirror

----
RID: `req-vuln-mosaic-mirror`

Status: `Implemented`

An instance with no egress is fed by an operator who copies each source's artifact into a mirror directory. The refresh then imports from the mirror and makes no network connection. The mirror is a copy of the artifact, not of a service.

#### Implementation

`settings.mirror.<source>` names a directory. It holds the artifact (for `cvelist`, a `git bundle` file; for `kev` and `epss` the downloaded file; for `osv` the zip; for `nvd` a JSON export of the stored records) beside `manifest.json` with `archive` (file name), `sha256`, `built` (the artifact's own build time) and `source`. The refresh refuses an artifact whose digest differs from its manifest, one built earlier than the installed dataset (no rollback), one stamped in the future, a symlink, and a malformed manifest; `checked_at` becomes the manifest's `built` (`req-vuln-mosaic-staleness`). A `git bundle` is imported into a non-blobless repository (the bundle carries its blobs); *ran* against a local bundle 2026-10-19. The NVD mirror (a JSON export) is not implemented in v0 and the refresh says so when one is configured. **Trust boundary, stated plainly:** anyone who can write the mirror directory (artifact and manifest together) or `settings.json` can substitute a dataset, and the checksum only catches accident and half-substitution; both are operator-writable only and neither is on the grid.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-mirror-1 | No Network | Implemented | With a mirror set for a source, that source's refresh makes no connection. | Asserted with egress blocked. |
| req-vuln-mosaic-mirror-2 | Digest, Rollback, Future Refused | Implemented | An artifact whose sha256 differs, one older than the installed dataset, and one built in the future are each refused and the installed dataset keeps serving. | |
| req-vuln-mosaic-mirror-3 | Symlink And Manifest Refused | Implemented | A symlinked artifact or a malformed manifest is refused. | |

### FIPS Declaration

----
RID: `req-vuln-mosaic-fips`

Status: `Implemented`

The plugin declares its crypto posture in the manifest `[fips]` table. Its own code uses only the standard library's TLS and hashing, which use the image's OpenSSL; the open question is the TLS library the `git` binary links.

#### Implementation

The collector's HTTPS fetches use `urllib` and `ssl`, and digests use `hashlib`; both resolve to the system OpenSSL, which in a FIPS image is the validated provider (unified-systems-com/tap `specs/spec-fips.md`). SQLite carries no cryptography. The `git` subprocess performs TLS through whichever library the Wolfi `git` package links, which is NOT verified. The manifest declares `status = "compatible"` if and only if the `crypto-providers` conformance check, run against the installed `git`, finds only the validated provider; otherwise it declares `status = "uses-nonvalidated"` with `providers` and a `reason`, and the operator may waive per plugin in the boot profile. The declaration is not a self-exemption (`req-tap-plugin-manifest-v0-fips`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-fips-1 | Declaration Present | Implemented | The manifest carries a `[fips]` table with a `status`, and a `reason` whenever the status is `uses-nonvalidated`. | |
| req-vuln-mosaic-fips-2 | Declaration Verified | Implemented | The `crypto-providers` check passes against the plugin's artifacts and the installed `git`, and the declared status matches what it finds. | A false `compatible` fails the check. |

### The Corpus Proof

----
RID: `req-vuln-mosaic-corpus`

Status: `Implemented`

The tests run over real records committed to the repository, with the network blocked, and each fail-closed path has a test that proves it fails.

#### Implementation

`tap_plugin/vuln_mosaic/tests/corpus/` holds real CVE JSON 5 records taken from cvelistV5 on a recorded commit: a PUBLISHED record with CISA-ADP SSVC, one with CNA-only CVSS, one with no CPE, one with no CISA-ADP container, and a REJECTED record. Fixture repositories for the git tests are built in a temporary directory from those records. Tests: the parser against each record; the store round trip; a bootstrap-then-increment and a multi-commit catch-up against a local git repository; the wanted and spool paths; the staleness arithmetic with an injected clock; every `req-vuln-mosaic-integrity` failure path; the mirror refusals; a run with egress blocked that completes from a mirror; and a cross-process test in which one process holds a refresh while another reads (the SQLite WAL question of `req-vuln-mosaic-store`), run on Linux in the container. Fixtures never ship in the wheel's runtime data and never seed a live grid.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-corpus-1 | Real Records | Implemented | The corpus contains real records covering PUBLISHED, REJECTED, CNA-only CVSS, no CISA-ADP and no CPE, and the parser tests use them. | |
| req-vuln-mosaic-corpus-2 | Egress Blocked | Implemented | The suite's fetch tests pass with all network access blocked. | |
| req-vuln-mosaic-corpus-3 | Cross-Process Read | Implemented | A reader in a second process reads consistent data while the writer refreshes, on Linux in the container. | Resolves the open WAL question. |
| req-vuln-mosaic-corpus-4 | Negative Per Path | Implemented | Each fail-closed path in `req-vuln-mosaic-integrity` has a test that injects the fault and asserts the previous data is unchanged. | |

### The CVE Panel

----
RID: `req-vuln-mosaic-panel-cve`

Status: `Implemented`

One panel type, `vuln-mosaic-cve`, shows what the local datasets hold about one vulnerability id, so an analyst does not leave the page. It is a reversal of the 2026-10-16 ruling "no pages or panels in v0", made at the maintainer's request on 2026-10-19 (relayed through the rampart-pg sessions): the panel is the only surface, `req-vuln-mosaic-status-panel` stays Backlog, and no page ships. A consumer plugin mounts an instance and owns the page.

#### Implementation

`tap_plugin/vuln_mosaic/panels/cve/__init__.py` defines `VulnMosaicCvePanelType` (slug `vuln-mosaic-cve`, view `vuln_mosaic/panels/cve.html`, css `vuln_mosaic/css/cve.css`), registered in `apps.py` `ready()` on `tap_web.registry.panel_type_registry`. The page forwards its query parameters to the panel request (*observed* 2026-10-19: the page's `hx-get` carries `?vuln_id=…`), and the panel reads the one named by the config key `vuln_id_var` (default `vuln_id`).

Config (`CVE_PANEL_CONFIG_SCHEMA`, every property described, unknown keys refused): `vuln_id_var` (string), `hide_header` (boolean), `queue_misses` (boolean, default true: a request for an id the stores do not hold queues it for the next refresh, which is a write on a read, so it is bounded to 5,000 spool entries and can be turned off), `max_references_per_tag` (integer, default 8). An instance is a `panel` node whose `view` is `vuln_mosaic/panels/cve.html` and whose `config` is that object.

The panel calls `get_cve`, `get_kev` and `get_epss` inside the request. The stores are local files, so the request path makes no network call (the module imports no HTTP, socket or subprocess module). Sections, all structured and without generated prose: record state and outside links; CISA KEV (listed, dateAdded, dueDate, ransomware flag, requiredAction as given); EPSS (score, percentile, model version, score date); record (published, updated, CWE); SSVC; CVSS from the CNA and CISA-ADP containers with the vector split into metric chips; affected products with `fixed_versions` only; references grouped by tag; and a dataset table (as of, checked, version, freshness). Colours are the stat-card tokens (red for KEV and critical/high, yellow for medium and stale, grey for zero, low, not listed and unobserved), with the same dark-mode selectors, and a tone is always paired with a word.

States: no id selected; invalid config; a CVE id (record found, rejected, or not fetched, where the id is queued by `get_cve` and the panel shows an unobserved placeholder); a GitHub advisory id (a note and advisory and OSV links, no CVE lookup, no error); anything else (a note, no links). A dataset with no `checked_at` reads *unobserved*, never fresh. Outside links are built only for ids of the owning source, and each form returned 200 on 2026-10-19: `https://www.cve.org/CVERecord?id=<CVE>`, `https://nvd.nist.gov/vuln/detail/<CVE>`, `https://github.com/advisories/<GHSA>`, `https://osv.dev/vulnerability/<id>`, `https://www.first.org/epss/` and `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`. A reference URL from a record is linked only if it is http or https, and all record text is escaped.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-panel-cve-1 | Registered With A Described Config | Implemented | The panel type is on the panel registry under `vuln-mosaic-cve`, and its config schema describes every property and refuses unknown keys. | |
| req-vuln-mosaic-panel-cve-2 | Local Datasets Only | Implemented | Rendering a held CVE shows its KEV entry, EPSS score and record sections, and the panel module imports no network module. | |
| req-vuln-mosaic-panel-cve-3 | Unobserved Is Not Fresh | Implemented | A dataset with no `checked_at` renders as unobserved, a not-fetched record renders a placeholder and is queued, and neither reads as fresh. | |
| req-vuln-mosaic-panel-cve-4 | Foreign Ids Handled | Implemented | A GHSA id renders a note and its own links without any CVE lookup and without an error; an unrecognised id renders a note with no links; links exist only for ids of the owning source. | |
| req-vuln-mosaic-panel-cve-5 | Only Range Ends As Fixes | Implemented | `unaffected_versions` never appear in the output; `fixed_versions` do. | |
| req-vuln-mosaic-panel-cve-6 | Hostile Record Text | Implemented | A `javascript:` reference is not linked and record-supplied markup is escaped. | |
| req-vuln-mosaic-panel-cve-7 | Follows The Page Theme | Implemented | Loose text inherits the page's colour, and surfaces, rules and muted text are tints of it; the four tone colours take their dark values only under `:root[data-theme="dark"]`, with the stat-card values. The stylesheet has no `prefers-color-scheme` rule. | v0.3.0 switched on the OS preference and painted light text on a light page when the OS was dark and the platform page was not (reported by rampart-pg, reproduced in headless Chrome 2026-10-20 by forcing the old rule on, and fixed in v0.4.1). Checked in headless Chrome on a light and a dark page; a real TAP page in a real browser is NOT OBSERVED by this session. |
| req-vuln-mosaic-panel-cve-8 | Queue Bounded And Optional | Implemented | With `queue_misses` false a miss writes nothing; with it true the spool never grows past its bound. | |

### Operator Commands

----
RID: `req-vuln-mosaic-commands`

Status: `Implemented`

Two Django management commands let an operator prime a stack without writing files by hand.

#### Implementation

`manage.py vuln_mosaic_want <consumer> [ids…] [--from-file F]` validates the consumer name (`^[a-z][a-z0-9_]{0,63}$`) and every id, skips malformed ids with a message, and writes `<home>/wanted/<consumer>.json` atomically, replacing that consumer's earlier list and touching no other consumer's file. `manage.py vuln_mosaic_refresh` runs one refresh in the calling process under the writer lock and prints each source's outcome; it exits non-zero when a source failed or is stale, or when the lock is held. Neither makes a network call except the refresh itself.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-commands-1 | Want Writes A Valid File | Implemented | The command writes a file the wanted scan accepts, drops duplicates and malformed ids, replaces its own earlier list, and refuses a bad consumer name or an empty list. | |
| req-vuln-mosaic-commands-2 | Refresh Reports | Implemented | The refresh command prints each outcome and fails when the run is not clean. | |

### Non-Goals

----
RID: `req-vuln-mosaic-nongoals`

Status: `Implemented`

Things this plugin is not going to do, stated so a later change cannot grow into them unnoticed.

#### Implementation

- **No scanning, matching or findings.** It does not decide which packages are affected by which CVE, and writes no finding. Scanning and matching belong to grype-tap; the vulnerability vocabulary belongs to compliance_core.
- **No vulnerability records as graph nodes** (`req-vuln-mosaic-grift-bridge` records the question).
- **No pages, and one panel type** (`req-vuln-mosaic-panel-cve`, added 2026-10-19 at the maintainer's request); a dataset status view stays Backlog (`req-vuln-mosaic-status-panel`).
- **KEV is a lookup, not a status source.** The KEV file is for CVEs Grype never matched; KEV status for matched vulnerabilities stays with grype-tap.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-nongoals-1 | No Findings Written | Implemented | A full run writes no `finding`, `vulnerability` or other graph node; its only grid footprint is the collection job and the seeded schedule. | |
| req-vuln-mosaic-nongoals-2 | No Pages Shipped | Implemented | The package ships no page, and the manifest declares no pages; its one panel type is registered in code. | |

### OSV Increments

----
RID: `req-vuln-mosaic-osv-incremental`

Status: `Backlog`

Apply OSV's per-ecosystem `modified_id.csv` (lines of `timestamp,id`, newest first, *observed* 2026-10-16) as increments to a stored ecosystem instead of swapping the whole zip. Blocked on deciding the stored shape for OSV records (the v0 form is the zip as received).

### A Platform Data Directory

----
RID: `req-vuln-mosaic-data-home`

Status: `Backlog`

A thin core convention for operator-owned data directories (one directory, a subdirectory per plugin, a shared helper for staged swap, lock and age, read-only mounts for consumers), shared with grype-tap's directory. Deferred by the maintainer on 2026-10-16: v0 stores in the container filesystem. It belongs in a core spec, not in this plugin.

### A Dataset Status Panel

----
RID: `req-vuln-mosaic-status-panel`

Status: `Backlog`

A page or panel showing each source's `as_of`, `checked_at`, `stale` and last run outcome. v0 exposes these only through the collection job and the read function.

### Records As Graph Nodes

----
RID: `req-vuln-mosaic-grift-bridge`

Status: `Backlog`

The default ruling is that vulnerability records stay files and consumers read them. If a future need arises for CVE records to be queryable on the grid, this requirement is where that question is decided; it is not scheduled.

## Reference data

Records are fetched, never seeded. One GRIFT document ships:

| Document | Contents | Seeded by |
| --- | --- | --- |
| `grift/schedule.grift.json` | The `schedule` node that fires `vuln_mosaic:refresh` hourly | Every record |
