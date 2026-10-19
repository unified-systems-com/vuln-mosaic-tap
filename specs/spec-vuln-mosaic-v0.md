# Vuln Mosaic Plugin Specification

**Vuln Mosaic is a standalone, near-pure-Python collector that keeps local copies of public vulnerability data (CVE records, the CISA KEV catalog, EPSS scores, NVD and OSV records) in stores it owns, plus a small read function for other modules, so that a running TAP instance reads vulnerability facts from local files and makes no lookup at use time.**

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
| req-vuln-mosaic-settings | [Operator Settings](#operator-settings) | Proposed | One validated settings file on the operator's filesystem; per-source switches, mode and age limit |
| req-vuln-mosaic-store | [The Stores](#the-stores) | Proposed | One SQLite file per record source, plain files for whole-file sources, in a directory the plugin owns |
| req-vuln-mosaic-staleness | [Staleness Is Derived](#staleness-is-derived) | Proposed | As-of and checked-at per source; `stale` computed at read time against the limit |
| req-vuln-mosaic-cvelist | [CVE Records From cvelistV5](#cve-records-from-cvelistv5) | Proposed | Blobless shallow git fetch; incremental by tree diff; REJECTED kept as state |
| req-vuln-mosaic-wanted | [The Wanted-Ids Contract](#the-wanted-ids-contract) | Proposed | A file the consumer writes, a request spool, and the wanted and full modes |
| req-vuln-mosaic-lookup | [The Read Function](#the-read-function) | Proposed | `get_cve`: record, not fetched or rejected; deferred by default, immediate by operator switch |
| req-vuln-mosaic-records | [The Record Parser](#the-record-parser) | Proposed | `vuln_mosaic.records`: CVSS CNA-first, CWE, SSVC; stdlib only |
| req-vuln-mosaic-integrity | [Integrity, Fail Closed](#integrity-fail-closed) | Proposed | Verify before apply; quarantine a malformed record; nothing upstream is signed |
| req-vuln-mosaic-refresh | [The Refresh Collector](#the-refresh-collector) | Proposed | `vuln_mosaic:refresh`; seeded hourly schedule; zero GRIFT batches; per-source outcomes in the collection job |
| req-vuln-mosaic-kev | [CISA KEV Catalog](#cisa-kev-catalog) | Proposed | Whole-file source; a lookup for CVEs Grype never matched |
| req-vuln-mosaic-epss | [FIRST EPSS Scores](#first-epss-scores) | Proposed | Whole-file source; keeps the model version and score date |
| req-vuln-mosaic-nvd | [NVD API 2.0](#nvd-api-20) | Proposed | By CVE id and by last-modified window for wanted ids; gated on terms and limits not yet read |
| req-vuln-mosaic-osv | [OSV, Per Ecosystem](#osv-per-ecosystem) | Proposed | Opt-in per ecosystem; whole zip swapped; the large ecosystems named |
| req-vuln-mosaic-mirror | [The Operator Mirror](#the-operator-mirror) | Proposed | No-egress fallback: an artifact copy plus a sha256 manifest, verified before use |
| req-vuln-mosaic-fips | [FIPS Declaration](#fips-declaration) | Proposed | `[fips]` table; stdlib crypto uses the image's OpenSSL; git's TLS path to be verified |
| req-vuln-mosaic-corpus | [The Corpus Proof](#the-corpus-proof) | Proposed | Tests from real committed records, an egress-blocked run and a negative test per fail-closed path |
| req-vuln-mosaic-nongoals | [Non-Goals](#non-goals) | Proposed | No scanning, matching or findings; no records as nodes; no pages in v0 |
| req-vuln-mosaic-osv-incremental | [OSV Increments](#osv-increments) | Backlog | Apply OSV's modified-id list instead of swapping whole zips |
| req-vuln-mosaic-data-home | [A Platform Data Directory](#a-platform-data-directory) | Backlog | A core convention for operator data directories, deferred |
| req-vuln-mosaic-status-panel | [A Dataset Status Panel](#a-dataset-status-panel) | Backlog | A page or panel showing each source's age and last outcome |
| req-vuln-mosaic-grift-bridge | [Records As Graph Nodes](#records-as-graph-nodes) | Backlog | The default ruling is no; recorded so the question has a home |

### Operator Settings

----
RID: `req-vuln-mosaic-settings`

Status: `Proposed`

All operator choices live in one file, `<home>/settings.json`, on the operator's filesystem. It is never read from the grid and no operator-only value sits on a grid node, so anyone who can write the file is the operator by construction. The file ships with a JSON Schema and the loader validates against it at load; an invalid or unparseable file fails loud and the run does not start.

#### Implementation

`<home>` is a fixed directory chosen at deployment. Its default is `/var/lib/tap/vuln-mosaic`, overridable by an environment variable the deployment sets (`VULN_MOSAIC_HOME`); that default path being writable by the `tap-web` user is NOT verified and is checked at first light. Where `<home>` should live long term, and how a platform would own it, is deferred (`req-vuln-mosaic-data-home`).

`tap_plugin/vuln_mosaic/schemas/settings.schema.json` (with a description on the top level and on every property) defines:

- `sources`: an object keyed by source name (`cvelist`, `kev`, `epss`, `nvd`, `osv`). Each entry has `enabled` (boolean), `max_age_days` (positive integer, default 3, the same default grype-tap uses), and for `cvelist` a `mode` of `wanted` (the default) or `full`; for `osv` an `ecosystems` array of ecosystem names.
- `immediate_fetch`: boolean, default `false` (`req-vuln-mosaic-lookup`).
- `mirror`: an object keyed by source name whose values are directory paths (`req-vuln-mosaic-mirror`).

Defaults when the file is absent: `cvelist` (wanted), `kev` and `epss` enabled; `nvd` and `osv` disabled until the operator enables them. Code reads settings only through `tap_plugin/vuln_mosaic/settings.py`, which returns a frozen object.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-settings-1 | Schema Validated | Proposed | A settings file that violates the schema (unknown source, non-positive age, wrong type) stops the run before any fetch and names the offending key. | |
| req-vuln-mosaic-settings-2 | Defaults When Absent | Proposed | With no settings file the loader returns the documented defaults and the run proceeds. | |
| req-vuln-mosaic-settings-3 | Never From The Grid | Proposed | No setting is read from a node, a dimension or a tag; the loader has no grid import. | Asserted by an import test. |

### The Stores

----
RID: `req-vuln-mosaic-store`

Status: `Proposed`

Each record source is one SQLite file with a single writer, the refresh collector. Whole-file sources are plain files published by staged swap. Everything lives under `<home>`, in the container's own filesystem for now.

#### Implementation

Layout under `<home>`:

- `stores/<source>.sqlite` for `cvelist` and `nvd`. Table `records(id TEXT PRIMARY KEY, state TEXT NOT NULL, date_updated TEXT, record_gz BLOB NOT NULL)` holds each record exactly as received, gzipped. Table `meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)` holds the dataset facts of `req-vuln-mosaic-staleness`. Table `wanted(id TEXT PRIMARY KEY, first_wanted TEXT NOT NULL, origin TEXT NOT NULL)` holds spool-added ids (`req-vuln-mosaic-wanted`). Table `quarantine(id TEXT NOT NULL, seen_at TEXT NOT NULL, reason TEXT NOT NULL)` holds records refused by `req-vuln-mosaic-integrity`. WAL journal mode, a busy timeout, and the standard library `sqlite3` module only.
- `files/<source>/<build>/<artifact>` plus a symlink `files/<source>/current` for `kev`, `epss` and each `osv/<ecosystem>`. A refresh stages beside the live copy, validates, moves the staging directory into `<build>`, atomically repoints `current`, and keeps the two newest builds. A reader resolves `current` once, at the start of its work, and uses that one real path.
- `<home>/.lock`: the writer holds an exclusive `flock` for the whole refresh and never waits for readers. SQLite readers need no lock.

The data is lost when the container is recreated (the directory is in the container filesystem, not a volume); the first run afterwards bootstraps from upstream, and until then every read answers *not fetched*. Wanted-ids mode keeps that bootstrap small; full mode is about 0.7 GB (*inferred* from the 8.5 times expansion measured on the delta sample; the expanded baseline itself is NOT measured). Only code running in the collector's container can read the stores; the collector and grype-tap's scan both run in `tap-web`, where the scheduler process runs (maintainer ruling, 2026-10-16).

Whether SQLite WAL reads work between two processes in that container, and what the read-only open requires of the `-shm` file, is NOT verified here and is the cross-process test of `req-vuln-mosaic-corpus`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-store-1 | Records Kept As Received | Proposed | A record read back from a store, once gunzipped, is byte-identical to the record fetched. | |
| req-vuln-mosaic-store-2 | Atomic Publish | Proposed | A reader that opens a whole-file source while a refresh swaps `current` sees either the old build or the new build in full, never a mixture. | Concurrency test. |
| req-vuln-mosaic-store-3 | Single Writer | Proposed | A second refresh started while one is running refuses to start and says so. | |
| req-vuln-mosaic-store-4 | Empty Store Reads Not Fetched | Proposed | With `<home>` empty, a read of any id returns *not fetched* and raises nothing. | Covers a recreated container. |

### Staleness Is Derived

----
RID: `req-vuln-mosaic-staleness`

Status: `Proposed`

Every dataset carries two times, and `stale` is computed from them at read time, never stored. A dataset past its limit reads stale; one with no time at all reads unobserved; none is ever reported as current or complete without that comparison.

#### Implementation

Dataset facts per source, kept in `meta` (record sources) or an `index.json` beside `current` (whole-file sources): `as_of` (the source's own build or release time: for `cvelist`, the committer time of the last-applied commit; for `kev`, `dateReleased`; for `epss`, `score_date`; for `osv`, the artifact's last-modified time), `checked_at` (the last time something vouched that the data matched upstream), `source_version` (the commit, `catalogVersion`, `model_version`, or build id), and `fetched_at`.

`checked_at` is the staleness clock, and it is the source's word, not the install's: for a live fetch it is the time of the successful fetch, including a fetch that found nothing new (so a catalog that legitimately did not change for several days is not reported stale); for an operator mirror import it is the artifact's own build time from its manifest, so a late import of an old artifact does not read fresh. `stale = now - checked_at > max_age_days`. If `checked_at` is absent, `stale` is `None` (unobserved), not `false`.

A run in which a source could not be reached, or whose newest data is past its limit, ends failed naming that source (`req-vuln-mosaic-refresh`); the previous data keeps serving, flagged stale once its age passes the limit.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-staleness-1 | Stale Is Computed | Proposed | The same stored dataset reads not stale before `max_age_days` and stale after it, with no write in between. | A clock-injected test; strictly greater than the limit is stale. |
| req-vuln-mosaic-staleness-2 | No-Change Fetch Refreshes The Clock | Proposed | A fetch that finds the source unchanged advances `checked_at` and leaves `as_of` untouched. | |
| req-vuln-mosaic-staleness-3 | Mirror Age From Build Time | Proposed | A mirror import of an artifact built five days ago reads stale at a three-day limit, however recent the import. | |
| req-vuln-mosaic-staleness-4 | Unobserved Is Not Fresh | Proposed | A dataset with no `checked_at` reads `stale = None`, and no code path renders `None` as current. | |

### CVE Records From cvelistV5

----
RID: `req-vuln-mosaic-cvelist`

Status: `Proposed`

The CVE records come from the CVE Program's cvelistV5 repository, fetched with git as a blobless, shallow, bare clone, then kept current by diffing trees. A tree diff gives the exact changed paths since any past point, deletions included, with one egress host and no 26 MB change log read per run.

#### Implementation

Constants: remote `https://github.com/CVEProject/cvelistV5.git`, branch `main`, bare repository at `<home>/git/cvelistV5.git`. The remote is a constant in code, never read from the grid or from a record. Every git call is an argument list with no shell, a scrubbed environment (`GIT_TERMINAL_PROMPT=0`, `GIT_ALLOW_PROTOCOL=https`, `GIT_CONFIG_NOSYSTEM=1`, a `HOME` under `<home>/git-home`, no hooks), `transfer.fsckObjects=true`, a timeout and an output cap.

- **Bootstrap:** `git fetch --depth 1 --filter=blob:none origin main` into the bare repository (*observed*: 2.7 s and 11 MB, 409,194 paths). The last-applied commit is kept under `refs/applied/last` so a later fetch cannot prune it.
- **Wanted mode (default):** records whose path is `cves/<year>/<bucket>xxx/CVE-<year>-<n>.json` for an id in the wanted set are read from the repository and written to the store. Fetching the blobs for many ids in one round trip (`git fetch` of object ids) depends on the server allowing it and is NOT verified; the fallback is the lazy fetch git performs on a read, which *observed* leaves one small pack per round trip, so the collector batches where it can and runs pack housekeeping after a run that fetched blobs.
- **Full mode (operator switch):** fetches without the blob filter and streams every record path into the store.
- **Incremental:** after `git fetch`, `git diff --name-status refs/applied/last FETCH_HEAD` lists added, modified and deleted paths since the last applied commit, whatever the gap (*observed*: 13 changes after eight minutes). Only paths matching the record pattern are considered, in wanted mode only wanted ids, and `cves/delta.json` and `cves/deltaLog.json` are ignored. After a successful apply `refs/applied/last` moves to the fetched commit and `meta` records it as `source_version`.
- **REJECTED:** a record whose `cveMetadata.state` is `REJECTED` is stored with that state and surfaced by `req-vuln-mosaic-lookup` as rejected, never as a live CVE (*observed*: 3 of 1,855 records in one day's changes).
- **Deleted upstream:** a path deleted upstream removes the row, and the read answers *not fetched*. Upstream deleting a record, as opposed to rejecting it, was NOT observed.

Egress host: `github.com` only.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-cvelist-1 | Bootstrap And Increment | Proposed | A bootstrap followed by a fetch applies exactly the paths `git diff --name-status` reports between the two commits. | Against a local fixture repository, no network. |
| req-vuln-mosaic-cvelist-2 | Catch-Up From Any Gap | Proposed | Applying after a gap of many commits yields the same store as applying each commit in turn. | |
| req-vuln-mosaic-cvelist-3 | Rejected Kept As State | Proposed | A rejected record is stored with state `REJECTED` and is never returned as a live record. | Fixture from a real REJECTED record. |
| req-vuln-mosaic-cvelist-4 | Non-Records Ignored | Proposed | Changes to `delta.json`, `deltaLog.json` and paths outside the record pattern never reach the store. | |
| req-vuln-mosaic-cvelist-5 | Subprocess Hygiene | Proposed | Git runs with an argument list, a scrubbed environment, `https` only, a timeout and an output cap; no grid or record text enters a command line. | |

### The Wanted-Ids Contract

----
RID: `req-vuln-mosaic-wanted`

Status: `Proposed`

Consumers tell the plugin which CVE ids matter by writing a plain file, and the plugin imports nothing from them. A request spool carries single ids asked for at read time. The default mode fetches only those ids; full mode, an operator switch, fetches everything.

#### Implementation

- **Batch path:** each consumer writes its own file `<home>/wanted/<consumer>.json`, one file per consumer so writers never race. The file validates against `tap_plugin/vuln_mosaic/schemas/wanted.schema.json` (a top-level `description` string and an `ids` array of strings matching `^CVE-[0-9]{4}-[0-9]{4,}$`, each with a described property). A file that fails validation is ignored for that run and named in the run's results; it never aborts the run.
- **Spool path:** a read that misses (`req-vuln-mosaic-lookup`) creates `<home>/spool/<CVE-id>` with `O_CREAT | O_EXCL`, so concurrent requests for one id are one file. The collector ingests each spool file into the `wanted` table of the store, fetches the record, and deletes the file. Ids added this way stay wanted and are refreshed with the rest; v0 does not prune the set (its size is bounded by the ids ever asked about).
- **Wanted set** for a run is the union of every valid `wanted/*.json` file and the `wanted` table.
- **Modes:** `wanted` (default) fetches and refreshes only the wanted set; `full` is `settings.sources.cvelist.mode = "full"` and fetches every record. The mode applies to `cvelist`; `nvd` is always wanted-ids.
- A consumer, such as grype-tap, writes its file and calls the read function; it does not import this plugin's internals, and this plugin does not import the consumer's vocabulary.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-wanted-1 | Only Wanted Ids Fetched | Proposed | In wanted mode, a run stores a record for each wanted id present upstream and for no other id. | |
| req-vuln-mosaic-wanted-2 | Bad File Does Not Abort | Proposed | A schema-invalid wanted file is skipped and named in the results; the other files and the run proceed. | |
| req-vuln-mosaic-wanted-3 | Spool Is Idempotent | Proposed | Two requests for one id leave one spool file, and a fetched id is deleted from the spool and added to `wanted`. | |
| req-vuln-mosaic-wanted-4 | No Consumer Vocabulary | Proposed | The package imports no other plugin; a test fails if `tap_plugin.*` other than its own is imported. | |

### The Read Function

----
RID: `req-vuln-mosaic-lookup`

Status: `Proposed`

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
- **Miss, immediate (only if `settings.immediate_fetch` is true):** calls the same fetch function the collector uses, with a timeout of 10 s, validates it (`req-vuln-mosaic-integrity`), stores it and returns it; on any failure it returns `not-fetched` with the reason in the result and still queues the id. There is one fetch function, so the two paths cannot drift.
- Reading takes no lock and writes nothing but the spool file.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-lookup-1 | Three Outcomes | Proposed | A held id returns found, a held REJECTED id returns rejected, an unheld id returns not-fetched; none returns an absent record as an empty one. | |
| req-vuln-mosaic-lookup-2 | Miss Queues | Proposed | With immediate fetch off, a miss makes no network connection and leaves one spool file. | Asserted with egress blocked. |
| req-vuln-mosaic-lookup-3 | Immediate Uses The Shared Fetch | Proposed | With immediate fetch on, a miss stores and returns the record through the collector's own fetch function; a failure returns not-fetched and queues the id. | |
| req-vuln-mosaic-lookup-4 | No Django | Proposed | Importing `vuln_mosaic.lookup` imports no Django module. | Import-blocked test. |
| req-vuln-mosaic-lookup-5 | Malformed Id Refused | Proposed | An id that does not match the pattern raises `ValueError` before any file or network access. | |

### The Record Parser

----
RID: `req-vuln-mosaic-records`

Status: `Proposed`

`vuln_mosaic.records` turns a stored CVE JSON 5 record into the facts consumers want. It is standard library only and lives here because this plugin owns the record format; CI-side enrichment can use the same module.

#### Implementation

`extract_record(record: dict) -> ParsedRecord` returns a frozen dataclass with: `cve_id`, `state`, the CVSS metrics found in the CNA container first and in the CISA-ADP container as a fallback (each with its source container, version, base score, severity and vector), CWE ids from the `problemTypes` of the CNA container then CISA-ADP, the SSVC decision points (exploitation, automatable, technical impact, with version and timestamp) from the CISA-ADP metrics entry of type `ssvc`, dates, the `affected` entries and reference URLs. The SSVC entry location (`metrics[].other.type == "ssvc"`) was *observed* on 1,736 of 1,855 sampled records; the exact shape of its options is *documented* and is confirmed against the corpus fixtures.

Absent data uses the three states: `None` is unobserved (the container or field is not in the record), an empty list or empty object is observed-empty. The CNA-first rule is evidence-backed: in the sample the CNA carried CVSS on 1,799 records and CWE on 1,825, and CISA-ADP carried CVSS on 38 and CWE on 28.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-records-1 | CNA First | Proposed | When both the CNA and CISA-ADP carry CVSS, both are returned and the CNA's is marked primary; when only CISA-ADP carries it, that is primary. | |
| req-vuln-mosaic-records-2 | SSVC From CISA-ADP | Proposed | A record with a CISA-ADP SSVC entry yields its three decision points, version and timestamp; one without yields `None`. | |
| req-vuln-mosaic-records-3 | Three States | Proposed | A record with no `problemTypes` yields `None` CWEs; one with an empty list yields an empty list. | |
| req-vuln-mosaic-records-4 | Standard Library Only | Proposed | The module imports nothing outside the standard library. | Import test. |

### Integrity, Fail Closed

----
RID: `req-vuln-mosaic-integrity`

Status: `Proposed`

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
| req-vuln-mosaic-integrity-1 | Malformed Record Quarantined | Proposed | A record with a wrong `dataType`, a mismatched `cveId` or an unknown `state` is quarantined with a reason, the earlier copy keeps serving, and the run ends failed. | |
| req-vuln-mosaic-integrity-2 | Bad Download Leaves Current | Proposed | A truncated, oversized or invalid whole-file download leaves `current` and the previous build unchanged. | |
| req-vuln-mosaic-integrity-3 | Zip Limits | Proposed | A zip with too many members, an oversized member, a member name containing `..`, or one malformed JSON member at any position is refused. | |
| req-vuln-mosaic-integrity-4 | TLS And Redirect Allow-List | Proposed | A redirect to a host outside a source's allow-list, or to plain HTTP, is refused. | |
| req-vuln-mosaic-integrity-5 | NVD Record Validated By NVD Rules | Proposed | An NVD object with a missing or mismatched `id` is quarantined, and a well-formed NVD object is not rejected for lacking CVE Record v5 fields. | |

### The Refresh Collector

----
RID: `req-vuln-mosaic-refresh`

Status: `Proposed`

One collector, `vuln_mosaic:refresh`, runs every enabled source on a seeded hourly schedule. It writes the stores, lands no GRIFT batch, and records each source's outcome in the tap_cares collection job, which is the only thing the grid ever sees.

#### Implementation

`VulnMosaicRefreshCollector(CollectorBase)` in `tap_plugin/vuln_mosaic/collectors/refresh/collector.py`, registered in `apps.py` `ready()` with `register_collector(key="refresh", scope="vuln_mosaic", cls=..., name=..., description=...)`; the scope is the plugin slug, never inferred from the module path, because the derived entity id is a durable grid key and a hardcoded schedule target (the same reason zizmor-tap gives).

- **Schedule:** `tap_plugin/vuln_mosaic/grift/schedule.grift.json`, declared under `[grift]`, seeds one tap_cares `schedule` node targeting `vuln_mosaic:refresh`, default cron `41 * * * *` (off the hour; cvelistV5 commits roughly every ten minutes, *observed* 2026-10-16), user-editable, one active run; the `schedule-grift-targets` guard verifies the target.
- **`run()`:** takes the writer lock, ingests the spool, then for each enabled source in a fixed order fetches, verifies (`req-vuln-mosaic-integrity`) and applies. One source failing never skips the rest. Each source's outcome is recorded with `record_info`, `record_warn` or `record_error` carrying the source, the `source_version`, counts and, on failure, the reason; the run `summary` names the sources that failed and those that are stale. `submit_grift` is never called, and `declare_no_surfaces()` says on the record that no listing surface was read. A run in which any source failed or is stale ends as a failed collection job naming each such source, never clean.
- **`self_test`:** `<home>` is writable, the settings file validates, the `git` binary is present, and each enabled source's host is named; a reachability check is read-only.
- **Gate:** whether the tap_cares task body accepts a run that lands zero batches is NOT verified. It is checked first at first light, and if it is refused the fix goes into tap_cares (the owning plugin) before this requirement is Implemented.
- **Actor:** the collector runs as the collection job's actor and writes no grid object itself; its only grid footprint is the job record. Which actor that is is NOT observed.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-refresh-1 | Seeded Schedule Fires | Proposed | After seeding, the schedule node exists with the default cron and a tick at a matching slot runs the collector. | Verified by the `schedule-grift-targets` guard. |
| req-vuln-mosaic-refresh-2 | Zero Batches Accepted | Proposed | A run that submits no GRIFT batch reaches a terminal state with its results and summary recorded. | The gate above. |
| req-vuln-mosaic-refresh-3 | One Source Failing | Proposed | With one source failing and others healthy, the healthy sources are applied and the job fails naming the failed one. | |
| req-vuln-mosaic-refresh-4 | Stable Scope | Proposed | The collector's registry scope is the literal `vuln_mosaic`, independent of the module path. | |
| req-vuln-mosaic-refresh-5 | Self-Test Reports | Proposed | `self_test` fails when `<home>` is unwritable, the settings are invalid or `git` is absent, and names which. | |

### CISA KEV Catalog

----
RID: `req-vuln-mosaic-kev`

Status: `Proposed`

The CISA Known Exploited Vulnerabilities catalog is held as a whole file, as a lookup for CVEs Grype never matched. grype-tap remains the source of KEV status for the vulnerabilities Grype matched; this file does not replace or duplicate that, it covers ids no scan has touched.

#### Implementation

URL `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (*observed*: about 1.7 MB, `catalogVersion` such as `2026.10.15`, `dateReleased`, `count`). Staged, validated and swapped into `files/kev/<build>/known_exploited_vulnerabilities.json` with `current` repointed. Validation: a JSON object with `catalogVersion`, `dateReleased`, `count` and a `vulnerabilities` array whose length equals `count`; each entry's `cveID` matches the id pattern; `catalogVersion` is not lower than the installed one (compared as dotted integers) and `dateReleased` is not in the future. The catalog has no delta, so a refresh downloads the whole file and an unchanged `catalogVersion` advances only `checked_at`. Egress host: `www.cisa.gov`. Consumers read `files/kev/current/known_exploited_vulnerabilities.json` and the dataset facts beside it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-kev-1 | Swap On New Version | Proposed | A catalog with a higher `catalogVersion` becomes `current`; the same version only advances `checked_at`. | |
| req-vuln-mosaic-kev-2 | Rollback And Count Refused | Proposed | A lower `catalogVersion`, a future `dateReleased`, or a `count` that disagrees with the array is refused and `current` is unchanged. | |

### FIRST EPSS Scores

----
RID: `req-vuln-mosaic-epss`

Status: `Proposed`

The FIRST EPSS daily scores are held as a whole file, keeping the model version and score date their header carries.

#### Implementation

URL `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, which redirects (same host) to a dated file `epss_scores-YYYY-MM-DD.csv.gz` (*observed*: 2.7 MB; first line `#model_version:v2026.06.15,score_date:2026-10-16T12:02:51Z`, then the header `cve,epss,percentile`). Staged, validated and swapped into `files/epss/<build>/` with `current`. Validation: gzip decompresses within a bound; the first line parses into `model_version` and `score_date`; the header row is exactly `cve,epss,percentile`; every row has a CVE id and two numbers in `[0, 1]` (the file is read in full, streamed); `score_date` is not earlier than the installed one and not in the future. `as_of` is `score_date`; `source_version` is `model_version`. Egress host: `epss.empiricalsecurity.com`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-epss-1 | Header Kept | Proposed | The stored dataset facts carry the file's `model_version` and `score_date`. | |
| req-vuln-mosaic-epss-2 | Invalid File Refused | Proposed | A file with a wrong header, an earlier `score_date`, or an out-of-range score on any row (first, last or middle) is refused and `current` is unchanged. | |

### NVD API 2.0

----
RID: `req-vuln-mosaic-nvd`

Status: `Proposed`

NVD records add what cvelistV5 lacks, chiefly CPE applicability and NVD-scored CVSS. They are fetched by CVE id for wanted ids and kept current by a last-modified window. This requirement is gated: NVD's terms, key policy and rate limits are NOT read, so it cannot move to Approved for Development until they are.

#### Implementation

Base URL `https://services.nvd.nist.gov/rest/json/cves/2.0`, queried with `cveId=` for a wanted id and with `lastModStartDate` and `lastModEndDate` for increments (*observed*: an unauthenticated one-hour window answered 200 with `totalResults` 2,048 and `resultsPerPage` 2,000, so pagination is required). Stored in `stores/nvd.sqlite` in the shape of `req-vuln-mosaic-store`, the vulnerability object as received. The request rate is set below NVD's published limit once that is read. If an API key is used, it is a TAP secret and its handling is reviewed under the `manage-secret` skill before this requirement is approved; no key is specified here. Egress host: `services.nvd.nist.gov`. Disabled unless the operator enables it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-nvd-1 | Terms And Limits Read | Proposed | The spec's Implementation names NVD's rate limits and terms, taken from NVD's own documentation, before the status moves. | The gate. |
| req-vuln-mosaic-nvd-2 | By Id And By Window | Proposed | A wanted id is fetched by `cveId`, and changed records by a last-modified window, with pagination followed to the end. | Against a recorded fixture. |
| req-vuln-mosaic-nvd-3 | Rate Limited | Proposed | A run never exceeds the documented request rate and backs off on a 429 or 403. | |

### OSV, Per Ecosystem

----
RID: `req-vuln-mosaic-osv`

Status: `Proposed`

OSV advisories are held per ecosystem as the whole zip OSV publishes, opt-in per ecosystem because they are large. Package-keyed advisories cover ecosystems and ids that have no CVE.

#### Implementation

URL `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` (ecosystem names URL-encoded; the list is `ecosystems.txt` at the bucket root). *Observed* sizes: Wolfi 300 MB, Chainguard 1.07 GB, Ubuntu 777 MB, Debian 76 MB, Red Hat 27.6 MB, PyPI 36 MB, Go 12 MB, Alpine 6.7 MB, Rocky Linux 5.2 MB, npm 218 MB. Each enabled ecosystem is staged, validated (`req-vuln-mosaic-integrity` zip rules) and swapped into `files/osv/<ecosystem>/<build>/all.zip` with `current`; the two kept builds mean the on-disk cost is about twice the sum of the enabled zips. Change detection uses the response's `Last-Modified` or `ETag` where present (a HEAD request returns no length on this bucket, *observed*, so size comes from a ranged GET's `Content-Range`); where neither is present the zip is downloaded. The data license is NOT read. Egress host: `osv-vulnerabilities.storage.googleapis.com`. Disabled unless the operator enables an ecosystem.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-osv-1 | Opt-In Per Ecosystem | Proposed | Only ecosystems listed in settings are fetched; a default install fetches none. | |
| req-vuln-mosaic-osv-2 | Whole Zip Swapped | Proposed | A new zip becomes `current` only after validation; an unchanged one advances `checked_at`. | |
| req-vuln-mosaic-osv-3 | Disk Budget Stated | Proposed | The settings documentation states the two-build cost of each enabled ecosystem and names Wolfi, Chainguard and Ubuntu as the largest. | |

### The Operator Mirror

----
RID: `req-vuln-mosaic-mirror`

Status: `Proposed`

An instance with no egress is fed by an operator who copies each source's artifact into a mirror directory. The refresh then imports from the mirror and makes no network connection. The mirror is a copy of the artifact, not of a service.

#### Implementation

`settings.mirror.<source>` names a directory. It holds the artifact (for `cvelist`, a `git bundle` file; for `kev` and `epss` the downloaded file; for `osv` the zip; for `nvd` a JSON export of the stored records) beside `manifest.json` with `archive` (file name), `sha256`, `built` (the artifact's own build time) and `source`. The refresh refuses an artifact whose digest differs from its manifest, one built earlier than the installed dataset (no rollback), one stamped in the future, a symlink, and a malformed manifest; `checked_at` becomes the manifest's `built` (`req-vuln-mosaic-staleness`). Whether a `git bundle` fetches into the blobless repository as designed is NOT tried. **Trust boundary, stated plainly:** anyone who can write the mirror directory (artifact and manifest together) or `settings.json` can substitute a dataset, and the checksum only catches accident and half-substitution; both are operator-writable only and neither is on the grid.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-mirror-1 | No Network | Proposed | With a mirror set for a source, that source's refresh makes no connection. | Asserted with egress blocked. |
| req-vuln-mosaic-mirror-2 | Digest, Rollback, Future Refused | Proposed | An artifact whose sha256 differs, one older than the installed dataset, and one built in the future are each refused and the installed dataset keeps serving. | |
| req-vuln-mosaic-mirror-3 | Symlink And Manifest Refused | Proposed | A symlinked artifact or a malformed manifest is refused. | |

### FIPS Declaration

----
RID: `req-vuln-mosaic-fips`

Status: `Proposed`

The plugin declares its crypto posture in the manifest `[fips]` table. Its own code uses only the standard library's TLS and hashing, which use the image's OpenSSL; the open question is the TLS library the `git` binary links.

#### Implementation

The collector's HTTPS fetches use `urllib` and `ssl`, and digests use `hashlib`; both resolve to the system OpenSSL, which in a FIPS image is the validated provider (unified-systems-com/tap `specs/spec-fips.md`). SQLite carries no cryptography. The `git` subprocess performs TLS through whichever library the Wolfi `git` package links, which is NOT verified. The manifest declares `status = "compatible"` if and only if the `crypto-providers` conformance check, run against the installed `git`, finds only the validated provider; otherwise it declares `status = "uses-nonvalidated"` with `providers` and a `reason`, and the operator may waive per plugin in the boot profile. The declaration is not a self-exemption (`req-tap-plugin-manifest-v0-fips`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-fips-1 | Declaration Present | Proposed | The manifest carries a `[fips]` table with a `status`, and a `reason` whenever the status is `uses-nonvalidated`. | |
| req-vuln-mosaic-fips-2 | Declaration Verified | Proposed | The `crypto-providers` check passes against the plugin's artifacts and the installed `git`, and the declared status matches what it finds. | A false `compatible` fails the check. |

### The Corpus Proof

----
RID: `req-vuln-mosaic-corpus`

Status: `Proposed`

The tests run over real records committed to the repository, with the network blocked, and each fail-closed path has a test that proves it fails.

#### Implementation

`tap_plugin/vuln_mosaic/tests/corpus/` holds real CVE JSON 5 records taken from cvelistV5 on a recorded commit: a PUBLISHED record with CISA-ADP SSVC, one with CNA-only CVSS, one with no CPE, one with no CISA-ADP container, and a REJECTED record. Fixture repositories for the git tests are built in a temporary directory from those records. Tests: the parser against each record; the store round trip; a bootstrap-then-increment and a multi-commit catch-up against a local git repository; the wanted and spool paths; the staleness arithmetic with an injected clock; every `req-vuln-mosaic-integrity` failure path; the mirror refusals; a run with egress blocked that completes from a mirror; and a cross-process test in which one process holds a refresh while another reads (the SQLite WAL question of `req-vuln-mosaic-store`), run on Linux in the container. Fixtures never ship in the wheel's runtime data and never seed a live grid.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-corpus-1 | Real Records | Proposed | The corpus contains real records covering PUBLISHED, REJECTED, CNA-only CVSS, no CISA-ADP and no CPE, and the parser tests use them. | |
| req-vuln-mosaic-corpus-2 | Egress Blocked | Proposed | The suite's fetch tests pass with all network access blocked. | |
| req-vuln-mosaic-corpus-3 | Cross-Process Read | Proposed | A reader in a second process reads consistent data while the writer refreshes, on Linux in the container. | Resolves the open WAL question. |
| req-vuln-mosaic-corpus-4 | Negative Per Path | Proposed | Each fail-closed path in `req-vuln-mosaic-integrity` has a test that injects the fault and asserts the previous data is unchanged. | |

### Non-Goals

----
RID: `req-vuln-mosaic-nongoals`

Status: `Proposed`

Things this plugin is not going to do, stated so a later change cannot grow into them unnoticed.

#### Implementation

- **No scanning, matching or findings.** It does not decide which packages are affected by which CVE, and writes no finding. Scanning and matching belong to grype-tap; the vulnerability vocabulary belongs to compliance_core.
- **No vulnerability records as graph nodes** (`req-vuln-mosaic-grift-bridge` records the question).
- **No pages or panels in v0** (`req-vuln-mosaic-status-panel`).
- **KEV is a lookup, not a status source.** The KEV file is for CVEs Grype never matched; KEV status for matched vulnerabilities stays with grype-tap.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-vuln-mosaic-nongoals-1 | No Findings Written | Proposed | A full run writes no `finding`, `vulnerability` or other graph node; its only grid footprint is the collection job and the seeded schedule. | |
| req-vuln-mosaic-nongoals-2 | No Pages Shipped | Proposed | The manifest declares no pages and no panel types. | |

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
