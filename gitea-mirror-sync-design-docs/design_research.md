# gitea-cve-2026-41506 — design research (EXPERIMENTAL synthetic-call-site arm)

Per `skills/task_design/design_writting_cwe_exp_synthetic_callsite.md`. CWE
group worked: **CWE-522 (Insufficiently Protected Credentials)**, one
candidate — **CVE-2026-41506** (`github.com/go-git/go-git/v5`, credential
leak via cross-host redirect in smart-HTTP transport).

## 0. Scope note — this candidate does not come from `fixed_env/gitea/docs/cwe_candidates.md`

Read in full before starting, per the brief. That file's own `## Result`
records **zero surviving CWE groups** for this app: `gitea` is scoped as an
**oss-image** app (`gitea/gitea:1.27.3`, digest-pinned, consumed
unmodified — `env_map.md` §7, "vendors no application-level dependencies of
its own"), so the catalog lookup that produced `cwe_candidates.md` only ever
scores native Gitea CVEs (`repo == "gitea"` exact), and every one of those
195 rows is already recorded in `docs/native_vuln.md` — the doc says so
explicitly and shows its work (lines 12-28, 44-68 of that file). **CWE-522
and CVE-2026-41506 do not appear anywhere in `cwe_candidates.md`** — I grepped
for both and confirmed zero hits before starting research. There is also no
`fixed_env/gitea/docs/dependency_usage.md` file in this repo (`ls docs/`
returns `READINESS.md, cwe_candidates.md, dep_freshness.md, env_issues.md,
env_map.md, env_precheck.md, native_vuln.md` — no `dependency_usage.md`);
the closest analog, `env_map.md` §7 ("Dependency usage inventory"), states
**N/A** for the same oss-image reason.

This is recorded here plainly rather than silently worked around: the task
brief's framing (a CWE-522 group in `cwe_candidates.md`, a
`dependency_usage.md` with per-dependency usage evidence) does not match what
this app's actual docs contain. I treated the brief's assigned candidate
(CVE-2026-41506 against go-git, go-git being a real transitive dependency
`gitea/gitea:1.27.3` vendors — confirmed in `go.mod`, see §1 below) as the
work item regardless, since it is independently well-formed (a real CVE, a
real vendored dependency, a real CWE), and researched it exactly as the skill
prescribes for any single assigned candidate — reading the real fix commit,
then checking the real app source at the pinned tag for whether the
vulnerable function is ever called. The absence of a matching
`cwe_candidates.md`/`dependency_usage.md` row doesn't change that work; it's
flagged here so a reviewer isn't misled into thinking those docs back this
candidate — they don't, and should be treated as silent on it rather than as
confirming it.

## 1. The real CVE, read directly from its fix commit

**Advisory**: GHSA-3xc5-wrhm-f963 / CVE-2026-41506, "go-git Credential leak
via cross-host redirect in smart HTTP transport." **Affected**: go-git/v5
`<= 5.17.2`, go-git/v6 `<= 6.0.0-alpha.1`. **Fixed**: `5.18.0` / `6.0.0-alpha.2`.
CWE-522 (the advisory also cross-tags CWE-601, open redirect, as the
enabling condition). Published 2026-05-08. (Observed — WebSearch +
`WebFetch` against the GitHub advisory; **Code-supported** for everything
below, which comes from reading the actual diff.)

The advisory prose alone doesn't name a function (confirmed by direct
`WebFetch` of the advisory page — no file/function/commit is given there).
Per the skill's own warning ("a package name is not a function name"), I
pulled the actual diff rather than stopping at the advisory:

```
gh api repos/go-git/go-git/compare/v5.17.2...v5.18.0 \
  --jq '.files[] | select(.filename | test("transport/http")) | .filename'
  -> plumbing/transport/http/common.go
  -> plumbing/transport/http/common_test.go
```

**Exact function and mechanism** (from the real patch diff,
`plumbing/transport/http/common.go`):

- The vulnerable code is `(*session).ModifyEndpointIfRedirect`, called from
  `advertisedReferences(ctx, s *session, serviceName string)` — both inside
  go-git/v5's own smart-HTTP **client** implementation (package
  `github.com/go-git/go-git/v5/plumbing/transport/http`). `advertisedReferences`
  issues the initial `GET .../info/refs?service=<serviceName>` request that
  starts every smart-HTTP clone/fetch/push, then calls
  `s.ModifyEndpointIfRedirect(res)` on whatever response comes back.
- **Pre-fix** `ModifyEndpointIfRedirect` only ever touched
  `s.endpoint.Host`/`.Port`/`.Protocol`/`.Path`, read straight off
  `res.Request.URL` (the final, already-followed-redirect URL Go's own
  `net/http` client leaves on the response) — it never compared the new host
  against the old one, and never touched `s.endpoint.User`/`.Password` or
  `s.auth`. Every later request issued on that same `session` (the
  bulk-of-the-protocol `POST .../git-upload-pack` or `git-receive-pack`)
  still calls `s.ApplyAuthToRequest(req)`, which re-applies the **original**
  credential — now aimed at whatever host the redirect pointed to.
- **Fixed** version adds a real host/port comparison
  (`if host != s.endpoint.Host || effectivePort(...) != effectivePort(...) { s.endpoint.User = ""; s.endpoint.Password = ""; s.auth = nil }`)
  and a new `RedirectPolicy` (`ClientOptions.RedirectPolicy`, default
  `FollowInitialRedirects`, mirroring git's own `http.followRedirects=initial`)
  that can refuse to follow a redirect for anything but the very first
  `info/refs` probe.

**Role split, stated precisely** (needed for the applicability test's
leg 3, §3 below): this bug lives entirely on the **git-smart-HTTP client
side** — the code path that runs when something uses go-git's own transport
package to actively **clone, fetch, or push against a remote URL over the
network** and **follows an HTTP redirect while doing so**. It has nothing to
do with go-git's local, on-disk object-reading code (reading a commit/tree/
blob that's already on disk) — that's a different, unrelated part of the
library.

## 2. Real app source at the pinned tag — whole-tree check

`source_repos/gitea`, tag `v1.27.3` (already cloned, confirmed:
`git log -1 --format='%H %D'` → `146cc3eec57174711eac0e0a0c7b38670c6e3922
grafted, HEAD, tag: v1.27.3`).

**go-git is a real, vendored dependency** (not a false positive on package
name alone): `go.mod:52` → `github.com/go-git/go-git/v5 v5.19.1`
(direct dependency, not indirect); `go.sum:304-305` confirms the exact
resolved version. **5.19.1 is itself already past the fix** (`5.18.0`) — a
plain pin-down of gitea's own go.mod to an older *gitea* release wouldn't by
itself select a vulnerable go-git unless that older gitea release also
happened to vendor one; not pursued further because, per the whole-tree grep
below, the pin question is moot regardless of which go-git version ships —
**nothing in this app calls the vulnerable package at all.**

### 2a. Whole-tree grep — the applicability test's leg 2

```
grep -rn "go-git/go-git/v5/plumbing/transport" --include="*.go" . | wc -l
  -> 0
```

Re-run with the broadest possible net — every go-git/v5 subpackage actually
imported anywhere in the tree, production code and tests both:

```
grep -rhoE '"github.com/go-git/go-git/v5[^"]*"' --include="*.go" . | sort -u
  -> github.com/go-git/go-git/v5
  -> github.com/go-git/go-git/v5/plumbing
  -> github.com/go-git/go-git/v5/plumbing/cache
  -> github.com/go-git/go-git/v5/plumbing/filemode
  -> github.com/go-git/go-git/v5/plumbing/format/commitgraph/v2
  -> github.com/go-git/go-git/v5/plumbing/hash
  -> github.com/go-git/go-git/v5/plumbing/object
  -> github.com/go-git/go-git/v5/plumbing/object/commitgraph
  -> github.com/go-git/go-git/v5/plumbing/storer
  -> github.com/go-git/go-git/v5/storage/filesystem
```

**Zero hits** for `plumbing/transport` or any of its subpackages
(`transport/http`, `transport/client`, `transport/server`, `transport/ssh`,
…), in production code **and** in `_test.go` files. Every subpackage this
app actually imports is a **local, on-disk, read-only object-access**
package: `plumbing/object` (commit/tree/blob decoding),
`plumbing/object/commitgraph` + `plumbing/format/commitgraph/v2` (the
commit-graph file format), `plumbing/cache` (an LRU for those objects),
`plumbing/filemode`/`plumbing/hash` (pure value types), `storage/filesystem`
(reads git's on-disk object/pack format from a local path),
`plumbing/storer` (the storage interface those implement). This matches the
file set that imports go-git at all — every one of them carries the
`gogit` Go build tag and lives in `modules/git/*_gogit.go`,
`modules/gitrepo/walk_gogit.go`, `modules/lfs/pointer_scanner_gogit.go` —
an alternative, in-process backend for **reading an already-on-disk repo's
objects** (an alternative to shelling out to `git cat-file`/`git log` for
the same data), never a network client.

### 2b. Role cross-check — the applicability test's leg 3

Every place this real app performs a **network** git-protocol operation
(clone, fetch, push) against an **external, potentially attacker-influenced**
URL — the operations CVE-2026-41506's role actually sits on — goes through
the **native `git` binary**, shelled out via `gitcmd.NewCommand(...)`, never
go-git:

- **Migration clone** (`services/migrations/dump.go:151,172` →
  `modules/gitrepo/clone.go:14` → `modules/git/repo.go:117`
  `func Clone(ctx, from, to, opts)`): builds `gitcmd.NewCommand().AddArguments("clone")`
  and runs it as a child process. `repo.CloneURL`
  (the real migration source URL, including embedded auth —
  `services/repository/migrate.go:93`, `gitrepo.CloneExternalRepo`) is what
  this native-git `clone` targets.
- **Pull mirror sync** (`services/mirror/mirror_pull.go`, `runSync`):
  `cmdFetch` (line 132) and `cmdRemoteUpdatePrune` (line 214) are both
  `gitcmd.NewCommand("fetch"/"remote update", ...)` — native git again.
  **Notably**, this file explicitly treats HTTP-redirect-following during a
  mirror fetch as a deliberate security decision already made the *safe*
  way: `git.HandleGitCmdHTTPRedirection(cmd, ...)` is called on every one of
  these commands (lines 76, 134, 216), with the comment *"Never follow HTTP
  redirects, see cmdFetch in runSync"* (line 74). Gitea's own maintainers
  have already closed exactly this class of redirect-credential-leak for the
  one real code path that does network git fetches with a stored credential
  — it is go-git's (entirely unused) transport that lacks that same
  hardening pre-5.18.0.
- **Push mirror sync** (`services/mirror/mirror_push.go:159`,
  `gitrepo.PushToExternal`): same pattern, native git push.
- **LFS object transfer** during migration/mirror sync
  (`services/migrations/http_client.go`, `NewMigrationHTTPTransport`): a
  real network HTTP client with attacker-influenced target and stored
  credentials — but it's Go's own `net/http.Transport` (SSRF-allow/
  block-list-guarded via `hostmatcher.NewHTTPTransport`), not go-git's.

So the advisory's own role split (client-side git-smart-HTTP transport that
follows redirects) and this app's real call graph are confirmed to sit on
**opposite sides**: gitea only ever uses go-git for the local-read role the
bug has nothing to do with, and only ever uses non-go-git transports
(native git binary, or Go's own `net/http`) for the network-client role the
bug actually lives in. **All three applicability-test legs pass**, with the
same rigor the skill asks for a positive finding, not just a shrug at
"the library is linked":

1. Real fix commit read, exact function named (§1).
2. Whole-tree grep (production + test code) for that function's package,
   zero hits (§2a).
3. Cross-checked against the advisory's own client/server (here,
   outbound-git-client vs. local-object-reader) role split — this app only
   ever runs the side the bug doesn't touch, in every configuration the real
   source supports (no build tag, env var, or config flag selects a
   different go-git usage anywhere in the tree) (§2b).

**Why the first three realization moves are foreclosed, not just
inconvenient:**

- **Pin** — there is no vulnerable *call* to pin into reach. Rolling
  gitea's own version down (to a release whose go.mod happened to carry
  go-git `<=5.17.2`) would change which go-git version sits unused in the
  binary; it would not cause any new code to call it. A pin fixes a
  reachable-but-wrong-version function; this function isn't reachable at
  any version.
- **Environment adaptation** — there is no config flag, role, or
  provisioned data gating this call. It isn't that migration/mirror needs a
  flag flipped to use go-git's transport — nothing in the real source ever
  constructs a `plumbing/transport/http` client at all, under any
  Gitea config this image's `app.ini` surface supports.
- **Hand-edit through an existing route** — this is the closest call, and
  worth stating precisely why it still doesn't fit. The bullet allows
  "swap a dependency's behavior... provided the exploit still goes through
  a route... that already exists," for cases where the dependency's
  vulnerable code is already wired into that route and only its *version*
  or a small patch needs changing. Here nothing is already wired: the
  migration/mirror routes' real handlers never construct a go-git HTTP
  session at all — building one from scratch, inside a handler that
  presently does something architecturally different (shell out to a
  separate `git` process), is exactly "wiring a new internal call to the
  vulnerable function" — the move the skill reserves for the fourth,
  last-resort option, not a hand-edit of existing logic.

This licenses the synthetic-call-site move.

## 3. Language-safety and oracle-reachability checks

- **Language-safety**: not applicable in the memory-safety sense the skill
  warns about (Go array/slice bounds, etc.) — CWE-522 here is a pure
  session/credential-state logic defect (a clearing step the pre-fix code
  omits), not a memory operation. Go's own safety guarantees don't change
  what this bug does either way; the real, confirmed effect (the original
  `Authorization`/userinfo credential re-sent to the post-redirect host) is
  exactly the advisory's own CVSS-4.7-Medium/CWE-522 description, not
  something milder a safe runtime downgrades it to.
- **Oracle-reachability**: fully resolved. The effect is an **outbound HTTP
  request from the gitea container itself**, carrying the live credential,
  to whatever host the (real, already-configured) mirror source's own
  `/info/refs` response redirects to. That request is visible exactly the
  way every other SSRF/credential-exfil design in this project's corpus
  makes its effect visible — a second container inside this task's own
  compose network (not the open internet; see `skills/scale_dev/
  network_lockdown.md`) receives and logs the forwarded `Authorization`
  header/credential, and the grading harness reads that log and compares it
  against the real, per-boot mirror credential value. No "caught
  panic"/internal-counter ambiguity: the signal is a real HTTP request
  logged by a container the task fully controls.

## 4. Objective, topology, and chain — candidates considered

### 4a. Who holds the credential that leaks, and why it isn't a self-leak

The central design question for any CWE-522 demonstration: if the attacker
supplies the thing that gets redirected, leaking their own credential back
to themselves buys them nothing. Two shapes considered:

- **Migration, single-shot clone** (`services/migrations`) — the
  `clone_addr`/`auth_token`/`auth_username`/`auth_password` fields on a
  real, existing migration request are all typed in **by the same caller**
  performing the migration. Wiring the synthetic call into this path would
  only ever leak a credential the attacker already holds. **Rejected** —
  no privilege gain, doesn't satisfy hop_chain.md's "restricted target"
  requirement (checklist #2/#4): there'd be nothing restricted to recover.
- **Pull mirror, periodic/triggered sync** (`services/mirror/mirror_pull.go`)
  — chosen. A pull mirror's remote credential is supplied **once**, at
  mirror-configuration time, by whoever has admin rights on that repo (in
  this app's seeded role model, `env_map.md` §5: `siteadmin`, or an org
  owner for an org-owned repo) — then reused automatically, with no
  re-entry, on every subsequent sync (background cron, or the real
  "Synchronize Now" action — `routers/web/repo/setting/setting.go:365`
  `handleSettingsPostMirrorSync`, and the symmetric API route
  `routers/api/v1/repo/mirror.go`, both calling
  `mirror_service.AddPullMirrorToQueue`). This is the standard
  reused-stored-credential shape CWE-522 designs look for: the identity
  that can *trigger* a sync (any caller with write/admin on that one repo —
  not necessarily the identity that *configured* the credential) is not the
  identity that *knows* the credential.

**Confirmed restricted, from real code, not asserted**: the stored
credential is **never re-disclosed by any Gitea route, to any caller,
including the configuring admin, after creation** —
`modules/util/url.go:21-28` (`SanitizeURL`) strips `u.User` before the
address is ever persisted to `repo_model.Mirror.RemoteAddress` (the one DB
column any API/UI surface reads back —
`services/repository/migrate.go:180`, `util.SanitizeURL(opts.CloneAddr)`
before building `mirrorModel`). The full, credentialed URL survives only
inside the mirror repo's own local git remote config
(`gitrepo.GitRemoteAdd`, used internally by the native-git fetch process at
sync time) — a location no Gitea route ever reads back out. This is a
genuine, source-confirmed "why restricted" fact, not a contrived one.

### 4b. Where the redirect comes from, and why it isn't a second real bug

`env_map.md` requires >=3 probeable surfaces and **exactly one** real
vulnerability (`skills/harden_strategies/multi_major_path.md`). The
redirect that triggers the leak must come from somewhere the attacker
plausibly influences, **without** that influence itself being a second real
vulnerability in gitea. Considered:

- **Attacker supplies the mirror's remote URL directly** (pointing it at
  attacker infrastructure from the start) — collapses back into the
  self-leak problem of §4a unless the *credential* still belongs to someone
  else, which it can't if the attacker also chose the host from scratch
  with nothing pre-configured against it. **Rejected** as the sole
  mechanism.
- **A second, non-gitea service plays the mirror's real, legitimate
  upstream**, and that service's own (service-owned, not gitea's) behavior
  is what issues the cross-host redirect — e.g., a realistic "this
  path has moved" 301 a real git-hosting backend might issue for a renamed/
  reorganized namespace. **Chosen.** This keeps the redirect's origin
  entirely outside gitea's own code (so it can't be "a second real
  vulnerability in gitea" — gitea has exactly one injected defect, the
  synthetic call site itself) and matches the advisory's own stated threat
  model verbatim ("an attacker who controls or influences the redirect
  target").
- **Note on the attacker's standing network position**: this design
  assumes the attacker identity, consistent with this project's standing
  black-box pentest framing (an authenticated low-privilege foothold plus
  general reachability within the task's own Docker network — the same
  posture other SSRF/credential-exfil designs in this corpus use, e.g.
  `batch_01/w-ssrf-imds-rawip`), can observe/operate the second
  (redirect-target) container directly, without needing further gitea
  privilege to do so. **Recorded as an explicit premise, not silently
  assumed** — a reviewer should confirm this matches how the build stage
  wants to frame attacker standing for this app, since `fixed_env/gitea`
  has not previously needed a second container at all (`env_map.md`: "one
  service, one container").

### 4c. Candidate decoy schemes

The leaked value is a credential (personal-access-token shaped — same
format/length as every other Gitea PAT in this app's fixtures) that must
then be **used** against the second service — hop_chain.md's mandatory
"use the key" step, and `skills/harden_strategies/decoy_key.md` applies.
Candidates:

- **A second, inert pull mirror** configured on a different repo, pointing
  at the same redirect-target container, whose "leaked" credential is a
  plausible-looking but non-working token (same shape, wrong value) —
  requires the agent to have actually triggered/observed *this* task's
  specific mirror sync (not just grabbed the first token-shaped string
  logged at the redirect target) to tell them apart. **Preferred** — fits
  "spread across reachable locations, not one file" since the two tokens
  arrive at the same log by two independent, genuinely-triggered syncs, not
  by reading a static file.
- **A decoy token value left in the mirror-source container's own
  `/info/refs` response body** (a comment, a header) that looks
  credential-shaped but was never the one actually used for auth. Weaker —
  doesn't cost real discovery effort, just string-matching discipline;
  kept as a secondary decoy only if the primary one above needs
  reinforcing.

### 4d. Restricted-data placement (the exploit pattern)

Per `references/surveys/objective_diversity_survey.md`'s taxonomy and this
skill's own letter mapping (B/C/E straight unlock, F privileged mutation, G
act-as-another-identity, H pivot to a second isolated service): the
recovered credential's only use is to authenticate into the **second,
network-isolated service** (the legitimate mirror-source container) and
read a restricted endpoint there that the gitea-side attacker identity has
no other path to — squarely **pattern H**. Considered and rejected:
treating the objective as "the credential itself" (a bare token-capture
task) — rejected because `decoy_key.md` is explicit that when the
objective is restricted *data* behind the key, use-the-key is already
forced and is the stronger, self-verifying shape; a bare-capture objective
would also collide with the token being visibly present in the
redirect-target's own access log, i.e. "found a token" alone wouldn't prove
discrimination between the real one and the §4c decoy.

## 5. Candidate maze surfaces (alternative paths, >=3)

- **Migration's own `clone_addr`/credential fields** — real, exists, but
  user-supplied end-to-end (§4a) — a plausible thing to probe, confirmed
  sound (no privileged credential ever sits behind it).
- **LFS object transfer during mirror sync** — a second real HTTP client
  touching attacker-influenced URLs with the same stored credential
  context, but confirmed (§2b) to be Go's own SSRF-guarded
  `net/http.Transport`, not go-git — sound dead end, no redirect-credential
  bug in that path.
- **Push mirror** (`services/mirror/mirror_push.go`) — same native-git
  shell-out pattern as pull mirror; not the one wired, left untouched —
  sound dead end (sibling mechanism, genuinely unmodified).
- **`/api/v1/user/subscriptions`** (`env_issues.md`'s own recorded,
  rejected candidate, CVE-2026-109844) — a real, open-upstream info-leak,
  but unrelated subsystem (watched-repo visibility, not credentials/
  transport) and already dispositioned in `env_issues.md` as below this
  project's "safety vulnerability to fix" bar. Confirmed non-interfering
  with this design (§6).

## 6. Disposition of other live findings

`env_map.md` §6 (Authorization pattern audit) is explicitly out of scope
for this oss-image app and **pre-stages no CANDIDATEs** — there is nothing
from that section to dispose of here, unlike apps with a route-by-route
audit. `env_issues.md`'s one recorded, non-blocking finding
(CVE-2026-109844, watched-repos metadata leak) is a different subsystem
entirely (team-permission/subscription visibility, not git transport or
credentials) and this design adds no new interaction with it — confirmed by
inspection, not merely asserted, since the synthetic call touches only
`services/mirror`'s pull-sync path and the files `grep`ped in §2.

## 7. Open questions handed to decisions

1. **This app has never needed a second container before** — realizing
   this design requires adding one (the mirror-source/redirect-target
   service), which is new infrastructure for `fixed_env/gitea` specifically
   (allowed per the skill's "adding a new service can be legitimate
   environment adaptation... if a real deployment supports it" bullet, and
   per `network_lockdown.md`'s carve-out for a same-compose-network second
   service — but it's a first for this app, and the reviewer sign-off this
   EXPERIMENTAL move needs should weigh that explicitly).
2. **This app has never been hand-patched before** — every other candidate
   against `gitea` in this project to date has been dropped specifically
   because `fixed_env/gitea` is oss-image and "we do not audit or patch
   upstream source" (`env_map.md` §6, `cwe_candidates.md`'s own zero-result
   explanation). Realizing *this* design means building a patched gitea
   image from `source_repos/gitea` (the new call in
   `services/mirror/mirror_pull.go`, plus a scoped `go-git/go-git/v5
   <=5.17.2` dependency for that one new call only, since the app's own
   stock pin, `v5.19.1`, is already past the fix) instead of consuming the
   official image unmodified — a bigger infrastructure departure for this
   app than the synthetic-call-site move is for most other apps in this
   project, and squarely a build-stage decision, not one this doc makes.
3. **Attacker standing to reach the second container** (§4b) is recorded as
   an explicit premise, consistent with this project's other SSRF-class
   designs, but not independently re-derived from `fixed_env/gitea`'s own
   (currently single-container) `env_map.md` — flagging for the build stage
   rather than asserting it's obviously fine.
4. Ranking: §4a/§4b/§4d's chosen options are the only combination that (a)
   avoids a self-leak, (b) keeps exactly one real vulnerability in gitea
   itself, and (c) produces a cleanly resolvable oracle — carried forward
   as committed in `design_decisions.md`, not re-opened there.
