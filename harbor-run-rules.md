# Harbor task rules: verifier output and CPU limits

These rules come from a pass@k run where every trial failed even though the
task's oracle and noop checks passed locally. Follow them when you write or
review a Harbor task.

## Rule 1: The verifier must always write a reward file

Harbor fails a trial with `RewardFileNotFoundError` if the verifier exits
without writing `/logs/verifier/reward.txt` or `/logs/verifier/reward.json`.
It doesn't record a 0; the trial is lost as an infra error.

- Write a default `0` reward at the very start of `tests/test.sh`, then
  overwrite it with the real result.
- Any check that can `exit` before that first write is a risk. Keep those
  checks to a minimum, and make each one fail loudly in the logs.
- Before you finish a task, test the verifier under real Harbor mount
  conditions (Rule 2), not only through the local oracle/noop scripts.

## Rule 2: Don't rely on how /logs/verifier is laid out in the image

At runtime, Harbor bind-mounts a host folder over `/logs/verifier` (and
`/logs/agent`). Anything the Dockerfile puts at those paths is hidden:
ownership, mode, subfolders and seed files are all gone.

Inside the container, the mounted folder typically:

- is owned by the host user's uid, not `root` or `agent`;
- is world-writable (`drwxrwxrwx`);
- is empty, so a subfolder such as `.results` won't exist.

What this means for your verifier:

- **Don't** require exact owner/mode on `/logs/verifier` (for example
  `root:agent 1770`) and exit when it doesn't match. That exact check is
  what caused the failure above.
- **Don't** keep private verifier files inside `/logs/verifier`. Use a
  root-only folder outside every agent-writable path, for example
  `mkdir -m 0700 /var/lib/task-verifier`, and confirm it is
  `root:root 700` and not a symlink.
- **Do** reject `/logs/verifier` if it is a symlink or missing.
- **Do** run `chmod +t /logs/verifier` (sticky bit) so non-root processes
  can't replace the reward files once root writes them. Write each file to a
  temp path in the private folder, then `mv -fT` it into place.
- **Don't** tighten `/logs/verifier` with `chmod 700` or a `chown` to a
  container-only uid/gid. Harbor on the host has to read the reward through
  the mount, and reward files must stay world-readable (`0644`).

## Rule 3: Size `cpus` to the machines that will actually run the task

`[environment] cpus` in `task.toml` is passed to Docker as a hard limit.
If the host has fewer CPUs, the container is never created:

```
Error response from daemon: range of CPUs is from 0.01 to 1.00, as there are only 1 CPUs available
```

- Run pass@k on a host with at least `cpus` cores. Run `nproc` to check
  before you start.
- Harbor retries and starts new jobs on this error, but they all fail the
  same way. Look in `trajectories/pass@k/<job>/<trial>/exception.txt` for
  the real error; `run.log` only shows a generic "fresh-boot retry".
- Running many trials at once (`n_concurrent_trials`) on a small host is
  slow, even when it starts.

## Rule 4: Report rubric failures don't block the reward

The LLM-judge report rubric runs after the reward is written. If it fails
(for example because the `REPORT_JUDGE_*` env vars aren't set), the verifier
records `report_status: infra_error` and still exits 0 with the correct
reward. Set `SKIP_REPORT_RUBRIC=1` to mark it as skipped.

Before you blame the rubric for a failed run, find the trial's actual error
in its `exception.txt`.

## How to test the verifier under Harbor-style mounts

```bash
T=$(mktemp -d); mkdir -m 777 "$T/verifier"; chmod 777 "$T/verifier"
docker run --rm --network none --user root \
  -v "$T/verifier:/logs/verifier" \
  -v "$PWD/tests:/tests:ro" \
  <task-main-image> bash /tests/test.sh
ls -la "$T/verifier"   # reward.txt and reward.json must exist, mode 0644
```

Without the web services running, the reward should be `0`, but the files
must still exist. Also run the same command without the `/logs/verifier`
mount to confirm the original image layout still works.
