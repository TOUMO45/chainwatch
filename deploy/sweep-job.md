# The scheduled sweep — Cloud Run Job + Cloud Scheduler

Capability 21 is the path with no human in it: a schedule fires, a list of
repositories is walked end to end, and the record lands in Firestore for
someone to read afterwards. Locally that is one command:

```bash
python chainwatch.py sweep --repos deploy/sweep-targets.txt --json sweep.json
```

On Google Cloud it is a **Cloud Run Job** (not a service: a sweep is a batch
that ends, and a request-scoped service would be the wrong shape and the wrong
timeout) triggered by **Cloud Scheduler**.

Everything below is reproducible from a fresh clone. Nothing here runs
automatically — run it deliberately, against a project you own.

## 1. Build the image (the same Dockerfile the service uses)

```bash
gcloud builds submit --tag gcr.io/$PROJECT/chainwatch:sweep .
```

## 2. Create the job

`--command`/`--args` override the image's web entrypoint with the sweep CLI.
The job needs a longer timeout than a request ever would: it walks many
repositories, and installing one protocol's dependencies alone can take
minutes.

```bash
gcloud run jobs create chainwatch-sweep \
    --image gcr.io/$PROJECT/chainwatch:sweep \
    --region us-central1 \
    --cpu 2 --memory 4Gi \
    --task-timeout 3600s \
    --max-retries 1 \
    --set-secrets=GEMINI_API_KEY=chainwatch-gemini-key:latest \
    --command python \
    --args chainwatch.py,sweep,--repos,deploy/sweep-targets.txt,--quiet
```

Add `--sweep-agent` to the `--args` list to run the ADK agent layer per
repository as well. It costs model requests per finding, so it is off by
default: an unattended job that silently burns a quota is a bad neighbour.

## 3. Schedule it

```bash
gcloud scheduler jobs create http chainwatch-sweep-daily \
    --location us-central1 \
    --schedule "0 3 * * *" \
    --time-zone "UTC" \
    --uri "https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/$PROJECT/jobs/chainwatch-sweep:run" \
    --http-method POST \
    --oauth-service-account-email $SWEEP_SA
```

`$SWEEP_SA` needs `roles/run.invoker` on the job and `roles/datastore.user` on
Firestore. It needs nothing else — the sweep is read-only on every repository
and on chain, and the only thing it writes is its own record.

## 4. Confirm it ran

```bash
gcloud run jobs executions list --job chainwatch-sweep --region us-central1
```

and in the app: the **Sweeps** panel (`GET /api/sweeps`) lists each run with
its per-repository outcome.

---

## Why a failing repository must not fail the job

`--max-retries 1` is deliberately low, because a retry is the wrong answer to
the failure this job actually sees. A repository that will not clone, will not
install, or trips a rule error fails the same way on the retry — and meanwhile
the other nineteen have already been walked successfully.

So `src/sweep.py` never lets a target's failure escape: it is recorded with its
reason and the sweep continues, and the job exits 0 having done the work it
could. `totals.failed` in the record is how a reader learns what did not
happen. **A sweep that exited non-zero because three of twenty repos were
unreachable is a job that gets muted within a week, and a muted job is a job
that is not running at all.**
