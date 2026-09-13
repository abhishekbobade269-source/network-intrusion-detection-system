# models/

Trained model artifacts (`.joblib`) and their `.metrics.json` sidecars land
here from `nids train` (`nids.ml.train`). Not committed — see
`.gitignore` — since they're generated, environment/dataset-specific
binary blobs, not source.

Generate one before running the API/CLI with `NIDS_ML_ENABLED=true`
(the default):

```bash
nids train --dataset synthetic --out models/anomaly_model.joblib
```

See `docs/model_card.md` for what "synthetic" does and doesn't tell you,
and how to retrain on CICIDS2017 or your own traffic instead.
