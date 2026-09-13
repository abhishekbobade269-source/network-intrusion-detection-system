# data/

Not committed (see `.gitignore`) — this holds locally-downloaded/generated
datasets and captures, which are either too large for git or carry their
own redistribution terms.

- `data/raw/` — put downloaded CICIDS2017 daily CSVs here (or wherever you
  point `nids train --cicids-csv`). Get them from
  <https://www.unb.ca/cic/datasets/ids-2017.html>.
- `data/interim/`, `data/processed/` — reserved for your own
  cleaning/feature-engineering scripts' intermediate output, if you extend
  `nids.ml.datasets` with a new source.

The synthetic dataset (`nids.ml.datasets.make_synthetic_dataset`, used by
`nids train --dataset synthetic` and the test suite) needs none of this —
it's generated in-memory on demand.
