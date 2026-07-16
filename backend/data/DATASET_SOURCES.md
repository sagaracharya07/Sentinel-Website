# Training Data Sources

`combined_dataset.csv` is built by `ml/prepare_data.py` from four public,
long-standing email corpora, following the compilation approach described in:

> Champa, A.I., Rony, M.F., & Islam, M.S. (2024). *Curated datasets and
> feature analysis for phishing email detection with machine learning.*

The four source corpora combined:

1. **CEAS 2008** — mixed phishing/legitimate email corpus from the 2008
   Conference on Email and Anti-Spam shared task.
2. **Apache SpamAssassin public corpus** — real spam and ham (legitimate)
   email, long used as a spam/phishing-detection benchmark.
3. **Nazario phishing corpus** — Jose Nazario's widely cited, phishing-only
   email feed.
4. **Nigerian Fraud ("419") corpus** — advance-fee fraud emails, a distinct
   and well-known phishing sub-genre.
5. **Enron email corpus** (subset) — used here specifically for its large
   volume of short, casual, internal *legitimate* business correspondence,
   which the phishing-focused corpora above under-represent. Without it,
   the model over-fires on short, informal legitimate emails (verified
   empirically during development — see the "Known limitations" section
   of the top-level README for how this was caught and fixed).

## Reproducing the combined dataset

```bash
cd backend
python3 -m ml.prepare_data     # writes data/combined_dataset.csv
python3 -m ml.train            # trains + evaluates the model
```

## Citing this in your report

If your unit requires a formal reference list, cite the Champa, Rony &
Islam (2024) paper above for the dataset compilation methodology, plus
the individual corpora (SpamAssassin, Nazario, Nigerian Fraud, CEAS,
Enron) as primary sources, consistent with how the Verizon DBIR, IBM, and
APWG reports are already cited elsewhere in the project proposal.
