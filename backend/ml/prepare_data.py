"""
Builds data/combined_dataset.csv from the four source corpora:
  - CEAS_08.csv        (mixed phishing/legit, large, clean, balanced)
  - SpamAssasin.csv    (mixed phishing/legit, real Apache SpamAssassin corpus)
  - Nazario.csv        (phishing-only corpus, Jose Nazario's well-known feed)
  - Nigerian_Fraud.csv (phishing-only, "419" advance-fee fraud corpus)

Source: Champa, A.I., Rony, M.F., & Islam, M.S. (2024), "Curated datasets
for phishing email detection with machine learning", a compilation of
several long-standing public corpora (Apache SpamAssassin, Nazario,
Nigerian Fraud, CEAS 2008). Using a named, citable dataset -- rather than
synthetic examples -- is what lets the platform's precision/recall figures
be reported honestly in the project documentation.

Run: python3 -m ml.prepare_data   (from the backend/ directory)
"""

import pandas as pd
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "data")


def load_and_clean(path, cap=None):
    df = pd.read_csv(path, on_bad_lines="skip", engine="python")
    cols = {c: c.strip() for c in df.columns}
    df = df.rename(columns=cols)
    for needed in ["subject", "body", "label"]:
        if needed not in df.columns:
            df[needed] = ""
    if "sender" not in df.columns:
        df["sender"] = ""
    df = df[["sender", "subject", "body", "label"]].copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label", "body"])
    df["label"] = df["label"].astype(int)
    df["subject"] = df["subject"].fillna("").astype(str)
    df["body"] = df["body"].astype(str)
    df["sender"] = df["sender"].fillna("").astype(str)
    df = df[df["body"].str.strip().str.len() > 0]
    df = df.drop_duplicates(subset=["subject", "body"])
    if cap:
        df = df.sample(n=min(cap, len(df)), random_state=42)
    return df


def main():
    ceas = load_and_clean(os.path.join(DATA_DIR, "CEAS_08.csv"))
    spamassassin = load_and_clean(os.path.join(DATA_DIR, "SpamAssasin.csv"))
    nazario = load_and_clean(os.path.join(DATA_DIR, "Nazario.csv"))
    nigerian = load_and_clean(os.path.join(DATA_DIR, "Nigerian_Fraud.csv"))
    enron = load_and_clean(os.path.join(DATA_DIR, "Enron.csv"))

    print("CEAS_08       :", ceas.shape, dict(ceas.label.value_counts()))
    print(
        "SpamAssassin  :", spamassassin.shape, dict(spamassassin.label.value_counts())
    )
    print("Nazario       :", nazario.shape, dict(nazario.label.value_counts()))
    print("Nigerian_Fraud:", nigerian.shape, dict(nigerian.label.value_counts()))
    print("Enron         :", enron.shape, dict(enron.label.value_counts()))

    # Cap CEAS so it doesn't dominate the corpus; keep all of the smaller,
    # phishing-only sets for variety of attack styles. Enron contributes
    # short, casual, internal-business-style *legitimate* mail, which the
    # phishing-focused corpora under-represent -- important so the model
    # doesn't over-fire on short, low-formality legitimate emails.
    ceas_capped = ceas.sample(n=min(16000, len(ceas)), random_state=42)
    nigerian_capped = nigerian.sample(n=min(3500, len(nigerian)), random_state=42)
    enron_legit = enron[enron["label"] == 0].sample(
        n=min(9000, (enron["label"] == 0).sum()), random_state=42
    )
    enron_phish = enron[enron["label"] == 1].sample(
        n=min(2000, (enron["label"] == 1).sum()), random_state=42
    )

    combined = pd.concat(
        [ceas_capped, spamassassin, nazario, nigerian_capped, enron_legit, enron_phish],
        ignore_index=True,
    )
    combined = combined.drop_duplicates(subset=["subject", "body"])
    combined = combined.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_path = os.path.join(DATA_DIR, "combined_dataset.csv")
    combined.to_csv(out_path, index=False)
    print("\nCombined dataset:", combined.shape)
    print(combined["label"].value_counts())
    print("Saved to", out_path)


if __name__ == "__main__":
    main()
