# Public corpus: unique regexes from PyPI modules

* **What:** `pypi-uniquePatterns.jsonl` (63,352 lines, one `{"pattern": "..."}` JSON object per
  line, the pattern JSON-encoded). Unmodified copy of `data/uniquePatterns.tgz` ->
  `pypi-uniquePatterns.json` from the artifact below. The matching npm file (349,852 patterns) is
  not used: CERTEX's target engine is CPython.
* **Paper:** J. C. Davis, C. A. Coghlan, F. Servant, D. Lee, "The Impact of Regular Expression
  Denial of Service (ReDoS) in Practice: an Empirical Study at the Ecosystem Scale", ESEC/FSE
  2018.
* **Artifact:** "Artifact (software + dataset) for ...", file
  `FSE18Artifact-DavisCoghlanServantLee.zip` (15.5 MB), Zenodo record
  <https://zenodo.org/records/1294301>, DOI 10.5281/zenodo.1294301.
* **Archive SHA-256:** `d90fee8a9fc5b8c74e53b3f22cce3777831dcb0bfe1fc77a346e7c474e67f3d7`
  (downloaded 2026-10-06 from the Zenodo file link above).
* **Licence:** Creative Commons Attribution 4.0 International (CC-BY-4.0) per the Zenodo
  record; the artifact's software carries an MIT licence (c) 2018 Davis, Coghlan, Servant, Lee.
* **Notes:** patterns are distributed without module attribution. Only patterns inside the v1
  syntax subset are analysed by CERTEX; the rest are counted and reported separately (never as
  passes).
