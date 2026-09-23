-- One row per CVE ID from the CVE Program (cvelistV5): the authoritative record.
CREATE TABLE cve (
  id TEXT PRIMARY KEY,
  state TEXT,              -- PUBLISHED | REJECTED
  assigner TEXT,           -- CNA short name
  date_reserved TEXT,
  date_published TEXT,
  date_updated TEXT,
  title TEXT,
  description TEXT
);
-- NVD view of the same CVE (enrichment status and dates).
CREATE TABLE nvd (
  cve_id TEXT PRIMARY KEY,
  status TEXT,             -- Analyzed | Awaiting Analysis | Deferred | Rejected | ...
  published TEXT,
  last_modified TEXT,
  description TEXT
);
-- Affected products as declared by the CNA or an ADP (e.g. CISA-ADP).
CREATE TABLE affected (
  cve_id TEXT, provider TEXT, vendor TEXT, product TEXT, platforms TEXT,
  default_status TEXT, versions TEXT, cpes TEXT
);
-- References from every provider; kind is derived from the URL at build time.
CREATE TABLE reference (
  cve_id TEXT, provider TEXT, url TEXT, kind TEXT, tags TEXT
);
CREATE TABLE weakness (
  cve_id TEXT, provider TEXT, cwe_id TEXT, description TEXT
);
CREATE TABLE metric (
  cve_id TEXT, provider TEXT, type TEXT, base_score REAL, severity TEXT, vector TEXT
);
-- NVD configuration CPE matches.
CREATE TABLE nvd_cpe (
  cve_id TEXT, vulnerable INTEGER, part TEXT, vendor TEXT, product TEXT, version TEXT,
  criteria TEXT, version_start_including TEXT, version_start_excluding TEXT,
  version_end_including TEXT, version_end_excluding TEXT
);
CREATE TABLE kev (
  cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT,
  due_date TEXT, known_ransomware TEXT, cwes TEXT
);
CREATE TABLE snapshot (key TEXT PRIMARY KEY, value TEXT);
-- GitHub Advisory Database (OSV format). reviewed = 1 for github-reviewed advisories.
CREATE TABLE ghsa (
  id TEXT PRIMARY KEY, reviewed INTEGER, published TEXT, modified TEXT, withdrawn TEXT,
  summary TEXT, details TEXT, severity TEXT, cvss_vector TEXT,
  github_reviewed_at TEXT, nvd_published_at TEXT, path TEXT
);
CREATE TABLE ghsa_alias (ghsa_id TEXT, alias TEXT);
-- One row per affected package; introduced/fixed/last_affected are the first such event.
CREATE TABLE ghsa_affected (
  ghsa_id TEXT, ecosystem TEXT, package TEXT, purl TEXT,
  introduced TEXT, fixed TEXT, last_affected TEXT, ranges TEXT, versions TEXT
);
CREATE TABLE ghsa_reference (ghsa_id TEXT, type TEXT, url TEXT, kind TEXT);
CREATE TABLE ghsa_cwe (ghsa_id TEXT, cwe_id TEXT);
