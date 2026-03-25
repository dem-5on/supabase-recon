# supabase-recon

Passive Supabase recon tool for authorized bug bounty research.

Detects Supabase credentials and configuration **leaked in HTML/JS assets** only.
Does **not** interact with any database or API endpoint.

---

## Install

```bash
# From source
git clone https://github.com/yourname/supabase-recon
cd supabase-recon
pip install .

# Editable (dev mode)
pip install -e .
```

Once installed the `supabase-recon` command is available globally.

---

## Usage

```
supabase-recon [OPTIONS]

Options:
  -t, --target   URL    Single target URL
  -f, --file     FILE   File with one URL per line (# = comment)
  -o, --output   FILE   Save JSON report
  -c, --concurrency INT Max concurrent requests (default: 10, max: 50)
      --timeout   INT   Per-request timeout in seconds (default: 15)
      --max-js    INT   Max JS files crawled per target (default: 30)
  -v, --verbose         Print results as they complete
      --version         Show version
```

### Examples

```bash
# Single target
supabase-recon --target https://example.com

# Batch scan with report
supabase-recon --file targets.txt --output report.json

# Fast, verbose batch scan
supabase-recon --file targets.txt --concurrency 20 --verbose
```

### targets.txt format

```
# Bug bounty scope
https://app.example.com
https://dashboard.acme.io
# https://skip-this-one.com
```

---

## What it detects

| Finding         | Severity | Description                                      |
|-----------------|----------|--------------------------------------------------|
| `jwt_key`       | HIGH     | Exposed anon/service-role JWT in HTML or JS      |
| `inline_config` | MEDIUM   | `supabaseUrl=` / `SUPABASE_ANON_KEY=` leaks      |
| `header`        | LOW      | PostgREST/Supabase server response headers       |
| `supabase_url`  | INFO     | `.supabase.co` project URL referenced            |
| `create_client` | INFO     | Supabase JS SDK `createClient()` call detected   |

---

## Output

Terminal output uses `rich` for colour-coded severity.  
`--output report.json` saves structured JSON:

```json
{
  "generated_at": "...",
  "total_targets": 5,
  "supabase_detected": 2,
  "results": [...]
}
```

---

## Legal

For use **only** on targets you are authorized to test.
