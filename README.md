# PackageGuard

Checks open-source dependencies before you install them. Hackathon project (OpenQuest, Domain 2).

## Quick start

1. Create and activate a virtual environment, then install the packages:
   - `python -m venv .venv`
   - Windows PowerShell: `.venv\Scripts\Activate.ps1`
   - macOS/Linux: `source .venv/bin/activate`
   - `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and paste your own keys. Never commit `.env`.
3. Test your keys: `python scripts/check_setup.py`
4. Run the app: `streamlit run app.py`

## Folder map

- `app.py`: Streamlit UI (Person 3)
- `checks.py`: registry, name-similarity and OSV checks (Person 1)
- `result_format.py`: the result format every part of the code uses
- `agent.py`: LLM agent and fix proposal (Person 2, step 3)
- `sbom.py`: CycloneDX SBOM export (Person 3, step 3)
- `demo/requirements.txt`: demo input for the live demo (Person 4)
- `scripts/check_setup.py`: tests your GitHub token and OSV.dev
