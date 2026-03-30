# Contributing to NIS2 Compass

## Development Setup

### Requirements

- Python 3.11+
- Node.js 20+ (for the web dashboard)
- Docker + Docker Compose
- PostgreSQL 15+ (or use the provided Docker Compose stack)

### Local Setup

```bash
git clone https://github.com/opensecstack/nis2compass
cd nis2compass

# Start dependencies
docker compose -f docker-compose.dev.yml up -d postgres redis

# Install Python dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run database migrations
flask db upgrade

# Seed NIS2 control templates
python seeds/01_nis2_controls.py

# Start the API server
flask run --debug

# In a separate terminal — start the web UI
cd web && npm install && npm run dev
```

The API runs at `http://localhost:5000`. The web UI runs at `http://localhost:5173`.

## Code Style

### Python

- Formatter: `black` (line length 100)
- Linter: `ruff`
- Type hints: required on all public functions

```bash
black .
ruff check .
```

### TypeScript (web)

- Linter: `eslint` with the provided `.eslintrc.cjs`
- Formatter: `prettier`

```bash
cd web && npm run lint
```

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=app --cov-report=term-missing

# Specific test file
pytest tests/test_assessments.py -v
```

Tests use a dedicated test database. The `conftest.py` creates and tears down the database per test session. Do not run tests against a production database.

## Submitting Pull Requests

### Branch Naming

```
feat/short-description
fix/short-description
docs/short-description
refactor/short-description
```

### Commit Messages

Use Conventional Commits format:

```
feat(assessments): add bulk status update endpoint
fix(auth): handle expired API keys gracefully
docs(api-reference): document new artifact endpoints
```

### PR Requirements

- All tests pass
- New code has test coverage
- `black` and `ruff` pass with no errors
- No new security vulnerabilities (checked by CI Trivy scan)
- One approval from a maintainer

## Proposing New Features

For significant changes, open an issue first to discuss the approach. For architectural changes, submit an ADR (`adrs/` directory) with the PR.

## DCO Sign-Off

All commits must include a Developer Certificate of Origin sign-off:

```bash
git commit -s -m "feat: add new endpoint"
```

This adds `Signed-off-by: Your Name <your@email.com>` to the commit message, certifying that you have the right to submit the code under the Apache 2.0 licence.
