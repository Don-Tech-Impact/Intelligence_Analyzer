# QA Check Script for Intelligence Analyzer

Write-Host "--- Running Flake8 (Linting) ---" -ForegroundColor Cyan
flake8 src

Write-Host "--- Running Black (Formatting) ---" -ForegroundColor Cyan
black --check src

Write-Host "--- Running isort (Imports) ---" -ForegroundColor Cyan
isort --check-only src

Write-Host "--- Running Mypy (Type Checking) ---" -ForegroundColor Cyan
# mypy src  # Optional: Uncomment if types are fully implemented

Write-Host "--- Running Tests ---" -ForegroundColor Cyan
$env:PYTHONPATH = "."
pytest --cov=src --cov-report=term-missing
