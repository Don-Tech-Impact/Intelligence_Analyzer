# SIEM Analyzer API Plan

This document outlines the strategy for moving to a Flask/FastAPI based management system and collaborating with frontend developers using Postman.

## Proposed API Structure

The API should handle tenant management, alert status updates, dashboard metrics, and report retrieval.

### Authentication
- **Mechanism**: JWT (JSON Web Tokens)
- **Roles**: `superadmin`, `business_admin`, `analyst`

### Endpoints (Proposed)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` | Authenticate and get JWT. |
| `GET` | `/api/dashboard/metrics` | High-level stats (Total Alerts, Severity Breakdown). |
| `GET` | `/api/alerts` | List/Filter alerts for the active tenant. |
| `PATCH` | `/api/alerts/{id}` | Update alert status (`acknowledged`, `resolved`). |
| `GET` | `/api/reports` | List generated reports. |
| `GET` | `/api/reports/{id}/download` | Download HTML/CSV report. |
| `POST` | `/api/ingest` | Manual log ingestion (for testing/integration). |

## Integration & Collaboration

### Postman Approach
1.  **Collection**: Create a Postman Collection with all endpoints documented.
2.  **Environments**: Set up `Local`, `Staging`, and `Production` environments in Postman.
3.  **Mock Server**: (Optional) Use Postman Mock Server so the frontend guy can start building before the API logic is 100% finished.
4.  **Documentation**: Use Postman's auto-generation for API docs.

### Next Steps for Flask Installation
Once this workflow is approved:
1.  Add `Flask`, `flask-jwt-extended`, and `flask-cors` to `requirements.txt`.
2.  Create `src/api/app.py` for the Flask application.
3.  Implement Blueprints for `auth`, `alerts`, and `reports`.
