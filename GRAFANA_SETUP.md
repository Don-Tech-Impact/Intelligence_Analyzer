# Grafana Setup for SIEM Analyzer

This guide explains how to start the SIEM Analyzer with Grafana visualization enabled.

## Prerequisites

*   Docker and Docker Compose installed.

## Starting the Stack

1.  Make sure you are in the project root directory.
2.  Start the services:
    ```bash
    docker-compose up -d
    ```

This command will start:
*   **Redis**: For log ingestion queues.
*   **SIEM Analyzer**: The core application (using SQLite).
*   **Grafana**: Visualization platform with SQLite support pre-configured.

## Accessing Grafana

1.  Open your web browser and navigate to: http://localhost:3000
2.  Login with the default credentials:
    *   **Username**: `admin`
    *   **Password**: `admin` (You may be prompted to change it).
3.  Go to **Dashboards** -> **Browse**.
4.  You should see a pre-provisioned dashboard named **SIEM Dashboard**.
5.  Click on it to view real-time logs and alerts.

## Troubleshooting

*   **No Data?** Ensure the `siem-analyzer` service is running and processing logs. You can send test logs using:
    ```bash
    python3 scripts/generate_test_logs.py
    ```
    (Note: You might need to install dependencies locally or run this script inside the container).

*   **Database Locked?** SQLite handles concurrency reasonably well for this use case, but if you see errors, ensure no other process has the database file open exclusively.

*   **Plugin Not Found?** The Grafana container installs the `fr-ser-sqlite-datasource` plugin on startup. Check the logs if it fails:
    ```bash
    docker-compose logs grafana
    ```
