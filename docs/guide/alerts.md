# Alerts & Notifications

Argus SBOM Guard can notify you when new vulnerabilities are discovered.

## Supported Channels

| Channel | Configuration |
|---------|---------------|
| **Slack** | Set `SLACK_WEBHOOK_URL` in `.env` |
| **Discord** | Set `DISCORD_WEBHOOK_URL` in `.env` |
| **Email** | Configure SMTP settings in `.env` |

## Creating an Alert Rule

**UI**: Settings → Alert Configurations → New Alert Rule

**API**:

```bash
curl -X POST http://localhost:8000/api/v1/alert-rules \
  -H "Authorization: Bearer argus_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "00000000-0000-0000-0000-000000000001",
    "severity_threshold": "high",
    "notification_type": "slack",
    "enabled": true
  }'
```

| Field | Values | Description |
|-------|--------|-------------|
| `project_id` | UUID | Project to monitor |
| `severity_threshold` | `critical`, `high`, `medium`, `low` | Minimum severity to trigger |
| `notification_type` | `slack`, `email` | Delivery channel |
| `enabled` | `true`, `false` | Enable/disable the rule |

## How Alerts Work

The Celery beat scheduler runs `check_alerts` periodically.
For each enabled alert rule:

1. Queries open vulnerabilities at or above the severity threshold
2. Checks for new vulnerabilities since the last notification
3. Sends a notification via the configured channel

## Managing Alert Rules

```bash
# List all alert rules
curl http://localhost:8000/api/v1/alert-rules \
  -H "Authorization: Bearer argus_xxx"

# Update an alert rule
curl -X PATCH http://localhost:8000/api/v1/alert-rules/{id} \
  -H "Authorization: Bearer argus_xxx" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Delete an alert rule
curl -X DELETE http://localhost:8000/api/v1/alert-rules/{id} \
  -H "Authorization: Bearer argus_xxx"
```
