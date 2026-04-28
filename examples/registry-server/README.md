# Example Registry Server

This is a simple example showing how to build a registry server for subs handle registration.

## Architecture

```
┌─────────┐     ┌──────────────────┐     ┌─────────┐
│  Users  │────>│  Registry Server │<────│  subsd  │
└─────────┘     └──────────────────┘     └─────────┘
                  (public)                 (private)
```

- **Users** submit handle registrations to the registry (public API)
- **subsd** pulls pending handles from the registry and stages them
- **subsd** calls webhook when handles are committed on-chain

This architecture keeps subsd private (it holds wallet keys) while the registry is the public-facing service.

## Usage

```bash
# Build
cargo build --release -p registry-server

# Run
registry-server --port 8080
```

Then configure subsd to use this registry:
1. Go to Settings in the subsd UI
2. Set Registry Endpoint to `http://localhost:8080`
3. Click Test to verify connectivity

## Endpoints

### Public (for users)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/register` | Register a new handle |
| GET | `/status/:handle` | Check registration status |

### Private (for subsd)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/pending` | Get pending handles to stage |
| POST | `/ack` | Acknowledge handles were staged |
| POST | `/webhook/committed` | Notify when handles are committed |

## Example Requests

### Register a handle (user)

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "handle": "alice@example",
    "script_pubkey": "5120..."
  }'
```

### Check status (user)

```bash
curl http://localhost:8080/status/alice@example
```

### Get pending handles (subsd)

```bash
curl http://localhost:8080/pending
```

### Acknowledge staged (subsd)

```bash
curl -X POST http://localhost:8080/ack \
  -H "Content-Type: application/json" \
  -d '{"handles": ["alice@example"]}'
```

## Production Considerations

This is a minimal example. In production, you should add:

- **User authentication**: OAuth, API keys, or other auth for registration
- **subsd authentication**: API key to protect `/pending`, `/ack`, `/webhook/*` endpoints
- **Payment verification**: Check that users have paid before accepting registrations
- **Database**: Use PostgreSQL/MySQL instead of in-memory storage
- **Webhook security**: Sign webhooks so registry can verify they came from subsd
- **Rate limiting**: Prevent abuse
- **Notifications**: Email/push notifications when handles are committed
- **Monitoring**: Metrics, logging, alerting
