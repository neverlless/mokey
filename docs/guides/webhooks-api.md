# Webhooks and JSON API

mokey writes an audit event for every account change: logins and failed
logins, password changes and resets, OTP token, passkey and SSH key changes,
signups and approvals, group join/leave requests and decisions, OTP
recovery, and admin actions. The admin panel shows the last 1000 of them.
The same events can be pushed to other systems with webhooks, or pulled
with a small read-only JSON API.

## Webhooks

```toml
[[webhooks]]
url = "https://hooks.example.com/mokey"
secret = "change-me"            # optional, signs each request
events = ["password", "otp"]    # optional, default: every event
```

Each event is sent as its own `POST` with `Content-Type: application/json`:

```json
{
  "seq": 4182,
  "time": "2026-11-05T10:12:44.193Z",
  "level": "INFO",
  "message": "User password changed",
  "username": "jdoe",
  "ip": "203.0.113.7",
  "attrs": {"username": "jdoe", "ip": "203.0.113.7"}
}
```

- `message` is the event, as it appears in the log after `AUDIT`. `events`
  matches substrings of it, case-insensitively.
- `actor` is set when someone else acted on `username` (an admin, a group
  sponsor, an inviter).
- `attrs` holds every field of the log line. Fields that the log redacts
  (passwords, OTP codes, tokens, secrets, URL passwords) arrive as
  `[REDACTED]`.
- `level` is `ERROR` or `WARN` for failed attempts, such as a wrong password.
- `seq` is the event's number in the audit log and the cursor of the
  [events API](#get-apiv1events).

Delivery runs in the background and never slows down the user's request.
Each target has a queue of 100 events; a request times out after 5 seconds
and is tried 3 times in all, 1 and 2 seconds apart. Any 2xx answer counts as
delivered. When the queue is full, for example while the endpoint is down,
new events for that target are dropped with a warning in the log. Webhooks
are a notification channel, not a guaranteed log: to catch up on missed
events, read the events API from the last `seq` you processed.

With several replicas, each replica sends the events it logged.

### Verifying the signature

With `secret` set, every request carries two headers:

```
X-Mokey-Timestamp: 1762337564
X-Mokey-Signature: sha256=5d1c...e9
```

The signature is the hex HMAC-SHA256, keyed with the secret, of the
timestamp, a dot, and the raw request body. Check it before parsing the
body, and reject old timestamps to stop replays:

```python
import hashlib, hmac, time

def verify(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-Mokey-Timestamp"]
    if abs(time.time() - int(ts)) > 300:
        return False
    want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + want, headers["X-Mokey-Signature"])
```

### Slack

The `[slack]` bot sends each user their own notifications as a direct
message. To post account events to a channel, create a Slack
[incoming webhook](https://api.slack.com/messaging/webhooks) and add it as a
target with `format = "slack"`:

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T000/B000/XXXX"
format = "slack"
events = ["admin", "approved"]
```

mokey then sends `{"text": "mokey: User password changed user=jdoe ip=203.0.113.7"}`.
The same body works with Mattermost and Rocket.Chat incoming webhooks.

## JSON API

The API is read-only and off until you set at least one token:

```toml
[api]
tokens = ["a-long-random-string"]
```

Generate tokens with `openssl rand -hex 32`. Send one as a bearer token:

```sh
curl -H "Authorization: Bearer $TOKEN" https://mokey.example.com/api/v1/events
```

A missing or wrong token gets `401 {"error": "unauthorized"}`. Failed
requests count towards the same per-IP rate limit as failed logins
(`server.rate_limit_max`). API calls never open a session or set a cookie,
and CSRF does not apply to them. Every token can read every endpoint.

There are no write endpoints. Group requests are approved by the group's
sponsors and OTP recovery by admins, in mokey's UI, under their own FreeIPA
sessions.

### `GET /api/v1/events`

Audit events after a cursor, oldest first.

| Parameter | Default | Description |
| --- | --- | --- |
| `after` | `0` | Return events with `seq` greater than this. |
| `limit` | `100` | Page size, 1 to 1000. |

```json
{
  "events": [
    {"seq": 4181, "time": "2026-11-05T10:12:40Z", "level": "INFO", "message": "User logged in", "username": "jdoe", "ip": "203.0.113.7", "attrs": {"username": "jdoe", "ip": "203.0.113.7"}},
    {"seq": 4182, "time": "2026-11-05T10:12:44Z", "level": "INFO", "message": "User password changed", "username": "jdoe", "ip": "203.0.113.7", "attrs": {"username": "jdoe", "ip": "203.0.113.7"}}
  ],
  "next": 4182
}
```

Pass `next` as `after` on the next call; an empty `events` list means you
are caught up. The audit log keeps the last 1000 events for 90 days, so a
poller that falls further behind skips the oldest ones. With `memory`
storage the sequence restarts with mokey; a cursor ahead of it starts again
from the oldest event.

### `GET /api/v1/group-requests`

Pending join and leave requests of every sponsor-managed group.

```json
{
  "requests": [
    {"group": "developers", "username": "jdoe", "type": "join", "requested_at": "2026-11-05T09:58:02Z"}
  ]
}
```

### `GET /api/v1/otp-recovery`

The OTP recovery queue: users who confirmed a "Lost OTP token?" request by
email and wait for an admin.

```json
{
  "requests": [
    {"username": "jdoe", "requested_at": "2026-11-05T08:30:11Z"}
  ]
}
```

The list is the stored queue; the admin panel drops entries for users who
were deleted or no longer need recovery when it next shows them.
