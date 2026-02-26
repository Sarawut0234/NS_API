# NS_API

Node.js API using Express for license verification by client IP.

## Endpoint

`GET /verify?key=<LICENSE_KEY>&script=<SCRIPT_NAME>`

Response:

- `{ "status": "success" }` when `license_key` + `script_name` are found and `allowed_ip` matches requester IP.
- `{ "status": "failed" }` otherwise.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy `.env.example` to `.env` and update DB credentials.
3. Run API:
   ```bash
   npm start
   ```

## MySQL Table Example

```sql
CREATE TABLE licenses (
  license_key VARCHAR(255) NOT NULL,
  allowed_ip VARCHAR(45) NOT NULL,
  script_name VARCHAR(255) NOT NULL
);
```