# @blindai/sdk

Fail-closed TypeScript client for the BlindAI authorization API.

```bash
npm install @blindai/sdk
```

> **Not yet published.** `@blindai/sdk` is not on npm; the line above is what it will be. Until the first release, install from this repository. Publishing is gated on both invariants and a contract run against a real deployment (see *Testing*), so the package appears when those pass and not before.

```ts
import { BlindAIClient } from '@blindai/sdk';

const blindai = new BlindAIClient({
  apiKey: process.env.BLINDAI_API_KEY!,
  baseUrl: process.env.BLINDAI_BASE_URL!, // required: no production default
});

const decision = await blindai.authorize({
  input_text: userMessage,
  user_id: 'u-1024',
  tool: 'send_email',
  preset: 'strict',
});

if (decision.blocked) {
  throw new Error(decision.reason ?? 'blocked by policy');
}
```

## The one rule

**Errors throw. No error path in this SDK produces an `allow`.**

- A response carrying neither `blocked` nor `allowed` throws `ContractError`.
- A `blocked` or `allowed` that isn't a boolean throws rather than being coerced.
- A 404, a timeout, a connection failure, and a non-JSON body all throw.
- There is no `continueOnError`-style option and no collapsed batch verdict.

If your application needs a fallback when authorization is unavailable, catch
the error and make that decision in your own code, where a reviewer can see it.

## API

### `new BlindAIClient(options)`

| Option | Required | Default | Notes |
|---|---|---|---|
| `apiKey` | yes | — | Must start with `ba_` |
| `baseUrl` | yes | — | No default: state your deployment explicitly |
| `timeoutMs` | no | `10000` | Per request |
| `maxRetries` | no | `2` | Retries 5xx, 408 and 429 only |
| `retryBaseMs` | no | `200` | Exponential backoff base |
| `authStyle` | no | `'bearer'` | Or `'x-api-key'`; both are accepted |
| `fetch` | no | global | For tests or a custom agent |

### `authorize(request)` → `Decision` · `POST /v1/authorize`
### `scan(request)` → `Decision` · `POST /v1/scan` (identical models)
### `ragScan(request)` → `RAGScanResponse` · `POST /v1/rag/scan`
### `authorizeBatch(requests)` → `BatchItem[]`

Each item is `{ ok: true, index, decision }` or `{ ok: false, index, error }`.
A failed item carries no decision, so it cannot be misread as an allow.

### Request

`input_text` is the only required field. Everything else is defaulted
server-side: `user_id` → `"anonymous"`, `action` → `"query"`, `role` → `"user"`
(lowercase), `preset` → `"balanced"`. Also accepted: `agent_id`, `tool`,
`session_id`, `parameters`, and `target_space_id` (control plane only).

Roles are `admin | user | viewer | guest | foreign`, lowercase. Anything the
server doesn't recognise is enforced as `guest`.

There is no `metadata` field. The server does not accept one.

### Decision

```ts
{
  blocked: boolean;        // `blocked` wins when present, else !allowed
  action: 'allow' | 'block';
  isThreat: boolean;       // blocked || threats.length > 0
  confidence: number;      // max across threats, 0 when none
  threats: ThreatDetail[];
  threatLevel: string;     // "none" | server value | "medium"; never null
  reason: string | null;
  latencyMs: number;
  preset: string | null;
  raw: AuthorizeResponse;
}
```

A request can carry detected threats and still be allowed, so check `blocked`
for enforcement and `isThreat` for reporting.

### Errors

| Class | When |
|---|---|
| `ContractError` | Response carried no usable decision |
| `AuthError` | 401 / 403; the server's `detail` string is included |
| `ValidationError` | 422; built from `loc` and `msg`, leading `body` stripped |
| `PresetUnavailableError` | 503; a preset needs server-side configuration |
| `ApiError` | Any other non-2xx; `retryable` says whether it was retried |
| `TimeoutError` / `TransportError` | Request never completed |

## Known server behaviour worth knowing

- **`POWER_USER` is not a role.** The server's vocabulary is
  `admin | user | viewer | guest | foreign`; anything else is enforced as
  `guest`, which is fail-closed. This SDK passes roles through unchanged and
  does not map `POWER_USER` to `admin`. Whether `power_user` becomes a real
  server role is an open decision.
- **Presets can 503.** Presets using the intent classifier refuse to start
  without `ANTHROPIC_API_KEY` rather than dropping a detection layer, so on a
  deployment without it the default `balanced` preset answers 503 instead of
  quietly downgrading. That surfaces as `PresetUnavailableError`, carrying the
  server's detail, and is not retried: it's a configuration answer.
- **422 bodies echo your request.** FastAPI's validation `detail` entries carry
  an `input` field containing the body you submitted, including `input_text`.
  This SDK reads `loc` and `msg` only and never logs or stores `input`.
- **Keys must start with `ba_`.** A Clerk JWT is rejected on these routes with a
  `detail` string saying so; that string appears in the `AuthError`.
- **An error body may not be JSON.** A proxy returning HTML on a 502 must not
  replace the 502: the status is preserved and the parse failure swallowed.

## Testing

```bash
npm run check                           # typecheck + unit tests
BLINDAI_BASE_URL=… BLINDAI_API_KEY=… npm run test:contract
```

Contract tests run against a real server and **fail** when `BLINDAI_BASE_URL`
and `BLINDAI_API_KEY` are absent, so a green build cannot mean "we never
checked". Set `BLINDAI_CONTRACT_OPTIONAL=1` to skip them locally; CI must not.
They assert that `/v1/authorize` and `/v1/scan` exist, that both auth styles
work, that `/api/v1/check` returns 404, and that a bad key raises rather than
returning a decision.
