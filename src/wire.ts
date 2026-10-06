/**
 * The wire constants this client shares with the control plane. The source of truth is
 * `specs/wire-constants.json` in the BlindAI repository; a verbatim copy lives in
 * `test/fixtures/wire-constants.json` and `test/wire.test.js` holds these to it.
 */

/** The header carrying an agent's identity token. Sent only when a token is held: never empty. */
export const IDENTITY_HEADER = 'X-BlindAI-Identity';

/** The control plane's token exchange: a runtime's secret for its agents' identity tokens. */
export const TOKENS_PATH = '/v1/cp/tokens';
