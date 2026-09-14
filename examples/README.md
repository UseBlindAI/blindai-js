# Examples

All three are typechecked in CI against the source next to them (`npm run typecheck:examples`), so
an example that does not compile cannot be tagged.

| File | Shows |
|---|---|
| `quickstart.ts` | The smallest useful integration: gate one tool call, and handle the errors that mean authorization was unavailable. |
| `with-openai.ts` | The shape inside an agent loop — authorize *before* the tool runs, and treat a throw as "do not run it". |
| `testing.ts` | Testing your integration without a server, including the two cases usually skipped: the server being down, and a response that is not a decision. |

They import `@blindai/sdk` because that is what you will write. In this repository that name is
mapped to `src/` so the examples are checked against the real surface rather than a published build
that may be older than the code beside them.
