# Project Quarry agent-guard demo

A local web demo that shows what [Project Quarry](https://github.com/cisco-ai-defense/project-quarry)
does for AI agents. A support agent for the fictional retailer Northstar Outfitters has real tools:
order lookup, customer profiles, web fetch, email, refunds, address changes and discount codes.
Every request runs twice, side by side:

- **Unprotected agent**: tools run as soon as the agent asks.
- **Quarry-guarded agent**: before each step takes effect, Quarry scans the conversation plus that
  step and can stop it at three points:

| Enforcement point | What the guard does | Example rule |
|---|---|---|
| A tool call, before it runs | **Blocks** it: the tool never executes | Customer data emailed to an outside address |
| A tool result, before the model reads it | **Quarantines** it: the model gets a notice instead | Prompt injection in fetched web content |
| The agent's reply, before the customer sees it | **Withholds** it: a safe message is shown | Full card number in the agent's reply |

Each stop shows its evidence: the conversation steps that triggered it, any captured value, and any
model score against its threshold. A "What actually happened" panel lists the simulated side
effects on each path (emails sent, money refunded, addresses changed).

All data is synthetic. No email is sent, no money moves and `fetch_url` only serves the demo's own
fictional pages.

---

## 1. Quick start (Docker)

You need **Docker Desktop**. Scripted scenarios need no API keys.

| | Windows | macOS / Linux |
|---|---|---|
| First run, build the image here | `.\start.ps1 -Build` | `bash start.sh --build` |
| Later runs, once the image is published (section 2) | double-click `start.cmd`, or `.\start.ps1` | `bash start.sh` |
| Stop | double-click `stop.cmd`, or `.\stop.ps1` | `bash stop.sh` |

The start script checks Docker, exports your network's HTTPS-inspection certificate into `certs`
if needed (same approach as the Northstar demo), starts the container on **127.0.0.1 only** and
opens **http://127.0.0.1:5075**. Port 5075 avoids a clash with Northstar on 5065.

Options: `-Port 5076` / `--port 5076`, `-NoPull` / `--no-pull`, `-Image <name>` / `--image <name>`,
`-RelaxStrictTls` / `--relax-strict-tls`, `-NoCertExport` / `--no-cert-export`,
`-NoBrowser` / `--no-browser`. `stop` keeps saved keys in the `quarry-demo-data` volume;
`-DeleteSavedSettings` / `--delete-saved-settings` removes them.

Or with Compose: `docker compose up -d --build`.

## 2. Publishing the image from GitHub

`.github/workflows/docker-publish.yml` runs the offline tests and then publishes
`ghcr.io/<owner>/project-quarry-demo` for amd64 and arm64 on every push to `main`. After the first
publish, make the package public under GitHub → Packages if colleagues should pull it without
logging in. The start scripts default to `ghcr.io/slblack/project-quarry-demo:latest`.

## 3. Running without Docker

Python 3.11–3.13 is required (Quarry does not support 3.10 or 3.14).

```sh
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m quarry_demo           # http://127.0.0.1:5075
```

`requirements.txt` installs Quarry from GitHub at a pinned commit, so the machine needs access to
github.com and PyPI.

---

## 4. Presenting it

**Scripted scenarios** are the dependable path for meetings: offline, repeatable, and every
enforcement point fires on cue. A suggested order:

1. **Poisoned review page steals customer data.** The headline attack. Point out that every
   individual step looks normal. Quarry quarantines the page, then blocks the email with two
   independent rules. Open the evidence: the captured address shows why emailing the customer
   would have been fine.
2. **Control: genuine refund and a copy to the customer.** Same tools, all allowed. This is about
   precision, not just blocking.
3. **Redirect the parcel, then claim a refund**, then **Control: refund first, then an address
   change.** The same actions in the opposite order. This is the "Quarry understands sequences"
   moment.
4. **Courier page quietly redirects a delivery (AI judge).** No injection keywords, so the regex
   rule misses it. The neurosymbolic rule calls the judge only because a consequential action is
   pending.
5. **Social-engineered £420 refund**, **Coupon site 90% discount**, **Full card number**: business
   limits and output checks.
6. **Rules tab.** Switch off "Refund above the agent's £150 limit" and rerun scenario 5 to show
   what gets through. Then write a rule live (an example is preloaded), test it against every
   scenario and add it to the guard.

Each scenario has **Presenter notes** with a short talk track. The playback speed is adjustable.

**Live agent** sends a message to two independent OpenAI-driven agents. It's impressive with an
engaged audience, but models vary from run to run, so keep scripted mode as the fallback. Both
agents are told to act decisively and follow instructions in fetched pages: the over-eager
configuration that makes these attacks realistic. A modern model may still refuse some attacks on
its own; when it does, the unprotected column shows that and the guard has nothing to stop.

### Setup (live mode only)

Click **Setup**:

- **OpenAI API key** and **agent model**, default `gpt-6-luna`. Live mode uses the OpenAI
  **Responses API** with function calling (the same API as the Northstar demo). **Verify** makes a
  tiny tool-calling request, so it tells you whether the model will work. For a model or
  OpenAI-compatible endpoint that only offers Chat Completions, set
  `QUARRY_DEMO_OPENAI_API=chat` (for Docker: `docker run -e QUARRY_DEMO_OPENAI_API=chat ...`).
  If OpenAI rejects a request, the page shows OpenAI's own reason.
- **Judge model**: leave blank to use the agent model. A small, fast model is enough.
- **Cisco AI Defense key and region** (optional). When set, tick *Add Cisco AI Defense prompt
  inspection* to inspect the customer message and the final reply on the guarded path, alongside
  Quarry's action-level checks. The client is the same one used in the Northstar demo.

Keys are stored in `settings.json` in the data volume (mode 0600), never returned to the browser
and never logged. Values from Setup take precedence over environment variables and `.env`.

---

## 5. The rules

All rules are in `quarry_demo/rules/`. Each one's `metadata` names its enforcement point
(`enforce`), severity and an OWASP LLM Top 10 mapping.

| Rule | Point | What makes it interesting |
|---|---|---|
| Customer data emailed to an outside address | tool call | `after` (order) plus a **capture**: the email address read from the profile is remembered, so the customer's own address is allowed |
| Customer data smuggled into a web request | tool call | `after` plus a regex over the pending URL |
| Refund the customer did not ask for | tool call | absence: no customer message mentions a refund or problem |
| Refund above the agent's £150 limit | tool call | argument check on the *pending* call (`call.response == null`) |
| Refund after a delivery address change | tool call | pure sequence: address change, then refund |
| Prompt injection in fetched web content | tool result | quarantines the content before the model reads it |
| Full card number in the agent's reply | reply | output check |
| Discount code above 30% | tool call | argument check |
| Action the customer did not ask for (AI judge) | tool call | **neurosymbolic**: a cheap symbolic check decides whether to ask the model at all |

### How the guard decides

For each step the guard scans the conversation as Quarry should see it, plus the new step. If a rule
matches **that did not match before**, and the rule's `enforce` point is this step, the step is
stopped. Blocked calls and quarantined content never enter Quarry's view of the conversation, so the
same rule fires again if the agent retries.

The first scan asks only for a verdict, which lets Quarry skip checks that can't change the result.
That is why the judge model is never called for ordinary lookups. Only when something newly matches
does the guard scan again with explanations to collect the evidence.

If a scan cannot complete (a timeout, judge error or invalid input), the guard **fails closed**.

## 6. Honest limits

- Quarry is alpha (v0.1). Its rule syntax may change before v1.0, which is why `requirements.txt`
  pins a commit.
- This Quarry version can't compare a numeric tool argument within a step (`amount > 150` fails to
  compile), so the £150 and 30% limits are regular expressions over the raw JSON arguments.
- In scripted mode the AI judge is an **offline keyword stand-in** so replays are deterministic. The
  UI says so. In live mode it is the OpenAI judge model.
- In scripted mode the agent's plan is fixed, so after a quarantine the "agent" still tries the next
  malicious step. This shows defence in depth. A live model may behave differently after it sees a
  quarantine notice.

## 7. Corporate networks and TLS inspection

This works as in the Northstar demo: the start scripts export your network's inspection root CA
into `certs/` when needed, and the app *adds* those certificates to the trust store. Verification is
never disabled. If Python 3.13's strict X.509 checks reject the corporate CA, start with
`-RelaxStrictTls` / `--relax-strict-tls` (sets `QUARRY_DEMO_TLS_RELAX_X509_STRICT=1`). Both the
OpenAI and AI Defense clients honour it. See `certs/README.md`.

## 8. Security model

A single-user localhost demo. It binds to 127.0.0.1, or to all interfaces only inside the container
with the port published to 127.0.0.1. It checks the Host header (against DNS rebinding), uses a
per-process CSRF token, refuses cross-origin requests and sends a strict Content-Security-Policy.
Untrusted text (tool results, model output) is inserted in the page as text, never as HTML. Neither
provider client follows redirects, so keys never leave the configured host.

## 9. Tests

```sh
pip install -r requirements-dev.txt
python -m pytest
```

There are 52 offline tests, with fake providers, no keys and no paid calls. They check that:

- every rule compiles
- every scripted scenario produces its intended stops, and controls stop nothing
- captures, ordering, refund limits, quarantine, reply withholding and fail-closed behave correctly
- the judge is skipped for non-consequential calls
- live mode works with a fake OpenAI, including AI Defense blocking and judge failure
- the real HTTP client works against local fake Responses and Chat Completions servers, including
  a full live attack end to end
- the app's hardening is in place

## 10. Files

```
quarry_demo/
  rules/*.rule        the nine Quarry rules (edit these to change the guard)
  texts/              policy text for the AI-judge rule
  data/store.json     synthetic customers, orders, products and web pages
  data/scenarios.json scripted scenarios and presenter notes
  guard.py            the Quarry guard: enforcement points, verdict/evidence scans, fail-closed
  judge.py            judge adapters (offline stand-in, live OpenAI)
  agent.py            scripted and live agent runners
  tools.py            the agent's tools against an in-memory copy of the store
  providers/          OpenAI client (Responses or Chat Completions), Cisco AI Defense client
  app.py, templates/, static/   the web app
tests/                offline test suite
start.*, stop.*, scripts/, certs/   Docker helpers (adapted from the Northstar demo)
```
