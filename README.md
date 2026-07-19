# simply360-reference-slack

Public **reference proof** for the Simply360 Integration Marketplace: Slack as
an **event destination**, **remote automation actions**, and **signed inbound
remote triggers** (Proof C, Ratified Direction 13).

> Status: **scaffold only.** No proof behavior is implemented yet. This
> repository is the foundation that **MKT-12** (Public Slack reference
> app/runtime) builds on. See the plan's "Autonomous Proof Integrations —
> Proof C" for the authoritative requirements.

## Purpose

Prove that an external Slack app, running entirely **outside the Simply360
monorepo** on **public platform boundaries only**, can:

- **consume Simply360 events** (event destination — e.g. post an update to a
  Slack channel);
- **expose approved remote automation actions** (e.g. send-to-channel);
- **prove signed inbound remote triggers** (e.g. create-record-from-message);
  and
- ship an **external Blueprint package** where team schema is useful.

A Zapier listing is a separate, post-platform distribution follow-on and does
**not** substitute for this proof.

## Boundary rules (non-negotiable)

- **Only public boundaries** (Ratified Direction 9 / 21): the future
  `@simply360/integration-sdk` and `@simply360/blueprint-sdk` packages,
  Simply360 OAuth, webhooks, manifests, and extension protocols.
- **No** Simply360 internal package imports, database/VPC access, or SSM/E2E
  credentials. Slack tokens and signing secrets live only in the reference
  stack's Secrets Manager path — **never committed here**.
- The `@simply360/*` SDKs are **not yet published**; integration points are
  marked with `TODO(MKT-12)` in `src/index.ts`.

## Layout

```
.
├── .github/
│   ├── dependabot.yml          # npm + github-actions weekly updates (dev branch)
│   └── workflows/
│       ├── ci.yml              # build + test (pinned action SHAs)
│       └── security.yml        # dependency-review + SBOM + build provenance
├── infra/
│   └── README.md               # intended OIDC role + NonProd stack (no AWS resources created)
├── src/
│   └── index.ts                # typed placeholder entry point + architecture sketch
├── test/
│   └── proof.test.js           # scaffold smoke test (node --test)
├── LICENSE                     # Apache-2.0
├── NOTICE
├── package.json                # public (private:false), Apache-2.0, Node 22, dev tooling only
└── tsconfig.json
```

## Develop

```bash
npm install      # dev tooling only (typescript, @types/node)
npm run type-check
npm run build
npm test
```

## CI / security posture

- `ci.yml` (build + test) and `security.yml` (dependency review, SPDX SBOM,
  build-provenance attestation) are committed with **all third-party actions
  pinned to a full commit SHA**.
- GitHub Actions is currently **billing-blocked account-wide**, so no run has
  executed yet. `dev` branch protection therefore does **not** require status
  checks until these workflows have a green baseline.
- Secret scanning and push protection are enabled on the repository.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
