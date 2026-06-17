> **Historical — preserved for context.** Original TLP-and-identity design addendum. The shipped TLP design lives in [`CLAUDE.md`](../../CLAUDE.md) §8 and identity remains a placeholder per §9.

---

# FragChain — TLP & Verified Contributors
**Addendum to:** FragChain_Ecosystem_Architecture.md  
**Purpose:** Bake trust and disclosure controls into the foundation, not bolt on later  

---

## 1. Why This Matters Now

Adding TLP and identity verification later means refactoring every table, every API endpoint, every UI screen, and the commons repo structure. Doing it now means the primitives exist from day one even if we don't use them aggressively at first.

Specifically: TLP classification on every contributable entity, plus a contributor tier system gated by GPG-verified identity. These primitives also unlock the embargo handling we'll need for pre-disclosure intel.

---

## 2. TLP Classification System

### 2.1 The TLP Levels (TLP 2.0)

FragChain uses the FIRST.org TLP 2.0 specification:

| Level | Meaning | FragChain enforcement |
|-------|---------|----------------------|
| `tlp:clear` | Public, no restrictions | Anyone can read. Goes to public commons. |
| `tlp:green` | Limited to community | Authenticated FragChain users. Community commons (separate feed). |
| `tlp:amber` | Limited to org + named partners | Single deployment + explicitly listed partner deployments. Never public. |
| `tlp:amber+strict` | Single org only | Single deployment only. No external sharing at all. |
| `tlp:red` | Named participants only | Specific named users. Maximum restriction. |

### 2.2 TLP Is on Every Contributable Entity

Add `tlp` field to:
- `cves` (the CVE record itself may be embargoed/restricted)
- `source_documents` (a source might be from a closed feed)
- `attack_chains` (chain may contain sensitive exploitation detail)
- `chain_ttps` (individual TTPs inherit chain TLP)
- `sigma_rules` (some detection logic shouldn't be widely shared)
- `review_queue` items (inherits from rule)

```sql
ALTER TABLE cves ADD COLUMN tlp VARCHAR(20) DEFAULT 'tlp:clear';
ALTER TABLE source_documents ADD COLUMN tlp VARCHAR(20) DEFAULT 'tlp:clear';
ALTER TABLE attack_chains ADD COLUMN tlp VARCHAR(20) DEFAULT 'tlp:clear';
ALTER TABLE sigma_rules ADD COLUMN tlp VARCHAR(20) DEFAULT 'tlp:clear';

-- For tlp:amber and below, track who has access
CREATE TABLE tlp_access_grants (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    granted_to_user_id UUID REFERENCES users(id),
    granted_to_deployment_id UUID,  -- for partner deployment grants
    granted_by_user_id UUID,
    granted_at TIMESTAMP,
    expires_at TIMESTAMP,
    reason TEXT
);

CREATE INDEX ON tlp_access_grants(entity_type, entity_id);
CREATE INDEX ON tlp_access_grants(granted_to_user_id);
```

### 2.3 TLP Propagation Rules

These are enforced at write time, not just read time:

**Rule 1 — Inheritance up the chain:**
A chain's TLP is `max(chain_explicit_tlp, max(source.tlp for source in chain.sources))`.
A rule's TLP is `max(rule_explicit_tlp, parent_chain.tlp)`.

You cannot generate a `tlp:clear` rule from an `tlp:amber` chain — the rule inherits amber.

**Rule 2 — No silent downgrade:**
Once an entity is classified above clear, only the original contributor can downgrade it, and only with explicit `tlp_downgrade_reason` recorded in the audit log.

**Rule 3 — Embargo overrides:**
If `embargo_until > now()`, effective TLP is `tlp:red` regardless of declared TLP. Auto-transitions to declared TLP when timer expires.

**Rule 4 — Connector declarations:**
Each connector declares its maximum output TLP. A connector pulling from a public source (NVD, EPSS) outputs `tlp:clear`. A connector pulling from a paid feed (Mandiant) outputs at least `tlp:amber` by default. Configurable per-connector in Settings.

### 2.4 TLP Enforcement in Code

```python
# fragchain/security/tlp.py

class TLP(StrEnum):
    CLEAR = "tlp:clear"
    GREEN = "tlp:green"
    AMBER = "tlp:amber"
    AMBER_STRICT = "tlp:amber+strict"
    RED = "tlp:red"

    @property
    def restriction_level(self) -> int:
        return {
            TLP.CLEAR: 0, TLP.GREEN: 1, TLP.AMBER: 2,
            TLP.AMBER_STRICT: 3, TLP.RED: 4
        }[self]

def max_tlp(*levels: TLP) -> TLP:
    return max(levels, key=lambda t: t.restriction_level)

async def can_user_access(user: User, entity_tlp: TLP, entity_id: UUID) -> bool:
    if entity_tlp == TLP.CLEAR:
        return True
    if user.is_anonymous:
        return False
    if entity_tlp == TLP.GREEN:
        return user.clearance_level >= TLP.GREEN
    if entity_tlp in (TLP.AMBER, TLP.AMBER_STRICT, TLP.RED):
        # Must have explicit grant
        return await has_explicit_grant(user.id, entity_id)
    return False
```

Every API endpoint that returns CVE/chain/rule data applies this filter — never trust the client to honour TLP.

---

## 3. Contributor Tier System

### 3.1 The Tiers

| Tier | Requirements | Permissions |
|------|--------------|-------------|
| `anonymous` | None | Read `tlp:clear` content only |
| `authenticated` | FragChain user account | Read `tlp:green` within own deployment |
| `verified` | GPG-verified identity + 2 trusted attestations | Read community `tlp:green` feed, contribute chains to commons, validation requires signed commits |
| `trusted` | Verified + 90 days activity + 10 accepted contributions + 0 rejected for cause | Review and merge commons PRs, access community `tlp:amber` feed, attest new Verified users |
| `maintainer` | Appointed by existing maintainers | Manage trust escalations, revoke trust, access all community-shared TLP levels |

### 3.2 Identity Schema

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    hashed_password VARCHAR(255),
    tier VARCHAR(20) DEFAULT 'authenticated',
    clearance_level VARCHAR(20) DEFAULT 'tlp:green',
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

CREATE TABLE user_identities (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    gpg_fingerprint VARCHAR(64) UNIQUE,  -- 40-char hex, possibly with 0x prefix
    gpg_public_key TEXT NOT NULL,
    verified_at TIMESTAMP,
    verification_challenge TEXT,           -- the challenge string signed for verification
    verification_signature TEXT,           -- detached signature proving key control
    revoked_at TIMESTAMP,
    revocation_reason TEXT
);

CREATE TABLE trust_attestations (
    id UUID PRIMARY KEY,
    attestor_user_id UUID REFERENCES users(id),       -- the trusted user vouching
    subject_user_id UUID REFERENCES users(id),         -- the candidate being attested
    attestation_type VARCHAR(50),                      -- 'identity', 'tier_upgrade'
    attestation_text TEXT,                             -- "I know this person professionally"
    signed_attestation TEXT,                           -- GPG-signed JSON of the above
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP
);

CREATE TABLE contribution_signatures (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),                           -- 'chain', 'rule_review', 'validation'
    entity_id UUID,
    signer_user_id UUID REFERENCES users(id),
    signer_fingerprint VARCHAR(64),
    content_hash VARCHAR(64),                          -- SHA-256 of canonical JSON
    signature TEXT,                                    -- ASCII-armored GPG signature
    signed_at TIMESTAMP DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE,
    UNIQUE(entity_type, entity_id, signer_user_id)
);

CREATE INDEX ON contribution_signatures(entity_type, entity_id);
CREATE INDEX ON contribution_signatures(signer_user_id);
```

### 3.3 Tier Escalation Workflow

**Authenticated → Verified:**
1. User uploads GPG public key in Settings → Identity
2. System generates a verification challenge string + records it
3. User signs the challenge with their private key, uploads detached signature
4. System verifies signature matches the uploaded public key
5. User must obtain attestations from 2 existing `trusted` users
   - Each attestation is signed by the attestor's GPG key
   - Attestations recorded in `trust_attestations` table
6. Once 2 valid attestations recorded → user.tier promoted to `verified`
7. Audit log entry, notification to attestors and subject

**Verified → Trusted:**
Automatic when criteria met (90 days verified, 10 accepted contributions, 0 rejections-for-cause). Maintainers can fast-track for known security community members.

**Trust revocation:**
Maintainers can revoke trust with recorded reason. Revoked user retains read access but loses contribution privileges. Past contributions remain in commons (already accepted), but new contributions require re-attestation.

### 3.4 What "Signed Commits" Means in Practice

When a `verified` or higher user contributes a chain to the commons:

1. The chain JSON is canonicalised (sorted keys, no whitespace)
2. SHA-256 hashed
3. The user's local FragChain instance signs the hash with their GPG key via their local agent (never sends private key)
4. Signature attached to the contribution PR as `provenance.contribution_signature`
5. The fragchain-intelligence CI validates the signature on PR
6. PR cannot merge if signature is invalid or user is not in approved tier

Same flow for chain validations — when a trusted user validates someone else's chain, the validation record is signed.

---

## 4. Trust × TLP Matrix — The Combined Model

| TLP Level | Anonymous | Authenticated | Verified | Trusted | Maintainer |
|-----------|-----------|---------------|----------|---------|------------|
| tlp:clear | ✅ read | ✅ R/W | ✅ R/W | ✅ R/W | ✅ R/W |
| tlp:green (own deployment) | ❌ | ✅ R/W | ✅ R/W | ✅ R/W | ✅ R/W |
| tlp:green (community feed) | ❌ | ❌ | ✅ R/W | ✅ R/W | ✅ R/W |
| tlp:amber (own deployment) | ❌ | ✅ R/W | ✅ R/W | ✅ R/W | ✅ R/W |
| tlp:amber (community partner) | ❌ | ❌ | ❌ | ✅ R | ✅ R/W |
| tlp:amber+strict | ❌ | own-org only | own-org only | own-org only | own-org only |
| tlp:red | grant only | grant only | grant only | grant only | grant only |

Reading the matrix: a `verified` user can read TLP:GREEN content from the community commons (the shared feed across deployments), but only reads TLP:AMBER content that exists within their own deployment unless they're a community partner.

`tlp:amber+strict` and `tlp:red` always require explicit grants regardless of tier. Tier only affects what a user is eligible to be granted access to.

---

## 5. Embargo Handling

Pre-disclosure intel needs special handling. The platform supports:

```sql
ALTER TABLE cves ADD COLUMN embargo_until TIMESTAMP;
ALTER TABLE attack_chains ADD COLUMN embargo_until TIMESTAMP;
ALTER TABLE source_documents ADD COLUMN embargo_until TIMESTAMP;

CREATE TABLE embargo_participants (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50),
    entity_id UUID,
    user_id UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by_user_id UUID REFERENCES users(id)
);
```

**Behaviour:**
- During embargo: effective TLP is `tlp:red`, only `embargo_participants` can access
- Auto-transition: Celery task `release_embargoed_content` runs every 5 minutes
  - Finds entities where `embargo_until < now()`
  - Sets effective TLP to the declared `tlp` field
  - Removes embargo_participants restriction
  - Emits WebSocket event `embargo_released`
  - Audit log entry
- Connector flag: a connector can set `embargo_until` on incoming intel automatically (e.g., a TAXII feed marking content as embargoed-until-{date})

**UI:**
- Embargoed entities show a red lock icon and countdown timer
- Cannot generate Sigma rules from embargoed chains (they'd be tlp:red)
- Approval to release early requires maintainer + recorded reason

---

## 6. Cryptographic Chain of Custody

Every significant action by a verified+ user is signed. The audit trail becomes verifiable post-hoc.

**Signed actions:**
- Chain contribution to commons
- Chain validation
- Rule approval (for the local repo + commons)
- Trust attestation
- TLP changes (any upgrade or downgrade)
- Embargo grants

**Verification:**

Any consumer of the commons can verify signatures independently:

```bash
# Verify a chain's signature chain
fragchain verify chains/2026/CVE-2026-43284.json

✓ Signature from <contributor> @ <fingerprint> — valid
✓ Validation 1/3 from <validator1> @ <fingerprint1> — valid
✓ Validation 2/3 from <validator2> @ <fingerprint2> — valid
✓ Validation 3/3 from <validator3> @ <fingerprint3> — valid
✓ All signatures verified. Chain provenance intact.
```

This means the commons isn't just trusted because GitHub says so — it's cryptographically auditable.

---

## 7. Commons Architecture — Updated for TLP

The intelligence commons now has three tiers:

```
fragchain-intelligence/                  ← Public, tlp:clear ONLY
├── chains/
├── mappings/
├── evaluations/
└── releases/
    Anyone can read. Public GitHub.

fragchain-intelligence-community/        ← Community, tlp:green
├── chains/
├── evaluations/
└── releases/
    Authenticated, verified+ users only.
    Hosted on private repo OR Gitea OR encrypted releases.
    Accessed via authenticated API with GPG-signed requests.

fragchain-intelligence-trusted/          ← Trusted contributors, tlp:amber
├── chains/
└── releases/
    Trusted+ tier only.
    Highly restricted distribution.
    May not exist in v1 — defer until community matures.
```

Most contributions land in the public repo (`tlp:clear`). The community tier exists for sensitive but not embargo-level intel. The trusted tier is for partnerships with national CERTs, vetted researchers, etc., and probably won't materialize until year 2+.

---

## 8. Connector Protocol Updates

The `IntelConnector` protocol gains TLP awareness:

```python
class IntelConnector(Protocol):
    # ... existing fields ...
    max_output_tlp: TLP              # connector's ceiling
    default_output_tlp: TLP          # what it tags by default
    supports_embargo: bool           # can mark content embargoed
    requires_verified_tier: bool     # only verified+ users can configure this connector

    async def enrich_cve(self, cve_id: str, cve_data: dict) -> EnrichmentResult | None
        # EnrichmentResult now includes:
        #   tlp: TLP                 (the connector's classification)
        #   embargo_until: datetime  (optional)
        #   signed_provenance: str   (optional, if connector signs its output)
```

Built-in connector TLP defaults:

| Connector | default_output_tlp | requires_verified_tier |
|-----------|-------------------|----------------------|
| nvd2 | tlp:clear | No |
| epss | tlp:clear | No |
| ctid | tlp:clear | No |
| kev | tlp:clear | No |
| github | tlp:clear | No |
| osssecurity | tlp:clear | No |
| exploitdb | tlp:clear | No |
| attackerkb | tlp:clear | No |
| vendor-* | tlp:clear | No |
| opencti | tlp:green | No (depends on what's in their OpenCTI) |
| misp | configurable | Yes (often AMBER intel) |
| mandiant (commercial) | tlp:amber | Yes |
| recorded-future (commercial) | tlp:amber | Yes |

The platform admin can adjust these defaults in Settings → Connectors → Per-connector config.

---

## 9. UI Changes

### TLP Badges Everywhere
Every CVE card, chain node, rule listing, source document shows a TLP badge using DarkOps colors:
- `tlp:clear` → text-dim, no border
- `tlp:green` → --accent3 border
- `tlp:amber` → --warning border  
- `tlp:amber+strict` → --warning border with diagonal stripes
- `tlp:red` → --danger background

### Identity Settings Screen
New screen: Settings → Identity
- Show current tier + clearance level
- Upload/manage GPG public key
- Run verification challenge
- View attestations (received + given)
- View own contribution signatures
- Trust escalation request workflow

### Embargo Indicators
Embargoed entities show:
- Red lock icon in the corner
- Countdown timer ("Releases in 14d 6h")
- "EMBARGOED" badge on the page
- Cannot be exported or referenced in chains visible to non-participants

### Commons Contribution UI
When clicking "Contribute to Commons":
- Show user's tier and what they're eligible to contribute
- Show effective TLP of the chain being contributed
- For verified+ users: prompt for GPG passphrase (signature happens via local agent, never sent over network)
- Show preview of the PR that will be created
- One-click confirmation creates the GitHub PR

### Trust Network Visualization
Settings → Identity → Web of Trust:
- Graph view of attestation network
- Who has attested for whom
- Path from user to other trusted contributors
- Useful for assessing the legitimacy of community contributions

---

## 10. Sprint Plan Implications

The TLP and verified contributor primitives need to land in Sprint 1 schema and Sprint 2 enforcement. Building the full identity workflow can wait for a dedicated sprint, but the data model must exist from day one.

**Sprint 1 additions:**
- Schema: add `tlp` to cves/source_documents/attack_chains/sigma_rules
- Schema: add `users.tier`, `users.clearance_level`
- Schema: create `user_identities`, `trust_attestations`, `contribution_signatures`, `tlp_access_grants`, `embargo_participants`
- Schema: add `embargo_until` fields to relevant tables
- All entities default to `tlp:clear` for now — enforcement is layer 2

**Sprint 2 additions:**
- TLP enforcement middleware on all API endpoints
- TLP propagation logic when storing chains (max of sources)
- Embargo timer Celery task (release_embargoed_content)
- Connector protocol: `max_output_tlp`, `default_output_tlp`
- Initial connectors tagged with appropriate TLP defaults

**Sprint 6 additions (UI):**
- TLP badges on all relevant components
- Identity Settings screen (basic version)
- Embargo countdown indicators

**Sprint 9 (NEW) — Identity & Trust:**
- Full identity verification workflow (GPG challenge/response)
- Attestation system
- Contribution signature generation + verification
- Trust escalation workflow
- Web of trust visualization

This is the right sequencing — primitives in early, full workflow when the platform is mature enough to actually have contributors using it.

---

## 11. What This Architecture Gives Us

By baking these in now:

1. **The platform is GVRT-ready** without being a GVRT yet — the structural capacity exists when the community needs it.
2. **Commercial intelligence feeds become first-class citizens.** A Mandiant connector ships intel as `tlp:amber` automatically; downstream rules inherit that classification.
3. **Embargoed disclosure works correctly.** A researcher with pre-disclosure intel can use FragChain confidently — the embargo timer prevents accidental release.
4. **Commons contributions become verifiable.** GPG signatures on every contribution mean the commons isn't trusted because of GitHub — it's trusted because of cryptography.
5. **No bolt-on refactor later.** Adding TLP after the fact would require migrating millions of rows and rewriting every API. Doing it now is a few extra columns and middleware.

The primitives stay light by default — most content is `tlp:clear` and most users are `authenticated`. The complexity only kicks in for the cases that actually need it.

---

*This addendum becomes part of the FragChain architectural foundation alongside the ecosystem document.*
