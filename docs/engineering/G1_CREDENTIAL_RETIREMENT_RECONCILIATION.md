# G1 credential retirement — uncertain-outcome reconciliation

**Status:** draft operational control. No automatic run, no production approval.
**Custody:** authorised database administrator plus a separate qualified reviewer.
**Scope:** only the explicitly approved Verivaro PostgreSQL database and the
pre-identified old login, proposed replacement login, and NOLOGIN service group.
Do not use this procedure to authorise a Neon migration or bypass role separation.

## Fail-closed operational decision

Classify the `retireServiceCredential` outcome and record the exact UTC time,
deployment commit, operator, approval reference, PostgreSQL cluster/database
identity and error **class** without secrets or raw database passwords.

| Outcome | Assumption permitted | Mandatory response |
| --- | --- | --- |
| Normal result, `remainingSessions=0` | The API observed retirement and zero sessions at its final check | Obtain independent follow-up review before declaring the rollout complete |
| `credential retirement failed` | Pre-commit failure and confirmed rollback on the client path | Do **not** assume the replacement is approved; independently inspect role state before another attempt |
| `CredentialRetirementStateUncertainError` | No conclusion about COMMIT, rollback or password state | Freeze rotations; do **not** automatically retry, restore privileges or disable another credential; obtain independent DBA inspection |
| `CredentialRetirementSessionsUnverifiedError` | COMMIT was acknowledged, but session termination was not confirmed | Keep replacement in controlled service operation only if separately authorised; investigate and resolve any authenticated old-login sessions under the DBA incident procedure |

Do not re-enable old logins, change group grants, drop roles, revoke passwords,
terminate backends or rotate again as part of the read-only diagnostic phase.
A second reviewer must approve any subsequent write, termination or emergency
containment action. The absence of an exception is not a substitute for staging
and production identity verification.

## Read-only PostgreSQL evidence (operator executes only after approval)

Run on the target cluster using a separately controlled, **read-only review
identity** with sufficient `pg_roles`, `pg_auth_members` and
`pg_stat_activity` visibility. Use a fresh connection and the approved,
recorded role identifiers. The example is for `psql`; its variable
interpolation quotes all role names as SQL string literals.

```sql
-- Supply -v old_login=... -v new_login=... -v group_role=...
-- psql -X -v ON_ERROR_STOP=1 ... -f <review copy of this SQL>
SELECT clock_timestamp() AS observed_at, current_database() AS db,
       current_user AS reviewer, session_user AS authenticated_reviewer;

SELECT rolname, rolcanlogin, rolinherit, rolcreatedb, rolcreaterole,
       rolbypassrls, rolreplication, rolsuper, rolvaliduntil
FROM pg_catalog.pg_roles
WHERE rolname IN (:'old_login', :'new_login', :'group_role')
ORDER BY rolname;

SELECT member.rolname AS principal, grp.rolname AS service_group,
       m.inherit_option, m.set_option, m.admin_option
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles member ON member.oid=m.member
JOIN pg_catalog.pg_roles grp ON grp.oid=m.roleid
WHERE member.rolname IN (:'old_login', :'new_login')
   OR grp.rolname=:'group_role'
ORDER BY principal, service_group;

SELECT usename AS principal, count(*)::int AS sessions
FROM pg_catalog.pg_stat_activity
WHERE usename IN (:'old_login', :'new_login')
GROUP BY usename ORDER BY principal;

SELECT coalesce(r.rolname, '[database default]') AS principal,
       s.setdatabase, cardinality(s.setconfig) AS override_count
FROM pg_catalog.pg_db_role_setting s
LEFT JOIN pg_catalog.pg_roles r ON r.oid=s.setrole
WHERE r.rolname IN (:'old_login', :'new_login', :'group_role')
   OR (s.setrole=0 AND s.setdatabase=(
       SELECT oid FROM pg_catalog.pg_database
       WHERE datname=current_database()));
```

**Evidence constraints:** this example records only the **count** of
configuration overrides, never `setconfig` values, which could contain
secrets. Evidence exports should contain approved redacted fields and stable,
independently signed timestamps. Empty `pg_stat_activity`
results are not authoritative if the reviewer lacks visibility of other
sessions. Querying this state is read-only; obtaining the required account,
network access and permission is a separate authorisation gate.

Compare these readings with the signed pre-rotation inventory, the service's
actual approved identity, catalogue grant policy and operator approval.
Reconcile old-login `LOGIN/NOLOGIN`, explicit password-disabled state
(**only a qualified administrator may inspect password-presence metadata,
never the hash**), service membership, new-login usability, active sessions,
and the expected database/schema privilege inventory. Do not infer the
password state from `pg_roles`, which does not expose it.

## Branching recovery decisions (no automatic mutations)

1. **Old login still LOGIN/member:** verify independently that its credential
   and sessions were not changed; classify the attempt as rolled back or
   partial only with supporting evidence. A further attempt requires fresh
   approval and renewed inspection of the replacement identity.
2. **Old login NOLOGIN and group membership removed:** the DDL may have
   committed. Verify replacement suitability and inspect all old sessions
   from a properly privileged independent connection. If any survive, an
   authorised administrator must obtain explicit containment approval before
   terminating them. Do not treat the original request's exception as an
   instruction to reverse a committed revocation.
3. **Contradictory or incomplete evidence:** keep the incident open, prevent
   subsequent rotation attempts, preserve the existing audit records, and
   escalate to the independent DBA/security reviewer. Re-check after network
   recovery; avoid repeated writes that can obscure the first attempt.
4. **No surviving old sessions and independently accepted replacement:**
   document independent sign-off and the observed state. This is operational
   reconciliation, **not** certification of production readiness.

## Synthetic fault verification

The isolated `tests/integration/live-credential-faults.test.mjs` file
exercises real PostgreSQL role DDL via a disposable admin pool while injecting
client-side failures. It verifies an actual rollback after a rejected REVOKE,
uncertain rollback with a forcibly destroyed socket, a successful real COMMIT
with a lost client acknowledgment, and successful COMMIT followed by a
synthetically blocked termination query while the old authenticated session
remains alive. These **do not** reproduce a real PostgreSQL primary failover,
multi-region connectivity loss or a malicious DBA. They are evidence for
application-level classification and observable persisted state only.

**Production release remains blocked** by approved Neon role separation,
independent DBA/security review, authorised live staging and release custody.
No remediation in this runbook is permission to execute those gated actions.
