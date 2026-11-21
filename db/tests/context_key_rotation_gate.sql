-- Disposable G1 CI only: the privileged fixture signer and key must NEVER
-- be available to runtime SQL or treated as a production rotation API.
-- Exercise a planned single-key rollover, not live HA key distribution.
\set ON_ERROR_STOP on
BEGIN;
-- B's unrevoked viewer membership should access only its own project.
SELECT verivaro_private.ci_sign(
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 pg_backend_pid(),pg_current_xact_id()::text) AS old_context \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'old_context', true) AS applied \gset
DO $old_valid$
BEGIN
 IF (SELECT count(*) FROM verivaro.projects)<>1
 THEN RAISE EXCEPTION 'valid pre-rotation context rejected'; END IF;
END $old_valid$;
RESET ROLE;
-- A privileged rotation invalidates existing HMAC envelopes immediately.
-- This UPDATE occurs inside a rollback-only test transaction.
DO $rotate$
DECLARE changed integer;
BEGIN
 UPDATE verivaro_private.context_key
 SET key_bytes=verivaro_private.gen_random_bytes(32) WHERE singleton;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'context key singleton not provisioned'; END IF;
END $rotate$;
SET ROLE verivaro_runtime;
DO $old_invalid$
BEGIN
 IF EXISTS (SELECT 1 FROM verivaro.projects)
 THEN RAISE EXCEPTION 'old signing key authorized access after rotation'; END IF;
END $old_invalid$;
RESET ROLE;
-- The new envelope uses the same backend/XID/session but the new key.
SELECT verivaro_private.ci_sign(
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 pg_backend_pid(),pg_current_xact_id()::text) AS new_context \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'new_context', true) AS applied \gset
DO $new_valid$
BEGIN
 IF (SELECT count(*) FROM verivaro.projects)<>1
 THEN RAISE EXCEPTION 'new signing key failed post-rotation authorization'; END IF;
 RAISE NOTICE 'context_key_rotation_old_denied_new_accepted';
END $new_valid$;
ROLLBACK;
RESET ROLE;
-- ROLLBACK must restore the disposable fixture key and session state.
BEGIN;
SELECT verivaro_private.ci_sign(
 '22222222-2222-4222-8222-222222222222',
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 pg_backend_pid(),pg_current_xact_id()::text) AS recovered_context \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'recovered_context', true) AS applied \gset
DO $rollback_valid$
BEGIN
 IF (SELECT count(*) FROM verivaro.projects)<>1
 THEN RAISE EXCEPTION 'rolled-back rotation did not restore original key'; END IF;
 RAISE NOTICE 'context_key_rotation_rollback_verified';
END $rollback_valid$;
ROLLBACK;
RESET ROLE;
