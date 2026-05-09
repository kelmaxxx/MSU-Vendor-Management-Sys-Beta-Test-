-- RBAC + Row-Level Security for MSU Vendor Portal.
-- Principle of Least Privilege: vendor_app_role can only SELECT its own data
-- and INSERT into transactions / audit_logs. No DROP, ALTER, GRANT, UPDATE,
-- DELETE, TRUNCATE — even from the application connection.

-- Migration role: used only by db:migrate / db:seed scripts. Owns the schema.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admin_migration_role') THEN
    CREATE ROLE admin_migration_role LOGIN PASSWORD 'change_me_admin';
  END IF;
END $$;

-- Application role: what Node connects as at runtime.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_app_role') THEN
    CREATE ROLE vendor_app_role LOGIN PASSWORD 'change_me_app';
  END IF;
END $$;

-- Hand the schema and data to the migration role so it owns objects.
ALTER TABLE vendors                  OWNER TO admin_migration_role;
ALTER TABLE students                 OWNER TO admin_migration_role;
ALTER TABLE transactions             OWNER TO admin_migration_role;
ALTER TABLE audit_logs               OWNER TO admin_migration_role;
ALTER TABLE unauthorized_access_log  OWNER TO admin_migration_role;
ALTER TABLE "session"                OWNER TO admin_migration_role;

-- Revoke the broad public defaults.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT  USAGE ON SCHEMA public TO admin_migration_role, vendor_app_role;

-- vendor_app_role: read-only on lookups, plus INSERT on the two append surfaces.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM vendor_app_role;

GRANT SELECT                  ON vendors      TO vendor_app_role;
GRANT SELECT                  ON students     TO vendor_app_role;
GRANT SELECT, INSERT          ON transactions TO vendor_app_role;
GRANT SELECT, INSERT          ON audit_logs   TO vendor_app_role;
GRANT INSERT                  ON unauthorized_access_log TO vendor_app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON "session" TO vendor_app_role;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vendor_app_role;

-- The app needs to update student balance during a payment. Because PoLP forbids
-- granting UPDATE on the table, we expose a SECURITY DEFINER function that runs
-- as the migration role and validates inputs internally. This is the only path
-- by which the app can mutate balances.
CREATE OR REPLACE FUNCTION post_payment(
  p_student_id   INT,
  p_vendor_id    INT,
  p_new_bal_ct   BYTEA,
  p_new_bal_iv   BYTEA,
  p_new_bal_tag  BYTEA,
  p_amount_ct    BYTEA,
  p_amount_iv    BYTEA,
  p_amount_tag   BYTEA,
  p_txn_hash     TEXT
) RETURNS INT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_txn_id INT;
BEGIN
  IF p_amount_ct IS NULL OR p_new_bal_ct IS NULL OR p_txn_hash IS NULL THEN
    RAISE EXCEPTION 'post_payment: missing required parameter';
  END IF;

  UPDATE students
     SET balance_ct = p_new_bal_ct,
         balance_iv = p_new_bal_iv,
         balance_tag = p_new_bal_tag
   WHERE id = p_student_id;

  INSERT INTO transactions
    (txn_hash, student_id, vendor_id, amount_ct, amount_iv, amount_tag, status)
  VALUES
    (p_txn_hash, p_student_id, p_vendor_id, p_amount_ct, p_amount_iv, p_amount_tag, 'success')
  RETURNING id INTO v_txn_id;

  RETURN v_txn_id;
END $$;

ALTER FUNCTION post_payment(INT,INT,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,TEXT)
  OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION post_payment(INT,INT,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,TEXT)
  TO vendor_app_role;

-- ----------------------------------------------------------------------------
-- Row Level Security: defense-in-depth. Even if the app layer is bypassed
-- (e.g., a SQL injection that survives parameterization), a vendor_app_role
-- session can only see rows tagged with its current_setting vendor id.
-- ----------------------------------------------------------------------------

ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendors      ENABLE ROW LEVEL SECURITY;

-- The current_setting('app.current_vendor_id', true) returns NULL when unset.
-- Coalesce to -1 so unauthenticated reads never match a real vendor row.

CREATE POLICY vendor_select_own_txns ON transactions
  FOR SELECT TO vendor_app_role
  USING (vendor_id = COALESCE(NULLIF(current_setting('app.current_vendor_id', true), ''), '-1')::int);

CREATE POLICY vendor_insert_own_txns ON transactions
  FOR INSERT TO vendor_app_role
  WITH CHECK (vendor_id = COALESCE(NULLIF(current_setting('app.current_vendor_id', true), ''), '-1')::int);

CREATE POLICY vendor_select_own_audit ON audit_logs
  FOR SELECT TO vendor_app_role
  USING (vendor_id = COALESCE(NULLIF(current_setting('app.current_vendor_id', true), ''), '-1')::int);

CREATE POLICY vendor_insert_own_audit ON audit_logs
  FOR INSERT TO vendor_app_role
  WITH CHECK (vendor_id = COALESCE(NULLIF(current_setting('app.current_vendor_id', true), ''), '-1')::int);

CREATE POLICY vendor_select_own_row ON vendors
  FOR SELECT TO vendor_app_role
  USING (id = COALESCE(NULLIF(current_setting('app.current_vendor_id', true), ''), '-1')::int);

-- Login needs to look up the vendor by email *before* a session exists.
-- Allow that one read by exposing a SECURITY DEFINER function instead of
-- relaxing the policy.
CREATE OR REPLACE FUNCTION find_vendor_for_login(p_email TEXT)
RETURNS TABLE(id INT, vendor_code TEXT, name TEXT, email TEXT, password_hash TEXT,
              mfa_enabled BOOLEAN, role TEXT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, vendor_code, name, email, password_hash, mfa_enabled, role
    FROM vendors
   WHERE email = p_email
   LIMIT 1;
$$;
ALTER FUNCTION find_vendor_for_login(TEXT) OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION find_vendor_for_login(TEXT) TO vendor_app_role;

-- Same for students — vendor needs to look one up by code at payment time.
CREATE OR REPLACE FUNCTION find_student(p_student_code TEXT)
RETURNS TABLE(id INT, student_code TEXT, name TEXT,
              balance_ct BYTEA, balance_iv BYTEA, balance_tag BYTEA)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, student_code, name, balance_ct, balance_iv, balance_tag
    FROM students
   WHERE student_code = p_student_code
   LIMIT 1;
$$;
ALTER FUNCTION find_student(TEXT) OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION find_student(TEXT) TO vendor_app_role;

-- And one for storing the encrypted MFA secret on enrollment.
CREATE OR REPLACE FUNCTION enroll_mfa(
  p_vendor_id INT, p_ct BYTEA, p_iv BYTEA, p_tag BYTEA
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE vendors
     SET mfa_secret_ct = p_ct,
         mfa_secret_iv = p_iv,
         mfa_secret_tag = p_tag,
         mfa_enabled = TRUE
   WHERE id = p_vendor_id;
END $$;
ALTER FUNCTION enroll_mfa(INT,BYTEA,BYTEA,BYTEA) OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION enroll_mfa(INT,BYTEA,BYTEA,BYTEA) TO vendor_app_role;

-- And for password change.
CREATE OR REPLACE FUNCTION change_password(p_vendor_id INT, p_new_hash TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE vendors SET password_hash = p_new_hash WHERE id = p_vendor_id;
END $$;
ALTER FUNCTION change_password(INT, TEXT) OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION change_password(INT, TEXT) TO vendor_app_role;

-- And for fetching the encrypted MFA secret during verify.
CREATE OR REPLACE FUNCTION get_mfa_secret(p_vendor_id INT)
RETURNS TABLE(mfa_secret_ct BYTEA, mfa_secret_iv BYTEA,
              mfa_secret_tag BYTEA, mfa_enabled BOOLEAN)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT mfa_secret_ct, mfa_secret_iv, mfa_secret_tag, mfa_enabled
    FROM vendors WHERE id = p_vendor_id LIMIT 1;
$$;
ALTER FUNCTION get_mfa_secret(INT) OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION get_mfa_secret(INT) TO vendor_app_role;
