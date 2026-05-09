-- Audit and immutability triggers.

-- 1. After every transaction insert, copy a row into audit_logs.
CREATE OR REPLACE FUNCTION log_transaction_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO audit_logs (user_id, vendor_id, action, txn_hash, success, detail)
  VALUES (
    NEW.student_id,
    NEW.vendor_id,
    'transaction.' || NEW.status,
    NEW.txn_hash,
    NEW.status = 'success',
    jsonb_build_object('transaction_id', NEW.id, 'created_at', NEW.created_at)
  );
  RETURN NEW;
END $$;
ALTER FUNCTION log_transaction_insert() OWNER TO admin_migration_role;

DROP TRIGGER IF EXISTS trg_log_transaction_insert ON transactions;
CREATE TRIGGER trg_log_transaction_insert
  AFTER INSERT ON transactions
  FOR EACH ROW EXECUTE FUNCTION log_transaction_insert();

-- 2. audit_logs is APPEND-ONLY. Any attempt to UPDATE or DELETE raises.
--    Even though vendor_app_role isn't granted UPDATE/DELETE, this guards
--    against compromise of the migration role and against future GRANT mistakes.
CREATE OR REPLACE FUNCTION block_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only — % is forbidden', TG_OP;
END $$;
ALTER FUNCTION block_audit_mutation() OWNER TO admin_migration_role;

DROP TRIGGER IF EXISTS trg_audit_no_update ON audit_logs;
CREATE TRIGGER trg_audit_no_update
  BEFORE UPDATE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION block_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_no_delete ON audit_logs;
CREATE TRIGGER trg_audit_no_delete
  BEFORE DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION block_audit_mutation();

-- 3. Event trigger: log any DDL DROP attempted in this database.
CREATE OR REPLACE FUNCTION log_unauthorized_drop()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
    INSERT INTO unauthorized_access_log
      (attempted_role, attempted_action, attempted_table, detail)
    VALUES
      (current_user, 'DROP', obj.object_identity,
       jsonb_build_object('object_type', obj.object_type,
                          'schema', obj.schema_name));
  END LOOP;
END $$;

DROP EVENT TRIGGER IF EXISTS trg_log_drops;
CREATE EVENT TRIGGER trg_log_drops
  ON sql_drop
  EXECUTE FUNCTION log_unauthorized_drop();

-- 4. Helper the app calls when it catches a permission error (42501) or RLS
--    denial. SECURITY DEFINER so it can write even if the caller can't see
--    audit tables.
CREATE OR REPLACE FUNCTION log_unauthorized_access(
  p_role   TEXT,
  p_action TEXT,
  p_table  TEXT,
  p_ip     TEXT,
  p_detail JSONB
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO unauthorized_access_log
    (attempted_role, attempted_action, attempted_table, ip, detail)
  VALUES
    (p_role, p_action, p_table, NULLIF(p_ip, '')::INET, p_detail);
END $$;
ALTER FUNCTION log_unauthorized_access(TEXT,TEXT,TEXT,TEXT,JSONB)
  OWNER TO admin_migration_role;
GRANT EXECUTE ON FUNCTION log_unauthorized_access(TEXT,TEXT,TEXT,TEXT,JSONB)
  TO vendor_app_role;
