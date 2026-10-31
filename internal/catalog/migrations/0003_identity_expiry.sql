-- Identity expiry bounds decision validity (specification 2.5, DEC-005).
-- NULL means the identity does not expire.
ALTER TABLE identities ADD COLUMN expires_at timestamptz;
