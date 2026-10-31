-- An UNKNOWN invocation held past its tool's maximum hold age is escalated
-- once (INV-006); escalated_at records when.
ALTER TABLE invocations ADD COLUMN escalated_at timestamptz;
