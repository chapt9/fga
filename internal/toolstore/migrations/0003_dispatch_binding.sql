-- A dispatch records the destination it was authorized for, exactly as it
-- was then (binding), and the time after which no worker may still send
-- (send_deadline); reconciliation asks that destination, and takes "never
-- received" for a failure only after the deadline (review v4 F01 to F03).
-- checked_at orders reconciliation so every open invocation is reached
-- (F06).
ALTER TABLE invocations ADD COLUMN binding jsonb;
ALTER TABLE invocations ADD COLUMN send_deadline timestamptz;
ALTER TABLE invocations ADD COLUMN checked_at timestamptz;
