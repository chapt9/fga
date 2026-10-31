-- The security journal is a hash chain (review v2 finding 1): the catalog
-- records the chain value of the last entry it saw with the count, so
-- recovery can tell the recorded history from a journal that lost an
-- entry and was appended to since. A binding recorded before the chain
-- has head '' until its next journaled change.
ALTER TABLE journal_state ADD COLUMN head text NOT NULL DEFAULT '';
