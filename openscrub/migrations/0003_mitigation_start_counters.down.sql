-- Reverse 0003.

ALTER TABLE mitigations DROP COLUMN IF EXISTS start_packets_dropped;
ALTER TABLE mitigations DROP COLUMN IF EXISTS start_bytes_dropped;
