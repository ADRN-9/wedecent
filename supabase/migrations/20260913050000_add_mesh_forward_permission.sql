-- Keep route forwarding authorization separate from terminal access.
-- This migration intentionally contains only the enum change so the new
-- value is committed before later migrations use it.

alter type public.device_permission
add value if not exists 'mesh.forward';
