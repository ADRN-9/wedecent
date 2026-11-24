-- Separate port-forward permissions remain distinct from terminal and routing authority.
-- Keep enum additions in their own migration so later migrations can safely use them.
alter type public.device_permission add value if not exists 'port_forward.local';
alter type public.device_permission add value if not exists 'port_forward.remote';
