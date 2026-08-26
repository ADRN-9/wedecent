# Supabase development assets

The `supabase/migrations/` directory contains the control-plane schema that will back WeDecent account authorization. The relay/terminal data path does not depend on this schema yet.

Apply migrations with the Supabase CLI against a disposable/local project first, then run `supabase test db` (pgTAP tests live in `supabase/tests/database/`), then deploy to a staging project before production. Do not place project service-role keys, database passwords, access tokens, or JWT signing material in this repository.

The account-authorization foundation intentionally gives browser-authenticated users no write privilege on `public.devices`, `public.device_enrollment_challenges`, or `public.connection_grants`. A future trusted enrollment/grant service will perform those writes only after verifying endpoint proof of possession and account authorization.
