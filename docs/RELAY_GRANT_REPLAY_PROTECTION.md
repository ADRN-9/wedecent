# Relay connection-grant replay protection

A valid account connection grant is a short-lived bearer credential. Relay admission
therefore treats its `jti` as single-use for the target device.

The outer Worker first verifies the endpoint `wdt2` ticket and the signed account
connection grant. Only after both proofs pass does it copy the verified grant `jti`
and expiry into internal headers sent to the target device's `DeviceRelay` Durable
Object. Client-supplied values for those internal headers are deleted first, and the
raw connection-grant and relay authorization credentials are stripped before the
request is forwarded internally.

`DeviceRelay` atomically records each verified `jti` in Durable Object storage before
upgrading the client WebSocket. A second attempt with the same grant is rejected with
HTTP 409. Client admission is serialized around agent-slot selection and replay
consumption so adding the storage await cannot allow two clients to claim the same
parked agent slot.

Replay records remain durable across Durable Object hibernation/restart. Each record
is retained through the connection grant's expiry plus the relay clock-skew window.
A Durable Object alarm deletes expired records and schedules the next cleanup.

Agent relay slots are unaffected and do not carry account connection grants.
