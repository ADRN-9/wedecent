import {
  DEVICE_ACCESS_PERMISSIONS,
  parseDeviceAccessPermission,
} from "./device-access-permission.ts";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

Deno.test("accepts terminal.connect without changing its meaning", () => {
  assert(
    parseDeviceAccessPermission("terminal.connect") === "terminal.connect",
    "terminal.connect must remain independently supported",
  );
});

Deno.test("accepts mesh.forward without implying terminal.connect", () => {
  assert(
    parseDeviceAccessPermission("mesh.forward") === "mesh.forward",
    "mesh.forward must remain independently supported",
  );
  assert(
    DEVICE_ACCESS_PERMISSIONS.length === 2,
    "only the two explicitly supported permissions may be accepted",
  );
});

Deno.test("rejects unknown, null, and non-string permissions", () => {
  for (const value of ["terminal", "mesh", "admin", "", null, 1, {}, ["mesh.forward"]]) {
    assert(
      parseDeviceAccessPermission(value) === null,
      "unsupported permission values must fail closed",
    );
  }
});
