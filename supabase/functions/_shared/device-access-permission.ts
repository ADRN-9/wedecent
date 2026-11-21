export const DEVICE_ACCESS_PERMISSIONS = [
  "terminal.connect",
  "mesh.forward",
] as const;

export type DeviceAccessPermission = typeof DEVICE_ACCESS_PERMISSIONS[number];

const permissionSet = new Set<string>(DEVICE_ACCESS_PERMISSIONS);

export function parseDeviceAccessPermission(
  value: unknown,
): DeviceAccessPermission | null {
  if (typeof value !== "string" || !permissionSet.has(value)) return null;
  return value as DeviceAccessPermission;
}
