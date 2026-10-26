// Only errors constructed with fixed application messages may cross a runtime
// boundary. Library/browser errors can contain private inputs or stored values.
export class SafeError extends Error {}

export const OPERATION_ERROR =
  'Operation failed. Check extension settings and try again.'
export function errorResponse(error) {
  return {
    error: {
      message: error instanceof SafeError ? error.message : OPERATION_ERROR
    }
  }
}
