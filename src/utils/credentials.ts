import { invoke } from "@tauri-apps/api/core";
import type { ConnectionParams } from "../types/connection";

// Re-use the canonical `ConnectionParams` shape from `types/connection`
// so that the SSL fields (`ssl_ca`, `ssl_cert`, `ssl_key`) and the AWS
// IAM auth flag (`use_iam_auth`) are typed and survive the roundtrip
// through `get_connection_by_id` -> form -> `update_connection` ->
// `export_connections_payload` -> `import_connections_payload`.
export type { ConnectionParams };

export interface SavedConnectionWithCredentials {
  id: string;
  name: string;
  params: ConnectionParams;
}

export async function fetchConnectionWithCredentials(
  id: string,
): Promise<SavedConnectionWithCredentials> {
  return await invoke<SavedConnectionWithCredentials>("get_connection_by_id", {
    id,
  });
}
