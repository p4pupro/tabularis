/**
 * Canonical TypeScript shape of a `ConnectionParams` value as it appears
 * on the wire between the Tauri backend and the React UI.
 *
 * Field names use snake_case to match the Rust model
 * (`src-tauri/src/models.rs::ConnectionParams`). Rust serializes with
 * default field names (no `rename_all`), so this is the same shape
 * that lands in the on-disk `connections.json` and in the export
 * payload (`ExportPayload.connections[*].params`).
 *
 * `Option<T>` in Rust maps to `T | undefined` here. Serde uses
 * `skip_serializing_if = "Option::is_none"` on the Rust side, so
 * `None` / `false` for booleans is omitted from the export JSON
 * unless the value is `Some(true)`.
 */

export type IconOverride =
  | { type: "pack"; id: string }
  | { type: "emoji"; value: string }
  | { type: "image"; path: string };

export interface ConnectionAppearance {
  icon?: IconOverride;
  accentColor?: string;
}

export interface ConnectionParams {
  driver: string;
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  /** String for single-db drivers, array for multi-db drivers. */
  database: string | string[];
  /** SSL/TLS mode: one of the driver-specific tokens (e.g.
   *  "disabled", "preferred", "required", "verify-ca", "verify-full"). */
  ssl_mode?: string;
  ssl_ca?: string;
  ssl_cert?: string;
  ssl_key?: string;
  /**
   * When `true`, the `password` field is a pre-signed RDS auth token
   * (from `aws rds generate-db-auth-token`) instead of a real
   * password. Requires TLS; only meaningful for the `mysql` driver.
   */
  use_iam_auth?: boolean;
  // SSH
  ssh_enabled?: boolean;
  ssh_connection_id?: string;
  // Legacy SSH fields (kept for backward compatibility during migration)
  ssh_host?: string;
  ssh_port?: number;
  ssh_user?: string;
  ssh_password?: string;
  ssh_key_file?: string;
  ssh_key_passphrase?: string;
  save_in_keychain?: boolean;
  // Kubernetes tunnel (mutually exclusive with SSH)
  k8s_enabled?: boolean;
  k8s_connection_id?: string;
  k8s_context?: string;
  k8s_namespace?: string;
  k8s_resource_type?: string; // "service" or "pod"
  k8s_resource_name?: string;
  k8s_port?: number;
  // Stable connection id used for pool lookups (set at runtime; not
  // always present on disk).
  connection_id?: string;
}

/** A connection persisted to `connections.json` and to the export file. */
export interface SavedConnection {
  id: string;
  name: string;
  params: ConnectionParams;
  detect_json_in_text_columns?: boolean;
  appearance?: ConnectionAppearance;
}

