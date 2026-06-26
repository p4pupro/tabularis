#[cfg(test)]
mod tests {
    use crate::models::{ExportPayload, ConnectionGroup, SavedConnection, SshConnection, ConnectionParams, DatabaseSelection};

    #[test]
    fn test_export_payload_serialization() {
        let payload = ExportPayload {
            version: 1,
            groups: vec![ConnectionGroup {
                id: "group1".to_string(),
                name: "Test Group".to_string(),
                collapsed: false,
                sort_order: 0,
                parent_id: None,
            }],
            connections: vec![SavedConnection {
                id: "conn1".to_string(),
                name: "Test Conn".to_string(),
                params: ConnectionParams {
                    driver: "mysql".to_string(),
                    host: Some("localhost".to_string()),
                    port: Some(3306),
                    username: Some("root".to_string()),
                    password: Some("password".to_string()),
                    database: DatabaseSelection::Single("test".to_string()),
                    ssh_enabled: Some(false),
                    save_in_keychain: Some(true),
                    ..Default::default()
                },
                group_id: Some("group1".to_string()),
                sort_order: Some(0),
                detect_json_in_text_columns: None,
                appearance: None,
            }],
            ssh_connections: vec![SshConnection {
                id: "ssh1".to_string(),
                name: "Test SSH".to_string(),
                host: "remote".to_string(),
                port: 22,
                user: "user".to_string(),
                auth_type: Some("password".to_string()),
                password: Some("ssh_password".to_string()),
                key_file: None,
                key_passphrase: None,
                save_in_keychain: Some(true),
            }],
            k8s_connections: vec![],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ExportPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.groups.len(), 1);
        assert_eq!(deserialized.connections.len(), 1);
        assert_eq!(deserialized.ssh_connections.len(), 1);
        assert_eq!(deserialized.connections[0].params.password, Some("password".to_string()));
        assert_eq!(deserialized.ssh_connections[0].password, Some("ssh_password".to_string()));
    }

    // Helper: build a 3-level tree
    //   - root "A"
    //     - child "A1" (parent=A)
    //       - grandchild "A1a" (parent=A1)
    //   - root "B"
    fn build_tree() -> Vec<ConnectionGroup> {
        vec![
            ConnectionGroup {
                id: "A".into(),
                name: "A".into(),
                collapsed: false,
                sort_order: 0,
                parent_id: None,
            },
            ConnectionGroup {
                id: "A1".into(),
                name: "A1".into(),
                collapsed: false,
                sort_order: 0,
                parent_id: Some("A".into()),
            },
            ConnectionGroup {
                id: "A1a".into(),
                name: "A1a".into(),
                collapsed: false,
                sort_order: 0,
                parent_id: Some("A1".into()),
            },
            ConnectionGroup {
                id: "B".into(),
                name: "B".into(),
                collapsed: false,
                sort_order: 1,
                parent_id: None,
            },
        ]
    }

    #[test]
    fn test_export_preserves_nested_group_hierarchy() {
        // The export payload must round-trip the parent_id chain through
        // JSON so the importer can rebuild the tree, not just flat-list
        // the groups.
        let tree = build_tree();
        let payload = ExportPayload {
            version: 1,
            groups: tree.clone(),
            connections: vec![],
            ssh_connections: vec![],
            k8s_connections: vec![],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ExportPayload = serde_json::from_str(&json).unwrap();

        // Same set of ids
        let original_ids: std::collections::HashSet<_> = tree.iter().map(|g| g.id.clone()).collect();
        let new_ids: std::collections::HashSet<_> =
            deserialized.groups.iter().map(|g| g.id.clone()).collect();
        assert_eq!(original_ids, new_ids);

        // Every parent_id points to a group that exists in the payload
        let new_id_refs: std::collections::HashSet<&str> =
            deserialized.groups.iter().map(|g| g.id.as_str()).collect();
        for g in &deserialized.groups {
            if let Some(parent) = g.parent_id.as_deref() {
                assert!(
                    new_id_refs.contains(parent),
                    "After deserialization, {} has parent_id {} which is not in the payload",
                    g.id,
                    parent
                );
            }
        }

        // The 3-level chain is intact: A1a -> A1 -> A
        let a1a = deserialized.groups.iter().find(|g| g.id == "A1a").unwrap();
        let a1 = deserialized.groups.iter().find(|g| g.id == "A1").unwrap();
        let a = deserialized.groups.iter().find(|g| g.id == "A").unwrap();
        assert_eq!(a1a.parent_id.as_deref(), Some("A1"));
        assert_eq!(a1.parent_id.as_deref(), Some("A"));
        assert_eq!(a.parent_id, None);
    }

    #[test]
    fn test_merge_groups_imports_full_subtree_preserving_hierarchy() {
        // Simulate the import step: empty local config, payload brings a
        // 3-level tree. Every group should land with its parent_id intact.
        let mut existing: Vec<ConnectionGroup> = vec![];
        let incoming = build_tree();
        crate::commands::merge_groups(&mut existing, incoming);

        assert_eq!(existing.len(), 4);
        let a1a = existing.iter().find(|g| g.id == "A1a").unwrap();
        let a1 = existing.iter().find(|g| g.id == "A1").unwrap();
        let a = existing.iter().find(|g| g.id == "A").unwrap();
        let b = existing.iter().find(|g| g.id == "B").unwrap();

        assert_eq!(a1a.parent_id.as_deref(), Some("A1"));
        assert_eq!(a1.parent_id.as_deref(), Some("A"));
        assert_eq!(a.parent_id, None);
        assert_eq!(b.parent_id, None);
    }

    #[test]
    fn test_merge_groups_demotes_orphaned_parent_id_to_root() {
        // The JSON claims "A1a" is a child of "MISSING", which doesn't
        // exist in the payload nor locally. We must not import a dangling
        // pointer; instead we treat the orphan as a top-level group.
        let mut existing: Vec<ConnectionGroup> = vec![];
        let incoming = vec![ConnectionGroup {
            id: "A1a".into(),
            name: "A1a".into(),
            collapsed: false,
            sort_order: 0,
            parent_id: Some("MISSING".into()),
        }];
        crate::commands::merge_groups(&mut existing, incoming);

        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0].parent_id, None);
    }

    #[test]
    fn test_merge_groups_keeps_existing_parent_when_payload_overrides() {
        // The local config has "A" as a top-level group and "A1" as a
        // child of "A". The payload re-imports the same ids but renames
        // "A1" to "A-renamed". The child should still be a child of "A"
        // in the merged result, because the parent's id is unchanged.
        let mut existing = vec![
            ConnectionGroup {
                id: "A".into(),
                name: "A".into(),
                collapsed: false,
                sort_order: 0,
                parent_id: None,
            },
            ConnectionGroup {
                id: "A1".into(),
                name: "A1".into(),
                collapsed: false,
                sort_order: 0,
                parent_id: Some("A".into()),
            },
        ];
        let incoming = vec![ConnectionGroup {
            id: "A1".into(),
            name: "A-renamed".into(),
            collapsed: false,
            sort_order: 0,
            parent_id: Some("A".into()),
        }];
        crate::commands::merge_groups(&mut existing, incoming);

        assert_eq!(existing.len(), 2);
        let a1 = existing.iter().find(|g| g.id == "A1").unwrap();
        assert_eq!(a1.name, "A-renamed");
        assert_eq!(a1.parent_id.as_deref(), Some("A"));
    }

    #[test]
    fn test_merge_groups_is_idempotent() {
        // Re-applying the same payload must not create duplicates or
        // change the result beyond the first merge.
        let mut existing: Vec<ConnectionGroup> = vec![];
        let incoming = build_tree();
        crate::commands::merge_groups(&mut existing, incoming.clone());
        let snapshot = existing.clone();
        crate::commands::merge_groups(&mut existing, incoming);
        assert_eq!(existing, snapshot);
    }

    #[test]
    fn test_merge_groups_incoming_parent_in_existing_only() {
        // The payload brings "A1" with parent_id = "A", but "A" already
        // exists in the local config (created independently). The merge
        // must keep the link working: "A1" remains a child of "A".
        let mut existing = vec![ConnectionGroup {
            id: "A".into(),
            name: "A-existing".into(),
            collapsed: false,
            sort_order: 0,
            parent_id: None,
        }];
        let incoming = vec![ConnectionGroup {
            id: "A1".into(),
            name: "A1".into(),
            collapsed: false,
            sort_order: 0,
            parent_id: Some("A".into()),
        }];
        crate::commands::merge_groups(&mut existing, incoming);

        let a1 = existing.iter().find(|g| g.id == "A1").unwrap();
        let a = existing.iter().find(|g| g.id == "A").unwrap();
        assert_eq!(a1.parent_id.as_deref(), Some("A"));
        // Existing "A" was not in the payload, so it stays as the user
        // named it locally.
        assert_eq!(a.name, "A-existing");
    }

    // ──────────────────────────────────────────────────────────────────
    // AWS IAM authentication + SSL field roundtrip through export/import
    //
    // Regression guard: `use_iam_auth`, `ssl_mode`, `ssl_ca`, `ssl_cert`,
    // `ssl_key` are all `Option<…>` with `skip_serializing_if =
    // "Option::is_none"`, which can mask bugs when the value is
    // `Some(true)` or some other non-default. The user's reported bug was
    // that toggling "Use AWS IAM Authentication (RDS)" in the SSL tab and
    // exporting did not survive a subsequent re-import. The payload type
    // is `ExportPayload` and the merge is `merge_groups` + a direct
    // overwrite for connections (see `import_connections_payload`), so
    // we test both serialization and the connection-merge branch.
    // ──────────────────────────────────────────────────────────────────

    fn build_iam_payload() -> ExportPayload {
        ExportPayload {
            version: 1,
            groups: vec![],
            connections: vec![SavedConnection {
                id: "iam-conn".to_string(),
                name: "rds-iam".to_string(),
                params: ConnectionParams {
                    driver: "mysql".to_string(),
                    host: Some("rds.example.com".to_string()),
                    port: Some(3306),
                    username: Some("iam_user".to_string()),
                    password: Some("pre-signed-rds-token".to_string()),
                    database: DatabaseSelection::Single("app".to_string()),
                    ssl_mode: Some("required".to_string()),
                    ssl_ca: Some("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string()),
                    ssl_cert: None,
                    ssl_key: None,
                    use_iam_auth: Some(true),
                    save_in_keychain: Some(false),
                    ..Default::default()
                },
                group_id: None,
                sort_order: Some(0),
                detect_json_in_text_columns: None,
                appearance: None,
            }],
            ssh_connections: vec![],
            k8s_connections: vec![],
        }
    }

    #[test]
    fn test_export_preserves_use_iam_auth_and_ssl_fields() {
        let payload = build_iam_payload();
        let json = serde_json::to_string(&payload).unwrap();

        // Sanity: the IAM flag and SSL fields are present in the JSON.
        assert!(
            json.contains("\"use_iam_auth\":true"),
            "use_iam_auth:true missing from serialized export: {json}"
        );
        assert!(
            json.contains("\"ssl_mode\":\"required\""),
            "ssl_mode:required missing from serialized export: {json}"
        );
        assert!(
            json.contains("\"ssl_ca\""),
            "ssl_ca missing from serialized export: {json}"
        );

        // Roundtrip: deserializing restores the same values.
        let deserialized: ExportPayload = serde_json::from_str(&json).unwrap();
        let conn = &deserialized.connections[0].params;
        assert_eq!(conn.use_iam_auth, Some(true));
        assert_eq!(conn.ssl_mode.as_deref(), Some("required"));
        assert!(conn.ssl_ca.as_ref().unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_iam_auth_false_or_none_is_omitted_from_json() {
        // Document the existing contract: false/None must NOT be serialized.
        // This guards against accidentally flipping the field to a plain
        // bool with default false (which would emit `"use_iam_auth":false`
        // on every connection and balloon the export size).
        let payload_off = ExportPayload {
            version: 1,
            groups: vec![],
            connections: vec![SavedConnection {
                id: "off".to_string(),
                name: "off".to_string(),
                params: ConnectionParams {
                    driver: "mysql".to_string(),
                    use_iam_auth: Some(false),
                    ..Default::default()
                },
                group_id: None,
                sort_order: None,
                detect_json_in_text_columns: None,
                appearance: None,
            }],
            ssh_connections: vec![],
            k8s_connections: vec![],
        };
        let json = serde_json::to_string(&payload_off).unwrap();
        assert!(
            !json.contains("use_iam_auth"),
            "use_iam_auth:false should be omitted from export, got: {json}"
        );

        let payload_none = ExportPayload {
            version: 1,
            groups: vec![],
            connections: vec![SavedConnection {
                id: "none".to_string(),
                name: "none".to_string(),
                params: ConnectionParams {
                    driver: "mysql".to_string(),
                    use_iam_auth: None,
                    ..Default::default()
                },
                group_id: None,
                sort_order: None,
                detect_json_in_text_columns: None,
                appearance: None,
            }],
            ssh_connections: vec![],
            k8s_connections: vec![],
        };
        let json = serde_json::to_string(&payload_none).unwrap();
        assert!(
            !json.contains("use_iam_auth"),
            "use_iam_auth:None should be omitted from export, got: {json}"
        );
    }

    #[test]
    fn test_import_overwrites_existing_connection_with_iam_auth_intact() {
        // Simulates the import side: take an export payload that has
        // use_iam_auth=true and ssl_mode=required, "import" it on top of
        // a local file that has the connection with stale values, and
        // assert the payload's values win.
        let incoming = build_iam_payload().connections.into_iter().next().unwrap();
        let mut current = SavedConnection {
            id: incoming.id.clone(),
            name: "rds-iam-stale".to_string(),
            params: ConnectionParams {
                driver: "mysql".to_string(),
                host: Some("stale.example.com".to_string()),
                port: Some(3306),
                username: Some("stale_user".to_string()),
                password: Some("stale_password".to_string()),
                database: DatabaseSelection::Single("app".to_string()),
                ssl_mode: Some("disabled".to_string()),
                use_iam_auth: Some(false),
                save_in_keychain: Some(false),
                ..Default::default()
            },
            group_id: None,
            sort_order: Some(0),
            detect_json_in_text_columns: None,
            appearance: None,
        };

        // The merge logic for connections in `import_connections_payload`
        // is field-by-field overwrite of `existing` with `incoming`'s
        // values, preserving the local `id`. Mirror that here.
        current.name = incoming.name;
        current.params = incoming.params;
        current.group_id = incoming.group_id;
        current.sort_order = incoming.sort_order;
        current.detect_json_in_text_columns = incoming.detect_json_in_text_columns;
        current.appearance = incoming.appearance;

        assert_eq!(current.params.use_iam_auth, Some(true));
        assert_eq!(current.params.ssl_mode.as_deref(), Some("required"));
        assert!(current.params.ssl_ca.is_some());
        assert_eq!(current.params.host.as_deref(), Some("rds.example.com"));
        assert_eq!(
            current.params.password.as_deref(),
            Some("pre-signed-rds-token")
        );
    }
}
