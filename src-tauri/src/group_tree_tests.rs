//! Unit tests for the nested connection-group tree helpers in `commands.rs`.
//!
//! Covers the cycle detector that gates re-parenting. Pure function over a
//! slice of `ConnectionGroup`s, so it doesn't need any Tauri runtime or
//! filesystem.

#[cfg(test)]
mod tests {
    use crate::commands::reject_if_would_create_cycle;
    use crate::models::ConnectionGroup;

    fn g(id: &str, parent: Option<&str>) -> ConnectionGroup {
        ConnectionGroup {
            id: id.to_string(),
            name: id.to_string(),
            collapsed: false,
            sort_order: 0,
            parent_id: parent.map(|s| s.to_string()),
        }
    }

    #[test]
    fn cycle_check_none_parent_is_always_ok() {
        let groups = vec![g("a", None), g("b", Some("a")), g("c", Some("b"))];
        assert!(reject_if_would_create_cycle(&groups, "c", None).is_ok());
    }

    #[test]
    fn cycle_check_same_id_is_rejected() {
        let groups = vec![g("a", None)];
        let err = reject_if_would_create_cycle(&groups, "a", Some("a")).unwrap_err();
        assert!(err.to_lowercase().contains("cycle"));
    }

    #[test]
    fn cycle_check_direct_parent_is_rejected() {
        let groups = vec![g("a", Some("b")), g("b", None)];
        let err = reject_if_would_create_cycle(&groups, "b", Some("a")).unwrap_err();
        assert!(err.to_lowercase().contains("cycle"));
    }

    #[test]
    fn cycle_check_deep_descendant_is_rejected() {
        let groups = vec![
            g("a", Some("b")),
            g("b", Some("c")),
            g("c", None),
        ];
        let err = reject_if_would_create_cycle(&groups, "c", Some("a")).unwrap_err();
        assert!(err.to_lowercase().contains("cycle"));
    }

    #[test]
    fn cycle_check_unrelated_target_is_ok() {
        let groups = vec![
            g("a1", Some("a")),
            g("a", None),
            g("b1", Some("b")),
            g("b", None),
        ];
        assert!(reject_if_would_create_cycle(&groups, "a", Some("b")).is_ok());
    }

    #[test]
    fn cycle_check_handles_preexisting_cycle_safely() {
        let c = g("c", None);
        let groups = vec![g("a", Some("b")), g("b", Some("a")), c];
        let result = reject_if_would_create_cycle(&groups, "c", Some("a"));
        assert!(result.is_err());
    }

    #[test]
    fn cycle_check_target_not_in_tree_is_ok() {
        let groups = vec![g("a", None), g("b", Some("a"))];
        assert!(reject_if_would_create_cycle(&groups, "b", Some("a")).is_ok());
    }
}
