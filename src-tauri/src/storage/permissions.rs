use super::roles::OrganizationRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    View,
    Create,
    Update,
    Delete,
    Share,
    ManageMembers,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Share => "share",
            Self::ManageMembers => "manage_members",
        }
    }
}

pub fn has_permission(role: OrganizationRole, permission: Permission) -> bool {
    match role {
        OrganizationRole::Admin => true,

        OrganizationRole::Manager => matches!(
            permission,
            Permission::View
                | Permission::Create
                | Permission::Update
                | Permission::Delete
                | Permission::Share
                | Permission::ManageMembers
        ),

        OrganizationRole::Member => matches!(permission, Permission::View),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_strings_are_correct() {
        assert_eq!(Permission::View.as_str(), "view");
        assert_eq!(Permission::Create.as_str(), "create");
        assert_eq!(Permission::Update.as_str(), "update");
        assert_eq!(Permission::Delete.as_str(), "delete");
        assert_eq!(Permission::Share.as_str(), "share");
        assert_eq!(Permission::ManageMembers.as_str(), "manage_members");
    }

    #[test]
    fn admin_has_all_permissions() {
        let permissions = [
            Permission::View,
            Permission::Create,
            Permission::Update,
            Permission::Delete,
            Permission::Share,
            Permission::ManageMembers,
        ];

        for permission in permissions {
            assert!(has_permission(OrganizationRole::Admin, permission));
        }
    }

    #[test]
    fn manager_has_all_vault_permissions() {
        let permissions = [
            Permission::View,
            Permission::Create,
            Permission::Update,
            Permission::Delete,
            Permission::Share,
            Permission::ManageMembers,
        ];

        for permission in permissions {
            assert!(has_permission(OrganizationRole::Manager, permission));
        }
    }

    #[test]
    fn member_can_only_view() {
        assert!(has_permission(OrganizationRole::Member, Permission::View));

        assert!(!has_permission(
            OrganizationRole::Member,
            Permission::Create
        ));

        assert!(!has_permission(
            OrganizationRole::Member,
            Permission::Update
        ));

        assert!(!has_permission(
            OrganizationRole::Member,
            Permission::Delete
        ));

        assert!(!has_permission(OrganizationRole::Member, Permission::Share));

        assert!(!has_permission(
            OrganizationRole::Member,
            Permission::ManageMembers
        ));
    }
}
