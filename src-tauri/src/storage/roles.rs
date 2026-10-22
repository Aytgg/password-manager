#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationRole {
    Admin,
    Manager,
    Member,
}

impl OrganizationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "Yönetici",
            Self::Manager => "Departman Yöneticisi",
            Self::Member => "Personel",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "Yönetici" => Ok(Self::Admin),
            "Departman Yöneticisi" => Ok(Self::Manager),
            "Personel" => Ok(Self::Member),
            _ => Err(format!("Bilinmeyen departman: {value}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_strings_are_correct() {
        assert_eq!(OrganizationRole::Admin.as_str(), "Yönetici");
        assert_eq!(OrganizationRole::Manager.as_str(), "Departman Yöneticisi");
        assert_eq!(OrganizationRole::Member.as_str(), "Personel");
    }

    #[test]
    fn role_can_be_parsed() {
        assert_eq!(
            OrganizationRole::parse("Yönetici").unwrap(),
            OrganizationRole::Admin
        );

        assert_eq!(
            OrganizationRole::parse("Departman Yöneticisi").unwrap(),
            OrganizationRole::Manager
        );

        assert_eq!(
            OrganizationRole::parse("Personel").unwrap(),
            OrganizationRole::Member
        );
    }

    #[test]
    fn role_round_trip_works() {
        let roles = [
            OrganizationRole::Admin,
            OrganizationRole::Manager,
            OrganizationRole::Member,
        ];

        for role in roles {
            assert_eq!(OrganizationRole::parse(role.as_str()).unwrap(), role);
        }
    }

    #[test]
    fn unknown_role_returns_error() {
        let result = OrganizationRole::parse("Bilinmeyen Rol");

        assert!(result.is_err());
    }
}
