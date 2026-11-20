//! An individual's personal CRM, made at runtime on its first use. The organisation, its stable
//! entity types and default policy are otherwise configuration the migrations path writes with the
//! admin credential (`python -m crm.migrate init`), never crm-api.

use crate::err::{CrmError, Detail, R};
use crate::store::Store;

/// crm-api's runtime path to an individual's personal CRM (`orgs`). crm-api's role may not write
/// the organisation, its policy or its definitions, so this calls `crm_bootstrap_personal_org`,
/// the function the migrations path made for exactly this. It accepts an org of one (`p-<id>`) only.
pub fn ensure_personal_org(store: &Store, org: &str, name: &str) -> R<()> {
    ensure_personal_org_created(store, org, name).map(|_| ())
}

/// `ensure_personal_org` with what it made (`org`, the type names, `field_classes`).
pub fn ensure_personal_org_created(store: &Store, org: &str, name: &str) -> R<Vec<String>> {
    let org = crate::val::strip(org);
    if !crate::orgs::is_personal_org(org) {
        return Err(CrmError::new("ValueError", 500, Detail::Internal("only an individual's own CRM (p-<id>) is made at runtime".into())));
    }
    let name = if name.is_empty() { org } else { name };
    store.engine_begin(|c| {
        let made = c.scalar("SELECT crm_bootstrap_personal_org($1, $2)", &[&org, &name])?;
        Ok(made.map(|v| crate::val::strings(&v)).unwrap_or_default())
    })
}
