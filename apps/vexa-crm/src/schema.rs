//! The CRM's tables (core/crm/src/crm/schema.py): every column, in table order, for a
//! `SELECT <columns>` that reads a row as SQLAlchemy's `select(table)` does. The schema itself is
//! the migrations path's (`python -m crm.migrate init`); this process never creates or alters it.

pub const SCHEMA_VERSION: i64 = 10;

pub const OBJECT_TYPES: &str = "org_id, name, definition";
pub const RECORDS: &str = "org_id, id, object_type, owner_id, revision, fields, narrative, quarantined, deleted, account_id, merged_into";
pub const POLICIES: &str = "org_id, subject_id, policy";
pub const SOURCE_MAPPINGS: &str = "org_id, system, source_org, object_type, source_id, record_id";
pub const RELATIONSHIPS: &str = "org_id, id, record_id, kind, target_domain, target_id";
pub const REVISIONS: &str = "org_id, record_id, revision, actor_id, created_at, reason, \"before\", \"after\", evidence, decision, credential_class, nonce, content_hash";
pub const CHANGE_PROPOSALS: &str = "org_id, id, record_id, base_revision, author_id, patch, evidence, reason, status";
pub const OUTBOX: &str = "org_id, id, record_id, revision, event, delivered";
pub const CARD_LAYOUTS: &str = "org_id, object_type, version, layout, actor_id, reason, created_at";
pub const ORGS: &str = "org_id, name, default_policy, created_at";
pub const MATCH_IDS: &str = "org_id, identifier, record_id, proof";
pub const PAGE_REFERENCES: &str = "org_id, workspace, page, record_id";
pub const WORKSPACE_HEADS: &str = "org_id, workspace, \"commit\", updated_at";
pub const WORKSPACE_ROSTERS: &str = "org_id, workspace, subject, role";
pub const WORKSPACE_BINDINGS: &str = "org_id, workspace, record_id, created_by, created_at";
pub const AUDIT: &str = "org_id, id, at, subject, caller, session, trace, op, record_id, outcome, principal, on_behalf_of, workspace";
pub const DESK: &str = "org_id, person, ref, placed_at, seen_at";
pub const DESK_LAYOUTS: &str = "org_id, person, version, name, layout, placements, ops, author, trace, created_at";
pub const DESK_PROPOSALS: &str = "org_id, id, person, ops, reason, author, trace, status, created_at";
pub const CARD_MEMBERS: &str = "org_id, record_id, subject, status, added_by, added_at";
pub const CARD_SEEN: &str = "org_id, person, record_id, seen_at";
pub const MEMBER_SETTINGS: &str = "org_id, person, workspace, pinned, hidden, muted, notify, room_order, level, collapsed, updated_at";
pub const FIELD_CLASSES: &str = "org_id, object_type, field, class, workspaces, set_by, set_at";
pub const PROFILES: &str = "org_id, record_id, claimed_by, unclaimed_by, fields, public_fields, published, handle, claimed_at, updated_at";
pub const CARD_NONCES: &str = "org_id, nonce, record_id, person, revision, content_hash, created_at, expires_at, used_at";

/// `crm_match_ids.proof`: identity proved the address for this account at its sign-in.
pub const PROOF_SIGNIN: &str = "signin:";
/// `crm_match_ids.proof`: given with the record at its creation.
pub const PROOF_RECORD: &str = "record";
