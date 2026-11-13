//! Vexa automation engine migration scaffold.
//!
//! This binary is intentionally a shadow control surface. The existing Python
//! services remain the only production owners until every route and worker
//! action has a parity test. It never starts a second worker and it never
//! reads a secret value.

use std::env;
use std::process::ExitCode;

const LEGACY_LANES: [&str; 4] = ["flows-api", "flows-worker", "flows-mailbox", "crm-outbox"];

fn print_help() {
    println!("vexa-automation <command>");
    println!("\nCommands:");
    println!("  status       Show the safe migration state.");
    println!("  contract     Show the required legacy service boundaries.");
    println!("  check-env    Check configuration presence without showing secrets.");
    println!("  start        Refuse to start until parity checks enable this engine.");
}

fn print_status() {
    println!("mode: shadow");
    println!("production_owner: legacy-python-services");
    println!("database_owner: legacy-postgres");
    println!("network_owner: legacy-compose");
    println!("lanes:");
    for lane in LEGACY_LANES {
        println!("  - {lane}: legacy owner remains active");
    }
    println!("start: disabled until route, queue, and delivery parity checks pass");
}

fn print_contract() {
    println!("Automation migration contract");
    println!("- flows-api owns authenticated HTTP intake and flow reads.");
    println!("- flows-worker owns reaction claims, schedules, receipts, and retention.");
    println!("- flows-mailbox owns inbound mail polling and mail fact admission.");
    println!("- crm-outbox owns signed CRM fact publication.");
    println!("- The future engine must preserve PostgreSQL transactions, service-door access, and key scope.");
    println!("- The future engine must run in shadow mode before it can claim work.");
}

fn configured(name: &str) -> &'static str {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => "set",
        _ => "unset",
    }
}

fn check_env() {
    for name in [
        "VEXA_FLOWS_DB_URL",
        "VEXA_FLOWS_API_KEY",
        "VEXA_FLOWS_SERVICE_KEY",
        "VEXA_FLOWS_TIMELINE_KEY",
        "VEXA_FLOWS_CRM_PUBLISH_KEY",
    ] {
        println!("{name}: {}", configured(name));
    }
}

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        "status" => {
            print_status();
            ExitCode::SUCCESS
        }
        "contract" => {
            print_contract();
            ExitCode::SUCCESS
        }
        "check-env" => {
            check_env();
            ExitCode::SUCCESS
        }
        "start" => {
            eprintln!(
                "refusing to start: this engine is in shadow mode; legacy services still own work"
            );
            ExitCode::from(2)
        }
        _ => {
            eprintln!("unknown command: {command}");
            print_help();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LEGACY_LANES;

    #[test]
    fn contract_lists_all_legacy_lanes() {
        assert_eq!(LEGACY_LANES.len(), 4);
        assert!(LEGACY_LANES.contains(&"flows-api"));
        assert!(LEGACY_LANES.contains(&"flows-worker"));
        assert!(LEGACY_LANES.contains(&"flows-mailbox"));
        assert!(LEGACY_LANES.contains(&"crm-outbox"));
    }
}
