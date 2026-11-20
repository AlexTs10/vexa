//! card_templates: the seeded lifecycle templates of the card kinds.
//!
//! A card of a KIND follows that kind's template: its stages, its side states, and the GATES a
//! person passes it through. A template is seeded policy: an org may restate the stage names in
//! `_global/POLICIES.md` as `card_templates.<kind>: Stage > Stage > … | Side | Side`; the gate
//! semantics are the platform's, because they are who may move a card.
//!
//! * **commitment** — proposed → accepted → delivered (with evidence) → confirmed → closed.
//! * **approval** (also `invitation`, `policy_change`) — opened → decided → executed (an effect
//!   receipt) → closed.
//! * **question** (also `ask`) — asked → answered → used → closed.
//!
//! Every handoff is two-phase: a gate names its next actor, who is `offered` the card; only that
//! person's acknowledgement (or a gate action they take) moves custody.

use serde_json::{json, Value};

/// kind -> template name
pub const KIND_TEMPLATE: [(&str, &str); 6] = [
    ("commitment", "commitment"),
    ("approval", "approval"),
    ("invitation", "approval"),
    ("policy_change", "approval"),
    ("question", "question"),
    ("ask", "question"),
];
pub const KINDS: [&str; 6] = ["commitment", "approval", "invitation", "policy_change", "question", "ask"];

/// Who a gate's next actor becomes after it passes.
pub const SAME: &str = "same";
pub const REQUESTER: &str = "requester";
pub const NOBODY: &str = "nobody";

/// The order actions are offered in a decision block (the primary first, decline last).
pub const ACTION_ORDER: [&str; 8] = ["acknowledge", "decide", "answer", "deliver", "confirm", "use", "execute", "decline"];
pub const ACTION_LABELS: [(&str, &str); 8] = [
    ("acknowledge", "Accept"), ("decide", "Approve"), ("answer", "Answer"), ("deliver", "Mark delivered"),
    ("confirm", "Confirm"), ("use", "Done"), ("execute", "Executed"), ("decline", "Decline"),
];
pub const DONE_WORDS: [(&str, &str); 8] = [
    ("acknowledge", "Accepted"), ("decide", "Approved"), ("answer", "Answered"), ("deliver", "Delivered"),
    ("confirm", "Confirmed"), ("use", "Used"), ("execute", "Executed"), ("decline", "Declined"),
];

/// A gate: `from` the stages it may be taken in, `to` the stage it moves to, `needs` what the
/// action must carry, `then` who is offered the card next, `passes` the stage it passes on the way.
#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
    pub from: Vec<String>,
    pub to: Option<String>,
    pub needs: Option<&'static str>,
    pub then: &'static str,
    pub passes: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    pub name: &'static str,
    pub stages: Vec<String>,
    pub side: Vec<String>,
    /// In the template's declared order.
    pub gates: Vec<(&'static str, Gate)>,
}

impl Template {
    pub fn gate(&self, action: &str) -> Option<&Gate> {
        self.gates.iter().find(|(a, _)| *a == action).map(|(_, g)| g)
    }
}

pub fn kind_template(kind: &str) -> Option<&'static str> {
    KIND_TEMPLATE.iter().find(|(k, _)| *k == kind).map(|(_, t)| *t)
}

pub fn done_word(action: &str) -> Option<&'static str> {
    DONE_WORDS.iter().find(|(a, _)| *a == action).map(|(_, w)| *w)
}

fn gate(from: &[&str], to: Option<&str>, needs: Option<&'static str>, then: &'static str, passes: Option<&str>) -> Gate {
    Gate { from: from.iter().map(|s| s.to_string()).collect(), to: to.map(str::to_owned), needs, then, passes: passes.map(str::to_owned) }
}

fn base(name: &str) -> Option<Template> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    Some(match name {
        "commitment" => Template {
            name: "commitment",
            stages: s(&["proposed", "accepted", "delivered", "confirmed", "closed"]),
            side: s(&["declined", "expired"]),
            gates: vec![
                ("acknowledge", gate(&["proposed"], Some("accepted"), None, SAME, None)),
                ("deliver", gate(&["proposed", "accepted"], Some("delivered"), Some("evidence"), REQUESTER, None)),
                ("confirm", gate(&["delivered"], Some("closed"), None, NOBODY, Some("confirmed"))),
                ("decline", gate(&["proposed", "accepted"], Some("declined"), None, NOBODY, None)),
            ],
        },
        "approval" => Template {
            name: "approval",
            stages: s(&["opened", "decided", "executed", "closed"]),
            side: s(&["declined", "expired"]),
            gates: vec![
                ("acknowledge", gate(&["opened"], None, None, SAME, None)),
                ("decide", gate(&["opened"], Some("decided"), None, REQUESTER, None)),
                ("execute", gate(&["decided"], Some("closed"), Some("receipt"), NOBODY, Some("executed"))),
                ("decline", gate(&["opened"], Some("declined"), None, NOBODY, None)),
            ],
        },
        "question" => Template {
            name: "question",
            stages: s(&["asked", "answered", "used", "closed"]),
            side: s(&["declined", "expired"]),
            gates: vec![
                ("acknowledge", gate(&["asked"], None, None, SAME, None)),
                ("answer", gate(&["asked"], Some("answered"), Some("answer"), REQUESTER, None)),
                ("use", gate(&["answered"], Some("closed"), None, NOBODY, Some("used"))),
                ("decline", gate(&["asked"], Some("declined"), None, NOBODY, None)),
            ],
        },
        _ => return None,
    })
}

/// The template of a card kind (a copy), or None for a card with no kind. `override_stages` is the
/// org's `card_templates.<kind>` line parsed as (stages, side); it renames stages only when it keeps
/// their count, so a gate always lands on a stage.
pub fn template_for(kind: &str, override_stages: Option<(&[String], &[String])>) -> Option<Template> {
    let name = kind_template(kind)?;
    let mut out = base(name)?;
    if let Some((stages, side)) = override_stages {
        if !stages.is_empty() && stages.len() == out.stages.len() && side.len() == out.side.len() && !(side.is_empty() && !out.side.is_empty()) {
            let from: Vec<String> = out.stages.iter().chain(out.side.iter()).cloned().collect();
            let to: Vec<String> = stages.iter().chain(side.iter()).cloned().collect();
            let rename = |s: &str| -> String {
                // dict(zip(...)): a later duplicate source name wins
                let mut got = s.to_owned();
                for (a, b) in from.iter().zip(to.iter()) {
                    if a == s {
                        got = b.clone();
                    }
                }
                got
            };
            out.stages = out.stages.iter().map(|s| rename(s)).collect();
            out.side = out.side.iter().map(|s| rename(s)).collect();
            for (_, g) in out.gates.iter_mut() {
                g.from = g.from.iter().map(|s| rename(s)).collect();
                if let Some(t) = &g.to {
                    g.to = Some(rename(t));
                }
                if let Some(p) = &g.passes {
                    g.passes = Some(rename(p));
                }
            }
        }
    }
    Some(out)
}

/// state not in side and state != the last stage.
pub fn is_open(template: &Template, state: &Value) -> bool {
    let st = state.as_str();
    !template.side.iter().any(|s| Some(s.as_str()) == st) && template.stages.last().map(String::as_str) != st
}

/// The route as a strip of gates: each stage after the first is a gate, `done` / `current` /
/// `ahead`, with who passed it and when (from the decision records, newest first).
pub fn gate_strip(template: &Template, state: &Value, decisions: &[Value]) -> Vec<Value> {
    let stages = &template.stages;
    let mut passed_by: Vec<(String, Value)> = Vec::new();
    for d in decisions.iter().rev() {
        let Some(g) = d.get("action").and_then(Value::as_str).and_then(|a| template.gate(a)) else { continue };
        for stage in [&g.passes, &g.to].into_iter().flatten() {
            if stage.is_empty() {
                continue;
            }
            let who = json!({"by": d.get("by").cloned().unwrap_or(Value::Null), "at": d.get("at").cloned().unwrap_or(Value::Null)});
            match passed_by.iter_mut().find(|(s, _)| s == stage) {
                Some(slot) => slot.1 = who,
                None => passed_by.push((stage.clone(), who)),
            }
        }
    }
    let st = state.as_str();
    let idx: i64 = if template.side.iter().any(|s| Some(s.as_str()) == st) {
        -1
    } else {
        stages.iter().position(|s| Some(s.as_str()) == st).map(|i| i as i64).unwrap_or(0)
    };
    let mut out = Vec::new();
    for (n, stage) in stages.iter().enumerate().skip(1) {
        let n = n as i64;
        let who = passed_by.iter().find(|(s, _)| s == stage).map(|(_, w)| w.clone());
        let state = if idx < 0 {
            if who.is_some() { "done" } else { "ahead" }
        } else if n <= idx {
            "done"
        } else if n == idx + 1 {
            "current"
        } else {
            "ahead"
        };
        let who = who.unwrap_or_else(|| json!({}));
        let done = state == "done";
        out.push(json!({"name": stage, "state": state,
                        "by": if done { who.get("by").cloned().unwrap_or(Value::Null) } else { Value::Null },
                        "at": if done { who.get("at").cloned().unwrap_or(Value::Null) } else { Value::Null }}));
    }
    out
}

/// The gate actions THIS viewer may take now. Only the next actor acts on an open card;
/// `acknowledge` is offered only while the handoff is not yet acknowledged.
pub fn actions_for(template: &Template, state: &Value, handoff: &Value, viewer: &str, next_actor: &Value) -> Vec<String> {
    if viewer.is_empty() || next_actor.as_str() != Some(viewer) || !is_open(template, state) {
        return Vec::new();
    }
    let st = state.as_str();
    let mut out = Vec::new();
    for action in ACTION_ORDER {
        let Some(g) = template.gate(action) else { continue };
        if !g.from.iter().any(|s| Some(s.as_str()) == st) {
            continue;
        }
        if action == "acknowledge" && handoff.as_str() == Some("acknowledged") {
            continue;
        }
        out.push(action.to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_gates_and_actions() {
        let t = template_for("ask", None).unwrap();
        assert_eq!(t.name, "question");
        assert!(template_for("nope", None).is_none());
        let stages: Vec<String> = ["A", "B", "C", "D"].iter().map(|s| s.to_string()).collect();
        let side: Vec<String> = ["X", "Y"].iter().map(|s| s.to_string()).collect();
        let r = template_for("approval", Some((&stages, &side))).unwrap();
        assert_eq!(r.gate("execute").unwrap().passes.as_deref(), Some("C"));
        assert_eq!(r.gate("decline").unwrap().to.as_deref(), Some("X"));
        let c = template_for("commitment", None).unwrap();
        assert!(is_open(&c, &json!("accepted")));
        assert!(!is_open(&c, &json!("closed")));
        assert!(!is_open(&c, &json!("expired")));
        assert_eq!(actions_for(&c, &json!("proposed"), &json!("offered"), "u", &json!("u")), vec!["acknowledge", "deliver", "decline"]);
        assert_eq!(actions_for(&c, &json!("proposed"), &json!("acknowledged"), "u", &json!("u")), vec!["deliver", "decline"]);
        assert!(actions_for(&c, &json!("proposed"), &Value::Null, "v", &json!("u")).is_empty());
        let decisions = vec![json!({"action": "confirm", "by": "r", "at": "t2"}), json!({"action": "deliver", "by": "u", "at": "t1"})];
        let strip = gate_strip(&c, &json!("closed"), &decisions);
        assert_eq!(strip[1], json!({"name": "delivered", "state": "done", "by": "u", "at": "t1"}));
        assert_eq!(strip[0], json!({"name": "accepted", "state": "done", "by": null, "at": null}));
        let side_strip = gate_strip(&c, &json!("declined"), &decisions);
        assert_eq!(side_strip[0]["state"], "ahead");
        assert_eq!(side_strip[2], json!({"name": "confirmed", "state": "done", "by": "r", "at": "t2"}));
    }
}
