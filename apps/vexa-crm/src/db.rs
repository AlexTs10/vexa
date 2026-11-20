//! Transactions as the store opens them (`engine.begin()`, `engine.connect()`, `Store.begin`),
//! the pending audit row of the operation in flight (H9), and a query builder for statements whose
//! WHERE clause depends on the caller.

use std::cell::RefCell;

use vexa_native_kit::pg::{Int, ToSql, Tx};

use crate::caller::Caller;

/// The audit row of the operation in flight (store.PENDING_AUDIT): written inside the operation's
/// own transaction by `Store::begin`, else by `audited` before the answer leaves.
#[derive(Debug, Clone)]
pub struct Pending {
    pub org: String,
    pub caller: Caller,
    pub op: String,
    pub record_id: String,
    pub written: bool,
}

thread_local! {
    pub static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

pub fn pending_set(p: Option<Pending>) -> Option<Pending> {
    PENDING.with(|c| std::mem::replace(&mut *c.borrow_mut(), p))
}

pub fn pending_get() -> Option<Pending> {
    PENDING.with(|c| c.borrow().clone())
}

pub fn pending_update(f: impl FnOnce(&mut Pending)) {
    PENDING.with(|c| {
        if let Some(p) = c.borrow_mut().as_mut() {
            f(p)
        }
    })
}

/// A statement and its parameters, numbered as they are added.
#[derive(Default)]
pub struct Sql {
    pub text: String,
    params: Vec<Box<dyn ToSql + Sync>>,
}

impl Sql {
    pub fn new(text: &str) -> Self {
        Sql { text: text.to_owned(), params: Vec::new() }
    }
    /// Add a parameter; returns its placeholder ($n).
    pub fn p<T: ToSql + Sync + 'static>(&mut self, v: T) -> String {
        self.params.push(Box::new(v));
        format!("${}", self.params.len())
    }
    pub fn int(&mut self, v: i64) -> String {
        self.p(Int(v))
    }
    pub fn push(&mut self, text: &str) -> &mut Self {
        self.text.push_str(text);
        self
    }
    pub fn args(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.params.iter().map(|b| b.as_ref() as &(dyn ToSql + Sync)).collect()
    }
    pub fn maps(&self, tx: &mut Tx) -> vexa_native_kit::pg::Result<Vec<crate::val::Obj>> {
        tx.maps(&self.text, &self.args())
    }
    pub fn tuples(&self, tx: &mut Tx) -> vexa_native_kit::pg::Result<Vec<Vec<serde_json::Value>>> {
        tx.tuples(&self.text, &self.args())
    }
    pub fn exec(&self, tx: &mut Tx) -> vexa_native_kit::pg::Result<u64> {
        tx.exec(&self.text, &self.args())
    }
}
