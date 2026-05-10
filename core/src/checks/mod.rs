//! Check modules. Each one exposes a `run(...)` function returning `Vec<Finding>`.
//!
//! The five seed checks are ported from `audit.py`. New checks are added as
//! sibling modules and registered in the `run_all_checks` pipeline in `lib.rs`.

pub mod ai_agent;
pub mod auth;
pub mod cors;
pub mod database;
pub mod secrets;
