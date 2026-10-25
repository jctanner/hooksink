//! A durable webhook sink. Senders post deliveries to a channel; consumers
//! read them back in order by cursor, optionally long-polling for new ones.

pub mod admin;
pub mod api;
pub mod config;
pub mod store;
pub mod tokens;
pub mod verify;
