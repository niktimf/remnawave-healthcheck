pub mod checks;
pub mod facts;

pub use checks::{check_host, egress_ip};
pub use facts::{gather, HostFacts};
