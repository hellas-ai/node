pub mod pb;

// define NAME and PACKAGE for Presence
use crate::pb::hellas::Presence;
use prost::Name;

impl Name for Presence {
    const NAME: &'static str = "Presence";
    const PACKAGE: &'static str = "hellas";
}
