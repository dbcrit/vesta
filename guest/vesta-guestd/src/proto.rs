// SPDX-License-Identifier: Apache-2.0
//! prost types generated from `api/proto` (build.rs). Module nesting mirrors
//! the proto packages so cross-package references resolve.

#[allow(clippy::all, missing_debug_implementations)]
pub mod vesta {
    pub mod channel {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/vesta.channel.v1.rs"));
        }
    }
    pub mod event {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/vesta.event.v1.rs"));
        }
    }
}

pub use vesta::channel::v1 as channel;
pub use vesta::event::v1 as event;

/// Protocol version implemented by this guestd (api/channel/constants.go).
pub const PROTO_MAJOR: u32 = 1;
pub const PROTO_MINOR: u32 = 0;
