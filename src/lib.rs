use ark_ec_vrfs::suites::bandersnatch::edwards as bandersnatch;
// use ark_ec_vrfs::suites::bandersnatch::edwards::RingContext;
// use bandersnatch::{IetfProof, Input, Output, Public, RingProof, Secret};
// use bandersnatch_vrfs::*;

pub mod bandersnatch_vrfs;
pub use bandersnatch::{IetfProof, Input, Output, Public, RingProof, Secret};

// #[swift_bridge::bridge]
// mod ffi {
//     // Export opaque Rust types, functions and methods for Swift to use.
//     extern "Rust" {
//         type RingContext;
//         type IetfProof;
//         type Input;
//         type Output;
//         type Public;
//         type RingProof;
//         type Secret;

//         type IetfVrfSignature;

//         fn ring_context() -> &'static RingContext;

//         fn vrf_input_point(vrf_input_data: &[u8]) -> Input;
//     }
// }
