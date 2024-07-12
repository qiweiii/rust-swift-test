use std::io::Cursor;
use std::os::raw::c_uchar;
use std::ptr;

use ark_ec_vrfs::{prelude::ark_serialize, suites::bandersnatch::edwards as bandersnatch};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch::Public;

use crate::bandersnatch_vrfs::{Prover, Verifier};

// TODO: add secret_new_from_seed, secret_get_public

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CPublic([u8; 32]);

impl From<CPublic> for Public {
    fn from(c_public: CPublic) -> Self {
        Public::deserialize_compressed(&c_public.0[..]).expect("CPublic to Public failed")
    }
}

impl From<Public> for CPublic {
    fn from(public: Public) -> Self {
        let mut buffer = Vec::with_capacity(32);
        let mut cursor = Cursor::new(&mut buffer);
        public
            .serialize_compressed(&mut cursor)
            .expect("Public to CPublic failed");

        let mut c_public_bytes = [0u8; 32];
        c_public_bytes.copy_from_slice(&buffer);
        CPublic(c_public_bytes)
    }
}

#[no_mangle]
pub extern "C" fn public_deserialize_compressed(data: *const u8, len: usize) -> *mut CPublic {
    if data.is_null() {
        std::ptr::null_mut()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        // println!("{:?}", slice);
        match Public::deserialize_compressed(slice) {
            Ok(public) => Box::into_raw(Box::new(public.into())),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn prover_new(
    ring: *const CPublic,
    ring_len: usize,
    prover_idx: usize,
    success: *mut bool,
) -> *mut Prover {
    if ring.is_null() || success.is_null() {
        unsafe { *success = false };
        std::ptr::null_mut()
    } else {
        let ring_slice_c = unsafe { std::slice::from_raw_parts(ring, ring_len) };
        let ring_vec = ring_slice_c.iter().map(|&cp| cp.into()).collect();
        let prover = Prover::new(ring_vec, prover_idx);
        let boxed_prover = Box::new(prover);
        unsafe { *success = true };
        Box::into_raw(boxed_prover)
    }
}

/// out is 784 bytes
#[no_mangle]
pub extern "C" fn prover_ring_vrf_sign(
    out: *mut u8,
    prover: *const Prover,
    vrf_input_data: *const u8,
    vrf_input_len: usize,
    aux_data: *const u8,
    aux_data_len: usize,
) -> bool {
    if prover.is_null()
        || vrf_input_data.is_null()
        || aux_data.is_null()
        || vrf_input_len == 0
        || aux_data_len == 0
        || out.is_null()
    {
        return false;
    }

    let vrf_input_slice = unsafe { std::slice::from_raw_parts(vrf_input_data, vrf_input_len) };
    let aux_data_slice = unsafe { std::slice::from_raw_parts(aux_data, aux_data_len) };
    let prover = unsafe { &*prover };

    let result = prover.ring_vrf_sign(vrf_input_slice, aux_data_slice);
    if result.len() != 784 {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(result.as_ptr(), out, result.len());
    }
    true
}

/// out is 96 bytes
#[no_mangle]
pub extern "C" fn prover_ietf_vrf_sign(
    out: *mut u8,
    prover: *const Prover,
    vrf_input_data: *const u8,
    vrf_input_len: usize,
    aux_data: *const u8,
    aux_data_len: usize,
) -> bool {
    if prover.is_null()
        || vrf_input_data.is_null()
        || aux_data.is_null()
        || vrf_input_len == 0
        || aux_data_len == 0
        || out.is_null()
    {
        return false;
    }

    let vrf_input_slice = unsafe { std::slice::from_raw_parts(vrf_input_data, vrf_input_len) };
    let aux_data_slice = unsafe { std::slice::from_raw_parts(aux_data, aux_data_len) };
    let prover = unsafe { &*prover };

    let result = prover.ietf_vrf_sign(vrf_input_slice, aux_data_slice);
    if result.len() != 96 {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(result.as_ptr(), out, result.len());
    }
    true
}

#[no_mangle]
pub extern "C" fn verifier_new(
    ring: *const CPublic,
    ring_len: usize,
    success: *mut bool,
) -> *mut Verifier {
    if ring.is_null() || success.is_null() {
        unsafe { *success = false };
        std::ptr::null_mut()
    } else {
        let ring_slice_c = unsafe { std::slice::from_raw_parts(ring, ring_len) };
        let ring_vec = ring_slice_c.iter().map(|&cp| cp.into()).collect();
        let verifier = Verifier::new(ring_vec);
        let boxed_verifier = Box::new(verifier);
        unsafe { *success = true };
        Box::into_raw(boxed_verifier)
    }
}

/// out is 32 bytes
#[no_mangle]
pub extern "C" fn verifier_ring_vrf_verify(
    out: *mut u8,
    verifier: *const Verifier,
    vrf_input_data: *const c_uchar,
    vrf_input_len: usize,
    aux_data: *const c_uchar,
    aux_data_len: usize,
    signature: *const c_uchar,
    signature_len: usize,
) -> bool {
    if verifier.is_null()
        || vrf_input_data.is_null()
        || aux_data.is_null()
        || signature.is_null()
        || vrf_input_len == 0
        || aux_data_len == 0
        || signature_len == 0
        || out.is_null()
    {
        return false;
    }

    let vrf_input_slice = unsafe { std::slice::from_raw_parts(vrf_input_data, vrf_input_len) };
    let aux_data_slice = unsafe { std::slice::from_raw_parts(aux_data, aux_data_len) };
    let signature_slice = unsafe { std::slice::from_raw_parts(signature, signature_len) };

    let verifier = unsafe { &*verifier };

    let result_array =
        match verifier.ring_vrf_verify(vrf_input_slice, aux_data_slice, signature_slice) {
            Ok(array) => array,
            Err(_) => return false, // Handle error case
        };

    unsafe {
        std::ptr::copy_nonoverlapping(result_array.as_ptr(), out, result_array.len());
    }

    true
}

/// out is 32 bytes
#[no_mangle]
pub extern "C" fn verifier_ietf_vrf_verify(
    out: *mut u8,
    verifier: *const Verifier,
    vrf_input_data: *const c_uchar,
    vrf_input_len: usize,
    aux_data: *const c_uchar,
    aux_data_len: usize,
    signature: *const c_uchar,
    signature_len: usize,
    signer_key_index: usize,
) -> bool {
    if verifier.is_null()
        || vrf_input_data.is_null()
        || aux_data.is_null()
        || signature.is_null()
        || vrf_input_len == 0
        || aux_data_len == 0
        || signature_len == 0
        || out.is_null()
    {
        return false;
    }

    let vrf_input_slice = unsafe { std::slice::from_raw_parts(vrf_input_data, vrf_input_len) };
    let aux_data_slice = unsafe { std::slice::from_raw_parts(aux_data, aux_data_len) };
    let signature_slice = unsafe { std::slice::from_raw_parts(signature, signature_len) };

    let verifier = unsafe { &*verifier };

    let result_array = match verifier.ietf_vrf_verify(
        vrf_input_slice,
        aux_data_slice,
        signature_slice,
        signer_key_index,
    ) {
        Ok(array) => array,
        Err(_) => return false, // Handle error case
    };

    unsafe {
        std::ptr::copy_nonoverlapping(result_array.as_ptr(), out, result_array.len());
    }

    true
}
