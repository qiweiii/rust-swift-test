// Code copied and modified based on: https://github.com/davxy/bandersnatch-vrfs-spec/blob/main/example/src/main.rs
// Changes: made RING_SIZE configurable, and add stuff for cbindgen

use std::mem::size_of;
use std::os::raw::c_uchar;
use std::ptr;

use ark_ec_vrfs::suites::bandersnatch::edwards as bandersnatch;
use ark_ec_vrfs::{prelude::ark_serialize, suites::bandersnatch::edwards::RingContext};
use bandersnatch::{IetfProof, Input, Output, Public, RingProof, Secret};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

const RING_SIZE_DEFAULT: usize = 1023;

#[no_mangle]
pub extern "C" fn sizeof_public() -> usize {
    size_of::<Public>()
}

#[no_mangle]
pub extern "C" fn public_deserialize_compressed(data: *const u8, len: usize) -> *mut Public {
    if data.is_null() {
        std::ptr::null_mut()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        match Public::deserialize_compressed(slice) {
            Ok(public) => Box::into_raw(Box::new(public)),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn prover_new(
    ring: *const Public,
    ring_len: usize,
    prover_idx: usize,
    success: *mut bool,
) -> *mut Prover {
    if ring.is_null() || success.is_null() {
        unsafe { *success = false };
        std::ptr::null_mut()
    } else {
        let ring_slice = unsafe { std::slice::from_raw_parts(ring, ring_len) };
        let ring_vec = ring_slice.to_vec();
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
    ring: *const Public,
    ring_len: usize,
    success: *mut bool,
) -> *mut Verifier {
    if ring.is_null() || success.is_null() {
        unsafe { *success = false };
        std::ptr::null_mut()
    } else {
        let ring_slice = unsafe { std::slice::from_raw_parts(ring, ring_len) };
        let ring_vec = ring_slice.to_vec();
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
        || signature_len != 32
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
        || signature_len != 64
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

// This is the IETF `Prove` procedure output as described in section 2.2
// of the Bandersnatch VRFs specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[repr(C)]
pub struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

// This is the IETF `Prove` procedure output as described in section 4.2
// of the Bandersnatch VRFs specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
#[repr(C)]
pub struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

// "Static" ring context data
fn ring_context() -> &'static RingContext {
    use std::sync::OnceLock;
    static RING_CTX: OnceLock<RingContext> = OnceLock::new();
    let ring_size: usize = std::env::var("RING_SIZE").map_or(RING_SIZE_DEFAULT, |s| {
        s.parse().unwrap_or_else(|_| RING_SIZE_DEFAULT)
    });
    RING_CTX.get_or_init(|| {
        use bandersnatch::PcsParams;
        use std::{fs::File, io::Read};
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
        let filename = format!("{}/data/zcash-srs-2-11-uncompressed.bin", manifest_dir);
        let mut file = File::open(filename).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
        RingContext::from_srs(ring_size, pcs_params).unwrap()
    })
}

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    let point =
        <bandersnatch::BandersnatchSha512Ell2 as ark_ec_vrfs::Suite>::data_to_point(vrf_input_data)
            .unwrap();
    Input::from(point)
}

// Prover actor.
pub struct Prover {
    pub prover_idx: usize,
    pub secret: Secret,
    pub ring: Vec<Public>,
}

impl Prover {
    fn new(ring: Vec<Public>, prover_idx: usize) -> Self {
        Self {
            prover_idx,
            secret: Secret::from_seed(&prover_idx.to_le_bytes()),
            ring,
        }
    }

    /// Anonymous VRF signature.
    ///
    /// Used for tickets submission.
    pub fn ring_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_ec_vrfs::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let ring_ctx = ring_context();
        let prover_key = ring_ctx.prover_key(&pts);
        let prover = ring_ctx.prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        // Output and Ring Proof bundled together (as per section 2.2)
        let signature = RingVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// Non-Anonymous VRF signature.
    ///
    /// Used for ticket claiming during block production.
    /// Not used with Safrole test vectors.
    pub fn ietf_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_ec_vrfs::ietf::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        let proof = self.secret.prove(input, output, aux_data);

        // Output and IETF Proof bundled together (as per section 2.2)
        let signature = IetfVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

/// cbindgen:ignore
pub type RingCommitment = ark_ec_vrfs::ring::RingCommitment<bandersnatch::BandersnatchSha512Ell2>;

// Verifier actor.
pub struct Verifier {
    pub commitment: RingCommitment,
    pub ring: Vec<Public>,
}

impl Verifier {
    pub fn new(ring: Vec<Public>) -> Self {
        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let verifier_key = ring_context().verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Self { ring, commitment }
    }

    /// Anonymous VRF signature verification.
    ///
    /// Used for tickets verification.
    ///
    /// On success returns the VRF output hash.
    pub fn ring_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
    ) -> Result<[u8; 32], ()> {
        use ark_ec_vrfs::ring::prelude::fflonk::pcs::PcsParams;
        use ark_ec_vrfs::ring::Verifier as _;
        use bandersnatch::VerifierKey;

        let signature = RingVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let ring_ctx = ring_context();

        // The verifier key is reconstructed from the commitment and the constant
        // verifier key component of the SRS in order to verify some proof.
        // As an alternative we can construct the verifier key using the
        // RingContext::verifier_key() method, but is more expensive.
        // In other words, we prefer computing the commitment once, when the keyset changes.
        let verifier_key = VerifierKey::from_commitment_and_kzg_vk(
            self.commitment.clone(),
            ring_ctx.pcs_params.raw_vk(),
        );
        let verifier = ring_ctx.verifier(verifier_key);
        if Public::verify(input, output, aux_data, &signature.proof, &verifier).is_err() {
            println!("Ring signature verification failure");
            return Err(());
        }
        println!("Ring signature verified");

        // This truncated hash is the actual value used as ticket-id/score in JAM
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }

    /// Non-Anonymous VRF signature verification.
    ///
    /// Used for ticket claim verification during block import.
    /// Not used with Safrole test vectors.
    ///
    /// On success returns the VRF output hash.
    pub fn ietf_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
        signer_key_index: usize,
    ) -> Result<[u8; 32], ()> {
        use ark_ec_vrfs::ietf::Verifier as _;

        let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let public = &self.ring[signer_key_index];
        if public
            .verify(input, output, aux_data, &signature.proof)
            .is_err()
        {
            println!("Ring signature verification failure");
            return Err(());
        }
        println!("Ietf signature verified");

        // This is the actual value used as ticket-id/score
        // NOTE: as far as vrf_input_data is the same, this matches the one produced
        // using the ring-vrf (regardless of aux_data).
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }
}
