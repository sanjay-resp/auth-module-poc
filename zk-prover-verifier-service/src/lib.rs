use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_std::rand::thread_rng;
use color_eyre::Result;
use num_bigint::{BigInt, BigUint, Sign};

type GrothBn = Groth16<Bn254>;

/// Load Circom 2.1.6 JWT Circuit with Inputs
pub fn load_circuit(
    msg_hash: Vec<u8>,
    epk_x: &[u8; 32],
    epk_y: &[u8; 32],
    address: &[u8; 32],
    modulus: Vec<u8>,
    signature: Vec<u8>,
    nonce: Vec<u8>,
    sid: Vec<u8>,
    aud: Vec<u8>,
    blinding_factor: &[u8; 32],
    spice: Vec<u8>,
) -> Result<CircomBuilder<Fr>> {
    println!("Loading circuit files (Circom 2.1.6)");
    let epk_x_bigint = BigInt::from_bytes_le(Sign::Plus, epk_x);
    let epk_y_bigint = BigInt::from_bytes_le(Sign::Plus, epk_y);
    let blinding_factor_bigint =
        BigInt::from_bytes_le(Sign::Plus, blinding_factor);
    let address = BigInt::from_bytes_le(Sign::Plus, address);
    let sid_bigint = BigInt::from_bytes_le(Sign::Plus, &sid);
    let aud_bigint = BigInt::from_bytes_le(Sign::Plus, &aud);
    let nonce_bigint = BigInt::from_bytes_le(Sign::Plus, &nonce);
    let spice_bigint = BigInt::from_bytes_le(Sign::Plus, &spice);
    let cfg = CircomConfig::<Fr>::new(
        "./circuits/web2_auth.wasm",
        "./circuits/web2_auth.r1cs",
    )?;

    println!("Circuit configuration loaded.");
    let mut builder = CircomBuilder::new(cfg);

    // Public Inputs
    for (i, val) in msg_hash.iter().enumerate() {
        builder.push_input(&format!("msg_hash[{}]", i), val.clone());
    }
    builder.push_input("epk_x", epk_x_bigint);
    builder.push_input("epk_y", epk_y_bigint);
    builder.push_input("address", address);

    // Handle modulus and signature as Vec<Fr>
    for (i, val) in modulus.iter().enumerate() {
        builder.push_input(&format!("modulus[{}]", i), val.clone());
    }
    for (i, val) in signature.iter().enumerate() {
        builder.push_input(&format!("signature[{}]", i), val.clone());
    }

    // Private Inputs
    builder.push_input("nonce", nonce_bigint);
    builder.push_input("blinding_factor", blinding_factor_bigint);
    builder.push_input("sid", sid_bigint);
    builder.push_input("aud", aud_bigint);
    builder.push_input("spice", spice_bigint);

    Ok(builder)
}

/// Generate zk-SNARK Proof
pub fn create_proof(
    builder: CircomBuilder<Fr>,
) -> Result<(ProvingKey<Bn254>, Proof<Bn254>, Vec<Fr>)> {
    let circom: CircomCircuit<Fr> = builder.setup();
    let mut rng = thread_rng();

    let params = GrothBn::generate_random_parameters_with_reduction(
        circom.clone(),
        &mut rng,
    )?;
    let circom = builder.build()?;
    let inputs = circom.get_public_inputs().expect("Public inputs needed");
    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    Ok((params, proof, inputs))
}

/// Verify the Proof
pub fn verify_proof(
    params: &ProvingKey<Bn254>,
    proof: &Proof<Bn254>,
    inputs: &[Fr],
) -> Result<bool> {
    let pvk = GrothBn::process_vk(&params.vk)?;
    let verified = GrothBn::verify_with_processed_vk(&pvk, inputs, proof)?;
    Ok(verified)
}

#[tokio::main]
pub async fn proof_verify_1(
    msg_hash: Vec<u8>,
    epk_x: &[u8; 32],
    epk_y: &[u8; 32],
    address: &[u8; 32],
    n: Vec<u8>,
    signature: Vec<u8>,
    nonce: Vec<u8>,
    sid: Vec<u8>,
    aud: Vec<u8>,
    blinding_factor: &[u8; 32],
    spice: Vec<u8>,
) -> Result<()> {
    let builder = load_circuit(
        msg_hash,
        epk_x,
        epk_y,
        address,
        n,
        signature,
        nonce,
        sid,
        aud,
        blinding_factor,
        spice,
    )?;

    let (params, proof, inputs) = create_proof(builder)?;
    let verified = verify_proof(&params, &proof, &inputs)?;

    println!("Public Inputs: {:?}", inputs);
    println!("Proof: {:?}", proof);
    println!("Proof verification result: {}", verified);
    assert!(verified);

    Ok(())
}
