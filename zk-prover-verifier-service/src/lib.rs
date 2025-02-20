use ark_bn254::{Bn254, Config, Fr};
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::Bn;
use ark_groth16::{Groth16, ProvingKey};
use ark_std::rand::thread_rng;
use color_eyre::{eyre::Ok, Result};
type GrothBn = Groth16<Bn254>;

pub fn load_circuit(val_a: i32, val_b: i32) -> Result<CircomBuilder<Fr>> {
    println!("Loading circuit files");
    let cfg = CircomConfig::<Fr>::new(
        "./circuits/main.wasm",
        "./circuits/main.r1cs",
    )?;
    println!("Circuit configuration loaded");
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", val_a);
    builder.push_input("b", val_b);
    Ok(builder)
}

pub fn create_proof(
    builder: CircomBuilder<Fr>,
) -> Result<(
    ProvingKey<ark_ec::models::bn::Bn<ark_bn254::Config>>,
    ark_groth16::Proof<Bn254>,
    Vec<Fr>,
)> {
    let circom: CircomCircuit<Fr> = builder.setup();
    let mut rng = thread_rng();
    let params =
        GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)
            .unwrap();

    let circom = builder.build()?;
    let inputs = circom.get_public_inputs().expect("Public inputs needed");
    let proof = GrothBn::prove(&params, circom, &mut rng)?;
    Ok((params, proof, inputs))
}

pub fn verify_proof(
    params: &ProvingKey<Bn<Config>>,
    proof: &ark_groth16::Proof<Bn254>,
    inputs: &[Fr],
) -> Result<bool> {
    let pvk = GrothBn::process_vk(&params.vk)?;
    let verified = GrothBn::verify_with_processed_vk(&pvk, inputs, proof)?;
    Ok(verified)
}

#[tokio::main]
pub async fn proof_verify_1() -> Result<()> {
    let builder = load_circuit(5, 77)?;
    let (params, proof, inputs) = create_proof(builder)?;
    let verified = verify_proof(&params, &proof, &inputs)?;
    println!("{:?}", inputs);
    println!("{:?}", proof);
    println!("Proof verification result: {}", verified);
    assert!(verified);
    Ok(())
}
