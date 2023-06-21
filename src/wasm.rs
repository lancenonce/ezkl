use halo2_proofs::plonk::*;
use halo2_proofs::poly::commitment::{CommitmentScheme, ParamsProver};
use halo2_proofs::poly::kzg::{
    commitment::{KZGCommitmentScheme, ParamsKZG},
    strategy::SingleStrategy as KZGSingleStrategy,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::ff::{FromUniformBytes, PrimeField};

use crate::tensor::TensorType;
use halo2curves::serde::SerdeObject;
use snark_verifier::system::halo2::compile;
use wasm_bindgen::prelude::JsValue;
use wasm_bindgen::prelude::*;

use console_error_panic_hook;

pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
/// Initialize panic hook for wasm
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

use crate::execute::{create_proof_circuit_kzg, verify_proof_circuit_kzg};
use crate::graph::{GraphCircuit, GraphSettings};
use crate::graph::{GraphCircuit, GraphSettings};
use crate::pfsys::Snarkbytes;

/// Generate circuit settings in browser
#[wasm_bindgen]
pub fn gen_circuit_settings_wasm(
    model_ser: wasm_bindgen::Clamped<Vec<u8>>,
    run_args_ser: wasm_bindgen::Clamped<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let run_args: crate::commands::RunArgs =
        serde_json::from_slice(&run_args_ser[..]).map_err(|e| {
            JsValue::from_str(&format!("Error deserializing run args: {}", e.to_string()))
        })?;

    // Read in circuit
    let mut reader = std::io::BufReader::new(&model_ser[..]);
    let model = crate::graph::Model::new(&mut reader, run_args).map_err(|e| {
        JsValue::from_str(&format!(
            "Error reading model from bytes: {}",
            e.to_string()
        ))
    })?;
    let circuit = GraphCircuit::new(Arc::new(model), run_args, crate::circuit::CheckMode::UNSAFE)
        .map_err(|e| JsValue::from_str(&format!("Error creating circuit: {}", e)))?;
    let circuit_settings = circuit.settings;
    serde_json::to_vec(&circuit_settings).map_err(|e| JsValue::from_str(&format!("{}", e)))
}

/// Generate proving key in browser
#[wasm_bindgen]
pub fn gen_pk_wasm(
    circuit_ser: wasm_bindgen::Clamped<Vec<u8>>,
    params_ser: wasm_bindgen::Clamped<Vec<u8>>,
    circuit_settings_ser: wasm_bindgen::Clamped<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    // Read in circuit settings
    let circuit_settings: GraphSettings = serde_json::from_slice(&circuit_settings_ser[..])
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Error deserializing circuit settings: {}",
                e.to_string()
            ))
        })?;
    // Read in kzg params
    let mut reader = std::io::BufReader::new(&params_ser[..]);
    let params: ParamsKZG<Bn256> =
        halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader).map_err(|e| {
            JsValue::from_str(&format!(
                "Error reading params from bytes: {}",
                e.to_string()
            ))
        })?;
    // Read in circuit
    let mut circuit_reader = std::io::BufReader::new(&circuit_ser[..]);
    let model =
        crate::graph::Model::new(&mut circuit_reader, circuit_settings.run_args).map_err(|e| {
            JsValue::from_str(&format!(
                "Error reading model from bytes: {}",
                e.to_string()
            ))
        })?;

    let circuit = GraphCircuit::new(
        Arc::new(model),
        circuit_settings.run_args,
        crate::circuit::CheckMode::UNSAFE,
    )
    .map_err(|e| JsValue::from_str(&format!("Error creating circuit: {}", e)))?;

    // Create proving key
    let pk = create_keys_wasm::<KZGCommitmentScheme<Bn256>, Fr, GraphCircuit>(&circuit, &params)
        .map_err(Box::<dyn std::error::Error>::from)
        .unwrap();

    let mut serialized_pk = Vec::new();
    pk.write(&mut serialized_pk, halo2_proofs::SerdeFormat::RawBytes)
        .map_err(|e| JsValue::from_str(&format!("Error writing pk to bytes: {}", e)))?;

    Ok(serialized_pk)
}

/// Generate verifying key in browser
#[wasm_bindgen]
pub fn gen_vk_wasm(
    pk: wasm_bindgen::Clamped<Vec<u8>>,
    circuit_settings_ser: wasm_bindgen::Clamped<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    // Read in circuit settings
    let circuit_settings = serde_json::from_slice::<GraphSettings>(&circuit_settings_ser[..])
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Error deserializing circuit settings: {}",
                e.to_string()
            ))
        });

    // Read in proving key
    let mut reader = std::io::BufReader::new(&pk[..]);
    let pk = ProvingKey::<G1Affine>::read::<_, GraphCircuit>(
        &mut reader,
        halo2_proofs::SerdeFormat::RawBytes,
        circuit_settings.unwrap().clone(),
    )
    .map_err(|e| JsValue::from_str(&format!("Error reading pk from bytes: {}", e)))?;

    let vk = pk.get_vk();

    let mut serialized_vk = Vec::new();
    vk.write(&mut serialized_vk, halo2_proofs::SerdeFormat::RawBytes)
        .map_err(|e| JsValue::from_str(&format!("Error writing vk to bytes: {}", e)))?;

    Ok(serialized_vk)
}

/// Verify proof in browser using wasm
#[wasm_bindgen]
pub fn verify_wasm(
    proof_js: wasm_bindgen::Clamped<Vec<u8>>,
    vk: wasm_bindgen::Clamped<Vec<u8>>,
    circuit_settings_ser: wasm_bindgen::Clamped<Vec<u8>>,
    params_ser: wasm_bindgen::Clamped<Vec<u8>>,
) -> Result<bool, JsValue> {
    let mut reader = std::io::BufReader::new(&params_ser[..]);
    let params: ParamsKZG<Bn256> =
        halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader).map_err(|e| {
            JsValue::from_str(&format!(
                "Error reading params from bytes: {}",
                e.to_string()
            ))
        })?;

    let circuit_settings: GraphSettings = serde_json::from_slice(&circuit_settings_ser[..])
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Error deserializing circuit settings: {}",
                e.to_string()
            ))
        })?;

    let snark_bytes: Snarkbytes = bincode::deserialize(&proof_js[..]).map_err(|e| {
        JsValue::from_str(&format!(
            "Error deserializing proof bytes: {}",
            e.to_string()
        ))
    })?;

    let instances = snark_bytes
        .instances
        .iter()
        .map(|i| {
            i.iter()
                .map(|e| Fr::from_raw_bytes_unchecked(e))
                .collect::<Vec<Fr>>()
        })
        .collect::<Vec<Vec<Fr>>>();

    let mut reader = std::io::BufReader::new(&vk[..]);
    let vk = VerifyingKey::<G1Affine>::read::<_, GraphCircuit>(
        &mut reader,
        halo2_proofs::SerdeFormat::RawBytes,
        circuit_settings,
    )
    .map_err(|e| JsValue::from_str(&format!("Error reading vk from bytes: {}", e)))?;

    let protocol = compile(
        &params,
        &vk,
        snark_verifier::system::halo2::Config::kzg()
            .with_num_instance(snark_bytes.num_instance.clone()),
    );

    let snark = crate::pfsys::Snark {
        instances,
        proof: snark_bytes.proof,
        protocol: Some(protocol),
        transcript_type: snark_bytes.transcript_type,
    };

    let strategy = KZGSingleStrategy::new(params.verifier_params());

    let result = verify_proof_circuit_kzg(params.verifier_params(), snark, &vk, strategy);

    if result.is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Prove in browser using wasm
#[wasm_bindgen]
pub fn prove_wasm(
    witness: wasm_bindgen::Clamped<Vec<u8>>,
    pk: wasm_bindgen::Clamped<Vec<u8>>,
    circuit_ser: wasm_bindgen::Clamped<Vec<u8>>,
    circuit_settings_ser: wasm_bindgen::Clamped<Vec<u8>>,
    params_ser: wasm_bindgen::Clamped<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    // read in kzg params
    let mut reader = std::io::BufReader::new(&params_ser[..]);
    let params: ParamsKZG<Bn256> =
        halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader).map_err(|e| {
            JsValue::from_str(&format!(
                "Error reading params from bytes: {}",
                e.to_string()
            ))
        })?;

    // read in model input
    let data_deser = serde_json::from_slice(&data[..]).map_err(|e| {
        JsValue::from_str(&format!(
            "Error deserializing model input: {}",
            e.to_string()
        ))
    });

    // read in circuit settings
    let circuit_settings: GraphSettings = serde_json::from_slice(&circuit_settings_ser[..])
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Error deserializing circuit settings: {}",
                e.to_string()
            ))
        })?;

    // read in proving key
    let mut reader = std::io::BufReader::new(&pk[..]);
    let pk = ProvingKey::<G1Affine>::read::<_, GraphCircuit>(
        &mut reader,
        halo2_proofs::SerdeFormat::RawBytes,
        circuit_settings.clone(),
    )
    .map_err(|e| JsValue::from_str(&format!("Error reading pk from bytes: {}", e)))?;

    // read in circuit
    let mut reader = std::io::BufReader::new(&circuit_ser[..]);
    let model = crate::graph::Model::new(&mut reader, circuit_settings.run_args).map_err(|e| {
        JsValue::from_str(&format!(
            "Error reading model from bytes: {}",
            e.to_string()
        ))
    })?;

    let mut circuit = GraphCircuit::new(
        Arc::new(model),
        circuit_settings.run_args,
        crate::circuit::CheckMode::UNSAFE,
    )
    .map_err(|e| JsValue::from_str(&format!("Error creating circuit: {}", e)))?;

    // prep public inputs
    let public_inputs = circuit
        .prepare_public_inputs(&data_deser.unwrap())
        .map_err(|e| {
            JsValue::from_str(&format!("Error preparing public inputs: {}", e.to_string()))
        })?;

    let proof = create_proof_circuit_kzg(
        circuit,
        &params,
        public_inputs,
        &pk,
        crate::pfsys::TranscriptType::EVM,
        KZGSingleStrategy::new(&params),
        crate::circuit::CheckMode::UNSAFE,
    )
    .map_err(|e| JsValue::from_str(&format!("Error creating proof: {}", e)))?;

    bincode::serialize(&proof.to_bytes()).map_err(|e| {
        JsValue::from_str(&format!("Error serializing proof bytes: {}", e.to_string()))
    })
}

// HELPER FUNCTIONS

/// Creates a [VerifyingKey] and [ProvingKey] for a [GraphCircuit] (`circuit`) with specific [CommitmentScheme] parameters (`params`) for the WASM target
#[cfg(target_arch = "wasm32")]
pub fn create_keys_wasm<Scheme: CommitmentScheme, F: PrimeField + TensorType, C: Circuit<F>>(
    circuit: &C,
    params: &'_ Scheme::ParamsProver,
) -> Result<ProvingKey<Scheme::Curve>, halo2_proofs::plonk::Error>
where
    C: Circuit<Scheme::Scalar>,
    <Scheme as CommitmentScheme>::Scalar: FromUniformBytes<64>,
{
    // Real proof
    let empty_circuit = <C as Circuit<F>>::without_witnesses(circuit);

    // Initialize the proving key
    let vk = keygen_vk(params, &empty_circuit)?;
    let pk = keygen_pk(params, vk, &empty_circuit)?;
    Ok(pk)
}
