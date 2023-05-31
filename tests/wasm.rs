#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[cfg(test)]
mod wasm32 {
    use ezkl_lib::pfsys::Snarkbytes;
    use ezkl_lib::wasm::{prove_wasm, verify_wasm};

    pub use wasm_bindgen_rayon::init_thread_pool;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub const KZG_PARAMS: &[u8] = include_bytes!("../tests/wasm/kzg");
    pub const CIRCUIT_PARAMS: &[u8] = include_bytes!("../tests/wasm/circuit");
    pub const VK: &[u8] = include_bytes!("../tests/wasm/test.key");
    pub const PK: &[u8] = include_bytes!("../tests/wasm/test.provekey");
    pub const INPUT: &[u8] = include_bytes!("../tests/wasm/test.input.json");
    pub const PROOF: &[u8] = include_bytes!("../tests/wasm/test.proof");
    pub const NETWORK: &[u8] = include_bytes!("../tests/wasm/test.onnx");

    #[wasm_bindgen_test]
    async fn verify_pass() {
        let value = verify_wasm(
            wasm_bindgen::Clamped(PROOF.to_vec()),
            wasm_bindgen::Clamped(VK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        assert!(value);
    }

    #[wasm_bindgen_test]
    async fn verify_fail() {
        let proof = Snarkbytes {
            proof: vec![0; 32],
            num_instance: vec![1],
            instances: vec![vec![vec![0_u8; 32]]],
            transcript_type: ezkl_lib::pfsys::TranscriptType::EVM,
        };
        let proof = bincode::serialize(&proof).unwrap();

        let value = verify_wasm(
            wasm_bindgen::Clamped(proof),
            wasm_bindgen::Clamped(VK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        // should fail
        assert!(!value);
    }

    #[wasm_bindgen_test]
    async fn prove_pass() {
        // prove
        let proof = prove_wasm(
            wasm_bindgen::Clamped(INPUT.to_vec()),
            wasm_bindgen::Clamped(PK.to_vec()),
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        assert!(proof.len() > 0);

        let value = verify_wasm(
            wasm_bindgen::Clamped(proof.to_vec()),
            wasm_bindgen::Clamped(VK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        // should not fail
        assert!(value);
    }

    #[wasm_bindgen_test]
    async fn gen_circuit_params_test() {
        let run_args = RunArgs {
            tolerance: Tolerance::default(),
            scale: 7,
            bits: 16,
            logrows: 17,
            public_inputs: false,
            public_outputs: true,
            public_params: false,
            pack_base: 1,
            allocated_constraints: Some(1000), // assuming an arbitrary value here for the sake of the example
        };

        let serialized_run_args = bincode::serialize(&run_args).expect("Failed to serialize RunArgs");

         // get serialized Varvisibility
        let var_visibility = VarVisibility::from_args(run_args).expect("Failed to create VarVisibility");
        let serialized_var_visibility = bincode::serialize(&var_visibility).expect("Failed to serialize VarVisibility");

        let circuit_params = gen_circuit_params(
            wasm_bindgen::Clamped(serialized_run_args),
            wasm_bindgen::Clamped(serialized_var_visibility),
        );

    }

    #[wasm_bindgen_test]
    async fn gen_pk_test() {
        
    }

    #[wasm_bindgen_test]
    async fn gen_vk_test() {
        
    }
}
