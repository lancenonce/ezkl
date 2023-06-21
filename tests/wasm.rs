#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[cfg(test)]
mod wasm32 {
    use ezkl_lib::circuit::Tolerance;
    use ezkl_lib::commands::RunArgs;
    use ezkl_lib::graph::GraphSettings;
    use ezkl_lib::graph::GraphSettings;
    use ezkl_lib::pfsys::Snarkbytes;
    use ezkl_lib::wasm::{
        gen_circuit_settings_wasm, gen_pk_wasm, gen_vk_wasm, prove_wasm, verify_wasm,
    };
    use serde_json::Error as JsonError;
    use std::fs::File;
    use std::io::Error as IoError;
    pub use wasm_bindgen_rayon::init_thread_pool;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub const KZG_PARAMS: &[u8] = include_bytes!("../tests/wasm/kzg");
    pub const CIRCUIT_PARAMS: &[u8] = include_bytes!("../tests/wasm/settings.json");
    pub const VK: &[u8] = include_bytes!("../tests/wasm/test.key");
    pub const PK: &[u8] = include_bytes!("../tests/wasm/test.provekey");
    pub const WITNESS: &[u8] = include_bytes!("../tests/wasm/test.witness.json");
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
        assert!(value.unwrap_or(false));
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
            wasm_bindgen::Clamped(WITNESS.to_vec()),
            wasm_bindgen::Clamped(PK.to_vec()),
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        assert!(proof.unwrap_or(Vec::new()).len() > 0);

        let value = verify_wasm(
            wasm_bindgen::Clamped(proof.unwrap_or(Vec::new()).to_vec()),
            wasm_bindgen::Clamped(VK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        // should not fail
        assert!(value.unwrap_or(false));
    }

    // HELPER FUNCTION FOR GEN_CIRCUIT_SETTINGS
    fn read_run_args_from_json_file(file_path: &str) -> Result<RunArgs, JsonError> {
        let mut file = File::open(file_path).map_err(|err| JsonError::custom(err.to_string()))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|err| JsonError::custom(err.to_string()))?;
        let run_args: RunArgs = serde_json::from_str(&contents)?;
        Ok(run_args)
    }

    #[wasm_bindgen_test]
    async fn gen_circuit_settings_test() {
        match read_run_args_from_json_file("./wasm/run_args.json") {
            Ok(run_args) => {
                let serialized_run_args =
                    bincode::serialize(&run_args).expect("Failed to serialize RunArgs");

                let circuit_settings_ser = gen_circuit_settings_wasm(
                    wasm_bindgen::Clamped(NETWORK.to_vec()),
                    wasm_bindgen::Clamped(serialized_run_args),
                );

                assert!(circuit_settings_ser.len() > 0);

                let _circuit_settings: GraphSettings =
                    serde_json::from_slice(&circuit_settings_ser[..]).unwrap();
            }
            Err(e) => println!("Error reading JSON file: {:?}", e),
        }
    }

    #[wasm_bindgen_test]
    async fn gen_pk_test() {
        let pk = gen_pk_wasm(
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
        );

        assert!(pk.len() > 0);
    }

    #[wasm_bindgen_test]
    async fn gen_vk_test() {
        let pk = gen_pk_wasm(
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
        );

        let vk = gen_vk_wasm(
            wasm_bindgen::Clamped(pk),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
        );

        assert!(vk.len() > 0);
    }

    #[wasm_bindgen_test]
    async fn circuit_settings_is_valid_test() {
        let run_args = RunArgs {
            tolerance: Tolerance::default(),
            scale: 0,
            bits: 5,
            logrows: 7,
            batch_size: 1,
            input_visibility: "private".into(),
            output_visibility: "public".into(),
            param_visibility: "private".into(),
            pack_base: 1,
            allocated_constraints: Some(1000), // assuming an arbitrary value here for the sake of the example
        };

        let serialized_run_args =
            bincode::serialize(&run_args).expect("Failed to serialize RunArgs");

        let circuit_settings_ser = gen_circuit_settings_wasm(
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(serialized_run_args),
        );

        assert!(circuit_settings_ser.len() > 0);

        let pk = gen_pk_wasm(
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
            wasm_bindgen::Clamped(circuit_settings_ser),
        );

        assert!(pk.len() > 0);
    }

    #[wasm_bindgen_test]
    async fn pk_is_valid_test() {
        let pk = gen_pk_wasm(
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
        );

        assert!(pk.len() > 0);

        // prove
        let proof = prove_wasm(
            wasm_bindgen::Clamped(WITNESS.to_vec()),
            wasm_bindgen::Clamped(pk.clone()),
            wasm_bindgen::Clamped(NETWORK.to_vec()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        assert!(proof.unwrap_or(Vec::new()).len() > 0);

        let vk = gen_vk_wasm(
            wasm_bindgen::Clamped(pk.clone()),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
        );

        let value = verify_wasm(
            wasm_bindgen::Clamped(proof.unwrap_or(Vec::new()).to_vec()),
            wasm_bindgen::Clamped(vk),
            wasm_bindgen::Clamped(CIRCUIT_PARAMS.to_vec()),
            wasm_bindgen::Clamped(KZG_PARAMS.to_vec()),
        );
        // should not fail
        assert!(value.unwrap_or(false));
    }
}
