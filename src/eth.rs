use crate::graph::input::{CallsToAccount, GraphWitness};
use crate::pfsys::evm::{DeploymentCode, EvmVerificationError};
use crate::pfsys::Snark;
use ethers::abi::Abi;
use ethers::abi::Contract;
use ethers::contract::abigen;
use ethers::contract::ContractFactory;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::ContractInstance;
#[cfg(target_arch = "wasm32")]
use ethers::prelude::Wallet;
use ethers::providers::Middleware;
use ethers::providers::{Http, Provider};
use ethers::signers::Signer;
use ethers::solc::{CompilerInput, Solc};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::Bytes;
use ethers::types::TransactionRequest;
use ethers::types::H160;
use ethers::types::U256;
#[cfg(not(target_arch = "wasm32"))]
use ethers::{
    prelude::{LocalWallet, Wallet},
    utils::{Anvil, AnvilInstance},
};
use halo2curves::bn256::{Fr, G1Affine};
use halo2curves::group::ff::PrimeField;
use log::{debug, info};
use std::error::Error;
use std::fmt::Write;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
use std::{convert::TryFrom, sync::Arc};

/// A local ethers-rs based client
pub type EthersClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

/// Return an instance of Anvil and a client for the given RPC URL. If none is provided, a local client is used.
#[cfg(not(target_arch = "wasm32"))]
pub async fn setup_eth_backend(
    rpc_url: Option<&str>,
) -> Result<(AnvilInstance, EthersClient), Box<dyn Error>> {
    // Launch anvil
    let anvil = Anvil::new().spawn();

    // Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    let endpoint = if let Some(rpc_url) = rpc_url {
        rpc_url.to_string()
    } else {
        anvil.endpoint()
    };

    // Connect to the network
    let provider = Provider::<Http>::try_from(endpoint)?.interval(Duration::from_millis(10u64));

    let chain_id = provider.get_chainid().await?;
    info!("using chain {}", chain_id);

    // Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(anvil.chain_id()),
    ));

    Ok((anvil, client))
}

/// Verify a proof using a Solidity verifier contract
#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_proof_via_solidity(
    proof: Snark<Fr, G1Affine>,
    sol_code_path: Option<PathBuf>,
    sol_bytecode_path: Option<PathBuf>,
) -> Result<bool, Box<dyn Error>> {
    let (anvil, client) = setup_eth_backend(None).await?;

    // sol code supercedes deployment code
    let factory = match sol_code_path {
        Some(path) => get_sol_contract_factory(path, "Verifier", client.clone()).unwrap(),
        None => match sol_bytecode_path {
            Some(path) => {
                let bytecode = DeploymentCode::load(&path)?;
                ContractFactory::new(
                    // our constructor is empty and ContractFactory only uses the abi constructor -- so this should be safe
                    Abi::default(),
                    (bytecode.code().clone()).into(),
                    client.clone(),
                )
            }
            None => {
                panic!("at least one path should be set");
            }
        },
    };

    let contract = factory.deploy(())?.send().await?;
    let addr = contract.address();

    abigen!(Verifier, "./Verifier.json");
    let contract = Verifier::new(addr, client.clone());

    let mut public_inputs = vec![];
    let flattened_instances = proof.instances.into_iter().flatten();

    for val in flattened_instances {
        let bytes = val.to_repr();
        let u = U256::from_little_endian(bytes.as_slice());
        public_inputs.push(u);
    }

    let tx = contract
        .verify(
            public_inputs.clone(),
            ethers::types::Bytes::from(proof.proof.to_vec()),
        )
        .tx;

    info!(
        "estimated verify gas cost: {:#?}",
        client.estimate_gas(&tx, None).await?
    );

    let result = contract
        .verify(
            public_inputs,
            ethers::types::Bytes::from(proof.proof.to_vec()),
        )
        .call()
        .await;

    if result.is_err() {
        return Err(Box::new(EvmVerificationError::SolidityExecution));
    }
    let result = result.unwrap();
    if !result {
        return Err(Box::new(EvmVerificationError::InvalidProof));
    }

    drop(anvil);
    Ok(result)
}

fn count_decimal_places(num: f32) -> usize {
    // Convert the number to a string
    let s = num.to_string();

    // Find the decimal point
    match s.find('.') {
        Some(index) => {
            // Count the number of characters after the decimal point
            s[index + 1..].len()
        }
        None => 0,
    }
}

///
pub async fn setup_test_contract<M: 'static + Middleware>(
    client: Arc<M>,
    data: &GraphWitness,
) -> Result<(ContractInstance<Arc<M>, M>, Vec<u8>), Box<dyn Error>> {
    let factory =
        get_sol_contract_factory(PathBuf::from("TestReads.sol"), "TestReads", client.clone())
            .unwrap();

    let mut decimals = vec![];
    let mut scaled_by_decimals_data = vec![];
    for input in &data.input_data[0] {
        let decimal_places = count_decimal_places(*input) as u8;
        let scaled_by_decimals = input * f32::powf(10., decimal_places.into());
        scaled_by_decimals_data.push(scaled_by_decimals as u128);
        decimals.push(decimal_places);
    }

    let contract = factory.deploy(scaled_by_decimals_data)?.send().await?;
    Ok((contract, decimals))
}

/// Verify a proof using a Solidity DataAttestationVerifier contract
#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_proof_with_data_attestation(
    proof: Snark<Fr, G1Affine>,
    sol_code_path: PathBuf,
    data: PathBuf,
) -> Result<bool, Box<dyn Error>> {
    let (anvil, client) = setup_eth_backend(None).await?;

    let data = GraphWitness::from_path(data)?;

    let (contract, _) = setup_test_contract(client.clone(), &data).await?;

    info!("contract address: {:#?}", contract.address());

    let data = data.on_chain_input_data;
    let factory =
        get_sol_contract_factory(sol_code_path, "DataAttestationVerifier", client.clone()).unwrap();

    let (contract_addresses, call_data, decimals) = if let Some(data) = data {
        let mut contract_addresses = vec![];
        let mut call_data = vec![];
        let mut decimals: Vec<u8> = vec![];
        for (i, val) in data.0.iter().enumerate() {
            let contract_address_bytes = hex::decode(val.address.clone())?;
            let contract_address = H160::from_slice(&contract_address_bytes);
            contract_addresses.push(contract_address);
            call_data.push(vec![]);
            for (call, decimal) in &val.call_data {
                let call_data_bytes = hex::decode(call)?;
                call_data[i].push(ethers::types::Bytes::from(call_data_bytes));
                decimals.push(*decimal);
            }
        }
        (contract_addresses, call_data, decimals)
    } else {
        panic!("No on_chain_input_data field found in .json data file")
    };

    info!("call_data length: {:#?}", call_data);
    info!("contract_addresses length: {:#?}", contract_addresses);

    let contract = factory
        .deploy((contract_addresses, call_data, decimals))?
        .send()
        .await?;
    info!("hello, past deploy");

    abigen!(DataAttestationVerifier, "./DataAttestationVerifier.json");
    let contract = DataAttestationVerifier::new(contract.address(), client.clone());

    let mut public_inputs = vec![];
    let flattened_instances = proof.instances.into_iter().flatten();

    for val in flattened_instances {
        let bytes = val.to_repr();
        let u = U256::from_little_endian(bytes.as_slice());
        public_inputs.push(u);
    }

    let tx = contract
        .verify_with_data_attestation(
            public_inputs.clone(),
            ethers::types::Bytes::from(proof.proof.to_vec()),
        )
        .tx;

    info!(
        "estimated verify gas cost: {:#?}",
        client.estimate_gas(&tx, None).await?
    );

    info!("public_inputs: {:#?}", public_inputs);

    let result = contract
        .verify_with_data_attestation(
            public_inputs,
            ethers::types::Bytes::from(proof.proof.to_vec()),
        )
        .call()
        .await;

    if result.is_err() {
        return Err(Box::new(EvmVerificationError::SolidityExecution));
    }
    let result = result.unwrap();
    if !result {
        return Err(Box::new(EvmVerificationError::InvalidProof));
    }
    drop(anvil);
    Ok(result)
}

/// get_provider returns a JSON RPC HTTP Provider
pub fn get_provider(rpc_url: &str) -> Result<Provider<Http>, Box<dyn Error>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    debug!("{:#?}", provider);
    Ok(provider)
}

/// Tests on-chain inputs by deploying a contract that stores the data.input_data in its storage
pub async fn test_on_chain_inputs<M: 'static + Middleware>(
    client: Arc<M>,
    data: &GraphWitness,
    witness: PathBuf,
    endpoint: String,
) -> Result<Vec<CallsToAccount>, Box<dyn Error>> {
    let (contract, decimals) = setup_test_contract(client.clone(), data).await?;

    abigen!(TestReads, "./TestReads.json");

    let contract = TestReads::new(contract.address(), client.clone());

    // Get the encoded call data for each input
    let mut calldata = vec![];
    for (i, _) in data.input_data[0].iter().enumerate() {
        let function = contract.method::<_, U256>("arr", i as u32).unwrap();
        let call = function.calldata().unwrap();
        // Push (call, decimals) to the calldata vector, and set the decimals to 0.
        calldata.push((hex::encode(call), decimals[i]));
    }
    // Instantiate a new CallsToAccount struct
    let calls_to_account = CallsToAccount {
        call_data: calldata,
        address: hex::encode(contract.address().as_bytes()),
    };
    info!("calls_to_account: {:#?}", calls_to_account);
    let calls_to_accounts = vec![calls_to_account];
    // Fill the on_chain_input_data field of the GraphWitness struct
    let mut data = data.clone();
    data.on_chain_input_data = Some((calls_to_accounts.clone(), endpoint));
    // Save the updated GraphWitness struct to the data_path
    data.save(witness)?;
    Ok(calls_to_accounts)
}

/// Reads on-chain inputs, returning the raw encoded data returned from making all the calls in on_chain_input_data
#[cfg(not(target_arch = "wasm32"))]
pub async fn read_on_chain_inputs<M: 'static + Middleware>(
    client: Arc<M>,
    address: H160,
    data: &Vec<CallsToAccount>,
) -> Result<(Vec<Bytes>, Vec<u8>), Box<dyn Error>> {
    // Iterate over all on-chain inputs
    let mut fetched_inputs = vec![];
    let mut decimals = vec![];
    for on_chain_data in data {
        // Construct the address
        let contract_address_bytes = hex::decode(on_chain_data.address.clone())?;
        let contract_address = H160::from_slice(&contract_address_bytes);
        for (call_data, decimal) in &on_chain_data.call_data {
            let call_data_bytes = hex::decode(call_data.clone())?;
            let tx: TypedTransaction = TransactionRequest::default()
                .to(contract_address)
                .from(address)
                .data(call_data_bytes)
                .into();
            debug!("transaction {:#?}", tx);

            let result = client.call(&tx, None).await?;
            debug!("return data {:#?}", result);
            fetched_inputs.push(result);
            decimals.push(*decimal);
        }
    }
    Ok((fetched_inputs, decimals))
}

///
#[cfg(not(target_arch = "wasm32"))]
pub async fn evm_quantize<M: 'static + Middleware>(
    client: Arc<M>,
    scale: f64,
    data: &(Vec<ethers::types::Bytes>, Vec<u8>),
) -> Result<Vec<i128>, Box<dyn Error>> {
    let factory = get_sol_contract_factory(
        PathBuf::from("./QuantizeData.sol"),
        "QuantizeData",
        client.clone(),
    )
    .unwrap();

    let contract = factory.deploy(())?.send().await?;

    abigen!(QuantizeData, "./QuantizeData.json");

    let contract = QuantizeData::new(contract.address(), client.clone());

    let fetched_inputs = data.0.clone();
    let decimals = data.1.clone();

    let fetched_inputs = fetched_inputs
        .iter()
        .map(|x| Result::<_, std::convert::Infallible>::Ok(ethers::types::Bytes::from(x.to_vec())))
        .collect::<Result<Vec<Bytes>, _>>()?;

    let decimals = decimals
        .iter()
        .map(|x| U256::from_dec_str(&x.to_string()))
        .collect::<Result<Vec<U256>, _>>()?;

    let results = contract
        .quantize_data(
            fetched_inputs,
            decimals,
            U256::from_dec_str(&scale.to_string())?,
        )
        .call()
        .await;

    let results = results.unwrap();
    info!("evm quantization results: {:#?}", results,);
    Ok(results.to_vec())
}

/// Generates the contract factory for a solidity verifier, optionally compiling the code with optimizer runs set on the Solc compiler.
fn get_sol_contract_factory<M: 'static + Middleware>(
    sol_code_path: PathBuf,
    contract_name: &str,
    client: Arc<M>,
) -> Result<ContractFactory<M>, Box<dyn Error>> {
    const MAX_RUNTIME_BYTECODE_SIZE: usize = 24577;
    // call get_contract_artificacts to get the abi and bytecode
    let (abi, bytecode, runtime_bytecode) =
        get_contract_artifacts(sol_code_path, contract_name, None)?;
    let size = runtime_bytecode.len();
    debug!("runtime bytecode size: {:#?}", size);
    if size > MAX_RUNTIME_BYTECODE_SIZE {
        // `_runtime_bytecode` exceeds the limit
        panic!(
            "Solidity runtime bytecode size is: {:#?}, 
            which exceeds 24577 bytes limit.
            Try setting '--optimzer-runs 1' when generating the verifier
            so SOLC can optimize for the smallest deployment",
            size
        );
    }
    Ok(ContractFactory::new(abi, bytecode, client))
}

/// Compiles a solidity verifier contract and returns the abi, bytecode, and runtime bytecode
#[cfg(not(target_arch = "wasm32"))]
pub fn get_contract_artifacts(
    sol_code_path: PathBuf,
    contract_name: &str,
    runs: Option<usize>,
) -> Result<(Contract, Bytes, Bytes), Box<dyn Error>> {
    // Create the compiler input, enabling the optimizer and setting the optimzer runs.
    let input: CompilerInput = if let Some(r) = runs {
        let mut i = CompilerInput::new(sol_code_path)?[0].clone().optimizer(r);
        i.settings.optimizer.enable();
        i
    } else {
        CompilerInput::new(sol_code_path)?[0].clone()
    };
    let compiled = Solc::default().compile(&input).unwrap();
    let (abi, bytecode, runtime_bytecode) = compiled
        .find(contract_name)
        .expect("could not find contract")
        .into_parts_or_default();
    Ok((abi, bytecode, runtime_bytecode))
}

use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Reads in raw bytes code and generates equivalent .sol file
/// Can optionally attest to on-chain inputs
pub fn fix_verifier_sol(
    input_file: PathBuf,
    scale: Option<u32>,
    data: Option<Vec<CallsToAccount>>,
) -> Result<String, Box<dyn Error>> {
    let file = File::open(input_file.clone())?;
    let reader = BufReader::new(file);

    let mut transcript_addrs: Vec<u32> = Vec::new();
    let mut modified_lines: Vec<String> = Vec::new();
    let mut proof_size: u32 = 0;

    // convert calldataload 0x0 to 0x40 to read from pubInputs, and the rest
    // from proof
    let calldata_pattern = Regex::new(r"^.*(calldataload\((0x[a-f0-9]+)\)).*$")?;
    let mstore_pattern = Regex::new(r"^\s*(mstore\(0x([0-9a-fA-F]+)+),.+\)")?;
    let mstore8_pattern = Regex::new(r"^\s*(mstore8\((\d+)+),.+\)")?;
    let mstoren_pattern = Regex::new(r"^\s*(mstore\((\d+)+),.+\)")?;
    let mload_pattern = Regex::new(r"(mload\((0x[0-9a-fA-F]+))\)")?;
    let keccak_pattern = Regex::new(r"(keccak256\((0x[0-9a-fA-F]+))")?;
    let modexp_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x5, (0x[0-9a-fA-F]+), 0xc0, (0x[0-9a-fA-F]+), 0x20)")?;
    let ecmul_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x7, (0x[0-9a-fA-F]+), 0x60, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecadd_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x6, (0x[0-9a-fA-F]+), 0x80, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecpairing_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x8, (0x[0-9a-fA-F]+), 0x180, (0x[0-9a-fA-F]+), 0x20)")?;
    let bool_pattern = Regex::new(r":bool")?;

    // Count the number of pub inputs
    let mut start = None;
    let mut end = None;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().starts_with("mstore(0x20") && start.is_none() {
            start = Some(i as u32);
        }

        if line.trim().starts_with("mstore(0x0") {
            end = Some(i as u32);
            break;
        }
    }

    let num_pubinputs = if let Some(s) = start {
        end.unwrap() - s
    } else {
        0
    };

    let mut max_pubinputs_addr = 0;
    if num_pubinputs > 0 {
        max_pubinputs_addr = num_pubinputs * 32 - 32;
    }

    let file = File::open(input_file)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let mut line = line?;
        let m = bool_pattern.captures(&line);
        if m.is_some() {
            line = line.replace(":bool", "");
        }

        let m = calldata_pattern.captures(&line);
        if let Some(m) = m {
            let calldata_and_addr = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            if addr_as_num <= max_pubinputs_addr {
                let pub_addr = format!("{:#x}", addr_as_num + 32);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(pubInputs, {}))", pub_addr),
                );
            } else {
                proof_size += 1;
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(proof, {}))", proof_addr),
                );
            }
        }

        let m = mstore8_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = addr.parse::<u32>()?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore8(add(transcript, {})", transcript_addr),
            );
        }

        let m = mstoren_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = addr.parse::<u32>()?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = modexp_pattern.captures(&line);
        if let Some(m) = m {
            let modexp = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            line = line.replace(
                modexp,
                &format!(
                    "staticcall(gas(), 0x5, add(transcript, {}), 0xc0, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecmul_pattern.captures(&line);
        if let Some(m) = m {
            let ecmul = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecmul,
                &format!(
                    "staticcall(gas(), 0x7, add(transcript, {}), 0x60, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecadd_pattern.captures(&line);
        if let Some(m) = m {
            let ecadd = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecadd,
                &format!(
                    "staticcall(gas(), 0x6, add(transcript, {}), 0x80, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecpairing_pattern.captures(&line);
        if let Some(m) = m {
            let ecpairing = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecpairing,
                &format!(
                    "staticcall(gas(), 0x8, add(transcript, {}), 0x180, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = mstore_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = keccak_pattern.captures(&line);
        if let Some(m) = m {
            let keccak = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                keccak,
                &format!("keccak256(add(transcript, {})", transcript_addr),
            );
        }

        // mload can show up multiple times per line
        loop {
            let m = mload_pattern.captures(&line);
            if m.is_none() {
                break;
            }
            let mload = m.as_ref().unwrap().get(1).unwrap().as_str();
            let addr = m.as_ref().unwrap().get(2).unwrap().as_str();

            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mload,
                &format!("mload(add(transcript, {})", transcript_addr),
            );
        }

        modified_lines.push(line);
    }

    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;

    let mut contract = if let Some(data) = data {
        let total_calls: usize = data.iter().map(|v| v.call_data.len()).sum();
        format!(
            r#" // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.17;
            
            contract DataAttestationVerifier {{
            
                /**
                 * @notice Struct used to make view only calls to accounts to fetch the data that EZKL reads from.
                 * @param the address of the account to make calls to
                 * @param the abi encoded function calls to make to the `contractAddress`
                 */
                struct AccountCall {{
                    address contractAddress;
                    mapping(uint256 => bytes) callData;
                    mapping(uint256 => uint256) decimals;
                    uint callCount;
                }}
                AccountCall[{}] public accountCalls;
            
                uint constant public SCALE = 1<<{};
            
                uint256 constant SIZE_LIMIT = uint256(uint128(type(int128).max));
            
                uint256 constant TOTAL_CALLS = {};
            
                /**
                 * @dev Initialize the contract with account calls the EZKL model will read from.
                 * @param _contractAddresses - The calls to all the contracts EZKL reads storage from.
                 * @param _callData - The abi encoded function calls to make to the `contractAddress` that EZKL reads storage from.
                 */
                constructor(address[] memory _contractAddresses, bytes[][] memory _callData, uint256[] memory _decimals) {{
                    require(_contractAddresses.length == _callData.length && accountCalls.length == _contractAddresses.length, "Invalid input length");
                    require(TOTAL_CALLS == _decimals.length, "Invalid number of decimals");
                    // fill in the accountCalls storage array
                    uint counter = 0;
                    for(uint256 i = 0; i < _contractAddresses.length; i++) {{
                        AccountCall storage accountCall = accountCalls[i];
                        accountCall.contractAddress = _contractAddresses[i];
                        accountCall.callCount = _callData[i].length;
                        for(uint256 j = 0; j < _callData[i].length; j++){{
                            accountCall.callData[j] = _callData[i][j];
                            accountCall.decimals[j] = 10**_decimals[counter + j];
                        }}
                        // count the total number of storage reads across all of the accounts
                        counter += _callData[i].length;
                    }}
                }}
            
                function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {{
                    unchecked {{
                        uint256 prod0;
                        uint256 prod1;
                        assembly {{
                            let mm := mulmod(x, y, not(0))
                            prod0 := mul(x, y)
                            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
                        }}
            
                        if (prod1 == 0) {{
                            return prod0 / denominator;
                        }}
            
                        require(denominator > prod1, "Math: mulDiv overflow");
            
                        uint256 remainder;
                        assembly {{
                            remainder := mulmod(x, y, denominator)
                            prod1 := sub(prod1, gt(remainder, prod0))
                            prod0 := sub(prod0, remainder)
                        }}
            
                        uint256 twos = denominator & (~denominator + 1);
                        assembly {{
                            denominator := div(denominator, twos)
                            prod0 := div(prod0, twos)
                            twos := add(div(sub(0, twos), twos), 1)
                        }}
            
                        prod0 |= prod1 * twos;
            
                        uint256 inverse = (3 * denominator) ^ 2;
            
                        inverse *= 2 - denominator * inverse;
                        inverse *= 2 - denominator * inverse;
                        inverse *= 2 - denominator * inverse;
                        inverse *= 2 - denominator * inverse;
                        inverse *= 2 - denominator * inverse;
                        inverse *= 2 - denominator * inverse;
            
                        result = prod0 * inverse;
                        return result;
                    }}
                }}
                function quantize_data(bytes memory data, uint256 decimals) internal pure returns (uint128 quantized_data) {{
                    uint x = abi.decode(data, (uint256));
                    uint output = mulDiv(x, SCALE, decimals);
                    if (mulmod(x, SCALE, decimals)*2 >= decimals) {{
                        output += 1;
                    }}
                    require(output < SIZE_LIMIT, "QuantizeData: overflow");
                    quantized_data = uint128(output);
                }}
            
                function staticCall (address target, bytes memory data) internal view returns (bytes memory) {{
                    (bool success, bytes memory returndata) = target.staticcall(data);
                    if (success) {{
                        if (returndata.length == 0) {{
                            require(target.code.length > 0, "Address: call to non-contract");
                        }}
                    return returndata;
                    }} else {{
                        revert("Address: low-level call failed");
                    }}
                }}
            
                function attestData(uint256[] memory pubInputs) internal view {{
                    require(pubInputs.length >= TOTAL_CALLS, "Invalid public inputs length");
                    uint256 _accountCount = accountCalls.length;
                    uint counter = 0; 
                    for (uint8 i = 0; i < _accountCount; ++i) {{
                        address account = accountCalls[i].contractAddress;
                        for (uint8 j = 0; j < accountCalls[i].callCount; j++) {{
                            bytes memory returnData = staticCall(account, accountCalls[i].callData[j]);
                            uint256 quantized_data = quantize_data(returnData, accountCalls[i].decimals[j]);
                            require(quantized_data == pubInputs[counter], "Public input does not match");
                            counter++;
                        }}
                    }}
                }}
            
                function verifyWithDataAttestation(
                    uint256[] memory pubInputs,
                    bytes memory proof
                ) public view returns (bool) {{
                    bool success = true;
                    bytes32[{}] memory transcript;
                    attestData(pubInputs);
                    assembly {{ 
                "#,
            data.len(),
            scale.unwrap(),
            total_calls,
            max_transcript_addr
        )
        .trim()
        .to_string()
    } else {
        format!(
            "// SPDX-License-Identifier: MIT
        pragma solidity ^0.8.17;
        
        contract Verifier {{
            function verify(
                uint256[] memory pubInputs,
                bytes memory proof
            ) public view returns (bool) {{
                bool success = true;
                bytes32[{}] memory transcript;
                assembly {{
            ",
            max_transcript_addr
        )
        .trim()
        .to_string()
    };

    // using a boxed Write trait object here to show it works for any Struct impl'ing Write
    // you may also use a std::fs::File here
    let write: Box<&mut dyn Write> = Box::new(&mut contract);

    for line in modified_lines[16..modified_lines.len() - 7].iter() {
        write!(write, "{}", line).unwrap();
    }
    writeln!(write, "}} return success; }} }}")?;

    // free memory pointer initialization
    let mut offset = 128;

    // replace all mload(add(pubInputs, 0x...))) with mload(0x...
    contract = replace_vars_with_offset(&contract, r"add\(pubInputs, (0x[0-9a-fA-F]+)\)", offset);

    offset += 32 * num_pubinputs + 32;

    // replace all mload(add(proof, 0x...))) with mload(0x...
    contract = replace_vars_with_offset(&contract, r"add\(proof, (0x[0-9a-fA-F]+)\)", offset);

    offset += 32 * proof_size + 32;

    // replace all (add(transcript, 0x...))) with (0x...)
    contract = replace_vars_with_offset(&contract, r"add\(transcript, (0x[0-9a-fA-F]+)\)", offset);

    Ok(contract)
}

fn replace_vars_with_offset(contract: &str, regex_pattern: &str, offset: u32) -> String {
    let re = Regex::new(regex_pattern).unwrap();
    let replaced = re.replace_all(contract, |caps: &regex::Captures| {
        let addr_as_num = u32::from_str_radix(caps[1].strip_prefix("0x").unwrap(), 16).unwrap();
        let new_addr = addr_as_num + offset;
        format!("{:#x}", new_addr)
    });
    replaced.into_owned()
}
