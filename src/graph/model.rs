use super::node::*;
use super::scale_to_multiplier;
use super::vars::*;
use super::GraphError;
use super::ModelParams;
use crate::circuit::hybrid::HybridOp;
use crate::circuit::Input;
use crate::circuit::Tolerance;
use crate::circuit::Unknown;
use crate::{
    circuit::{lookup::LookupOp, ops::poly::PolyOp, BaseConfig as PolyConfig, CheckMode, Op},
    commands::{Cli, Commands, RunArgs},
    tensor::{Tensor, TensorType, ValTensor},
};

use halo2_proofs::circuit::Region;
use halo2curves::ff::PrimeField;
use log::warn;
use serde::Deserialize;
use serde::Serialize;
use tract_onnx::prelude::{
    DatumExt, Graph, InferenceFact, InferenceModelExt, SymbolValues, TypedFact, TypedOp,
};
use tract_onnx::tract_hir::ops::scan::Scan;

// use tract_onnx::tract_hir::internal::GenericFactoid;
//use clap::Parser;
use core::panic;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::ConstraintSystem,
};
use itertools::Itertools;
use log::error;
use log::{debug, info, trace};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use tabled::Table;
use tract_onnx;
use tract_onnx::prelude::Framework;
/// Mode we're using the model in.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum Mode {
    /// Initialize the model and display the operations table / graph
    #[default]
    Table,
    /// Initialize the model and generate a mock proof
    Mock,
    /// Initialize the model and generate a proof
    Prove,
    /// Initialize the model, generate a proof, and verify
    FullProve,
    /// Initialize the model and verify an already generated proof
    Verify,
}

/// A circuit configuration for the entirety of a model loaded from an Onnx file.
#[derive(Clone, Debug)]
pub struct ModelConfig<F: PrimeField + TensorType + PartialOrd> {
    /// The base configuration for the circuit
    pub base: PolyConfig<F>,
    /// A wrapper for holding all columns that will be assigned to by the model
    pub vars: ModelVars<F>,
}

/// Representation of execution graph
pub type NodeGraph<F> = BTreeMap<usize, NodeType<F>>;

/// A struct for loading from an Onnx file and converting a computational graph to a circuit.
#[derive(Clone, Debug, Default)]
pub struct Model<F: PrimeField + TensorType + PartialOrd> {
    /// input indices
    pub graph: ParsedNodes<F>,
    /// The [RunArgs] being used
    pub run_args: RunArgs,
    /// The [Mode] we're using the model in.
    pub mode: Mode,
    /// Defines which inputs to the model are public and private (params, inputs, outputs) using [VarVisibility].
    pub visibility: VarVisibility,
}

/// Enables model as subnode of other models
#[derive(Clone, Debug)]
pub enum NodeType<F: PrimeField + TensorType + PartialOrd> {
    /// A node in the model
    Node(Node<F>),
    /// A submodel
    SubGraph {
        /// The subgraph
        model: Model<F>,
        /// The subgraph's inputs
        inputs: Vec<usize>,
        /// the subgraph's idx within the parent graph
        idx: usize,
    },
}

impl<F: PrimeField + TensorType + PartialOrd> NodeType<F> {
    /// Returns the indices of the node's inputs.
    pub fn inputs(&self) -> Vec<usize> {
        match self {
            NodeType::Node(n) => n.inputs.clone(),
            NodeType::SubGraph { inputs, .. } => inputs.clone(),
        }
    }

    /// Returns the dimensions of the node's output.
    pub fn out_dims(&self) -> Vec<Vec<usize>> {
        match self {
            NodeType::Node(n) => vec![n.out_dims.clone()],
            NodeType::SubGraph { model, .. } => model.graph.output_shapes(),
        }
    }
    /// Returns the lookups required by a graph
    pub fn required_lookups(&self) -> Vec<LookupOp> {
        match self {
            NodeType::Node(n) => n.opkind.required_lookups(),
            NodeType::SubGraph { model, .. } => model.required_lookups(),
        }
    }
    /// Returns the scales of the node's output.
    pub fn out_scales(&self) -> Vec<u32> {
        match self {
            NodeType::Node(n) => vec![n.out_scale],
            NodeType::SubGraph { model, .. } => model.graph.get_output_scales(),
        }
    }

    /// Runs a forward pass on sample data
    pub fn f(&self, inputs: &[Tensor<i128>]) -> Result<Tensor<i128>, Box<dyn Error>> {
        match self {
            NodeType::Node(n) => n.opkind.f(inputs).map_err(|e| e.into()),
            NodeType::SubGraph { model, .. } => {
                let res = model.forward(inputs)?;
                assert_eq!(res.len(), 1);
                Ok(res[0].clone())
            }
        }
    }
    /// Returns a string representation of the operation.
    pub fn as_str(&self) -> String {
        match self {
            NodeType::Node(n) => n.opkind.as_string(),
            NodeType::SubGraph { .. } => "SUBGRAPH".into(),
        }
    }

    /// Returns true if the operation is an input.
    pub fn is_input(&self) -> bool {
        match self {
            NodeType::Node(n) => n.opkind.is_input(),
            NodeType::SubGraph { .. } => false,
        }
    }
    /// Returns the node's unique identifier.
    pub fn idx(&self) -> usize {
        match self {
            NodeType::Node(n) => n.idx,
            NodeType::SubGraph { idx, .. } => *idx,
        }
    }

    /// Returns the operation kind of the node (if any).
    pub fn opkind(&self) -> Box<dyn Op<F>> {
        match self {
            NodeType::Node(n) => n.opkind.clone_dyn(),
            NodeType::SubGraph { .. } => Unknown.clone_dyn(),
        }
    }
}

#[derive(Clone, Debug, Default)]
/// A set of EZKL nodes that represent a computational graph.
pub struct ParsedNodes<F: PrimeField + TensorType + PartialOrd> {
    nodes: BTreeMap<usize, NodeType<F>>,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
}

impl<F: PrimeField + TensorType + PartialOrd> ParsedNodes<F> {
    /// Returns the number of the computational graph's inputs
    pub fn num_inputs(&self) -> usize {
        let input_nodes = self.inputs.iter();
        input_nodes.len()
    }

    ///  Returns shapes of the computational graph's inputs
    pub fn input_shapes(&self) -> Vec<Vec<usize>> {
        self.inputs
            .iter()
            .flat_map(|o| self.nodes.get(o).unwrap().out_dims())
            .collect_vec()
    }

    /// Returns the number of the computational graph's outputs
    pub fn num_outputs(&self) -> usize {
        let output_nodes = self.outputs.iter();
        output_nodes.len()
    }

    /// Returns shapes of the computational graph's outputs
    pub fn output_shapes(&self) -> Vec<Vec<usize>> {
        self.outputs
            .iter()
            .flat_map(|o| self.nodes.get(o).unwrap().out_dims())
            .collect_vec()
    }

    /// Returns the fixed point scale of the computational graph's outputs
    pub fn get_output_scales(&self) -> Vec<u32> {
        let output_nodes = self.outputs.iter();
        output_nodes
            .flat_map(|o| self.nodes.get(o).unwrap().out_scales())
            .collect_vec()
    }
}

impl<F: PrimeField + TensorType + PartialOrd> Model<F> {
    fn required_lookups(&self) -> Vec<LookupOp> {
        self.graph
            .nodes
            .values()
            .flat_map(|n| n.required_lookups())
            .collect_vec()
    }

    /// Creates a `Model` from a specified path to an Onnx file.
    /// # Arguments
    /// * `reader` - A reader for an Onnx file.
    /// * `run_args` - [RunArgs]
    /// * `mode` - The [Mode] we're using the model in.
    /// * `visibility` - Which inputs to the model are public and private (params, inputs, outputs) using [VarVisibility].
    pub fn new(
        reader: &mut dyn std::io::Read,
        run_args: RunArgs,
        mode: Mode,
        visibility: VarVisibility,
    ) -> Result<Self, Box<dyn Error>> {
        let graph = Self::load_onnx_model(reader, &run_args, &mode, &visibility)?;

        let om = Model {
            run_args,
            graph,
            mode,
            visibility,
        };

        debug!("\n {}", om.table_nodes());

        Ok(om)
    }

    /// Generate model parameters for the circuit
    pub fn gen_params(&self, check_mode: CheckMode) -> Result<ModelParams, Box<dyn Error>> {
        let instance_shapes = self.instance_shapes();
        // this is the total number of variables we will need to allocate
        // for the circuit
        let num_constraints = if let Some(num_constraints) = self.run_args.allocated_constraints {
            num_constraints
        } else {
            self.dummy_layout(&self.graph.input_shapes()).unwrap()
        };

        // extract the requisite lookup ops from the model
        let mut lookup_ops: Vec<LookupOp> = self.required_lookups();

        // if we're using percentage tolerance, we need to add the necessary range check ops for it.
        if let Tolerance::Percentage { val, .. } = self.run_args.tolerance {
            let tolerance = Tolerance::Percentage {
                val,
                scale: scale_to_multiplier(self.run_args.scale) as usize,
            };
            let opkind: Box<dyn Op<F>> = Box::new(HybridOp::RangeCheck(tolerance));
            lookup_ops.extend(opkind.required_lookups());
        }

        // if we're using percentage tolerance, we need to add the necessary range check ops for it.
        if let Tolerance::Percentage { val, .. } = self.run_args.tolerance {
            let tolerance = Tolerance::Percentage {
                val,
                scale: scale_to_multiplier(self.run_args.scale) as usize,
            };
            let opkind: Box<dyn Op<F>> = Box::new(HybridOp::RangeCheck(tolerance));
            lookup_ops.extend(opkind.required_lookups());
        }

        let set: HashSet<_> = lookup_ops.drain(..).collect(); // dedup
        lookup_ops.extend(set.into_iter().sorted());

        Ok(ModelParams {
            run_args: self.run_args.clone(),
            visibility: self.visibility.clone(),
            instance_shapes,
            num_constraints,
            required_lookups: lookup_ops,
            check_mode,
        })
    }

    /// Runs a forward pass on sample data !
    /// # Arguments
    /// * `reader` - A reader for an Onnx file.
    /// * `model_inputs` - A vector of [Tensor]s to use as inputs to the model.
    /// * `run_args` - [RunArgs]
    pub fn forward(
        &self,
        model_inputs: &[Tensor<i128>],
    ) -> Result<Vec<Tensor<i128>>, Box<dyn Error>> {
        let mut results: BTreeMap<&usize, Tensor<i128>> = BTreeMap::new();
        let mut max_lookup_inputs = 0;
        let mut input_idx = 0;
        for (idx, n) in self.graph.nodes.iter() {
            let mut inputs = vec![];
            if n.is_input() {
                let mut t = model_inputs[input_idx].clone();
                input_idx += 1;
                t.reshape(&n.out_dims()[0]);
                inputs.push(t);
            } else {
                debug!("executing {}: {}", idx, n.as_str());
                trace!("dims: {:?}", n.out_dims());
                for i in n.inputs().iter() {
                    match results.get(&i) {
                        Some(value) => inputs.push(value.clone()),
                        None => return Err(Box::new(GraphError::MissingNode(*i))),
                    }
                }
            };

            if !n.required_lookups().is_empty() {
                let mut max = 0;
                for i in &inputs {
                    max = max.max(i.iter().map(|x| x.abs()).max().unwrap());
                }
                max_lookup_inputs = max_lookup_inputs.max(max);
            }

            match n {
                NodeType::Node(n) => {
                    let res = Op::<F>::f(&*n.opkind, &inputs)?;
                    results.insert(idx, res);
                }
                NodeType::SubGraph { model, .. } => {
                    let res = model.forward(&inputs)?;
                    let mut res = res.last().unwrap().clone();
                    res.flatten();
                    results.insert(idx, res);
                }
            }
        }

        let output_nodes = self.graph.outputs.iter();
        debug!(
            "model outputs are nodes: {:?}",
            output_nodes.clone().collect_vec()
        );
        let outputs = output_nodes
            .map(|o| results.get(&o).unwrap().clone().map(|x| x))
            .collect_vec();

        let max_range = 2i128.pow(self.run_args.bits as u32 - 1);
        if max_lookup_inputs >= max_range {
            let recommended_bits = (max_lookup_inputs as f64).log2().ceil() as u32 + 1;
            let recommended_scale = 1.0
                + (max_lookup_inputs as f64 / max_range as f64).log2().ceil()
                - self.run_args.scale as f64;
            warn!("At the selected lookup bits and fixed point scale, the largest input to a lookup table is too large to be represented (max: {}, bits: {}, scale: {}).",  max_lookup_inputs, self.run_args.bits, self.run_args.scale);
            if recommended_scale > 0.0 {
                warn!("Either increase the lookup bits to [{}] or decrease the scale to [{}] (or both).", recommended_bits, recommended_scale);
                warn!("Remember to increase the circuit logrows if you increase the bits.");
                warn!("Remember to re-run the forward pass with the new values.");
            } else if recommended_bits <= 27 {
                warn!("Increase the lookup bits to [{}]. The current scale cannot be decreased enough to fit the largest lookup input. ", recommended_bits);
                warn!("Remember to increase the circuit logrows if you increase the bits.");
                warn!("Remember to re-run the forward pass with the new values.");
            } else {
                let max_range = 2i128.pow(27_u32 - 1);
                let recommended_scale = self.run_args.scale as f64
                    - (max_lookup_inputs as f64 / max_range as f64).log2().ceil();
                if recommended_scale > 0.0 {
                    warn!(
                        "Increase the bits to [27] and the scale to [{}]",
                        recommended_scale
                    );
                    warn!("Remember to increase the circuit logrows if you increase the bits.");
                    warn!("Remember to re-run the forward pass with the new values.");
                } else {
                    warn!("No possible value of bits or scale can accomodate this value.")
                }
            }
        }

        Ok(outputs)
    }

    /// Loads an Onnx model from a specified path.
    /// # Arguments
    /// * `reader` - A reader for an Onnx file.
    /// * `scale` - The scale to use for quantization.
    /// * `public_params` - Whether to make the params public.
    fn load_onnx_model(
        reader: &mut dyn std::io::Read,
        run_args: &RunArgs,
        mode: &Mode,
        visibility: &VarVisibility,
    ) -> Result<ParsedNodes<F>, Box<dyn Error>> {
        let mut model = tract_onnx::onnx().model_for_read(reader).map_err(|e| {
            error!("Error loading model: {}", e);
            GraphError::ModelLoad
        })?;

        for (i, id) in model.clone().inputs.iter().enumerate() {
            let input = model.node(id.node);

            let mut dims = vec![];
            let extracted_dims: Vec<usize> = input.outputs[0]
                .fact
                .shape
                .dims()
                .filter_map(tract_onnx::tract_hir::internal::Factoid::concretize)
                .map(|x| match x.to_i64() {
                    Ok(x) => x as usize,
                    Err(_e) => {
                        if x.to_string() == "batch_size" {
                            1
                        } else {
                            panic!("Unknown dimension {}: {:?}", x.to_string(), x)
                        }
                    }
                })
                .collect();

            dims.extend(extracted_dims);

            model.set_input_fact(i, f32::fact(dims).into())?;
        }

        for (i, _) in model.clone().outputs.iter().enumerate() {
            model.set_output_fact(i, InferenceFact::default()).unwrap();
        }
        // Note: do not optimize the model, as the layout will depend on underlying hardware
        let model = model.into_typed()?.into_decluttered()?;
        let batch_size = model.symbol_table.sym("batch_size");
        let seq_len = model.symbol_table.sym("sequence_length");
        let model = model
            .concretize_dims(&SymbolValues::default().with(&batch_size, 1))?
            .concretize_dims(&SymbolValues::default().with(&seq_len, 1))?;

        let nodes = Self::nodes_from_graph(
            &model,
            run_args,
            mode,
            visibility,
            model.inputs.iter().map(|_| run_args.scale).collect(),
        )?;

        debug!("\n {}", model);

        let parsed_nodes = ParsedNodes {
            nodes,
            inputs: model.inputs.iter().map(|o| o.node).collect(),
            outputs: model.outputs.iter().map(|o| o.node).collect(),
        };

        Ok(parsed_nodes)
    }

    /// Formats nodes (including subgraphs) into tables !
    pub fn table_nodes(&self) -> String {
        let mut node_accumulator = vec![];
        let mut string = String::new();
        for (idx, node) in &self.graph.nodes {
            match node {
                NodeType::Node(n) => {
                    node_accumulator.push(n);
                }
                NodeType::SubGraph { model, inputs, .. } => {
                    let mut table = Table::new(node_accumulator.iter());
                    table.with(tabled::settings::Style::modern());
                    table.with(tabled::settings::Shadow::new(1));
                    table.with(
                        tabled::settings::style::BorderColor::default()
                            .top(tabled::settings::Color::BG_YELLOW),
                    );
                    string = format!("{} \n\n  MAIN GRAPH \n\n{}", string, table);
                    node_accumulator = vec![];
                    string = format!(
                        "{}\n\n SUBGRAPH AT IDX {} WITH INPUTS {:?}\n{}",
                        string,
                        idx,
                        inputs,
                        model.table_nodes(),
                    );
                }
            }
        }

        let mut table = Table::new(node_accumulator.iter());
        table.with(tabled::settings::Style::modern());
        format!("{} \n{}", string, table)
    }

    /// Creates ezkl nodes from a tract graph
    /// # Arguments
    /// * `graph` - A tract graph.
    /// * `run_args` - [RunArgs]
    /// * `mode` - The [Mode] we're using the model in.
    /// * `visibility` - Which inputs to the model are public and private (params, inputs, outputs) using [VarVisibility].
    pub fn nodes_from_graph(
        graph: &Graph<TypedFact, Box<dyn TypedOp>>,
        run_args: &RunArgs,
        mode: &Mode,
        visibility: &VarVisibility,
        input_scales: Vec<u32>,
    ) -> Result<BTreeMap<usize, NodeType<F>>, Box<dyn Error>> {
        let mut nodes = BTreeMap::<usize, NodeType<F>>::new();
        let mut input_idx = 0;
        for (i, n) in graph.nodes.iter().enumerate() {
            // Extract the slope layer hyperparams
            match n.op().downcast_ref::<Scan>() {
                Some(b) => {
                    let model = b.body.clone();
                    let input_scales = n
                        .inputs
                        .iter()
                        .map(|i| nodes.get(&i.node).unwrap().out_scales()[0])
                        .collect_vec();
                    let subgraph_nodes =
                        Self::nodes_from_graph(&model, run_args, mode, visibility, input_scales)?;

                    let subgraph = ParsedNodes {
                        nodes: subgraph_nodes,
                        inputs: model.inputs.iter().map(|o| o.node).collect(),
                        outputs: model.outputs.iter().map(|o| o.node).collect(),
                    };

                    let om = Model {
                        graph: subgraph,
                        run_args: run_args.clone(),
                        mode: mode.clone(),
                        visibility: visibility.clone(),
                    };
                    nodes.insert(
                        i,
                        NodeType::SubGraph {
                            model: om,
                            inputs: n.inputs.iter().map(|i| i.node).collect_vec(),

                            idx: i,
                        },
                    );
                }
                None => {
                    let mut n = Node::<F>::new(
                        n.clone(),
                        &mut nodes,
                        run_args.scale,
                        run_args.public_params,
                        i,
                    )?;
                    if n.opkind.is_input() {
                        n.opkind = Box::new(Input {
                            scale: input_scales[input_idx],
                        });
                        n.out_scale = n.opkind.out_scale(vec![], 0);
                        input_idx += 1
                    }
                    nodes.insert(i, NodeType::Node(n));
                }
            }
        }

        Ok(nodes)
    }

    /// Creates a `Model` from parsed CLI arguments
    /// # Arguments
    /// * `cli` - A [Cli] struct holding parsed CLI arguments.
    pub fn from_ezkl_conf(cli: Cli) -> Result<Self, Box<dyn Error>> {
        match cli.command {
            Commands::Table { model, args, .. } | Commands::Mock { model, args, .. } => {
                let visibility = VarVisibility::from_args(args.clone())?;
                Model::new(
                    &mut std::fs::File::open(model)?,
                    args,
                    Mode::Mock,
                    visibility,
                )
            }
            Commands::Setup { model, args, .. } => {
                let visibility = VarVisibility::from_args(args.clone())?;
                Model::new(
                    &mut std::fs::File::open(model)?,
                    args,
                    Mode::Prove,
                    visibility,
                )
            }
            #[cfg(not(target_arch = "wasm32"))]
            Commands::Fuzz { model, args, .. } => {
                let visibility = VarVisibility::from_args(args.clone())?;
                Model::new(
                    &mut std::fs::File::open(model)?,
                    args,
                    Mode::Prove,
                    visibility,
                )
            }
            #[cfg(feature = "render")]
            Commands::RenderCircuit { model, args, .. } => {
                let visibility = VarVisibility::from_args(args.clone())?;
                Model::new(
                    &mut std::fs::File::open(model)?,
                    args,
                    Mode::Table,
                    visibility,
                )
            }
            _ => panic!(),
        }
    }

    /// Creates a `Model` from parsed model params
    /// # Arguments
    /// * `params` - A [ModelParams] struct holding parsed CLI arguments.
    pub fn from_model_params(
        params: &ModelParams,
        model: &std::path::PathBuf,
    ) -> Result<Self, Box<dyn Error>> {
        let visibility = VarVisibility::from_args(params.run_args.clone())?;
        Model::new(
            &mut std::fs::File::open(model)?,
            params.run_args.clone(),
            Mode::Prove,
            visibility,
        )
    }

    /// Creates a `Model` based on CLI arguments
    pub fn from_arg() -> Result<Self, Box<dyn Error>> {
        let conf = Cli::create()?;
        Self::from_ezkl_conf(conf)
    }

    /// Configures a model for the circuit
    /// # Arguments
    /// * `meta` - The constraint system.
    /// * `vars` - The variables for the circuit.
    /// * `run_args` - [RunArgs]
    /// * `required_lookups` - The required lookup operations for the circuit.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        vars: &mut ModelVars<F>,
        num_bits: usize,
        tolerance: Tolerance,
        required_lookups: Vec<LookupOp>,
        check_mode: CheckMode,
    ) -> Result<PolyConfig<F>, Box<dyn Error>> {
        info!("configuring model");
        // Extract the abs tolerance value for the baseop range check. Will be zero if percentage tolerance is used.
        let tol_abs = match tolerance {
            Tolerance::Abs { val } => val,
            _ => 0,
        };
        let mut base_gate = PolyConfig::configure(
            meta,
            vars.advices[0..2].try_into()?,
            &vars.advices[2],
            check_mode,
            tol_abs as i32,
        );
        // set scale for HybridOp::RangeCheck and call self.conf_lookup on that op for percentage tolerance case
        let input = &vars.advices[0];
        let output = &vars.advices[1];
        for op in required_lookups {
            base_gate.configure_lookup(meta, input, output, num_bits, &op)?;
        }

        Ok(base_gate)
    }

    /// Assigns values to the regions created when calling `configure`.
    /// # Arguments
    /// * `config` - [ModelConfig] holding all node configs.
    /// * `layouter` - Halo2 Layouter.
    /// * `inputs` - The values to feed into the circuit.
    /// * `vars` - The variables for the circuit.
    pub fn layout(
        &self,
        mut config: ModelConfig<F>,
        layouter: &mut impl Layouter<F>,
        inputs: &[ValTensor<F>],
        vars: &ModelVars<F>,
    ) -> Result<(), Box<dyn Error>> {
        info!("model layout...");
        let mut results = BTreeMap::<usize, ValTensor<F>>::new();
        for (i, input_idx) in self.graph.inputs.iter().enumerate() {
            if self.visibility.input.is_public() {
                results.insert(*input_idx, vars.instances[i].clone());
            } else {
                results.insert(*input_idx, inputs[i].clone());
            }
        }

        config.base.layout_tables(layouter)?;

        layouter.assign_region(
            || "model",
            |mut region| {
                let mut offset: usize = 0;

                let thread_safe_region = Arc::new(Mutex::new(Some(&mut region)));

                let mut outputs = self
                    .layout_nodes(
                        &mut config,
                        thread_safe_region.clone(),
                        &mut results,
                        &mut offset,
                    )
                    .map_err(|e| {
                        error!("{}", e);
                        halo2_proofs::plonk::Error::Synthesis
                    })?;

                // pack outputs if need be
                if self.run_args.pack_base > 1 {
                    for i in 0..outputs.len() {
                        debug!("packing outputs...");
                        outputs[i] = config
                            .base
                            .layout(
                                thread_safe_region.clone(),
                                &outputs[i..i + 1],
                                &mut offset,
                                Box::new(PolyOp::Pack(
                                    self.run_args.pack_base,
                                    self.run_args.scale,
                                )),
                            )
                            .map_err(|e| {
                                error!("{}", e);
                                halo2_proofs::plonk::Error::Synthesis
                            })?
                            .unwrap();
                        // only use with mock prover
                        if matches!(self.mode, Mode::Mock) {
                            trace!("------------ packed output {:?}", outputs[i].show());
                        }
                    }
                }

                if self.run_args.public_outputs {
                    let tolerance = match self.run_args.tolerance {
                        Tolerance::Percentage { val, .. } => Tolerance::Percentage {
                            val,
                            scale: scale_to_multiplier(self.run_args.scale) as usize,
                        },
                        _ => self.run_args.tolerance,
                    };
                    let _ = outputs
                        .into_iter()
                        .enumerate()
                        .map(|(i, output)| {
                            let mut instance_offset = 0;
                            if self.visibility.input.is_public() {
                                instance_offset += inputs.len();
                            };
                            config.base.layout(
                                thread_safe_region.clone(),
                                &[output, vars.instances[instance_offset + i].clone()],
                                &mut offset,
                                Box::new(HybridOp::RangeCheck(tolerance)),
                            )
                        })
                        .collect_vec();
                }

                Ok(())
            },
        )?;
        info!("computing...");
        Ok(())
    }

    fn layout_nodes(
        &self,
        config: &mut ModelConfig<F>,
        region: Arc<Mutex<Option<&mut Region<F>>>>,
        results: &mut BTreeMap<usize, ValTensor<F>>,
        offset: &mut usize,
    ) -> Result<Vec<ValTensor<F>>, Box<dyn Error>> {
        for (idx, node) in self.graph.nodes.iter() {
            let values: Vec<ValTensor<F>> = node
                .inputs()
                .iter()
                .map(|i| results.get(i).unwrap().clone())
                .collect_vec();

            debug!("laying out {}: {}, offset:{}", idx, node.as_str(), offset);
            trace!("dims: {:?}", node.out_dims());
            match node {
                NodeType::Node(n) => {
                    let res = config
                        .base
                        .layout(region.clone(), &values, offset, n.opkind.clone_dyn())
                        .map_err(|e| {
                            error!("{}", e);
                            halo2_proofs::plonk::Error::Synthesis
                        })?;

                    if let Some(vt) = res {
                        // we get the max as for fused nodes this corresponds to the node output
                        results.insert(*idx, vt);
                        //only use with mock prover
                        if matches!(self.mode, Mode::Mock) {
                            trace!(
                                "------------ output node {:?}: {:?}",
                                idx,
                                results.get(idx).unwrap().show()
                            );
                        }
                    }
                }
                NodeType::SubGraph { model, .. } => {
                    let res = model.layout_nodes(config, region.clone(), results, offset)?;
                    let mut res = res.last().unwrap().clone();
                    res.flatten();
                    results.insert(*idx, res);
                }
            }
        }
        let output_nodes = self.graph.outputs.iter();
        debug!(
            "model outputs are nodes: {:?}",
            output_nodes.clone().collect_vec()
        );
        let outputs = output_nodes
            .map(|o| results.get(o).unwrap().clone())
            .collect_vec();

        Ok(outputs)
    }

    /// Assigns dummy values to the regions created when calling `configure`.
    /// # Arguments
    /// * `input_shapes` - The shapes of the inputs to the model.
    pub fn dummy_layout(&self, input_shapes: &[Vec<usize>]) -> Result<usize, Box<dyn Error>> {
        info!("calculating num of constraints using dummy model layout...");
        let mut results = BTreeMap::<usize, ValTensor<F>>::new();

        let inputs: Vec<ValTensor<F>> = input_shapes
            .iter()
            .map(|shape| {
                let t: Tensor<Value<F>> = Tensor::new(None, shape).unwrap();
                t.into()
            })
            .collect_vec();

        for (i, input_idx) in self.graph.inputs.iter().enumerate() {
            results.insert(*input_idx, inputs[i].clone());
        }

        let mut dummy_config = PolyConfig::dummy(self.run_args.logrows as usize);

        let mut offset: usize = 0;

        let mut outputs = self.dummy_layout_nodes(
            &mut dummy_config,
            &self.graph.nodes,
            &mut results,
            &mut offset,
        )?;

        // pack outputs if need be
        if self.run_args.pack_base > 1 {
            for i in 0..outputs.len() {
                debug!("packing outputs...");
                outputs[i] = dummy_config
                    .layout(
                        Arc::new(Mutex::new(None)),
                        &outputs[i..i + 1],
                        &mut offset,
                        Box::new(PolyOp::Pack(self.run_args.pack_base, self.run_args.scale)),
                    )
                    .map_err(|e| {
                        error!("{}", e);
                        halo2_proofs::plonk::Error::Synthesis
                    })?
                    .unwrap();
            }
        }

        if self.run_args.public_outputs {
            let tolerance = match self.run_args.tolerance {
                Tolerance::Percentage { val, .. } => Tolerance::Percentage {
                    val,
                    scale: scale_to_multiplier(self.run_args.scale) as usize,
                },
                _ => self.run_args.tolerance,
            };
            let _ = outputs
                .clone()
                .into_iter()
                .map(|output| {
                    dummy_config
                        .layout(
                            Arc::new(Mutex::new(None)),
                            &[output.clone(), output],
                            &mut offset,
                            Box::new(HybridOp::RangeCheck(tolerance)),
                        )
                        .unwrap()
                })
                .collect_vec();
        }

        Ok(offset)
    }

    fn dummy_layout_nodes(
        &self,
        dummy_config: &mut PolyConfig<F>,
        _nodes: &NodeGraph<F>,
        results: &mut BTreeMap<usize, ValTensor<F>>,
        offset: &mut usize,
    ) -> Result<Vec<ValTensor<F>>, Box<dyn Error>> {
        for (idx, node) in self.graph.nodes.iter() {
            debug!(
                "dummy layout {}: {}, offset: {}",
                idx,
                node.as_str(),
                offset
            );

            match node {
                NodeType::Node(n) => {
                    let values: Vec<ValTensor<F>> = node
                        .inputs()
                        .iter()
                        .map(|i| results.get(i).unwrap().clone())
                        .collect_vec();
                    let res = dummy_config
                        .layout(
                            Arc::new(Mutex::new(None)),
                            &values,
                            offset,
                            n.opkind.clone_dyn(),
                        )
                        .map_err(|e| {
                            error!("{}", e);
                            halo2_proofs::plonk::Error::Synthesis
                        })?;

                    if let Some(vt) = res {
                        results.insert(*idx, vt);
                    }
                }
                NodeType::SubGraph { model, .. } => {
                    let res = model.dummy_layout_nodes(dummy_config, _nodes, results, offset)?;
                    let mut res = res.last().unwrap().clone();
                    res.flatten();
                    results.insert(*idx, res);
                }
            }
        }

        let output_nodes = self.graph.outputs.iter();
        debug!(
            "model outputs are nodes: {:?}",
            output_nodes.clone().collect_vec()
        );
        let outputs = output_nodes
            .map(|o| results.get(o).unwrap().clone())
            .collect_vec();

        Ok(outputs)
    }

    /// Shapes of the computational graph's public inputs (if any)
    pub fn instance_shapes(&self) -> Vec<Vec<usize>> {
        let mut instance_shapes = vec![];
        if self.visibility.input.is_public() {
            instance_shapes.extend(self.graph.input_shapes());
        }
        if self.visibility.output.is_public() {
            instance_shapes.extend(self.graph.output_shapes());
        }
        instance_shapes
    }
}
