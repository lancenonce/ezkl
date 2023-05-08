use super::utilities::node_output_shapes;
use crate::circuit::Op;
use crate::graph::new_op_from_onnx;
use crate::graph::GraphError;
use crate::tensor::TensorType;
use anyhow::Result;
use halo2curves::ff::PrimeField;
use log::trace;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use tabled::Tabled;
use tract_onnx;
use tract_onnx::prelude::Node as OnnxNode;
use tract_onnx::prelude::TypedFact;
use tract_onnx::prelude::TypedOp;

/// Representation of an execution graph divided into execution 'buckets'.
pub type NodeGraph<F> = BTreeMap<usize, Node<F>>;

fn display_vector<T: fmt::Debug>(v: &Vec<T>) -> String {
    if !v.is_empty() {
        format!("{:?}", v)
    } else {
        String::new()
    }
}

fn display_opkind<F: PrimeField + TensorType + PartialOrd>(v: &Box<dyn Op<F>>) -> String {
    v.as_str().to_string()
}

/// A single operation in a Model.
#[derive(Clone, Debug, Tabled)]
pub struct Node<F: PrimeField + TensorType + PartialOrd> {
    /// [OpKind] enum, i.e what operation this node represents.
    #[tabled(display_with = "display_opkind")]
    pub opkind: Box<dyn Op<F>>,
    /// The denominator in the fixed point representation for the node's output. Tensors of differing scales should not be combined.
    pub out_scale: u32,
    // Usually there is a simple in and out shape of the node as an operator.  For example, an Affine node has three input_shapes (one for the input, weight, and bias),
    // but in_dim is [in], out_dim is [out]
    #[tabled(display_with = "display_vector")]
    /// The indices of the node's inputs.
    pub inputs: Vec<usize>,
    #[tabled(display_with = "display_vector")]
    /// Dimensions of output.
    pub out_dims: Vec<usize>,
    /// The node's unique identifier.
    pub idx: usize,
}

impl<F: PrimeField + TensorType + PartialOrd> Node<F> {
    /// Create a new node from an [OnnxNode].
    /// The node's inputs must already be present in the `other_nodes` map.
    /// The node's output shape must be known.
    /// The node's op must be supported.
    /// The node's inputs must be consistent with the op's inputs.
    /// # Arguments
    /// * `node` - The [OnnxNode] to be converted into a [Node].
    /// * `other_nodes` - A map of the other nodes in the graph.
    /// * `scale` - The scale of the node's output.
    /// * `public_params` - Whether the node's parameters are public.
    /// * `idx` - The node's unique identifier.
    pub fn new(
        mut node: OnnxNode<TypedFact, Box<dyn TypedOp>>,
        other_nodes: &mut BTreeMap<usize, Node<F>>,
        scale: u32,
        public_params: bool,
        idx: usize,
    ) -> Result<Self, Box<dyn Error>> {
        trace!("Create {:?}", node);
        trace!("Create op {:?}", node.op);

        // load the node inputs
        let mut inputs = vec![];

        for i in node.inputs.iter_mut() {
            match other_nodes.get(&i.node) {
                Some(n) => inputs.push(n.clone()),
                None => return Err(Box::new(GraphError::MissingNode(i.node))),
            }
        }

        let mut opkind = new_op_from_onnx(idx, scale, public_params, node.clone(), &mut inputs)?; // parses the op name

        // rescale the inputs if necessary to get consistent fixed points
        let in_scales: Vec<u32> = inputs.iter().map(|i| i.out_scale).collect();
        opkind = opkind.rescale(in_scales.clone(), scale);
        let out_scale = match in_scales.len() {
            0 => scale,
            _ => opkind.out_scale(in_scales, scale),
        };

        // get the output shape
        let mut out_dims = {
            let output_shapes = match node_output_shapes(&node) {
                Ok(s) => Some(s),
                _ => None,
            };

            if let Some([Some(v)]) = output_shapes.as_deref() {
                v.to_vec()
            } else {
                // Turn  `outputs: [?,3,32,32,F32 >3/0]` into `vec![3,32,32]`  in two steps
                node.outputs[0]
                    .fact
                    .shape
                    .iter()
                    // .filter_map(|x| x.concretize())
                    .map(|x| x.to_i64().unwrap() as usize)
                    .collect()
            }
        };

        // rm batch
        if !out_dims.is_empty() && out_dims[0] == 1 && out_dims.len() > 1 {
            out_dims = out_dims[1..].to_vec();
        }
        if out_dims.iter().product::<usize>() == 1 {
            out_dims = vec![1];
        };

        Ok(Node {
            idx,
            opkind,
            inputs: inputs.iter().map(|i| i.idx).collect(),
            out_dims,
            out_scale,
        })
    }
}
