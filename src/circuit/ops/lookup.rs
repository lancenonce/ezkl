use super::*;
use halo2_proofs::circuit::Region;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::{
    circuit::{layouts, utils},
    fieldutils::i128_to_felt,
    graph::scale_to_multiplier,
    tensor::{self, Tensor, TensorError, TensorType},
};

use super::Op;
use halo2curves::ff::PrimeField;

#[allow(missing_docs)]
/// An enum representing the operations that can be used to express more complex operations via accumulation
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
pub enum LookupOp {
    Div { denom: utils::F32 },
    ReLU { scale: usize },
    Sqrt { scales: (usize, usize) },
    Rsqrt { scales: (usize, usize) },
    Recip { scale: usize },
    LeakyReLU { scale: usize, slope: utils::F32 },
    Sigmoid { scales: (usize, usize) },
    Exp { scales: (usize, usize) },
    Tanh { scales: (usize, usize) },
    Erf { scales: (usize, usize) },
    GreaterThan { a: utils::F32 },
}

impl LookupOp {
    /// a value which is always in the table
    pub fn default_pair<F: PrimeField + TensorType + PartialOrd>(&self) -> (F, F) {
        let x = vec![0_i128].into_iter().into();
        (
            <F as TensorType>::zero().unwrap(),
            i128_to_felt(Op::<F>::f(self, &[x]).unwrap()[0]),
        )
    }
}

impl<F: PrimeField + TensorType + PartialOrd> Op<F> for LookupOp {
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Matches a [Op] to an operation in the `tensor::ops` module.
    fn f(&self, x: &[Tensor<i128>]) -> Result<Tensor<i128>, TensorError> {
        match &self {
            LookupOp::GreaterThan { a } => Ok(tensor::ops::nonlinearities::greater_than(
                &x[0],
                f32::from(*a).into(),
            )),
            LookupOp::Div { denom } => Ok(tensor::ops::nonlinearities::const_div(
                &x[0],
                f32::from(*denom).into(),
            )),
            LookupOp::Recip { scale } => {
                Ok(tensor::ops::nonlinearities::recip(&x[0], *scale as u32))
            }
            LookupOp::ReLU { scale } => {
                Ok(tensor::ops::nonlinearities::leakyrelu(&x[0], *scale, 0_f64))
            }

            LookupOp::LeakyReLU { scale, slope } => Ok(tensor::ops::nonlinearities::leakyrelu(
                &x[0],
                *scale,
                slope.0.into(),
            )),
            LookupOp::Sigmoid { scales } => Ok(tensor::ops::nonlinearities::sigmoid(
                &x[0], scales.0, scales.1,
            )),
            LookupOp::Sqrt { scales } => {
                Ok(tensor::ops::nonlinearities::sqrt(&x[0], scales.0, scales.1))
            }
            LookupOp::Rsqrt { scales } => Ok(tensor::ops::nonlinearities::rsqrt(
                &x[0], scales.0, scales.1,
            )),
            LookupOp::Tanh { scales } => {
                Ok(tensor::ops::nonlinearities::tanh(&x[0], scales.0, scales.1))
            }
            LookupOp::Erf { scales } => Ok(tensor::ops::nonlinearities::erffunc(
                &x[0], scales.0, scales.1,
            )),
            LookupOp::Exp { scales } => {
                Ok(tensor::ops::nonlinearities::exp(&x[0], scales.0, scales.1))
            }
        }
    }

    /// Returns the name of the operation
    fn as_str(&self) -> &'static str {
        match self {
            LookupOp::GreaterThan { .. } => "GREATER_THAN",
            LookupOp::Recip { .. } => "RECIP",
            LookupOp::Div { .. } => "DIV",
            LookupOp::ReLU { .. } => "RELU",
            LookupOp::LeakyReLU { .. } => "LEAKY_RELU",
            LookupOp::Sigmoid { .. } => "SIGMOID",
            LookupOp::Sqrt { .. } => "SQRT",
            LookupOp::Tanh { .. } => "TANH",
            LookupOp::Erf { .. } => "ERF",
            LookupOp::Rsqrt { .. } => "RSQRT",
            LookupOp::Exp { .. } => "EXP",
        }
    }

    fn layout(
        &self,
        config: &mut crate::circuit::BaseConfig<F>,
        region: &mut Option<&mut Region<F>>,
        values: &[ValTensor<F>],
        offset: &mut usize,
    ) -> Result<Option<ValTensor<F>>, Box<dyn Error>> {
        Ok(Some(layouts::nonlinearity(
            config,
            region,
            values[..].try_into()?,
            self,
            offset,
        )?))
    }

    fn rescale(&self, inputs_scale: Vec<u32>, global_scale: u32) -> Box<dyn Op<F>> {
        match self {
            LookupOp::Recip { .. } => Box::new(LookupOp::Recip {
                scale: scale_to_multiplier(inputs_scale[0] + global_scale) as usize,
            }),
            LookupOp::Div { denom } => Box::new(LookupOp::Div {
                denom: crate::circuit::utils::F32(
                    denom.0 * scale_to_multiplier(inputs_scale[0] - global_scale),
                ),
            }),
            LookupOp::ReLU { .. } => Box::new(LookupOp::ReLU {
                scale: scale_to_multiplier(inputs_scale[0] - global_scale) as usize,
            }),
            LookupOp::LeakyReLU { slope, .. } => Box::new(LookupOp::LeakyReLU {
                scale: scale_to_multiplier(inputs_scale[0] - global_scale) as usize,
                slope: *slope,
            }),
            LookupOp::Sigmoid { .. } => Box::new(LookupOp::Sigmoid {
                scales: (
                    scale_to_multiplier(inputs_scale[0]) as usize,
                    scale_to_multiplier(global_scale) as usize,
                ),
            }),
            LookupOp::Sqrt { .. } => Box::new(LookupOp::Sqrt {
                scales: (
                    scale_to_multiplier(inputs_scale[0]) as usize,
                    scale_to_multiplier(global_scale) as usize,
                ),
            }),
            LookupOp::Rsqrt { .. } => Box::new(LookupOp::Rsqrt {
                scales: (
                    scale_to_multiplier(inputs_scale[0]) as usize,
                    scale_to_multiplier(global_scale) as usize,
                ),
            }),
            LookupOp::Tanh { .. } => Box::new(LookupOp::Tanh {
                scales: (
                    scale_to_multiplier(inputs_scale[0]) as usize,
                    scale_to_multiplier(global_scale) as usize,
                ),
            }),
            LookupOp::Erf { .. } => Box::new(LookupOp::Erf {
                scales: (
                    scale_to_multiplier(inputs_scale[0]) as usize,
                    scale_to_multiplier(global_scale) as usize,
                ),
            }),
            LookupOp::Exp { .. } => Box::new(LookupOp::Exp {
                scales: (
                    scale_to_multiplier(inputs_scale[0]) as usize,
                    scale_to_multiplier(global_scale) as usize,
                ),
            }),
            LookupOp::GreaterThan { a } => Box::new(LookupOp::GreaterThan {
                a: utils::F32(a.0 * scale_to_multiplier(inputs_scale[0])),
            }),
        }
    }

    fn required_lookups(&self) -> Vec<LookupOp> {
        vec![self.clone()]
    }

    fn clone_dyn(&self) -> Box<dyn Op<F>> {
        Box::new(self.clone()) // Forward to the derive(Clone) impl
    }
}
