use std::{any::Any, error::Error, marker::PhantomData};

use halo2_proofs::circuit::Region;
use serde::{Deserialize, Serialize};

use crate::{tensor::{self, Tensor, TensorError, TensorType, ValTensor}};
use halo2curves::ff::PrimeField;

use self::lookup::LookupOp;

///
pub mod base;
///
pub mod hybrid;
/// Layouts for specific functions (composed of base ops)
pub mod layouts;
///
pub mod lookup;
///
pub mod poly;

/// An enum representing operations that can be represented as constraints in a circuit.
pub trait Op<F: PrimeField + TensorType + PartialOrd>: std::fmt::Debug + Send + Sync + Any {
    /// Matches a [Op] to an operation in the `tensor::ops` module.
    fn f(&self, x: &[Tensor<i128>]) -> Result<Tensor<i128>, TensorError>;
    /// Returns a string representation of the operation.
    fn as_str(&self) -> &'static str;

    /// Layouts the operation in a circuit.
    fn layout(
        &self,
        config: &mut crate::circuit::BaseConfig<F>,
        region: &mut Option<&mut Region<F>>,
        values: &[ValTensor<F>],
        offset: &mut usize,
    ) -> Result<Option<ValTensor<F>>, Box<dyn Error>>;

    /// Returns the scale of the output of the operation.
    fn out_scale(&self, _: Vec<u32>, global_scale: u32) -> u32 {
        global_scale
    }

    /// Do any of the inputs to this op require homogenous input scales?
    fn requires_homogenous_input_scales(&self) -> Vec<usize> {
        vec![]
    }

    /// Returns the lookups required by the operation.
    fn required_lookups(&self) -> Vec<LookupOp> {
        vec![]
    }

    /// Rescales the operation given a vector of input scales and a global (circuit) scale.
    fn rescale(&self, inputs_scale: Vec<u32>, global_scale: u32) -> Box<dyn Op<F>>;

    /// Returns true if the operation is an input.
    fn is_input(&self) -> bool {
        false
    }

    /// Boxes and clones
    fn clone_dyn(&self) -> Box<dyn Op<F>>;

    /// Returns a reference to the Any trait.
    fn as_any(&self) -> &dyn Any;
}

impl<F: PrimeField + TensorType + PartialOrd> Clone for Box<dyn Op<F>> {
    fn clone(&self) -> Self {
        self.clone_dyn()
    }
}

impl<F: PrimeField + TensorType + PartialOrd> Eq for Box<dyn Op<F>> {}

impl<F: PrimeField + TensorType + PartialOrd> PartialEq for Box<dyn Op<F>> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<F: PrimeField + TensorType + PartialOrd> PartialOrd for Box<dyn Op<F>> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_str().partial_cmp(other.as_str())
    }
}

impl<F: PrimeField + TensorType + PartialOrd> Ord for Box<dyn Op<F>> { 
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

// trait DLOp<F: PrimeField + TensorType + PartialOrd>: 
// std::fmt::Debug + Send + Sync {
//     fn default_pair(&self) -> (F, F) {
//         let x = vec![0_i128].into_iter().into();
//         (
//             <F as TensorType>::zero().unwrap(),
//             i128_to_felt(Op::<F>::f(self, &[x]).unwrap()[0]),
//         )
//     }
//     fn partial ord / ord
// }

///
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Input;

impl<F: PrimeField + TensorType + PartialOrd> Op<F> for Input {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn f(&self, x: &[Tensor<i128>]) -> Result<Tensor<i128>, TensorError> {
        Ok(x[0].clone())
    }

    fn as_str(&self) -> &'static str {
        "Input"
    }
    fn layout(
        &self,
        _: &mut crate::circuit::BaseConfig<F>,
        _: &mut Option<&mut Region<F>>,
        _: &[ValTensor<F>],
        _: &mut usize,
    ) -> Result<Option<ValTensor<F>>, Box<dyn Error>> {
        Ok(None)
    }

    fn rescale(&self, _: Vec<u32>, _: u32) -> Box<dyn Op<F>> {
        Box::new(self.clone())
    }

    fn is_input(&self) -> bool {
        true
    }

    fn clone_dyn(&self) -> Box<dyn Op<F>> {
        Box::new(self.clone()) // Forward to the derive(Clone) impl
    }
}

/// A wrapper for an operation that has been rescaled.
#[derive(Clone, Debug)]
pub struct Rescaled<F: PrimeField + TensorType + PartialOrd> {
    /// The operation to be rescaled.
    pub inner: Box<dyn Op<F>>,
    /// The scale of the operation's inputs.
    pub scale: Vec<(usize, u128)>,
}

impl<F: PrimeField + TensorType + PartialOrd> Op<F> for Rescaled<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn f(&self, x: &[Tensor<i128>]) -> Result<Tensor<i128>, TensorError> {
        if self.scale.len() != x.len() {
            return Err(TensorError::DimMismatch("rescaled inputs".to_string()));
        }

        let mut rescaled_inputs = vec![];
        let inputs = &mut x.to_vec();
        for (i, ri) in inputs.iter_mut().enumerate() {
            rescaled_inputs.push(tensor::ops::rescale(ri, self.scale[i].1)?);
        }
        Ok(Op::<F>::f(&*self.inner, &rescaled_inputs)?)
    }

    fn rescale(&self, _: Vec<u32>, _: u32) -> Box<dyn Op<F>> {
        Box::new(self.clone())
    }

    fn as_str(&self) -> &'static str {
        self.inner.as_str()
    }

    fn out_scale(&self, in_scales: Vec<u32>, _g: u32) -> u32 {
        let in_scales = in_scales
            .into_iter()
            .zip(self.scale.iter())
            .map(|(a, b)| a + crate::graph::mult_to_scale(b.1 as f32))
            .collect();

        Op::<F>::out_scale(&*self.inner, in_scales, _g)
    }

    fn layout(
        &self,
        config: &mut crate::circuit::BaseConfig<F>,
        region: &mut Option<&mut Region<F>>,
        values: &[ValTensor<F>],
        offset: &mut usize,
    ) -> Result<Option<ValTensor<F>>, Box<dyn Error>> {
        if self.scale.len() != values.len() {
            return Err(Box::new(TensorError::DimMismatch(
                "rescaled inputs".to_string(),
            )));
        }

        let res =
            &layouts::rescale(config, region, values[..].try_into()?, &self.scale, offset)?[..];
        self.inner.layout(config, region, res, offset)
    }

    fn clone_dyn(&self) -> Box<dyn Op<F>> {
        Box::new(self.clone()) // Forward to the derive(Clone) impl
    }
}

/// An unknown operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Unknown;

impl<F: PrimeField + TensorType + PartialOrd> Op<F> for Unknown {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn f(&self, _: &[Tensor<i128>]) -> Result<Tensor<i128>, TensorError> {
        Err(TensorError::WrongMethod)
    }

    fn as_str(&self) -> &'static str {
        "Unknown"
    }
    fn layout(
        &self,
        _: &mut crate::circuit::BaseConfig<F>,
        _: &mut Option<&mut Region<F>>,
        _: &[ValTensor<F>],
        _: &mut usize,
    ) -> Result<Option<ValTensor<F>>, Box<dyn Error>> {
        Err(Box::new(super::CircuitError::UnsupportedOp))
    }
    fn rescale(&self, _: Vec<u32>, _: u32) -> Box<dyn Op<F>> {
        Box::new(self.clone())
    }

    fn clone_dyn(&self) -> Box<dyn Op<F>> {
        Box::new(self.clone()) // Forward to the derive(Clone) impl
    }
}

///
#[derive(Clone, Debug)]
pub struct Constant<F: PrimeField + TensorType + PartialOrd> {
    ///
    pub values: Tensor<f32>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField + TensorType + PartialOrd> Constant<F> {
    ///
    pub fn new(values: Tensor<f32>) -> Self {
        Self {
            values,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> Op<F> for Constant<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn f(&self, _: &[Tensor<i128>]) -> Result<Tensor<i128>, TensorError> {
        Err(TensorError::WrongMethod)
    }

    fn as_str(&self) -> &'static str {
        "CONST"
    }
    fn layout(
        &self,
        _: &mut crate::circuit::BaseConfig<F>,
        _: &mut Option<&mut Region<F>>,
        _: &[ValTensor<F>],
        _: &mut usize,
    ) -> Result<Option<ValTensor<F>>, Box<dyn Error>> {
        Err(Box::new(TensorError::WrongMethod))
    }
    fn rescale(&self, _: Vec<u32>, _: u32) -> Box<dyn Op<F>> {
        Box::new(self.clone())
    }

    fn clone_dyn(&self) -> Box<dyn Op<F>> {
        Box::new(self.clone()) // Forward to the derive(Clone) impl
    }
}
