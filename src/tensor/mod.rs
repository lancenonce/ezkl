/// Implementations of common operations on tensors.
pub mod ops;
/// A wrapper around a tensor of circuit variables / advices.
pub mod val;
/// A wrapper around a tensor of Halo2 Value types.
pub mod var;

use halo2curves::ff::PrimeField;
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
pub use val::*;
pub use var::*;

use crate::{
    circuit::utils,
    fieldutils::{felt_to_i32, i128_to_felt, i32_to_felt},
};

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ops::Range;
use std::{cmp::max, ops::Add};
use std::{error::Error, ops::Mul};
use std::{fmt::Debug, ops::Sub};
use std::{iter::Iterator, ops::Div};
use thiserror::Error;
/// A wrapper for tensor related errors.
#[derive(Debug, Error)]
pub enum TensorError {
    /// Shape mismatch in a operation
    #[error("dimension mismatch in tensor op: {0}")]
    DimMismatch(String),
    /// Shape when instantiating
    #[error("dimensionality error when manipulating a tensor")]
    DimError,
    /// wrong method was called on a tensor-like struct
    #[error("wrong method called")]
    WrongMethod,
    /// Significant bit truncation when instantiating
    #[error("Significant bit truncation when instantiating")]
    SigBitTruncationError,
}

/// The (inner) type of tensor elements.
pub trait TensorType: Clone + Debug + 'static {
    /// Returns the zero value.
    fn zero() -> Option<Self> {
        None
    }
    /// Returns the unit value.
    fn one() -> Option<Self> {
        None
    }
    /// Max operator for ordering values.
    fn tmax(&self, _: &Self) -> Option<Self> {
        None
    }
}

macro_rules! tensor_type {
    ($rust_type:ty, $tensor_type:ident, $zero:expr, $one:expr) => {
        impl TensorType for $rust_type {
            fn zero() -> Option<Self> {
                Some($zero)
            }
            fn one() -> Option<Self> {
                Some($one)
            }

            fn tmax(&self, other: &Self) -> Option<Self> {
                Some(max(*self, *other))
            }
        }
    };
}

impl TensorType for f32 {
    fn zero() -> Option<Self> {
        Some(0.0)
    }

    // f32 doesnt impl Ord so we cant just use max like we can for i32, usize.
    // A comparison between f32s needs to handle NAN values.
    fn tmax(&self, other: &Self) -> Option<Self> {
        match (self.is_nan(), other.is_nan()) {
            (true, true) => Some(f32::NAN),
            (true, false) => Some(*other),
            (false, true) => Some(*self),
            (false, false) => {
                if self >= other {
                    Some(*self)
                } else {
                    Some(*other)
                }
            }
        }
    }
}

impl TensorType for f64 {
    fn zero() -> Option<Self> {
        Some(0.0)
    }

    // f32 doesnt impl Ord so we cant just use max like we can for i32, usize.
    // A comparison between f32s needs to handle NAN values.
    fn tmax(&self, other: &Self) -> Option<Self> {
        match (self.is_nan(), other.is_nan()) {
            (true, true) => Some(f64::NAN),
            (true, false) => Some(*other),
            (false, true) => Some(*self),
            (false, false) => {
                if self >= other {
                    Some(*self)
                } else {
                    Some(*other)
                }
            }
        }
    }
}

tensor_type!(i128, Int128, 0, 1);
tensor_type!(i32, Int32, 0, 1);
tensor_type!(usize, USize, 0, 1);
tensor_type!((), Empty, (), ());
tensor_type!(utils::F32, F32, utils::F32(0.0), utils::F32(1.0));

impl<T: TensorType> TensorType for Tensor<T> {
    fn zero() -> Option<Self> {
        Some(Tensor::new(Some(&[T::zero().unwrap()]), &[1]).unwrap())
    }
    fn one() -> Option<Self> {
        Some(Tensor::new(Some(&[T::one().unwrap()]), &[1]).unwrap())
    }
}

impl<T: TensorType> TensorType for Value<T> {
    fn zero() -> Option<Self> {
        Some(Value::known(T::zero().unwrap()))
    }

    fn one() -> Option<Self> {
        Some(Value::known(T::one().unwrap()))
    }

    fn tmax(&self, other: &Self) -> Option<Self> {
        Some(
            (self.clone())
                .zip(other.clone())
                .map(|(a, b)| a.tmax(&b).unwrap()),
        )
    }
}

impl<F: PrimeField + PartialOrd> TensorType for Assigned<F>
where
    F: Field,
{
    fn zero() -> Option<Self> {
        Some(F::ZERO.into())
    }

    fn one() -> Option<Self> {
        Some(F::ONE.into())
    }

    fn tmax(&self, other: &Self) -> Option<Self> {
        if self.evaluate() >= other.evaluate() {
            Some(*self)
        } else {
            Some(*other)
        }
    }
}

impl<F: PrimeField> TensorType for Expression<F>
where
    F: Field,
{
    fn zero() -> Option<Self> {
        Some(Expression::Constant(F::ZERO))
    }

    fn one() -> Option<Self> {
        Some(Expression::Constant(F::ONE))
    }

    fn tmax(&self, _: &Self) -> Option<Self> {
        todo!()
    }
}

impl TensorType for Column<Advice> {}
impl TensorType for Column<Fixed> {}

impl<F: PrimeField + PartialOrd> TensorType for AssignedCell<Assigned<F>, F> {
    fn tmax(&self, other: &Self) -> Option<Self> {
        let mut output: Option<Self> = None;
        self.value_field().zip(other.value_field()).map(|(a, b)| {
            if a.evaluate() >= b.evaluate() {
                output = Some(self.clone());
            } else {
                output = Some(other.clone());
            }
        });
        output
    }
}

impl<F: PrimeField + PartialOrd> TensorType for AssignedCell<F, F> {
    fn tmax(&self, other: &Self) -> Option<Self> {
        let mut output: Option<Self> = None;
        self.value().zip(other.value()).map(|(a, b)| {
            if a >= b {
                output = Some(self.clone());
            } else {
                output = Some(other.clone());
            }
        });
        output
    }
}

// specific types
impl TensorType for halo2curves::pasta::Fp {
    fn zero() -> Option<Self> {
        Some(halo2curves::pasta::Fp::zero())
    }

    fn one() -> Option<Self> {
        Some(halo2curves::pasta::Fp::one())
    }

    fn tmax(&self, other: &Self) -> Option<Self> {
        Some((*self).max(*other))
    }
}

impl TensorType for halo2curves::bn256::Fr {
    fn zero() -> Option<Self> {
        Some(halo2curves::bn256::Fr::zero())
    }

    fn one() -> Option<Self> {
        Some(halo2curves::bn256::Fr::one())
    }

    fn tmax(&self, other: &Self) -> Option<Self> {
        Some((*self).max(*other))
    }
}

/// A generic multi-dimensional array representation of a Tensor.
/// The `inner` attribute contains a vector of values whereas `dims` corresponds to the dimensionality of the array
/// and as such determines how we index, query for values, or slice a Tensor.
#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Tensor<T: TensorType> {
    inner: Vec<T>,
    dims: Vec<usize>,
}

impl<T: TensorType> IntoIterator for Tensor<T> {
    type Item = T;
    type IntoIter = ::std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<T: TensorType> Deref for Tensor<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        self.inner.deref()
    }
}

impl<T: TensorType> DerefMut for Tensor<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        self.inner.deref_mut()
    }
}

impl<T: PartialEq + TensorType> PartialEq for Tensor<T> {
    fn eq(&self, other: &Tensor<T>) -> bool {
        self.dims == other.dims && self.deref() == other.deref()
    }
}

impl<I: Iterator> From<I> for Tensor<I::Item>
where
    I::Item: TensorType + Clone,
    Vec<I::Item>: FromIterator<I::Item>,
{
    fn from(value: I) -> Tensor<I::Item> {
        let data: Vec<I::Item> = value.collect::<Vec<I::Item>>();
        Tensor::new(Some(&data), &[data.len()]).unwrap()
    }
}

impl<T> FromIterator<T> for Tensor<T>
where
    T: TensorType + Clone,
    Vec<T>: FromIterator<T>,
{
    fn from_iter<I: IntoIterator<Item = T>>(value: I) -> Tensor<T> {
        let data: Vec<I::Item> = value.into_iter().collect::<Vec<I::Item>>();
        Tensor::new(Some(&data), &[data.len()]).unwrap()
    }
}

impl<F: PrimeField + Clone + TensorType + PartialOrd> From<Tensor<AssignedCell<Assigned<F>, F>>>
    for Tensor<i32>
{
    fn from(value: Tensor<AssignedCell<Assigned<F>, F>>) -> Tensor<i32> {
        let mut output = Vec::new();
        value.map(|x| {
            x.evaluate().value().map(|y| {
                let e = felt_to_i32(*y);
                output.push(e);
                e
            })
        });
        Tensor::new(Some(&output), value.dims()).unwrap()
    }
}

impl<F: PrimeField + Clone + TensorType + PartialOrd> From<Tensor<AssignedCell<F, F>>>
    for Tensor<i32>
{
    fn from(value: Tensor<AssignedCell<F, F>>) -> Tensor<i32> {
        let mut output = Vec::new();
        value.map(|x| {
            let mut i = 0;
            x.value().map(|y| {
                let e = felt_to_i32(*y);
                output.push(e);
                i += 1;
            });
            if i == 0 {
                output.push(0);
            }
        });
        Tensor::new(Some(&output), value.dims()).unwrap()
    }
}

impl<F: PrimeField + Clone + TensorType + PartialOrd> From<Tensor<AssignedCell<Assigned<F>, F>>>
    for Tensor<Value<F>>
{
    fn from(value: Tensor<AssignedCell<Assigned<F>, F>>) -> Tensor<Value<F>> {
        let mut output = Vec::new();
        for (_, x) in value.iter().enumerate() {
            output.push(x.value_field().evaluate());
        }
        Tensor::new(Some(&output), value.dims()).unwrap()
    }
}

impl<F: PrimeField + TensorType + Clone + PartialOrd> From<Tensor<Value<F>>> for Tensor<i32> {
    fn from(t: Tensor<Value<F>>) -> Tensor<i32> {
        let mut output = Vec::new();
        t.map(|x| {
            let mut i = 0;
            x.map(|y| {
                let e = felt_to_i32(y);
                output.push(e);
                i += 1;
            });
            if i == 0 {
                output.push(0);
            }
        });
        Tensor::new(Some(&output), t.dims()).unwrap()
    }
}

impl<F: PrimeField + TensorType + Clone + PartialOrd> From<Tensor<Value<F>>>
    for Tensor<Value<Assigned<F>>>
{
    fn from(t: Tensor<Value<F>>) -> Tensor<Value<Assigned<F>>> {
        let mut ta: Tensor<Value<Assigned<F>>> = Tensor::from((0..t.len()).map(|i| t[i].into()));
        ta.reshape(t.dims());
        ta
    }
}

impl<F: PrimeField + TensorType + Clone> From<Tensor<i32>> for Tensor<Value<F>> {
    fn from(t: Tensor<i32>) -> Tensor<Value<F>> {
        let mut ta: Tensor<Value<F>> =
            Tensor::from((0..t.len()).map(|i| Value::known(i32_to_felt::<F>(t[i]))));
        ta.reshape(t.dims());
        ta
    }
}

impl<F: PrimeField + TensorType + Clone> From<Tensor<i128>> for Tensor<Value<F>> {
    fn from(t: Tensor<i128>) -> Tensor<Value<F>> {
        let mut ta: Tensor<Value<F>> =
            Tensor::from((0..t.len()).map(|i| Value::known(i128_to_felt::<F>(t[i]))));
        ta.reshape(t.dims());
        ta
    }
}

impl<T: Clone + TensorType + std::marker::Send + std::marker::Sync>
    rayon::iter::IntoParallelIterator for Tensor<T>
{
    type Iter = rayon::vec::IntoIter<T>;
    type Item = T;
    fn into_par_iter(self) -> Self::Iter {
        self.inner.into_par_iter()
    }
}

impl<'data, T: Clone + TensorType + std::marker::Send + std::marker::Sync>
    rayon::iter::IntoParallelRefMutIterator<'data> for Tensor<T>
{
    type Iter = rayon::slice::IterMut<'data, T>;
    type Item = &'data mut T;
    fn par_iter_mut(&'data mut self) -> Self::Iter {
        self.inner.par_iter_mut()
    }
}

impl<T: Clone + TensorType> Tensor<T> {
    /// Sets (copies) the tensor values to the provided ones.
    pub fn new(values: Option<&[T]>, dims: &[usize]) -> Result<Self, TensorError> {
        let total_dims: usize = dims.iter().product();
        match values {
            Some(v) => {
                if total_dims != v.len() {
                    return Err(TensorError::DimError);
                }
                Ok(Tensor {
                    inner: Vec::from(v),
                    dims: Vec::from(dims),
                })
            }
            None => Ok(Tensor {
                inner: vec![T::zero().unwrap(); total_dims],
                dims: Vec::from(dims),
            }),
        }
    }

    /// Returns the number of elements in the tensor.
    pub fn len(&self) -> usize {
        self.dims().iter().product::<usize>()
    }
    /// Checks if the number of elements in tensor is 0.
    pub fn is_empty(&self) -> bool {
        self.dims().iter().product::<usize>() == 0
    }

    /// Set one single value on the tensor.
    ///
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<i32>::new(None, &[3, 3, 3]).unwrap();
    ///
    /// a.set(&[0, 0, 1], 10);
    /// assert_eq!(a[0 + 0 + 1], 10);
    ///
    /// a.set(&[2, 2, 0], 9);
    /// assert_eq!(a[2*9 + 2*3 + 0], 9);
    /// ```
    pub fn set(&mut self, indices: &[usize], value: T) {
        let index = self.get_index(indices);
        self[index] = value;
    }

    /// Get a single value from the Tensor.
    ///
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<i32>::new(None, &[2, 3, 5]).unwrap();
    ///
    /// a[1*15 + 1*5 + 1] = 5;
    /// assert_eq!(a.get(&[1, 1, 1]), 5);
    /// ```
    pub fn get(&self, indices: &[usize]) -> T {
        let index = self.get_index(indices);
        self[index].clone()
    }

    /// Get a slice from the Tensor.
    ///
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<i32>::new(Some(&[1, 2, 3]), &[3]).unwrap();
    /// let mut b = Tensor::<i32>::new(Some(&[1, 2]), &[2]).unwrap();
    ///
    /// assert_eq!(a.get_slice(&[0..2]).unwrap(), b);
    /// ```
    pub fn get_slice(&self, indices: &[Range<usize>]) -> Result<Tensor<T>, TensorError> {
        if self.dims.len() < indices.len() {
            return Err(TensorError::DimError);
        }
        let mut res = Vec::new();
        // if indices weren't specified we fill them in as required
        let mut full_indices = indices.to_vec();

        for i in 0..(self.dims.len() - indices.len()) {
            full_indices.push(0..self.dims()[indices.len() + i])
        }
        for e in full_indices.iter().cloned().multi_cartesian_product() {
            let index = self.get_index(&e);
            res.push(self[index].clone())
        }
        let dims: Vec<usize> = full_indices.iter().map(|e| e.end - e.start).collect();
        // for i in (0..indices.len()).rev() {
        //     if (dims[i] == 1) && (dims.len() > 1) {
        //         dims.remove(i);
        //     }
        // }

        Tensor::new(Some(&res), &dims)
    }

    /// Get the array index from rows / columns indices.
    ///
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let a = Tensor::<f32>::new(None, &[3, 3, 3]).unwrap();
    ///
    /// assert_eq!(a.get_index(&[2, 2, 2]), 26);
    /// assert_eq!(a.get_index(&[1, 2, 2]), 17);
    /// assert_eq!(a.get_index(&[1, 2, 0]), 15);
    /// assert_eq!(a.get_index(&[1, 0, 1]), 10);
    /// ```
    pub fn get_index(&self, indices: &[usize]) -> usize {
        assert_eq!(self.dims.len(), indices.len());
        let mut index = 0;
        let mut d = 1;
        for i in (0..indices.len()).rev() {
            assert!(self.dims[i] > indices[i]);
            index += indices[i] * d;
            d *= self.dims[i];
        }
        index
    }

    /// Duplicates every nth element
    ///
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let a = Tensor::<i32>::new(Some(&[1, 2, 3, 4, 5, 6]), &[6]).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[1, 2, 3, 3, 4, 5, 5, 6]), &[8]).unwrap();
    /// assert_eq!(a.duplicate_every_n(3, 0).unwrap(), expected);
    /// assert_eq!(a.duplicate_every_n(7, 0).unwrap(), a);
    ///
    /// let expected = Tensor::<i32>::new(Some(&[1, 1, 2, 3, 3, 4, 5, 5, 6]), &[9]).unwrap();
    /// assert_eq!(a.duplicate_every_n(3, 2).unwrap(), expected);
    ///
    /// ```
    pub fn duplicate_every_n(
        &self,
        n: usize,
        initial_offset: usize,
    ) -> Result<Tensor<T>, TensorError> {
        let mut inner: Vec<T> = vec![];
        let mut offset = initial_offset;
        for (i, elem) in self.inner.clone().into_iter().enumerate() {
            if (i + offset + 1) % n == 0 {
                inner.extend(vec![elem; 2].into_iter());
                offset += 1;
            } else {
                inner.push(elem.clone());
            }
        }
        Tensor::new(Some(&inner), &[inner.len()])
    }

    /// Removes every nth element
    ///
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let a = Tensor::<i32>::new(Some(&[1, 2, 3, 3, 4, 5, 6, 6]), &[8]).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[1, 2, 3, 4, 5, 6]), &[6]).unwrap();
    /// assert_eq!(a.remove_every_n(4, 0).unwrap(), expected);
    ///
    /// let a = Tensor::<i32>::new(Some(&[1, 2, 3, 3, 4, 5, 6]), &[7]).unwrap();
    /// assert_eq!(a.remove_every_n(4, 0).unwrap(), expected);
    /// assert_eq!(a.remove_every_n(9, 0).unwrap(), a);
    ///
    /// let a = Tensor::<i32>::new(Some(&[1, 1, 2, 3, 3, 4, 5, 5, 6]), &[9]).unwrap();
    /// assert_eq!(a.remove_every_n(3, 2).unwrap(), expected);
    ///
    pub fn remove_every_n(
        &self,
        n: usize,
        initial_offset: usize,
    ) -> Result<Tensor<T>, TensorError> {
        let mut inner: Vec<T> = vec![];
        for (i, elem) in self.inner.clone().into_iter().enumerate() {
            if (i + initial_offset + 1) % n == 0 {
            } else {
                inner.push(elem.clone());
            }
        }
        Tensor::new(Some(&inner), &[inner.len()])
    }

    /// Returns the tensor's dimensions.
    pub fn dims(&self) -> &[usize] {
        &self.dims
    }

    ///Reshape the tensor
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<f32>::new(None, &[3, 3, 3]).unwrap();
    /// a.reshape(&[9, 3]);
    /// assert_eq!(a.dims(), &[9, 3]);
    /// ```
    pub fn reshape(&mut self, new_dims: &[usize]) {
        assert!(self.len() == new_dims.iter().product::<usize>());
        self.dims = Vec::from(new_dims);
    }

    /// Broadcasts the tensor to a given shape
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<i32>::new(Some(&[1, 2, 3]), &[3, 1]).unwrap();
    ///
    /// let mut expected = Tensor::<i32>::new(Some(&[1, 1, 1, 2, 2, 2, 3, 3, 3]), &[3, 3]).unwrap();
    /// assert_eq!(a.expand(&[3, 3]).unwrap(), expected);
    ///
    /// ```
    pub fn expand(&self, shape: &[usize]) -> Result<Self, TensorError> {
        assert!(self.dims().len() <= shape.len());

        if shape == self.dims() {
            return Ok(self.clone());
        }

        for d in self.dims() {
            assert!(shape.contains(d) || *d == 1);
        }

        let cartesian_coords = shape
            .iter()
            .map(|d| 0..*d)
            .multi_cartesian_product()
            .collect::<Vec<Vec<usize>>>();

        let mut output = Tensor::new(None, shape)?;

        for coord in cartesian_coords {
            let mut new_coord = Vec::with_capacity(self.dims().len());
            for (i, c) in coord.iter().enumerate() {
                if i < self.dims().len() && self.dims()[i] == 1 {
                    new_coord.push(0);
                } else if i >= self.dims().len() {
                    // do nothing at this point does not exist in the original tensor
                } else {
                    new_coord.push(*c);
                }
            }
            output.set(&coord, self.get(&new_coord));
        }

        Ok(output)
    }

    ///Flatten the tensor shape
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<f32>::new(None, &[3, 3, 3]).unwrap();
    /// a.flatten();
    /// assert_eq!(a.dims(), &[27]);
    /// ```
    pub fn flatten(&mut self) {
        self.dims = Vec::from([self.dims.iter().product::<usize>()]);
    }

    /// Maps a function to tensors
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<i32>::new(Some(&[1, 4]), &[2]).unwrap();
    /// let mut c = a.map(|x| i32::pow(x,2));
    /// assert_eq!(c, Tensor::from([1, 16].into_iter()))
    /// ```
    pub fn map<F: FnMut(T) -> G, G: TensorType>(&self, mut f: F) -> Tensor<G> {
        let mut t = Tensor::from(self.inner.iter().map(|e| f(e.clone())));
        t.reshape(self.dims());
        t
    }

    /// Maps a function to tensors and enumerates
    /// ```
    /// use ezkl_lib::tensor::{Tensor, TensorError};
    /// let mut a = Tensor::<i32>::new(Some(&[1, 4]), &[2]).unwrap();
    /// let mut c = a.enum_map::<_,_,TensorError>(|i, x| Ok(i32::pow(x + i as i32, 2))).unwrap();
    /// assert_eq!(c, Tensor::from([1, 25].into_iter()));
    /// ```
    pub fn enum_map<F: FnMut(usize, T) -> Result<G, E>, G: TensorType, E: Error>(
        &self,
        mut f: F,
    ) -> Result<Tensor<G>, E> {
        let vec: Result<Vec<G>, E> = self
            .inner
            .iter()
            .enumerate()
            .map(|(i, e)| f(i, e.clone()))
            .collect();
        let mut t: Tensor<G> = Tensor::from(vec?.iter().cloned());
        t.reshape(self.dims());
        Ok(t)
    }
}

impl<T: Clone + TensorType> Tensor<Tensor<T>> {
    /// Flattens a tensor of tensors
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// let mut a = Tensor::<i32>::new(Some(&[1, 2, 3, 4, 5, 6]), &[2, 3]).unwrap();
    /// let mut b = Tensor::<i32>::new(Some(&[1, 4]), &[2, 1]).unwrap();
    /// let mut c = Tensor::new(Some(&[a,b]), &[2]).unwrap();
    /// let mut d = c.combine().unwrap();
    /// assert_eq!(d.dims(), &[8]);
    /// ```
    pub fn combine(&self) -> Result<Tensor<T>, TensorError> {
        let mut dims = 0;
        let mut inner = Vec::new();
        for t in self.inner.clone().into_iter() {
            dims += t.len();
            inner.extend(t.inner);
        }
        Tensor::new(Some(&inner), &[dims])
    }
}

impl<T: TensorType + Add<Output = T> + std::marker::Send + std::marker::Sync> Add for Tensor<T> {
    type Output = Result<Tensor<T>, TensorError>;
    /// Adds tensors.
    /// # Arguments
    ///
    /// * `self` - Tensor
    /// * `rhs` - Tensor
    /// # Examples
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// use std::ops::Add;
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2, 3, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let result = x.add(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[4, 4, 4, 2, 2, 2]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    /// // Now test 1D casting
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2]),
    ///     &[1]).unwrap();
    /// let result = x.add(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[4, 3, 4, 3, 3, 3]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    ///
    /// // Now test 2D casting
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2, 3]),
    ///     &[2]).unwrap();
    /// let result = x.add(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[4, 3, 4, 4, 4, 4]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    /// ```
    fn add(self, rhs: Self) -> Self::Output {
        let broadcasted_shape = get_broadcasted_shape(self.dims(), rhs.dims()).unwrap();
        let mut lhs = self.expand(&broadcasted_shape).unwrap();
        let rhs = rhs.expand(&broadcasted_shape).unwrap();

        lhs.par_iter_mut().zip(rhs).for_each(|(o, r)| {
            *o = o.clone() + r;
        });

        Ok(lhs)
    }
}

impl<T: TensorType + Sub<Output = T> + std::marker::Send + std::marker::Sync> Sub for Tensor<T> {
    type Output = Result<Tensor<T>, TensorError>;
    /// Subtracts tensors.
    /// # Arguments
    ///
    /// * `self` - Tensor
    /// * `rhs` - Tensor
    /// # Examples
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// use std::ops::Sub;
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2, 3, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let result = x.sub(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[0, -2, 0, 0, 0, 0]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    /// // Now test 1D sub
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2]),
    ///     &[1],
    /// ).unwrap();
    /// let result = x.sub(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[0, -1, 0, -1, -1, -1]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    /// // Now test 2D sub
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2, 3]),
    ///     &[2],
    /// ).unwrap();
    /// let result = x.sub(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[0, -1, 0, -2, -2, -2]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    /// ```
    fn sub(self, rhs: Self) -> Self::Output {
        let broadcasted_shape = get_broadcasted_shape(self.dims(), rhs.dims()).unwrap();
        let mut lhs = self.expand(&broadcasted_shape).unwrap();
        let rhs = rhs.expand(&broadcasted_shape).unwrap();

        lhs.par_iter_mut().zip(rhs).for_each(|(o, r)| {
            *o = o.clone() - r;
        });

        Ok(lhs)
    }
}

impl<T: TensorType + Mul<Output = T> + std::marker::Send + std::marker::Sync> Mul for Tensor<T> {
    type Output = Result<Tensor<T>, TensorError>;
    /// Elementwise multiplies tensors.
    /// # Arguments
    ///
    /// * `self` - Tensor
    /// * `rhs` - Tensor
    /// # Examples
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// use std::ops::Mul;
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2, 3, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let result = x.mul(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[4, 3, 4, 1, 1, 1]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    /// // Now test 1D mult
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2]),
    ///     &[1]).unwrap();
    /// let result = x.mul(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[4, 2, 4, 2, 2, 2]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    /// // Now test 2D mult
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let k = Tensor::<i32>::new(
    ///     Some(&[2, 2]),
    ///     &[2]).unwrap();
    /// let result = x.mul(k).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[4, 2, 4, 2, 2, 2]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    /// ```
    fn mul(self, rhs: Self) -> Self::Output {
        let broadcasted_shape = get_broadcasted_shape(self.dims(), rhs.dims()).unwrap();
        let mut lhs = self.expand(&broadcasted_shape).unwrap();
        let rhs = rhs.expand(&broadcasted_shape).unwrap();

        lhs.par_iter_mut().zip(rhs).for_each(|(o, r)| {
            *o = o.clone() * r;
        });

        Ok(lhs)
    }
}

impl<T: TensorType + Mul<Output = T> + std::marker::Send + std::marker::Sync> Tensor<T> {
    /// Elementwise raise a tensor to the nth power.
    /// # Arguments
    ///
    /// * `self` - Tensor
    /// * `b` - Single value
    /// # Examples
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// use std::ops::Mul;
    /// let x = Tensor::<i32>::new(
    ///     Some(&[2, 15, 2, 1, 1, 0]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let result = x.pow(3).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[8, 3375, 8, 1, 1, 0]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    /// ```
    pub fn pow(&self, mut exp: u32) -> Result<Self, TensorError> {
        // calculate value of output
        let mut base = self.clone();
        let mut acc = base.map(|_| T::one().unwrap());

        while exp > 1 {
            if (exp & 1) == 1 {
                acc = acc.mul(base.clone())?;
            }
            exp /= 2;
            base = base.clone().mul(base)?;
        }

        // since exp!=0, finally the exp must be 1.
        // Deal with the final bit of the exponent separately, since
        // squaring the base afterwards is not necessary and may cause a
        // needless overflow.
        acc.mul(base)
    }
}

impl<T: TensorType + Div<Output = T> + std::marker::Send + std::marker::Sync> Div for Tensor<T> {
    type Output = Result<Tensor<T>, TensorError>;
    /// Elementwise divide a tensor with another tensor.
    /// # Arguments
    ///
    /// * `self` - Tensor
    /// * `rhs` - Tensor
    /// # Examples
    /// ```
    /// use ezkl_lib::tensor::Tensor;
    /// use std::ops::Div;
    /// let x = Tensor::<i32>::new(
    ///     Some(&[4, 1, 4, 1, 1, 4]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let y = Tensor::<i32>::new(
    ///     Some(&[2, 1, 2, 1, 1, 1]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let result = x.div(y).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[2, 1, 2, 1, 1, 4]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    ///
    /// // test 1D casting
    /// let x = Tensor::<i32>::new(
    ///     Some(&[4, 1, 4, 1, 1, 4]),
    ///     &[2, 3],
    /// ).unwrap();
    /// let y = Tensor::<i32>::new(
    ///     Some(&[2]),
    ///     &[1],
    /// ).unwrap();
    /// let result = x.div(y).unwrap();
    /// let expected = Tensor::<i32>::new(Some(&[2, 0, 2, 0, 0, 2]), &[2, 3]).unwrap();
    /// assert_eq!(result, expected);
    /// ```
    fn div(self, rhs: Self) -> Self::Output {
        let broadcasted_shape = get_broadcasted_shape(self.dims(), rhs.dims()).unwrap();
        let mut lhs = self.expand(&broadcasted_shape).unwrap();
        let rhs = rhs.expand(&broadcasted_shape).unwrap();

        lhs.par_iter_mut().zip(rhs).for_each(|(o, r)| {
            *o = o.clone() / r;
        });

        Ok(lhs)
    }
}

/// Returns the broadcasted shape of two tensors
/// ```
/// use ezkl_lib::tensor::get_broadcasted_shape;
/// let a = vec![2, 3];
/// let b = vec![2, 3];
/// let c = get_broadcasted_shape(&a, &b).unwrap();
/// assert_eq!(c, vec![2, 3]);
///
/// let a = vec![2, 3];
/// let b = vec![3];
/// let c = get_broadcasted_shape(&a, &b).unwrap();
/// assert_eq!(c, vec![2, 3]);
///
/// let a = vec![2, 3];
/// let b = vec![2, 1];
/// let c = get_broadcasted_shape(&a, &b).unwrap();
/// assert_eq!(c, vec![2, 3]);
///
/// let a = vec![2, 3];
/// let b = vec![1, 3];
/// let c = get_broadcasted_shape(&a, &b).unwrap();
/// assert_eq!(c, vec![2, 3]);
///
/// let a = vec![2, 3];
/// let b = vec![1, 1];
/// let c = get_broadcasted_shape(&a, &b).unwrap();
/// assert_eq!(c, vec![2, 3]);
///
/// ```

pub fn get_broadcasted_shape(
    shape_a: &[usize],
    shape_b: &[usize],
) -> Result<Vec<usize>, Box<dyn Error>> {
    let num_dims_a = shape_a.len();
    let num_dims_b = shape_b.len();

    // reewrite the below using match
    if num_dims_a == num_dims_b {
        let mut broadcasted_shape = Vec::with_capacity(num_dims_a);
        for (dim_a, dim_b) in shape_a.iter().zip(shape_b.iter()) {
            let max_dim = dim_a.max(dim_b);
            broadcasted_shape.push(*max_dim);
        }
        Ok(broadcasted_shape)
    } else if num_dims_a < num_dims_b {
        Ok(shape_b.to_vec())
    } else {
        Ok(shape_a.to_vec())
    }
}
////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor() {
        let data: Vec<f32> = vec![-1.0f32, 0.0, 1.0, 2.5];
        let tensor = Tensor::<f32>::new(Some(&data), &[2, 2]).unwrap();
        assert_eq!(&tensor[..], &data[..]);
    }

    #[test]
    fn tensor_clone() {
        let x = Tensor::<i32>::new(Some(&[1, 2, 3]), &[3]).unwrap();
        assert_eq!(x, x.clone());
    }

    #[test]
    fn tensor_eq() {
        let a = Tensor::<i32>::new(Some(&[1, 2, 3]), &[3]).unwrap();
        let mut b = Tensor::<i32>::new(Some(&[1, 2, 3]), &[3, 1]).unwrap();
        b.reshape(&[3]);
        let c = Tensor::<i32>::new(Some(&[1, 2, 4]), &[3]).unwrap();
        let d = Tensor::<i32>::new(Some(&[1, 2, 4]), &[3, 1]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }
    #[test]
    fn tensor_slice() {
        let a = Tensor::<i32>::new(Some(&[1, 2, 3, 4, 5, 6]), &[2, 3]).unwrap();
        let b = Tensor::<i32>::new(Some(&[1, 4]), &[2, 1]).unwrap();
        assert_eq!(a.get_slice(&[0..2, 0..1]).unwrap(), b);
    }
}
