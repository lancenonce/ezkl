use super::{
    ops::{intercalate_values, pad, resize},
    *,
};
use halo2_proofs::{arithmetic::Field, plonk::Instance};

#[derive(Debug, Clone)]
/// A [ValType] is a wrapper around Halo2 value(s).
pub enum ValType<F: PrimeField + TensorType + std::marker::Send + std::marker::Sync + PartialOrd> {
    /// value
    Value(Value<F>),
    /// assigned  value
    AssignedValue(Value<Assigned<F>>),
    /// previously assigned value
    PrevAssigned(AssignedCell<F, F>),
    /// constant
    Constant(F),
}

impl<F: PrimeField + TensorType + PartialOrd> From<ValType<F>> for i32 {
    fn from(val: ValType<F>) -> Self {
        match val {
            ValType::Value(v) => {
                let mut output = 0_i32;
                let mut i = 0;
                v.map(|y| {
                    let e = felt_to_i32(y);
                    output = e;
                    i += 1;
                });
                output
            }
            ValType::AssignedValue(v) => {
                let mut output = 0_i32;
                let mut i = 0;
                v.evaluate().map(|y| {
                    let e = felt_to_i32(y);
                    output = e;
                    i += 1;
                });
                output
            }
            ValType::PrevAssigned(v) => {
                let mut output = 0_i32;
                let mut i = 0;
                v.value().map(|y| {
                    let e = felt_to_i32(*y);
                    output = e;
                    i += 1;
                });
                output
            }
            ValType::Constant(v) => felt_to_i32(v),
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<F> for ValType<F> {
    fn from(t: F) -> ValType<F> {
        ValType::Constant(t)
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<Value<F>> for ValType<F> {
    fn from(t: Value<F>) -> ValType<F> {
        ValType::Value(t)
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<Value<Assigned<F>>> for ValType<F> {
    fn from(t: Value<Assigned<F>>) -> ValType<F> {
        ValType::AssignedValue(t)
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<AssignedCell<F, F>> for ValType<F> {
    fn from(t: AssignedCell<F, F>) -> ValType<F> {
        ValType::PrevAssigned(t)
    }
}

impl<F: PrimeField + TensorType + PartialOrd> TensorType for ValType<F>
where
    F: Field,
{
    fn zero() -> Option<Self> {
        Some(ValType::Value(Value::known(<F as Field>::ZERO)))
    }
    fn one() -> Option<Self> {
        Some(ValType::Value(Value::known(<F as Field>::ONE)))
    }
}

/// A [ValTensor] is a wrapper around a [Tensor] of [ValType].
/// or a column of an [Instance].
/// This is the type used for all intermediate values in a circuit.
/// It is also the type used for the inputs and outputs of a circuit.
#[derive(Debug, Clone)]
pub enum ValTensor<F: PrimeField + TensorType + PartialOrd> {
    /// A tensor of [Value], each containing a field element
    Value {
        /// Underlying [Tensor].
        inner: Tensor<ValType<F>>,
        /// Vector of dimensions of the tensor.
        dims: Vec<usize>,
        ///
        scale: u32,
    },
    /// A tensor backed by an [Instance] column
    Instance {
        /// [Instance]
        inner: Column<Instance>,
        /// Vector of dimensions of the tensor.
        dims: Vec<usize>,
        ///
        scale: u32,
    },
}

impl<F: PrimeField + TensorType + PartialOrd> From<Tensor<ValType<F>>> for ValTensor<F> {
    fn from(t: Tensor<ValType<F>>) -> ValTensor<F> {
        ValTensor::Value {
            inner: t.map(|x| x),
            dims: t.dims().to_vec(),
            scale: 1,
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<Tensor<F>> for ValTensor<F> {
    fn from(t: Tensor<F>) -> ValTensor<F> {
        ValTensor::Value {
            inner: t.map(|x| x.into()),
            dims: t.dims().to_vec(),
            scale: 1,
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<Tensor<Value<F>>> for ValTensor<F> {
    fn from(t: Tensor<Value<F>>) -> ValTensor<F> {
        ValTensor::Value {
            inner: t.map(|x| x.into()),
            dims: t.dims().to_vec(),
            scale: 1,
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<Tensor<Value<Assigned<F>>>> for ValTensor<F> {
    fn from(t: Tensor<Value<Assigned<F>>>) -> ValTensor<F> {
        ValTensor::Value {
            inner: t.map(|x| x.into()),
            dims: t.dims().to_vec(),
            scale: 1,
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> From<Tensor<AssignedCell<F, F>>> for ValTensor<F> {
    fn from(t: Tensor<AssignedCell<F, F>>) -> ValTensor<F> {
        ValTensor::Value {
            inner: t.map(|x| x.into()),
            dims: t.dims().to_vec(),
            scale: 1,
        }
    }
}

impl<F: PrimeField + TensorType + PartialOrd> ValTensor<F> {
    /// Allocate a new [ValTensor::Instance] from the ConstraintSystem with the given tensor `dims`, optionally enabling `equality`.
    pub fn new_instance(cs: &mut ConstraintSystem<F>, dims: Vec<usize>, scale: u32) -> Self {
        let col = cs.instance_column();
        cs.enable_equality(col);
        ValTensor::Instance {
            inner: col,
            dims,
            scale,
        }
    }

    /// Set the [ValTensor]'s scale.
    pub fn set_scale(&mut self, scale: u32) {
        match self {
            ValTensor::Value { scale: s, .. } => *s = scale,
            ValTensor::Instance { scale: s, .. } => *s = scale,
        }
    }

    /// Returns the [ValTensor]'s scale.
    pub fn scale(&self) -> u32 {
        match self {
            ValTensor::Value { scale, .. } => *scale,
            ValTensor::Instance { scale, .. } => *scale,
        }
    }

    /// Calls `int_evals` on the inner tensor.
    pub fn get_int_evals(&self) -> Result<Vec<i128>, Box<dyn Error>> {
        // finally convert to vector of integers
        let mut integer_evals: Vec<i128> = vec![];
        match self {
            ValTensor::Value {
                inner: v, dims: _, ..
            } => {
                // we have to push to an externally created vector or else vaf.map() returns an evaluation wrapped in Value<> (which we don't want)
                let _ = v.map(|vaf| match vaf {
                    ValType::Value(v) => v.map(|f| {
                        integer_evals.push(crate::fieldutils::felt_to_i128(f));
                    }),
                    ValType::AssignedValue(v) => v.map(|f| {
                        integer_evals.push(crate::fieldutils::felt_to_i128(f.evaluate()));
                    }),
                    ValType::PrevAssigned(v) => v.value_field().map(|f| {
                        integer_evals.push(crate::fieldutils::felt_to_i128(f.evaluate()));
                    }),
                    ValType::Constant(v) => {
                        integer_evals.push(crate::fieldutils::felt_to_i128(v));
                        Value::unknown()
                    }
                });
            }
            _ => return Err(Box::new(TensorError::WrongMethod)),
        };
        Ok(integer_evals)
    }

    /// Calls `get_slice` on the inner tensor.
    pub fn get_slice(&self, indices: &[Range<usize>]) -> Result<ValTensor<F>, Box<dyn Error>> {
        let slice = match self {
            ValTensor::Value {
                inner: v,
                dims: _,
                scale,
            } => {
                let slice = v.get_slice(indices)?;
                ValTensor::Value {
                    inner: slice.clone(),
                    dims: slice.dims().to_vec(),
                    scale: *scale,
                }
            }
            _ => return Err(Box::new(TensorError::WrongMethod)),
        };
        Ok(slice)
    }

    /// Fetches the inner tensor as a [Tensor<Value<F>>]
    pub fn get_inner_tensor(&self) -> Result<Tensor<ValType<F>>, TensorError> {
        Ok(match self {
            ValTensor::Value { inner: v, .. } => v.clone(),
            ValTensor::Instance { .. } => return Err(TensorError::WrongMethod),
        })
    }

    /// Fetches the inner tensor as a [Tensor<Value<F>>]
    pub fn get_inner(&self) -> Result<Tensor<Value<F>>, TensorError> {
        Ok(match self {
            ValTensor::Value { inner: v, .. } => v.map(|x| match x {
                ValType::Value(v) => v,
                ValType::AssignedValue(v) => v.evaluate(),
                ValType::PrevAssigned(v) => v.value_field().evaluate(),
                ValType::Constant(v) => Value::known(v),
            }),
            ValTensor::Instance { .. } => return Err(TensorError::WrongMethod),
        })
    }
    /// Calls `expand` on the inner tensor.
    pub fn expand(&mut self, dims: &[usize]) -> Result<(), Box<dyn Error>> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = v.expand(dims)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(Box::new(TensorError::WrongMethod));
            }
        };
        Ok(())
    }

    /// Sets the [ValTensor]'s shape.
    pub fn reshape(&mut self, new_dims: &[usize]) -> Result<(), Box<dyn Error>> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                v.reshape(new_dims);
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { dims: d, .. } => {
                if d.iter().product::<usize>() != new_dims.iter().product::<usize>() {
                    return Err(Box::new(TensorError::DimError));
                }
                *d = new_dims.to_vec();
            }
        };
        Ok(())
    }

    /// Sets the [ValTensor]'s shape.
    pub fn slice(
        &mut self,
        axis: &usize,
        start: &usize,
        end: &usize,
    ) -> Result<(), Box<dyn Error>> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = crate::tensor::ops::slice(v, axis, start, end)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(Box::new(TensorError::WrongMethod));
            }
        };
        Ok(())
    }

    /// Calls `flatten` on the inner [Tensor].
    pub fn flatten(&mut self) {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                v.flatten();
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { dims: d, .. } => {
                *d = vec![d.iter().product()];
            }
        }
    }

    /// Calls `duplicate_every_n` on the inner [Tensor].
    pub fn duplicate_every_n(
        &mut self,
        n: usize,
        initial_offset: usize,
    ) -> Result<(), TensorError> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = v.duplicate_every_n(n, initial_offset)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(TensorError::WrongMethod);
            }
        }
        Ok(())
    }

    /// Calls `duplicate_every_n` on the inner [Tensor].
    pub fn remove_every_n(&mut self, n: usize, initial_offset: usize) -> Result<(), TensorError> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = v.remove_every_n(n, initial_offset)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(TensorError::WrongMethod);
            }
        }
        Ok(())
    }

    /// Calls `intercalate_values` on the inner [Tensor].
    pub fn intercalate_values(
        &mut self,
        value: ValType<F>,
        stride: usize,
        axis: usize,
    ) -> Result<(), TensorError> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = intercalate_values(v, value, stride, axis)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(TensorError::WrongMethod);
            }
        }
        Ok(())
    }
    /// Calls `resize` on the inner [Tensor].
    pub fn resize(&mut self, scales: &[usize]) -> Result<(), TensorError> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = resize(v, scales)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(TensorError::WrongMethod);
            }
        };
        Ok(())
    }
    /// Calls `pad` on the inner [Tensor].
    pub fn pad(&mut self, padding: (usize, usize)) -> Result<(), TensorError> {
        match self {
            ValTensor::Value {
                inner: v, dims: d, ..
            } => {
                *v = pad(v, padding)?;
                *d = v.dims().to_vec();
            }
            ValTensor::Instance { .. } => {
                return Err(TensorError::WrongMethod);
            }
        }
        Ok(())
    }

    /// Calls `len` on the inner [Tensor].
    pub fn len(&self) -> usize {
        match self {
            ValTensor::Value { dims, .. } | ValTensor::Instance { dims, .. } => {
                dims.iter().product::<usize>()
            }
        }
    }

    ///
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Calls `concats` on the inner [Tensor].
    pub fn concat(&self, other: Self) -> Result<Self, TensorError> {
        let res = match (self, other) {
            (ValTensor::Value { inner: v1, .. }, ValTensor::Value { inner: v2, .. }) => {
                ValTensor::from(Tensor::new(Some(&[v1.clone(), v2]), &[2])?.combine()?)
            }
            _ => {
                return Err(TensorError::WrongMethod);
            }
        };
        Ok(res)
    }

    /// Returns the `dims` attribute of the [ValTensor].
    pub fn dims(&self) -> &[usize] {
        match self {
            ValTensor::Value { dims: d, .. } | ValTensor::Instance { dims: d, .. } => d,
        }
    }
    /// A [String] representation of the [ValTensor] for display, for example in showing intermediate values in a computational graph.
    pub fn show(&self) -> String {
        match self.clone() {
            ValTensor::Value {
                inner: v, dims: _, ..
            } => {
                let r: Tensor<i32> = v.map(|x| x.into());
                if r.len() > 10 {
                    format!("Value {:?} ..", r[..10].to_vec())
                } else {
                    format!("Value {:?}", r)
                }
            }
            _ => "ValTensor not PrevAssigned".into(),
        }
    }
}
