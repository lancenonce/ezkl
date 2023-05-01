use std::{error::Error, marker::PhantomData};

use halo2curves::ff::PrimeField;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, TableColumn, Column, Advice},
};

use crate::{
    circuit::CircuitError,
    fieldutils::i128_to_felt,
    tensor::{Tensor, TensorType},
};

use crate::circuit::lookup::LookupOp;
use crate::circuit::hybrid::HybridOp;

use super::Op;

/// Halo2 lookup table for element wise non-linearities.
// Table that should be reused across all lookups (so no Clone)
#[derive(Clone, Debug)]
pub struct Table<F: PrimeField> {
    /// composed operations represented by the table
    pub nonlinearity: LookupOp,
    /// Input to table.
    pub table_input: TableColumn,
    /// Output of table
    pub table_output: TableColumn,
    /// Flags if table has been previously assigned to.
    pub is_assigned: bool,
    /// Number of bits used in lookup table.
    pub bits: usize,
    _marker: PhantomData<F>,
}

impl<F: PrimeField + TensorType + PartialOrd> Table<F> {
    /// Configures the table.
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        bits: usize,
        nonlinearity: &LookupOp,
    ) -> Table<F> {
        Table {
            nonlinearity: nonlinearity.clone(),
            table_input: cs.lookup_table_column(),
            table_output: cs.lookup_table_column(),
            is_assigned: false,
            bits,
            _marker: PhantomData,
        }
    }
    /// Assigns values to the constraints generated when calling `configure`.
    pub fn layout(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Box<dyn Error>> {
        if self.is_assigned {
            return Err(Box::new(CircuitError::TableAlreadyAssigned));
        }

        let base = 2i128;
        let smallest = -base.pow(self.bits as u32 - 1);
        let largest = base.pow(self.bits as u32 - 1);

        let inputs = Tensor::from(smallest..largest);
        let evals = Op::<F>::f(&self.nonlinearity, &[inputs.clone()])?;

        self.is_assigned = true;
        layouter
            .assign_table(
                || "nl table",
                |mut table| {
                    let _ = inputs
                        .iter()
                        .enumerate()
                        .map(|(row_offset, input)| {
                            table.assign_cell(
                                || format!("nl_i_col row {}", row_offset),
                                self.table_input,
                                row_offset,
                                || Value::known(i128_to_felt::<F>(*input)),
                            )?;

                            table.assign_cell(
                                || format!("nl_o_col row {}", row_offset),
                                self.table_output,
                                row_offset,
                                || Value::known(i128_to_felt::<F>(evals[row_offset])),
                            )?;
                            Ok(())
                        })
                        .collect::<Result<Vec<()>, halo2_proofs::plonk::Error>>()?;
                    Ok(())
                },
            )
            .map_err(Box::<dyn Error>::from)
    }
}

/// Halo2 lookup table for dynamic lookups
/// Recorded as an advice column
#[derive(Clone, Debug)]
pub struct DynamicTable<F: PrimeField> {
    /// composed operations represented by the table
    pub operation: Box<dyn Op<F>>,
    /// Input of dynamic table
    pub dyn_table_input: Column<Advice>,
    /// Output of dynamic table
    pub dyn_table_output: Column<Advice>,
    /// Flags if table has been previously assigned to.
    pub is_assigned: bool,
    /// Number of bits used in lookup table.
    pub bits: usize,
    _marker: PhantomData<F>,
}

//TODO: Integrate with softmax and other dynamic lookups
impl<F: PrimeField + TensorType + PartialOrd> DynamicTable<F> {
    /// Configure the table
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        bits: usize,
        operation: &Box<dyn Op<F>>,
    ) -> DynamicTable<F> {
        DynamicTable {
            operation: operation.clone(),
            dyn_table_input: cs.advice_column(),
            dyn_table_output: cs.advice_column(),
            is_assigned: false,
            bits,
            _marker: PhantomData,
        }
    }
    
    /// Assigns values to the constraints generated when calling `configure`.
    pub fn layout(&mut self, layouter: &mut impl Layouter<F>) -> Result<(), Box<dyn Error>> {
        // if the cell is already assigned, throw an error
        if self.is_assigned {
            return Err(Box::new(CircuitError::TableAlreadyAssigned));
        }

        let base = 2i128;
        // why are we binding bits to u32 - 1?
        let smallest = -base.pow(self.bits as u32 - 1);
        let largest = base.pow(self.bits as u32 - 1);

        let inputs = Tensor::from(smallest..largest);
        // Change the nonlinearity to a hybrid operation
        let evals = Op::<F>::f(&self.operation, &[inputs.clone()])?;
        // set the table to assigned
        self.is_assigned = true;
        // layout the table with advice region vs. fixed
        layouter
            .assign_region(
                || "hybrid table",
                |mut table| {
                    let _ = inputs
                        .iter()
                        .enumerate()
                        .map(|(row_offset, input)| {
                            table.assign_advice(
                                || format!("hybriud_i_col row {}", row_offset),
                                self.dyn_table_input,
                                row_offset,
                                || Value::known(i128_to_felt::<F>(*input)),
                            )?;

                            table.assign_advice(
                                || format!("hybrid_o_col row {}", row_offset),
                                self.dyn_table_output,
                                row_offset,
                                || Value::known(i128_to_felt::<F>(evals[row_offset])),
                            )?;
                            Ok(())
                        })
                        .collect::<Result<Vec<()>, halo2_proofs::plonk::Error>>()?;
                    Ok(())
                },
            )
            .map_err(Box::<dyn Error>::from)
    }
}

