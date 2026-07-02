use super::{Commitments, Evaluations, RotationDescription};
use std::collections::HashMap;

#[derive(Clone, Eq, PartialEq, Debug)]
#[allow(dead_code)]
pub(crate) enum ScalarOperation {
    Zero,
    Mul(Box<ScalarOperation>, Evaluations),
    MulS(Box<ScalarOperation>, Box<ScalarOperation>),
    Power(char, i32),
    Add(Box<ScalarOperation>, Box<ScalarOperation>),
    Rotation(RotationDescription),
}

#[derive(Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum MsmOperations {
    Empty,
    Append(Box<MsmOperations>, ScalarOperation, Commitments),
    AppendW(Box<MsmOperations>, ScalarOperation, usize),
    AppendNegatedG1(Box<MsmOperations>, ScalarOperation),
    Add(Box<MsmOperations>, Box<MsmOperations>),
    Scale(Box<MsmOperations>, ScalarOperation),
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ElementMSM {
    Element(ScalarOperation, Commitments),
    ElementW(ScalarOperation, usize),
    ElementNegatedG1(ScalarOperation),
}

#[derive(Debug)]
pub(crate) struct OptimizedMSM {
    pub elements: Vec<ElementMSM>,
}

#[allow(dead_code)]
impl ElementMSM {
    fn get_scalar(&mut self) -> &mut ScalarOperation {
        match self {
            ElementMSM::Element(scalar, _) => scalar,
            ElementMSM::ElementW(scalar, _) => scalar,
            ElementMSM::ElementNegatedG1(scalar) => scalar,
        }
    }
}
#[allow(dead_code)]
impl MsmOperations {
    /// Flattens the recursive MSM operations tree into a linear list of elements,
    /// producing an optimized flat structure ready for Aiken code generation.
    pub(crate) fn flatten_msm(&self) -> OptimizedMSM {
        match self {
            MsmOperations::Empty => OptimizedMSM { elements: vec![] },
            MsmOperations::Append(msm, scalar, commitment) => {
                let mut flattened = msm.flatten_msm();
                flattened
                    .elements
                    .push(ElementMSM::Element(scalar.clone(), *commitment));
                flattened
            }
            MsmOperations::AppendW(msm, scalar, index) => {
                let mut flattened = msm.flatten_msm();
                flattened
                    .elements
                    .push(ElementMSM::ElementW(scalar.clone(), *index));
                flattened
            }
            MsmOperations::AppendNegatedG1(msm, scalar) => {
                let mut flattened = msm.flatten_msm();
                flattened
                    .elements
                    .push(ElementMSM::ElementNegatedG1(scalar.clone()));
                flattened
            }
            MsmOperations::Add(msm_a, msm_b) => {
                let mut flattened_a = msm_a.flatten_msm();
                let mut flattened_b = msm_b.flatten_msm();
                flattened_a.elements.append(&mut flattened_b.elements);
                flattened_a
            }
            MsmOperations::Scale(msm, scalar) => {
                let mut flattened = msm.flatten_msm();
                flattened.elements.iter_mut().for_each(|e| {
                    let s = e.get_scalar();
                    *s = ScalarOperation::MulS(Box::new(scalar.clone()), Box::new(s.clone()))
                });
                flattened
            }
        }
    }
}

impl OptimizedMSM {
    /// Optimizes MSM by combining elements with the same G1 point.
    /// Elements sharing the same point have their scalars added together,
    /// reducing the number of point operations.
    #[allow(dead_code)]
    pub(crate) fn optimize_msm(self) -> OptimizedMSM {
        // Key to identify unique G1 points
        #[derive(Clone, Eq, PartialEq, Hash)]
        enum G1PointKey {
            Commitment(Commitments),
            W(usize),
            NegatedG1,
        }

        let mut groups: HashMap<G1PointKey, Vec<ScalarOperation>> = HashMap::new();
        let mut insertion_order: Vec<G1PointKey> = Vec::new();

        // Group elements by their G1 point
        for element in self.elements {
            let (key, scalar) = match element {
                ElementMSM::Element(scalar, commitment) => {
                    (G1PointKey::Commitment(commitment), scalar)
                }
                ElementMSM::ElementW(scalar, index) => (G1PointKey::W(index), scalar),
                ElementMSM::ElementNegatedG1(scalar) => (G1PointKey::NegatedG1, scalar),
            };

            // Track insertion order for deterministic output
            if !groups.contains_key(&key) {
                insertion_order.push(key.clone());
            }

            groups.entry(key).or_default().push(scalar);
        }

        // Combine scalars for each G1 point
        let optimized_elements: Vec<ElementMSM> = insertion_order
            .into_iter()
            .map(|key| {
                let scalars = groups.remove(&key).unwrap();

                // Combine all scalars by adding them together
                let combined_scalar = scalars
                    .into_iter()
                    .reduce(|acc, scalar| ScalarOperation::Add(Box::new(acc), Box::new(scalar)))
                    .unwrap();

                // Reconstruct the element with combined scalar
                match key {
                    G1PointKey::Commitment(commitment) => {
                        ElementMSM::Element(combined_scalar, commitment)
                    }
                    G1PointKey::W(index) => ElementMSM::ElementW(combined_scalar, index),
                    G1PointKey::NegatedG1 => ElementMSM::ElementNegatedG1(combined_scalar),
                }
            })
            .collect();

        OptimizedMSM {
            elements: optimized_elements,
        }
    }

    /// Finds the maximum power exponent for a given variable in an MSM.
    /// Recursively traverses all scalar operations to find Power(var_name, exponent).
    #[allow(dead_code)]
    pub(crate) fn find_max_power(&self, var_name: char) -> i32 {
        self.elements
            .iter()
            .map(|element| {
                let scalar = match element {
                    ElementMSM::Element(s, _) => s,
                    ElementMSM::ElementW(s, _) => s,
                    ElementMSM::ElementNegatedG1(s) => s,
                };
                Self::find_max_power_in_scalar(scalar, var_name)
            })
            .max()
            .unwrap_or(0)
    }

    /// Recursively finds max power exponent in a scalar operation tree
    #[allow(dead_code)]
    pub(crate) fn find_max_power_in_scalar(scalar: &ScalarOperation, var_name: char) -> i32 {
        match scalar {
            ScalarOperation::Power(name, exponent) if *name == var_name => *exponent,
            ScalarOperation::Mul(s, _) => Self::find_max_power_in_scalar(s, var_name),
            ScalarOperation::MulS(s1, s2) => Self::find_max_power_in_scalar(s1, var_name)
                .max(Self::find_max_power_in_scalar(s2, var_name)),
            ScalarOperation::Add(s1, s2) => Self::find_max_power_in_scalar(s1, var_name)
                .max(Self::find_max_power_in_scalar(s2, var_name)),
            _ => 0,
        }
    }
}
