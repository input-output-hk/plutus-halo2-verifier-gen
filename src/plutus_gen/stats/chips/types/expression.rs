use super::scalar_ops::ScalarOps;

pub(crate) type Argument = Vec<ScalarExpression>;

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct ScalarExpression {
    pub(crate) degree: usize,
    pub(crate) ops: ScalarOps,
}

impl ScalarExpression {
    pub(crate) fn gate_expression(
        degree: usize,
        neg: usize,
        add: usize,
        sub: usize,
        mul: usize,
        from_int: usize,
    ) -> Self {
        Self {
            degree,
            ops: ScalarOps::new(neg, add, sub, mul, from_int),
        }
    }

    pub(crate) fn lookup_expression(
        input_degree: usize,
        table_degree: usize,
        neg: usize,
        add: usize,
        sub: usize,
        mul: usize,
        from_int: usize,
    ) -> Self {
        Self {
            degree: 4.max(2 + input_degree.max(1) + table_degree.max(1)),
            ops: ScalarOps::new(neg, add, sub, mul, from_int),
        }
    }

    pub(crate) fn trashcan_expression(
        degree: usize,
        neg: usize,
        add: usize,
        sub: usize,
        mul: usize,
        from_int: usize,
    ) -> Self {
        Self {
            degree: degree.max(2),
            ops: ScalarOps::new(neg, add, sub, mul, from_int),
        }
    }

    pub(crate) fn batch_expressions(expressions: Vec<Self>) -> Self {
        let mut iter = expressions.into_iter();
        let Some(first) = iter.next() else {
            return Self::default();
        };
        iter.fold(first, |acc, exp| {
            let mut combined = Self {
                degree: acc.degree.max(exp.degree),
                ops: acc.ops.add(&exp.ops),
            };
            combined.ops.nb_add += 1;
            combined.ops.nb_mul += 1;
            combined
        })
    }
}
