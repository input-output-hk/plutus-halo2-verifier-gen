use super::rotation_set::RotationSet;

/// Types of columns used in chips
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub(crate) enum ColumnType {
    Advice,
    Selector,
    ComplexSelector,
    SharedFixed,
    ExclusiveFixed,
    Table,
}

/// Column structure: column type, copy-constraint flag, and queried rotations.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub(crate) struct Column {
    column_type: ColumnType,
    copy_constrained: bool,
    rotations: RotationSet,
}

impl Column {
    fn new(column_type: ColumnType, rotations: RotationSet, copy_constrained: bool) -> Self {
        match column_type {
            ColumnType::Selector | ColumnType::ComplexSelector => assert!(
                !copy_constrained && rotations.count() == 1 && rotations.curr,
                "Selector columns are not copy-constrained and are only queried at current row."
            ),
            ColumnType::SharedFixed | ColumnType::ExclusiveFixed => assert!(
                !rotations.is_empty(),
                "Fixed columns must be queried at some rotation."
            ),
            ColumnType::Advice => assert!(
                !rotations.is_empty(),
                "Advice columns must be queried at some rotation."
            ),
            ColumnType::Table => assert!(
                !rotations.is_empty() && !copy_constrained,
                "Table columns must be queried at some rotation and must not be copy-constrained."
            ),
        }
        if copy_constrained {
            assert!(
                rotations.curr,
                "Copy-constrained columns must include a CUR rotation."
            );
        }
        Self {
            column_type,
            rotations,
            copy_constrained,
        }
    }

    pub(crate) fn advice(rotations: RotationSet, copy_constrained: bool) -> Self {
        Self::new(ColumnType::Advice, rotations, copy_constrained)
    }

    pub(crate) fn empty_advice() -> Self {
        Self {
            column_type: ColumnType::Advice,
            copy_constrained: false,
            rotations: RotationSet::default(),
        }
    }

    pub(crate) fn shared_fixed(rotations: RotationSet, copy_constrained: bool) -> Self {
        Self::new(ColumnType::SharedFixed, rotations, copy_constrained)
    }

    pub(crate) fn empty_shared() -> Self {
        Self {
            column_type: ColumnType::SharedFixed,
            copy_constrained: false,
            rotations: RotationSet::default(),
        }
    }

    pub(crate) fn exclusive_fixed(rotations: RotationSet, copy_constrained: bool) -> Self {
        Self::new(ColumnType::ExclusiveFixed, rotations, copy_constrained)
    }

    pub(crate) fn selector() -> Self {
        Self::new(ColumnType::Selector, RotationSet::curr(), false)
    }

    pub(crate) fn complex_selector() -> Self {
        Self::new(ColumnType::ComplexSelector, RotationSet::curr(), false)
    }

    pub(crate) fn table(rotations: RotationSet) -> Self {
        Self::new(ColumnType::Table, rotations, false)
    }

    pub(crate) fn is_copy_constrained(&self) -> bool {
        self.copy_constrained
    }

    pub(crate) fn set_copy_constrained(&mut self) {
        self.copy_constrained = true
    }

    pub(crate) fn rotations(&self) -> RotationSet {
        self.rotations
    }

    pub(crate) fn set_curr(&mut self) {
        self.rotations = RotationSet {
            curr: true,
            ..self.rotations
        };
    }

    pub(crate) fn set_next(&mut self) {
        self.rotations = RotationSet {
            next: true,
            ..self.rotations
        };
    }

    pub(crate) fn set_prev(&mut self) {
        self.rotations = RotationSet {
            prev: true,
            ..self.rotations
        };
    }

    /// Merges another column of the same type: unions rotations, inherits copy-constraint.
    pub(crate) fn merge_column(&mut self, col: Column) {
        assert!(
            self.column_type == col.column_type,
            "Cannot merge columns of different types"
        );
        self.copy_constrained |= col.is_copy_constrained();
        self.rotations.merge(&col.rotations);
    }
}
