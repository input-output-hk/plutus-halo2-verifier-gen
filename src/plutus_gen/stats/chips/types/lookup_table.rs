/// A lookup table used by one or more chips.
#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct LookupTable {
    pub name: String,
    pub nb_columns: usize,
    pub nb_arguments: usize,
    pub input_degree: usize,
    pub table_degree: usize,
}

impl LookupTable {
    /// Register a lookup table inside a chip descriptor.
    /// Arguments and degrees are intentionally zeroed — they are counted via `lookup_args`.
    pub(crate) fn register(name: String, nb_columns: usize) -> Self {
        Self {
            name,
            nb_columns,
            nb_arguments: 0,
            input_degree: 0,
            table_degree: 0,
        }
    }

    /// Create a standalone lookup table for user-supplied extra lookups.
    /// Must NOT be used inside chip descriptors.
    pub fn new(
        name: String,
        nb_columns: usize,
        nb_arguments: usize,
        input_degree: usize,
        table_degree: usize,
    ) -> Self {
        Self {
            name,
            nb_columns,
            nb_arguments: nb_arguments.max(1),
            input_degree: input_degree.max(2),
            table_degree: table_degree.max(1),
        }
    }
}
