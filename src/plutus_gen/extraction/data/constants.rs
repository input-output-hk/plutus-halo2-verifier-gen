//! Common naming across languages for variables and constants

// Common challenges names
pub(crate) const BETA_STR: &str = "beta";
pub(crate) const GAMMA_STR: &str = "gamma";
pub(crate) const THETA_STR: &str = "theta";

pub(crate) const X_STR: &str = "x";
pub(crate) const XN_MINUS_ONE_STR: &str = "xn_minus_one";

// Common constant names
pub(crate) const SCALAR_DELTA_STR: &str = "scalarDelta";
pub(crate) const ONE_STR: &str = "scalarOne";
pub(crate) const ZERO_STR: &str = "scalarZero";

// Common variable names
pub(crate) const EVAL_0_STR: &str = "evaluation_at_0";
pub(crate) const EVAL_LAST_STR: &str = "last_evaluation";
pub(crate) const VANISH_G_STR: &str = "vanishing_g";
pub(crate) fn perm_eval_str(i: &char, j: usize) -> String {
    format!("permutations_evaluated_{}_{}", i, j)
}
pub(crate) fn h_com_str(index: usize) -> String {
    format!("hCommitment{:?}", index)
}
