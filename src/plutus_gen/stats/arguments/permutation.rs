use super::super::circuit_statistics::CircuitStatistics;

pub(crate) fn evaluate_permutation_terms(
    stats: &mut CircuitStatistics,
    nb_non_fixed: usize,
    nb_permutations: usize,
) {
    // Evaluated boundary/cross-product terms
    // term1: Product(var, Sum(var, Neg(var)))
    stats.mul_scalar();
    stats.add_scalar();
    stats.neg_scalar();
    // term2: Product(var, Sum(Product(v,v), Neg(v)))
    stats.mul_scalar();
    stats.mul_scalar();
    stats.add_scalar();
    stats.neg_scalar();
    // cross terms (nb_permutations - 1): Product(Sum(var, Neg(var)), var)
    (0..nb_permutations - 1).for_each(|_| {
        stats.mul_scalar();
        stats.add_scalar();
        stats.neg_scalar();
    });

    // Left terms: Sum(Sum(eval, Product(beta, sigma)), gamma) per column
    (0..nb_non_fixed).for_each(|_| {
        stats.mul_scalar(); // Product(beta, sigma)
        stats.add_scalar(); // inner Sum
        stats.add_scalar(); // outer Sum with gamma
    });
    (nb_permutations..nb_non_fixed).for_each(|_| stats.mul_scalar()); // non-first in set
    (0..nb_permutations).for_each(|_| stats.mul_scalar()); // set batching

    // Right terms: Sum(Sum(eval, Product(Product(beta,x), PowMod(delta,p))), gamma) per column
    (0..nb_non_fixed).for_each(|_| {
        stats.mul_scalar(); // Product(beta, x)
        stats.mul_scalar(); // Product(..., PowMod)
        stats.pow_scalar(); // PowMod(delta, power)
        stats.add_scalar(); // inner Sum
        stats.add_scalar(); // outer Sum with gamma
    });
    (nb_permutations..nb_non_fixed).for_each(|_| stats.mul_scalar());
    (0..nb_permutations).for_each(|_| stats.mul_scalar());

    // Combine left and right sets
    (0..nb_permutations).for_each(|_| {
        stats.mul_scalar();
        stats.sub_scalar();
        stats.sub_scalar();
        stats.add_scalar();
    });
}
