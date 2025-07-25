Idea for the optimization:

1. Remove modulo inverse calls from halo2 version of KZG
2. Provide pairs of `[(A, invA)]` with proof data, such that it contains all inverses needed in particular proof verification
3. At the beginning of the verifier add logic that will check for all elements in the list that `1 = A * invA mod prime`
4. Implement logic that will instead of calculating inverse on chain do a lookup in provided pairs
