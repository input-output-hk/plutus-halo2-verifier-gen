# how to use profiler

- build plutus project such that you have `plutus-verifier/plutus-halo2/VerifierScript.flat`
- build aiken project such that you have `aiken-verifier/aiken_halo2/plutus.json` and first element of validators is
  `profiler.halo2_profiler.else`
- run `profiling_setup/profiling.sh`

# how it works?

- profiling.sh picks script that is generated from test data in `aiken-verifier/aiken_halo2/validators/profiler.ak` and
  apply this function to `unit.flat` which is just `(program 1.1.0(con unit ()))` but compiled to UPLC, this is required
  for the profiler to be able to run the function.
- then it is running the program with uplc tool with `evaluate` command and `--trace-mode LogsWithBudgets` flag. This
  produces breakdown table of all elements used in the program, and CPU / MEM usage for each specific part.
- then it is doing the same `evaluate` call with uplc produced by plinth, but in this case application is not required
  as `plutus-verifier/plutus-halo2/VerifierScript.flat` is already provided in correct format.
