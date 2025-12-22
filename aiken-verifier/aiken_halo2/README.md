## Running tests

Some tests are for generated code so before running them you have to generate test code.
To do that you have to run this command from the roof of the repository

```bash
cargo run --example equations_test
cargo run --example atms_with_lookups
```

after this you can just run `aiken check` in the Aiken project directory
