# Zero-knowledge data quality for multi-party computation

Artefact for *Zero-Knowledge Data Quality for Multi-Party Computation*.

Three proof systems prove the same data-quality statement over the same synthetic transport-order
dataset, so their cost can be compared: **UltraHonk** and **Groth16**, **Nova**.

## Requirements

`python`, `rust`, `uv`, `nargo` and `bb`.

```bash
uv sync
cargo build --release
```

# Structure

The project is structured as follows:
- `bench/` contains the measuring code for the three proof systems.
- `datasets/` contains the rust models for both `groth16` and `nova`.
- `groth16/` contains the Groth16 code.
- `noir/` contains the UltraHonk code.
- `nova/` contains the Nova code.
- `mpc/` contains the MPC side verification in MPyC.
- `shared/` contains the data generation code.


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
