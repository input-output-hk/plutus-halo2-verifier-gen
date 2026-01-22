use anyhow::{Context, Result};
use blstrs::Bls12;
use halo2_proofs::poly::kzg::params::ParamsKZG;
use halo2_proofs::utils::helpers::SerdeFormat;
use log::warn;
use rand_core::RngCore;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

const KZG_PARAMS_DIR: &str = "kzg_params";

/// Returns the path to the KZG params file for a given circuit size k.
fn params_path(k: u32) -> std::path::PathBuf {
    Path::new(KZG_PARAMS_DIR).join(format!("kzg_params_{}", k))
}

/// Gets or creates KZG parameters for the given circuit size k.
/// The generated parameters are unsafe and should only be used for testing purposes.
///
/// This function first tries to read cached parameters from `kzg_params/kzg_params_{k}`.
/// If the file doesn't exist, it generates new parameters using `unsafe_setup` and
/// caches them for future use.
///
/// # Arguments
/// * `k` - The circuit size parameter (log2 of the number of rows)
/// * `rng` - Random number generator for parameter generation
///
/// # Returns
/// The KZG parameters for the given circuit size
pub fn get_or_create_kzg_params(k: u32, rng: impl RngCore) -> Result<ParamsKZG<Bls12>> {
    let path = params_path(k);

    if path.exists() {
        read_params(&path)
    } else {
        warn!("Generating unsafe KZG params with k={}. Use only for testing.", k);
        let params = ParamsKZG::<Bls12>::unsafe_setup(k, rng);
        write_params(&path, &params)?;
        Ok(params)
    }
}

/// Reads KZG parameters from a file.
fn read_params(path: &Path) -> Result<ParamsKZG<Bls12>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open KZG params file: {:?}", path))?;
    let params =
        ParamsKZG::<Bls12>::read_custom(&mut BufReader::new(file), SerdeFormat::RawBytesUnchecked)
            .with_context(|| format!("Failed to read KZG params from: {:?}", path))?;
    Ok(params)
}

/// Writes KZG parameters to a file, creating the directory if needed.
fn write_params(path: &Path, params: &ParamsKZG<Bls12>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    let mut buf = Vec::new();
    params
        .write_custom(&mut buf, SerdeFormat::RawBytesUnchecked)
        .with_context(|| "Failed to serialize KZG params")?;

    let file = File::create(path)
        .with_context(|| format!("Failed to create KZG params file: {:?}", path))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(&buf)
        .with_context(|| format!("Failed to write KZG params to: {:?}", path))?;
    writer.flush()?;

    Ok(())
}
