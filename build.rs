use std::fs;
use std::path::Path;

use color_eyre::eyre::{Context, eyre};

#[path = "src/key_validator.rs"]
mod key_validator;

fn main() -> color_eyre::Result<()> {
    let key_filename = "dns_update.key";
    let key_path = Path::new(key_filename);

    println!("cargo:rerun-if-changed={}", key_filename);

    if !key_path.exists() {
        return Err(eyre!(
            "No key file found. Did you generate {key_path:?} yet?"
        ));
    }

    let key_bytes = fs::read(key_path).wrap_err("While trying to read key")?;
    let _ = key_validator::load_and_validate(&key_bytes)?;
    Ok(())
}
