use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use std::{env, io};

use souls_vfs::Vfs;

use crate::keys::eldenring_keys;

mod keys;

#[test]
pub fn loads_er_archive() -> Result<(), Box<dyn Error>> {
    let er_path = PathBuf::from(env::var("ER_PATH").expect("no elden ring path provided"));
    let keys = eldenring_keys()?;
    let vfs = Vfs::create(
        [
            er_path.join("Data0.bhd"),
            er_path.join("Data1.bhd"),
            er_path.join("Data2.bhd"),
            er_path.join("Data3.bhd"),
            er_path.join("sd/sd.bhd"),
        ],
        &keys,
    )?;

    let mut vfs_file = vfs.open("/action/eventnameid.txt")?;
    let mut file = File::create("eventnameid.txt")?;
    io::copy(&mut vfs_file, &mut file)?;

    Ok(())
}
