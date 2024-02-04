# souls-kit

A set of libraries for interacting with FROMSOFTWARE game data.

## Components

### Virtual File System

A DVDBND/BHD backed virtual file system implementation is provided, which allows reading data directly from the game archives without the need to first unpack them like would be done traditionally with tools like UXM.

#### Example


```rs
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

    std::io::copy(&mut vfs_file, &mut file)?;
```