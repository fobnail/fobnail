use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

mod cert;

use anyhow::Context;
use clap::Parser;
use littlefs2::{
    consts::{U16, U512},
    fs::{Allocation, Attribute, FileType, Filesystem, ReadDirAllocation},
    io::{Read as _, Result as LfsResult},
};

#[derive(Parser)]
struct Options {
    #[clap(short, long)]
    file: PathBuf,

    /// Format flash before command (requires valid command)
    #[clap(long)]
    format: bool,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    Version,
    Dir {
        path: PathBuf,
    },
    Mkdir {
        path: PathBuf,
        #[clap(short, long)]
        recursive: bool,
    },
    Del {
        path: PathBuf,
    },
    #[clap(about = "Copy from image to host")]
    CopyFrom {
        source: PathBuf,
        destination: PathBuf,
    },
    #[clap(about = "Copy from host to image")]
    CopyTo {
        source: PathBuf,
        destination: PathBuf,
    },
    SetAttr {
        path: PathBuf,
        id: u8,
        data: u8,
    },
    GetAttr {
        path: PathBuf,
        id: u8,
    },
    InstallCertificate {
        #[clap(long)]
        trusted: bool,
        #[clap(long)]
        reinstall: bool,
        #[clap(long)]
        der: bool,
        path: Vec<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();

    let mut flash = Flash::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&options.file)
            .context("Failed to open flash")?,
    );
    let mut alloc = Allocation::new();

    if options.format {
        Filesystem::format(&mut flash).unwrap();
    }

    let fs = Filesystem::mount(&mut alloc, &mut flash).unwrap();

    match options.command {
        Command::Version => {
            let version = littlefs2::version();
            println!(
                "LittleFS version: format={}.{} backend={}.{}",
                version.format.0, version.format.1, version.backend.0, version.backend.1
            );
        }
        Command::Dir { path } => {
            list_directory(&fs, &path)?;
        }
        Command::Mkdir { path, recursive } => {
            make_directory(&fs, &path, recursive)?;
        }
        Command::Del { path } => {
            del(&fs, &path)?;
        }
        Command::CopyFrom {
            source,
            destination,
        } => {
            copy_from(&fs, &source, &destination)?;
        }
        Command::CopyTo {
            source,
            destination,
        } => {
            copy_to(&fs, &source, &destination)?;
        }
        Command::SetAttr { path, id, data } => {
            setattr(&fs, &path, id, &[data])?;
        }
        Command::GetAttr { id, path } => {
            if let Some(attr) = getattr(&fs, &path, id)? {
                let data = attr.data();
                for (i, b) in data.iter().enumerate() {
                    if i >= 16 && i % 16 == 0 {
                        println!()
                    }

                    print!("{:02X} ", b)
                }
                println!()
            } else {
                anyhow::bail!("No such attribute");
            }
        }
        Command::InstallCertificate {
            path,
            trusted,
            reinstall,
            der,
        } => {
            for path in &path {
                if let Err(e) = cert::install(&fs, &path, trusted, reinstall, der) {
                    println!("Failed to install {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(())
}

fn path_to_lfs_path(path: &Path) -> littlefs2::path::PathBuf {
    littlefs2::path::PathBuf::from(path.to_str().unwrap())
}

fn list_directory(fs: &Filesystem<Flash>, path: &Path) -> anyhow::Result<()> {
    let mut alloc = ReadDirAllocation::new();
    let it = unsafe { fs.read_dir(&mut alloc, &path_to_lfs_path(&path)) }.unwrap();
    for f in it {
        let f = f.unwrap();

        match f.file_type() {
            FileType::Dir => {
                println!("  {:10} {}", "<DIR>", f.file_name())
            }
            FileType::File => {
                println!("  {:10} {}", f.metadata().len(), f.file_name())
            }
        }
    }
    Ok(())
}

fn make_directory(fs: &Filesystem<Flash>, path: &Path, recursive: bool) -> anyhow::Result<()> {
    if recursive {
        fs.create_dir_all(&path_to_lfs_path(&path)).unwrap()
    } else {
        fs.create_dir(&path_to_lfs_path(&path)).unwrap();
    }
    Ok(())
}

fn del(fs: &Filesystem<Flash>, path: &Path) -> anyhow::Result<()> {
    fs.remove(&path_to_lfs_path(path)).unwrap();
    Ok(())
}

pub fn write_file(
    fs: &Filesystem<Flash>,
    path: &littlefs2::path::Path,
    data: &[u8],
) -> anyhow::Result<()> {
    fs.open_file_with_options_and_then(
        |opt| opt.create(true).write(true),
        path,
        |d| {
            let mut written = 0;
            let mut left = data.len();
            while left > 0 {
                let n = d.write(&data[written..written + left]).expect(&format!(
                    "Wrote {} bytes out of {}",
                    written,
                    data.len()
                ));
                if n == 0 {
                    panic!("Wrote {} bytes out of {}", written, data.len());
                }
                written += n;
                left -= n;
            }
            Ok(())
        },
    )
    .unwrap();

    Ok(())
}

fn copy_from(fs: &Filesystem<Flash>, source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut data = vec![];
    fs.open_file_with_options_and_then(
        |opt| opt.read(true).write(false),
        &path_to_lfs_path(source),
        |s| {
            let len = s.len()?;
            data.resize(len, 0);
            s.read_exact(&mut data[..])?;

            Ok(())
        },
    )
    .unwrap();

    dst.write_all(&data)?;
    dst.flush()?;

    Ok(())
}

fn copy_to(fs: &Filesystem<Flash>, source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut src = OpenOptions::new().read(true).write(false).open(&source)?;
    let file_size = src.metadata()?.len();
    let mut data = vec![0u8; file_size.try_into().unwrap()];
    src.read_exact(&mut data[..])?;

    write_file(fs, &path_to_lfs_path(destination), &data)?;

    Ok(())
}

fn setattr(fs: &Filesystem<Flash>, path: &Path, id: u8, data: &[u8]) -> anyhow::Result<()> {
    let mut attr = Attribute::new(id);
    attr.set_data(data);
    fs.set_attribute(&path_to_lfs_path(&path), &attr).unwrap();

    Ok(())
}

fn getattr(fs: &Filesystem<Flash>, path: &Path, id: u8) -> anyhow::Result<Option<Attribute>> {
    Ok(fs.attribute(&path_to_lfs_path(&path), id).unwrap())
}

pub struct Flash {
    file: RefCell<File>,
}

impl Flash {
    pub fn new(file: File) -> Self {
        Self {
            file: RefCell::new(file),
        }
    }
}

impl littlefs2::driver::Storage for Flash {
    // Emulate flash with similar parameters to these found on nRF52840.
    const READ_SIZE: usize = 4;
    const WRITE_SIZE: usize = 4;

    // Must be kept in-sync with definitions from pal_pc and pal_nrf for this
    // tool to work.
    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = 32;

    // We don't need wear-leveling on PC.
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U512;
    type LOOKAHEADWORDS_SIZE = U16;

    fn read(&self, off: usize, buf: &mut [u8]) -> LfsResult<usize> {
        // For let's just unwrap errors, we assume that littlefs won't call us
        // with some weird requests and that I/O operations are infallible.
        // If needed this may be extended into a correct error handling.

        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(off.try_into().unwrap())).unwrap();
        Ok(file.read(buf).unwrap())
    }

    fn write(&mut self, off: usize, buf: &[u8]) -> LfsResult<usize> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(off.try_into().unwrap())).unwrap();
        Ok(file.write(buf).unwrap())
    }

    fn erase(&mut self, off: usize, len: usize) -> LfsResult<usize> {
        // Use the same erase polarity as nRF flash has.
        let pattern: u8 = 0xff;
        let buf = vec![pattern; len];

        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(off.try_into().unwrap())).unwrap();
        Ok(file.write(&buf[..]).unwrap())
    }
}
