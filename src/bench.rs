use std::{
    ffi::OsString,
    fmt::{self, Display},
    path::Path,
    time::{Duration, Instant},
};

use anstyle::{AnsiColor, Color, Style};
use anyhow::{anyhow, Result};

use crate::gocryptfs::{self, content::FileHeader, DynCipher, MasterKey};

pub enum Tree {
    Dir {
        iv: gocryptfs::names::Iv,
        name: OsString,
        entries: Vec<Tree>,
    },
    File {
        name: OsString,
        content: Vec<u8>,
    },
}

impl Tree {
    pub fn len(&self) -> usize {
        match self {
            Tree::Dir { entries, .. } => 1 + entries.iter().map(Self::len).sum::<usize>(),
            Tree::File { .. } => 1,
        }
    }
}

pub fn build_tree(dir: &Path) -> Result<Vec<Tree>> {
    let mut tree = Vec::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let file_name = entry.file_name();
        let path = entry.path();

        if gocryptfs::is_crypto_dir(file_type, &path) {
            tree.push(Tree::Dir {
                iv: gocryptfs::names::load_iv(&path)?,
                name: file_name,
                entries: build_tree(&path)?,
            });
        } else if gocryptfs::is_crypto_file(file_type, &file_name) {
            tree.push(Tree::File {
                name: file_name,
                content: std::fs::read(entry.path())?,
            });
        } else {
            continue;
        }
    }

    Ok(tree)
}

#[derive(Default)]
pub struct DecryptReport {
    names: DecryptStats,
    contents: DecryptStats,
}

impl DecryptReport {
    pub fn merge(mut self, other: &Self) -> Self {
        self.names = self.names.merge(&other.names);
        self.contents = self.contents.merge(&other.contents);
        self
    }

    pub fn print(&self) {
        static STYLE: Style = Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Cyan)))
            .bold();

        println!("\n{STYLE}=== Names ==={STYLE:#}");
        self.names.print();
        println!("\n{STYLE}=== Contents ==={STYLE:#}");
        self.contents.print();
    }
}

#[derive(Default)]
struct DecryptStats {
    count: usize,
    size: usize,
    duration: Duration,
}

impl DecryptStats {
    fn merge(mut self, other: &Self) -> Self {
        self.count += other.count;
        self.size += other.size;
        self.duration += other.duration;
        self
    }

    #[allow(clippy::cast_precision_loss)]
    fn print(&self) {
        static NUMBER: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
        static NUMBER_BOLD: Style = NUMBER.bold();

        println!("Count:    {NUMBER}{}{NUMBER:#}", self.count);
        println!(
            "Bytes:    {NUMBER}{}{NUMBER:#}",
            BytesScale(self.size as f64),
        );
        println!("Duration: {NUMBER}{:.2?}{NUMBER:#}", self.duration);
        println!(
            "Speed:    {NUMBER_BOLD}{:.2}{NUMBER_BOLD:#}",
            SpeedScale(self.size as f64, self.duration),
        );
    }
}

struct BytesScale(f64);

impl Display for BytesScale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 > 1_000_000_000.0 {
            write!(f, "{:.2} GB", self.0 / 1_000_000_000.0)
        } else if self.0 > 1_000_000.0 {
            write!(f, "{:.2} MB", self.0 / 1_000_000.0)
        } else if self.0 > 1_000.0 {
            write!(f, "{:.2} kB", self.0 / 1_000.0)
        } else {
            write!(f, "{:.2} B", self.0)
        }
    }
}

struct SpeedScale(f64, Duration);

impl Display for SpeedScale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0 / self.1.as_secs_f64();
        if value > 1_000_000_000.0 {
            write!(f, "{:.2} GB/s", value / 1_000_000_000.0)
        } else if value > 1_000_000.0 {
            write!(f, "{:.2} MB/s", value / 1_000_000.0)
        } else if value > 1_000.0 {
            write!(f, "{:.2} kB/s", value / 1_000.0)
        } else {
            write!(f, "{value:.2} B/s")
        }
    }
}

pub fn decrypt_tree(
    cipher: &DynCipher,
    master_key: &MasterKey,
    parent_iv: &gocryptfs::names::Iv,
    tree: &Tree,
) -> Result<DecryptReport> {
    match tree {
        Tree::Dir {
            iv, name, entries, ..
        } => {
            let start = Instant::now();
            let plain_name = gocryptfs::names::decrypt(master_key, parent_iv, name)?
                .into_string()
                .map_err(|_| anyhow!("non-utf8 file name"))?;
            let name_duration = start.elapsed();

            let results = entries
                .iter()
                .map(|entry| decrypt_tree(cipher, master_key, iv, entry))
                .try_fold(DecryptReport::default(), |acc, report| {
                    anyhow::Ok(acc.merge(&report?))
                })?;

            Ok(results.merge(&DecryptReport {
                names: DecryptStats {
                    count: 1,
                    size: plain_name.len(),
                    duration: name_duration,
                },
                contents: DecryptStats::default(),
            }))
        }
        Tree::File { name, content, .. } => {
            let start = Instant::now();
            let plain_name = gocryptfs::names::decrypt(master_key, parent_iv, name)?
                .into_string()
                .map_err(|_| anyhow!("non-utf8 file name"))?;
            let name_duration = start.elapsed();

            let start = Instant::now();
            let (header, content) = FileHeader::read(content)?;
            let plain_content = cipher.decrypt(master_key, &header, content, 0)?;
            let content_duration = start.elapsed();

            Ok(DecryptReport {
                names: DecryptStats {
                    count: 1,
                    size: plain_name.len(),
                    duration: name_duration,
                },
                contents: DecryptStats {
                    count: 1,
                    size: plain_content.len(),
                    duration: content_duration,
                },
            })
        }
    }
}
