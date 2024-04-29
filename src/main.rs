#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]

use std::path::Path;

use anyhow::{ensure, Context, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use fuser::MountOption;
use log::{debug, info};
use zeroize::Zeroizing;

use crate::{
    bench::{DecryptReport, Tree},
    cli::Cli,
    gocryptfs::DynCipher,
};

mod bench;
mod cli;
mod daemon;
mod fuse;
mod gocryptfs;
mod logger;

fn main() -> Result<()> {
    crate::logger::init()?;

    let cli = Cli::parse();
    match cli.cmd {
        cli::Command::Bench(args) => {
            let cfg = gocryptfs::config::load(&args.dir)?;
            info!(creator = cfg.creator, version = cfg.version; "config loaded");

            let root_iv = gocryptfs::names::load_iv(&args.dir)?;

            let master_key = {
                let password = prompt_password()?;
                gocryptfs::decrypt_master_key(&cfg, &password)?
            };

            let tree = bench::build_tree(&args.dir)?;
            debug!(elements = tree.iter().map(Tree::len).sum::<usize>(); "built tree");

            let cipher = DynCipher::new(&cfg.feature_flags);

            let report = tree
                .iter()
                .map(|item| bench::decrypt_tree(&cipher, &master_key, &root_iv, item))
                .try_fold(DecryptReport::default(), |a, b| anyhow::Ok(a.merge(&b?)))?;

            report.print();
        }
        cli::Command::Mount(args) => {
            let cfg = gocryptfs::config::load(&args.source)?;
            info!(creator = cfg.creator, version = cfg.version; "config loaded");

            let root_iv = gocryptfs::names::load_iv(&args.source)?;

            if !check_target(&args.target)? {
                std::fs::create_dir(&args.target)?;
            }

            let master_key = if args.foreground {
                let password = prompt_password()?;
                gocryptfs::decrypt_master_key(&cfg, &password)?
            } else {
                let who = daemon::execute(|| {
                    let password = prompt_password()?;
                    gocryptfs::decrypt_master_key(&cfg, &password)?;

                    Ok(password)
                })?;

                match who {
                    daemon::Who::Parent => return Ok(()),
                    daemon::Who::Child(password) => gocryptfs::decrypt_master_key(&cfg, &password)?,
                }
            };

            let fs_name = args
                .target
                .file_name()
                .context("path doesn't represent a regular directory")?
                .to_string_lossy()
                .into_owned();

            let mut options = vec![
                MountOption::FSName(fs_name.clone()),
                MountOption::Subtype("tacowrap".to_owned()),
                MountOption::NoDev,
                MountOption::NoSuid,
            ];

            if cfg!(target_os = "macos") {
                options.push(MountOption::CUSTOM(format!("volname={fs_name}")));
            }

            let (unmount_tx, unmount_rx) = flume::bounded(1);

            let handle = fuser::spawn_mount2(
                fuse::Fuse::new(args.source, master_key, root_iv, &cfg.feature_flags)?
                    .with_shutdown(unmount_tx),
                &args.target,
                &options,
            )?;

            let (ctrlc_tx, ctrlc_rx) = flume::bounded(1);
            ctrlc::set_handler(move || {
                info!("shutdown signal received");
                ctrlc_tx.send(()).ok();
            })?;

            info!("filesystem ready");
            flume::Selector::new()
                .recv(&unmount_rx, |_| ())
                .recv(&ctrlc_rx, |_| ())
                .wait();
            info!("stopping filesystem");
            handle.join();
            info!("goodbye!");
        }
    }

    Ok(())
}

fn prompt_password() -> Result<Zeroizing<String>> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Password")
        .interact()
        .map(Into::into)
        .map_err(Into::into)
}

fn check_target(path: &Path) -> Result<bool> {
    if path.exists() {
        ensure!(path.metadata()?.is_dir(), "target isn't a directory");
        ensure!(
            path.read_dir()?.next().is_none(),
            "target directory isn't empty"
        );

        Ok(true)
    } else {
        Ok(false)
    }
}
