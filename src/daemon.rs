use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
};

use anyhow::Result;
use daemonize::{Daemonize, Outcome};
use zeroize::Zeroizing;

const SOCKET_PATH: &str = concat!("/tmp/", env!("CARGO_CRATE_NAME"), ".sock");

pub enum Who {
    Parent,
    Child(Zeroizing<String>),
}

pub fn execute(read_pw: impl Fn() -> Result<Zeroizing<String>>) -> Result<Who> {
    let stdout = File::create(concat!("/tmp/", env!("CARGO_CRATE_NAME"), ".out"))?;
    let stderr = File::create(concat!("/tmp/", env!("CARGO_CRATE_NAME"), ".err"))?;

    let outcome = Daemonize::new()
        .pid_file(concat!("/tmp/", env!("CARGO_CRATE_NAME"), ".pid"))
        .chown_pid_file(true)
        // .user(unsafe { libc::geteuid() })
        // .group(unsafe { libc::getegid() })
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(read_password)
        .execute();

    match outcome {
        Outcome::Parent(res) => {
            let exit_code = res?.first_child_exit_code;

            if exit_code == libc::EXIT_SUCCESS {
                let pw = read_pw()?;
                send_password(&pw)?;

                Ok(Who::Parent)
            } else {
                std::process::exit(exit_code);
            }
        }
        Outcome::Child(res) => {
            let password = res?.privileged_action_result?;
            Ok(Who::Child(password))
        }
    }
}

/// Read the password from the child process.
fn read_password() -> Result<Zeroizing<String>> {
    remove_socket()?;

    let listener = UnixListener::bind(SOCKET_PATH)?;
    let (mut conn, _) = listener.accept()?;

    let mut buf = Zeroizing::default();
    conn.read_to_string(&mut buf)?;

    remove_socket()?;

    Ok(buf)
}

/// Send the password from parent to child process.
fn send_password(pw: &str) -> Result<()> {
    let mut conn = UnixStream::connect(SOCKET_PATH)?;

    conn.write_all(pw.as_bytes())?;
    conn.flush()?;

    Ok(())
}

/// Delete the socket file, if it exists.
fn remove_socket() -> Result<()> {
    match std::fs::remove_file(SOCKET_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
