use std::{env, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("focusctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> std::io::Result<()> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next();

    if command.as_deref() != Some("status") || arguments.next().is_some() {
        eprintln!("usage: focusctl status");
        return Ok(());
    }

    let socket_path = env::var("FOCUS_SOCKET_PATH")
        .unwrap_or_else(|_| focusctl::DEFAULT_SOCKET_PATH.to_owned());
    let status = focusctl::status_at(Path::new(&socket_path))?;
    print!("{status}");
    Ok(())
}
