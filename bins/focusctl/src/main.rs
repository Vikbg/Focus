use std::{env, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("focusctl: {error}");
        std::process::exit(1);
    }
}

fn run() -> std::io::Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let Some(command) = command_line(&arguments) else {
        eprintln!(
            "usage: focusctl status | session | doctor | vpn list | vpn up <id> | vpn down <id>"
        );
        return Ok(());
    };

    let socket_path =
        env::var("FOCUS_SOCKET_PATH").unwrap_or_else(|_| focusctl::DEFAULT_SOCKET_PATH.to_owned());
    let response = focusctl::request_at(Path::new(&socket_path), &command)?;
    print!("{response}");
    Ok(())
}

fn command_line(arguments: &[String]) -> Option<String> {
    match arguments {
        [command] if matches!(command.as_str(), "status" | "session" | "doctor") => {
            Some(command.clone())
        }
        [vpn, action] if vpn == "vpn" && action == "list" => Some("vpn list".to_owned()),
        [vpn, action, id]
            if vpn == "vpn"
                && matches!(action.as_str(), "up" | "down")
                && id.parse::<u128>().is_ok() =>
        {
            Some(format!("vpn {action} {id}"))
        }
        _ => None,
    }
}
