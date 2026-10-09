use aster_compose_credentials::create_generation;
use std::{env, path::PathBuf, process::ExitCode};

#[derive(Debug)]
struct CreateCommand {
    output_parent: PathBuf,
    token_file: PathBuf,
}

impl CreateCommand {
    fn parse(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Self, ()> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        match arguments.as_slice() {
            [command, output_flag, output_parent, token_flag, token_file]
                if command == "create"
                    && output_flag == "--output-parent"
                    && token_flag == "--token-file" =>
            {
                Ok(Self {
                    output_parent: output_parent.into(),
                    token_file: token_file.into(),
                })
            }
            _ => Err(()),
        }
    }
}

fn execute(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
    input: impl std::io::Read,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> u8 {
    let command = match CreateCommand::parse(arguments) {
        Ok(command) => command,
        Err(()) => {
            let _ = writeln!(stderr, "ERROR invalid invocation");
            return 2;
        }
    };
    match create_generation(&command.output_parent, &command.token_file, input) {
        Ok(receipt) => {
            if writeln!(
                stdout,
                "CREATE disposition=created generation={}",
                receipt.generation_hex()
            )
            .is_ok()
            {
                0
            } else {
                let _ = writeln!(stderr, "ERROR credential generation output failed");
                1
            }
        }
        Err(error) => {
            let _ = writeln!(stderr, "ERROR {error}");
            1
        }
    }
}

fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(execute(
        env::args_os().skip(1),
        std::io::stdin().lock(),
        &mut stdout,
        &mut stderr,
    ))
}
