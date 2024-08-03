use std::io::{BufRead, Write};

use lsp_server::{Connection, Message, Request, Response};
use lsp_types::{
    GotoDefinitionParams, GotoDefinitionResponse, InitializeResult, Position, ServerCapabilities
};
use std::process::Stdio;
use tokio::runtime::Runtime;

fn main() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Create a connection to the client
        let (connection, io_threads) = Connection::stdio();

        // Read the initialize request from the client
        let (initialize_id, _initialize_params) = connection.initialize_start().unwrap();

        // Initialize server capabilities
        let capabilities = ServerCapabilities {
            definition_provider: Some(lsp_types::OneOf::Left(true)),
            ..Default::default()
        };

        let initialize_result = InitializeResult {
            capabilities,
            server_info: None,
        };

        // Serialize InitializeResult to serde_json::Value
        let initialize_result_value = serde_json::to_value(initialize_result).unwrap();

        // Send the initialize response to the client
        connection
            .initialize_finish(initialize_id, initialize_result_value)
            .unwrap();

        // Main message loop
        for msg in &connection.receiver {
            match msg {
                Message::Request(req) => {
                    if connection.handle_shutdown(&req).unwrap() {
                        return;
                    }
                    handle_request(req, &connection).await;
                }
                _ => {}
            }
        }

        // Shut down IO threads
        io_threads.join().unwrap();
    });
}

async fn handle_request(req: Request, connection: &Connection) {
    if let Ok((id, params)) = req.extract::<GotoDefinitionParams>("textDocument/definition") {
        let response = goto_definition(params).await;
        let resp = Response::new_ok(id, response);
        connection.sender.send(Message::Response(resp)).unwrap();
    }
}

async fn goto_definition(params: GotoDefinitionParams) -> Option<GotoDefinitionResponse> {
    // debug log
    let mut debug_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("c:/temp/hack_log.txt")
        .ok()?;

    let uri = params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    // Get the line
    // Why does LSP not just give it to us!?
    let filepath = uri.to_file_path().ok()?;
    let file = std::fs::File::open(&filepath).ok()?;
    let reader = std::io::BufReader::new(&file);
    let line = reader.lines().skip(position.line as usize).next()?.ok()?;

    // Determine symbol
    let chars: Vec<char> = line.chars().collect();
    let mut start = position.character as usize;

    let is_symbol_char = |c: char| c.is_alphanumeric() || c == '_';
    if !is_symbol_char(chars[start]) {
        return None;
    }

    loop {
        if !is_symbol_char(chars[start as usize]) {
            start += 1;
            break;
        } else {
            if start == 0 {
                break;
            }
            start -= 1;
        }
    }

    let mut end = start + 1;
    while end < chars.len() && is_symbol_char(chars[end]) {
        end += 1;
    }

    let symbol: String = chars.iter().skip(start).take(end - start).collect();
    debug_log.write_all(symbol.as_bytes()).ok()?;
    debug_log.write_all("\n".as_bytes()).ok()?;

    // Run child process
    // Define the command and arguments you want to run
    let result = std::process::Command::new("C:/temp/code/github/raddebugger/build/rdi_lsp.exe")
        .arg(format!("--goto_definition={symbol}"))
        .arg("C:/source_control/fts_gamemath_jai/src/scratch3.rdi")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let child = result.ok()?;

    // Capture the stdout
    let output = child.wait_with_output().ok()?;

    // Check if the command was successful
    if !output.status.success() {
        return None;
    }

    // Convert the stdout to a String
    let stdout = String::from_utf8(output.stdout).ok()?;
    debug_log.write_all("stdout: ".as_bytes()).ok()?;
    debug_log.write_all(stdout.as_bytes()).ok()?;
    debug_log.write_all("/n".as_bytes()).ok()?;

    let stderr = String::from_utf8(output.stderr).ok()?;
    debug_log.write_all("stderr: ".as_bytes()).ok()?;
    debug_log.write_all(stderr.as_bytes()).ok()?;
    debug_log.write_all("/n".as_bytes()).ok()?;

    let parts : Vec<_> = stdout.split(';').collect();
    if parts.len() != 2 {
        return None;
    }

    let line : u32 = parts[0].parse().ok()?;
    let pos = Position::new(line, 0);

    let filepath : std::path::PathBuf = parts[1].into();
    let file_url = url::Url::from_file_path(&filepath).ok()?;

    let location = lsp_types::Location {
        uri: file_url,
        range: lsp_types::Range {
            start: pos,
            end: pos,
        },
    };

    Some(GotoDefinitionResponse::Scalar(location))
}

mod test {
    #[test]
    fn test_hack() {}
}
