use anyhow::anyhow;
use capstone::prelude::*;
use goblin::pe::PE;
use lsp_server::{Connection, Message, Request, Response};
use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, InitializeResult, Position, ServerCapabilities};
use normpath::PathExt;
use pdb::{FallibleIterator, PDB};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use symbolic::common::{ByteView, DSymPathExt};
use symbolic::debuginfo::Archive;
use symbolic::symcache::{SymCache, SymCacheConverter};
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
        connection.initialize_finish(initialize_id, initialize_result_value).unwrap();

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
        let resp = Response::new_ok(id, response.ok());
        connection.sender.send(Message::Response(resp)).unwrap();
    }
}

async fn goto_definition(params: GotoDefinitionParams) -> anyhow::Result<GotoDefinitionResponse> {
    let mut debug_log = std::fs::OpenOptions::new().create(true).append(true).open("c:/temp/hack_log.txt")?;

    // HACK: hardcoded for testing
    // Paths to the EXE and PDB files
    let exe_path = "C:/temp/code/cpp/scratch/x64/Debug/scratch.exe";
    let pdb_path = "C:/temp/code/cpp/scratch/x64/Debug/scratch.pdb";

    let uri = params.text_document_position_params.text_document.uri;
    let filepath = uri.to_file_path().ok().ok_or_else(|| anyhow!("Couldn't get filepath from [{:?}]", uri))?;
    let source_file = filepath.normalize()?;
    let line_number = params.text_document_position_params.position.line + 1;

    debug_log.write_all("Target File: ".as_bytes())?;
    debug_log.write_all(source_file.as_path().to_string_lossy().as_bytes())?;
    debug_log.write_all("\n".as_bytes())?;

    // Open the EXE file and parse it using goblin
    let exe_data = std::fs::read(exe_path)?;
    let pe = PE::parse(&exe_data)?;

    // Open the PDB file
    let pdb_file = File::open(pdb_path)?;
    let mut pdb = PDB::open(pdb_file)?;
    let di = pdb.debug_information()?;
    let string_table = pdb.string_table()?;

    // Get the address map from the PDB
    let address_map = pdb.address_map()?;

    // Iterate over all modules and their line information
    let mut modules = di.modules()?;
    let mut address_ranges: Vec<(u32, u32)> = Vec::new();

    while let Some(module) = modules.next()? {
        let info = pdb.module_info(&module)?.unwrap();
        let line_program = info.line_program()?;

        let mut lines = line_program.lines();
        while let Some(line) = lines.next()? {
            if line.line_start != line_number {
                continue;
            }

            let file_info = line_program.get_file_info(line.file_index)?;
            let file_name = string_table.get(file_info.name)?;

            if let Ok(file_path) = PathBuf::from_str(&file_name.to_string())?.normalize() {
                debug_log.write_all(file_path.as_path().to_string_lossy().as_bytes())?;
                debug_log.write_all("\n".as_bytes())?;

                if are_paths_equal_case_insensitive(file_path.as_path(), source_file.as_path()) {
                    let rva = line.offset.to_rva(&address_map).unwrap();
                    address_ranges.push((rva.0, rva.0 + line.length.unwrap()));
                }
            }
        }
    }

    if address_ranges.is_empty() {
        anyhow::bail!("No address ranges found for the specified file and line number.");
    }

    // Disassemble the address ranges (capstone)
    let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()?;
    let text_section = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap() == ".text")
        .ok_or_else(|| anyhow!("Could not find text section"))?;
    let bytes = &exe_data[text_section.pointer_to_raw_data as usize..text_section.size_of_raw_data as usize];
    let all_exe_instructions = cs.disasm_all(bytes, text_section.virtual_address as u64)?;
    let exe_instruction_map: HashMap<_, _> = all_exe_instructions.iter().map(|inst| (inst.address(), inst)).collect();

    let mut result: Vec<(String, u32)> = Default::default();

    for (start, end) in address_ranges.clone() {
        let section = pe
            .sections
            .iter()
            .find(|sec| sec.virtual_address <= start && start < sec.virtual_address + sec.virtual_size);
        if let Some(section) = section {
            let offset = (start - section.virtual_address) as usize;
            let size = (end - start) as usize;
            let bytes = &exe_data[section.pointer_to_raw_data as usize + offset..section.pointer_to_raw_data as usize + offset + size];
            let instructions = cs.disasm_all(bytes, start as u64)?;

            for instruction in instructions.iter() {
                //println!("{}", instruction);
                if instruction.mnemonic().unwrap_or_default() == "call" {
                    // looks like op_code performs the relative address computation for us
                    // maybe_target_address == target_address
                    let offset_bytes = &instruction.bytes()[1..5];
                    let offset = i32::from_le_bytes([offset_bytes[0], offset_bytes[1], offset_bytes[2], offset_bytes[3]]);
                    let _maybe_target_address = (instruction.address() as i64 + instruction.len() as i64) + (offset as i64);

                    let op_str = instruction.op_str().unwrap();
                    let mut target_address = u64::from_str_radix(op_str.trim_start_matches("0x"), 16).unwrap();

                    // lookup target instruction, may be jmp
                    let maybe_inst = exe_instruction_map.get(&target_address);
                    if let Some(instruction) = maybe_inst {
                        if instruction.mnemonic().unwrap_or_default() == "jmp" {
                            let op_str = instruction.op_str().unwrap();
                            let new_target_address = u64::from_str_radix(op_str.trim_start_matches("0x"), 16).unwrap();
                            //println!("    Remapping call 0x{:x} to 0x{:x}", target_address, new_target_address);
                            target_address = new_target_address;
                        }
                    }

                    let r = map_address_to_file_and_line(&pdb_path, target_address);
                    match r {
                        Ok((file, line)) => {
                            //println!("    Function Address: 0x{:x}", target_address);
                            //println!("      File: [{file}]");
                            //println!("      Line: [{line}]");
                            result.push((file, line));
                        }
                        Err(e) => {
                            //println!("    );
                            anyhow::bail!("No mapping found for address 0x{:x}. Error: {}", target_address, e);
                        }
                    }
                }
            }
        }
    }

    if result.len() == 0 {
        anyhow::bail!("Failed to map file/line to anything");
    }
    if result.len() == 1 {
        let file = &result[0].0;
        let pos = Position::new(result[0].1 - 1, 0); // lines start at 0?
        let uri = url::Url::from_file_path(&file)
        .ok()
        .ok_or_else(|| anyhow!("Could not create URL from [{:?}]", file))?;

        let location = lsp_types::Location {
            uri: uri,
            range: lsp_types::Range { start: pos, end: pos },
        };

        return Ok(GotoDefinitionResponse::Scalar(location));
    } else {
        let mut locations: Vec<lsp_types::Location> = Default::default();
        for entry in &result {
            let file = &entry.0;
            let pos = Position::new(entry.1 - 1, 0);
            let uri = url::Url::from_file_path(&file)
                .ok()
                .ok_or_else(|| anyhow!("Could not create URL from [{:?}]", file))?;

            let location = lsp_types::Location {
                uri: uri,
                range: lsp_types::Range { start: pos, end: pos },
            };

            locations.push(location);
        }

        return Ok(GotoDefinitionResponse::Array(locations));
    }
}

async fn _goto_definition_old(params: GotoDefinitionParams) -> Option<GotoDefinitionResponse> {
    // debug log
    let mut debug_log = std::fs::OpenOptions::new().create(true).append(true).open("c:/temp/hack_log.txt").ok()?;

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

    let parts: Vec<_> = stdout.split(';').collect();
    if parts.len() != 2 {
        return None;
    }

    let line: u32 = parts[0].parse().ok()?;
    let pos = Position::new(line, 0);

    let filepath: std::path::PathBuf = parts[1].into();
    let file_url = url::Url::from_file_path(&filepath).ok()?;

    let location = lsp_types::Location {
        uri: file_url,
        range: lsp_types::Range { start: pos, end: pos },
    };

    Some(GotoDefinitionResponse::Scalar(location))
}

fn map_address_to_file_and_line(path: &str, address: u64) -> anyhow::Result<(String, u32)> {
    let pb: PathBuf = path.into();
    let dsym_path = pb.resolve_dsym();
    let byteview = ByteView::open(dsym_path.as_deref().unwrap_or_else(|| pb.as_ref()))?;

    let fat_obj = Archive::parse(&byteview)?;
    let objects_result: Result<Vec<_>, _> = fat_obj.objects().collect();
    let objects = objects_result?;
    assert!(objects.len() == 1);
    let obj = &objects[0];

    let mut converter = SymCacheConverter::new();
    converter.process_object(obj)?;

    let mut result = Vec::new();
    converter.serialize(&mut std::io::Cursor::new(&mut result))?;
    let buffer = ByteView::from_vec(result);
    let symcache = SymCache::parse(&buffer)?;

    let m = symcache.lookup(address).collect::<Vec<_>>();
    if m.len() == 0 {
        anyhow::bail!("Could not find function at address [0x{:x}]", address);
    }
    assert!(m.len() == 1); // what does multiple answers mean?

    let sym = &m[0];
    let path = sym.file().map(|file| file.full_path()).unwrap_or_else(|| "<unknown file>".into());
    let line = sym.line();
    Ok((path, line))
}

fn are_paths_equal_case_insensitive(path1: &Path, path2: &Path) -> bool {
    path1
        .to_str()
        .and_then(|s| path2.to_str().map(|t| s.to_lowercase() == t.to_lowercase()))
        .unwrap_or(false)
}
