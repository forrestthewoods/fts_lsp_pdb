use anyhow::anyhow;
use capstone::prelude::*;
use goblin::pe::PE;
use itertools::Itertools;
use lsp_server::{Connection, Message, Request, Response};
use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, InitializeResult, Position, ServerCapabilities};
use normpath::PathExt;
use pdb::{FallibleIterator, PDB};
use rayon::iter::{ParallelIterator, IntoParallelRefIterator};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use symbolic::common::{ByteView, DSymPathExt};
use symbolic::debuginfo::Archive;
use symbolic::symcache::{SymCache, SymCacheConverter};
use tokio::runtime::Runtime;

// Config that comes from VSCode Extension
#[derive(Clone, Default, serde::Deserialize)]
struct Config {
    pdbs: Vec<PathBuf>,
}

// Cache Root
struct Cache {
    exe_caches: Vec<ExeCache>,
}

// Cache for a single exe/PDB
self_cell::self_cell!(
    struct ExeCache {
        owner: ExeCacheOwner,

        #[covariant]
        dependent: ExeCacheRefs,
    }
);

struct ExeCacheOwner {
    exe_bytes: Pin<Box<[u8]>>,
    exe_capstone: capstone::Capstone,

    pdb_path: PathBuf,
    pdb_last_modified: u64,
    files: HashMap<String, HashMap<u32, Vec<pdb::LineInfo>>>,

    symcache_bytes: Pin<Box<[u8]>>,
}

self_cell::self_cell!(
    struct ExeCacheRefs<'a> {
        owner: ExeCacheRefs1<'a>,

        #[covariant]
        dependent: ExeCacheRefs2,
    }
);

struct ExeCacheRefs1<'a> {
    exe_parsed: goblin::pe::PE<'a>,
    exe_instructions: capstone::Instructions<'a>,
    symcache: SymCache<'a>,
}

struct ExeCacheRefs2<'a> {
    exe_instructions_sorted: HashMap<u64, &'a capstone::Insn<'a>>,
}

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
        let mut cache: Option<Cache> = None;
        for msg in &connection.receiver {
            match msg {
                Message::Request(req) => {
                    if connection.handle_shutdown(&req).unwrap() {
                        return;
                    }

                    if let Some(cache) = &mut cache {
                        refresh_cache(cache);
                    }
                    handle_request(req, &connection, &cache).await;
                }
                Message::Notification(notif) => match notif.method.as_str() {
                    "workspace/updateConfig" => {
                        if let Ok(config) = serde_json::from_value::<Config>(notif.params) {
                            cache = build_cache(config).ok();
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Shut down IO threads
        io_threads.join().unwrap();
    });
}

unsafe impl Send for ExeCache {}

fn build_cache(config: Config) -> anyhow::Result<Cache> {
    //let mut debug_log = std::fs::OpenOptions::new().create(true).append(true).open("c:/temp/hack_log.txt")?;

    let exe_caches : Vec<ExeCache> = config.pdbs.par_iter().filter_map(|pdb_path : &PathBuf| {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build_exe_cache(&pdb_path)));
        match result {
            Ok(inner_result) => inner_result.ok(),
            Err(err) => {
                let _panic_msg = get_panic_msg(&err);
                //debug_log.write_fmt(format_args!("PANIC! {}\n", _panic_msg))?;
                None
            }
        }
    }).collect();

    //debug_log.write_all(b"Build Cache Complete\n")?;
    Ok(Cache { exe_caches })
}

fn build_exe_cache(pdb_path: &Path) -> anyhow::Result<ExeCache> {
    let mut exe_path = pdb_path.to_owned();
    exe_path.set_extension("exe");
    //debug_log.write_fmt(format_args!("{}\n", pdb_path.to_string_lossy()))?;

    let exe_bytes = std::fs::read(&exe_path)?;
    let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()?;
    let pdb_file = File::open(&pdb_path)?;
    let pdb_last_modified = std::fs::metadata(&pdb_path)?.last_write_time();
    let mut pdb = PDB::open(pdb_file)?;

    // Pre-process PDB
    let di = pdb.debug_information()?;
    let string_table = pdb.string_table()?;
    let mut modules = di.modules()?;

    let mut file_name_lower: HashMap<pdb::RawString, String> = Default::default();
    let mut file_name_excluded: HashSet<pdb::RawString> = Default::default();
    let mut files: HashMap<String, HashMap<u32, Vec<pdb::LineInfo>>> = Default::default();
    while let Some(module) = modules.next()? {
        let info = pdb.module_info(&module)?.ok_or_else(|| anyhow::anyhow!("Failed to get PDB module info"));

        let info = match info {
            Ok(i) => i,
            Err(_) => {
                continue;
            }
        };

        let line_program = info.line_program()?;

        let mut lines = line_program.lines();
        while let Some(line) = lines.next()? {
            let file_info = line_program.get_file_info(line.file_index)?;
            let file_name = string_table.get(file_info.name)?;

            if file_name_excluded.contains(&file_name) {
                continue;
            }

            // Ensure entry for filepath
            if !file_name_lower.contains_key(&file_name) {
                if let Ok(pb) = PathBuf::from_str(&file_name.to_string()).unwrap().normalize() {
                    if let Some(lower) = pb.as_path().to_str().and_then(|s| Some(s.to_lowercase())) {
                        //debug_log.write_fmt(format_args!("    {}\n", &lower))?;
                        file_name_lower.insert(file_name, lower);
                    }
                } else {
                    file_name_excluded.insert(file_name.clone());
                    continue;
                }
            }

            if let Some(lower) = file_name_lower.get(&file_name) {
                if !files.contains_key(lower) {
                    files.insert(lower.clone(), Default::default());
                }

                files.get_mut(lower).unwrap().entry(line.line_start).or_default().push(line);
            }
        }
    }

    // Create SymCache
    let dsym_path = pdb_path.resolve_dsym();
    let byteview = ByteView::open(dsym_path.as_deref().unwrap_or_else(|| pdb_path.as_ref()))?;

    let fat_obj = Archive::parse(&byteview)?;
    let objects_result: Result<Vec<_>, _> = fat_obj.objects().collect();
    let objects = objects_result?;
    if objects.len() != 1 {
        anyhow::bail!("Error initializing symcache. Expected 1 object found {}", objects.len());
    }
    let obj = &objects[0];

    let mut converter = SymCacheConverter::new();
    converter.process_object(obj)?;

    let mut symcache_bytes = Vec::new();
    converter.serialize(&mut std::io::Cursor::new(&mut symcache_bytes))?;

    // Construct Cache
    Ok(ExeCache::new(
        ExeCacheOwner {
            //exe_path,
            exe_bytes: Pin::new(exe_bytes.into_boxed_slice()),
            exe_capstone: cs,
            pdb_path: pdb_path.to_owned(),
            pdb_last_modified,
            files,
            symcache_bytes: Pin::new(symcache_bytes.into_boxed_slice()),
        },
        |exe_cache| -> ExeCacheRefs {
            let pe = PE::parse(&exe_cache.exe_bytes).unwrap();

            let text_section = pe.sections.iter().find(|s| s.name().unwrap() == ".text").unwrap();
            let bytes = &exe_cache.exe_bytes[text_section.pointer_to_raw_data as usize..text_section.size_of_raw_data as usize];
            let exe_instructions = exe_cache.exe_capstone.disasm_all(bytes, text_section.virtual_address as u64).unwrap();

            ExeCacheRefs::new(
                ExeCacheRefs1 {
                    exe_parsed: pe,
                    exe_instructions,
                    symcache: SymCache::parse(&exe_cache.symcache_bytes).unwrap(),
                },
                move |refs| {
                    let mut exe_instructions_sorted: HashMap<u64, &capstone::Insn> = Default::default();
                    for inst in refs.exe_instructions.iter() {
                        exe_instructions_sorted.insert(inst.address(), inst);
                    }

                    ExeCacheRefs2 { exe_instructions_sorted }
                },
            )
        },
    ))
}

fn refresh_cache(cache: &mut Cache) {
    for exe_cache in &mut cache.exe_caches {
        let _ = (|| -> anyhow::Result<()> {
            let pdb_last_modified = std::fs::metadata(&exe_cache.borrow_owner().pdb_path)?.last_write_time();
            let ec = exe_cache.borrow_owner();
            if pdb_last_modified > ec.pdb_last_modified {
                *exe_cache = build_exe_cache(&ec.pdb_path)?;
            }

            Ok(())
        })();
    }
}

async fn handle_request(req: Request, connection: &Connection, cache: &Option<Cache>) {
    if let Ok((id, params)) = req.extract::<GotoDefinitionParams>("textDocument/definition") {
        let id_copy = id.clone();
        let result = std::panic::catch_unwind(|| {
            let response = goto_definition(params, cache);
            let msg = match response {
                Ok(r) => Response::new_ok(id, r),
                Err(_e) => Response::new_ok(id, GotoDefinitionResponse::Array(vec![])), // empty array = silent error
            };
            let _ = connection.sender.send(Message::Response(msg));
        });

        if let Err(err) = result {
            let panic_msg = get_panic_msg(&err);
            let _ = connection.sender.send(Message::Response(Response::new_err(id_copy, -1, panic_msg)));
        }
    }
}

fn goto_definition(params: GotoDefinitionParams, cache: &Option<Cache>) -> anyhow::Result<GotoDefinitionResponse> {
    let cache = match cache {
        Some(c) => c,
        None => {
            anyhow::bail!("No cache");
        }
    };

    //let mut debug_log = std::fs::OpenOptions::new().create(true).append(true).open("c:/temp/hack_log.txt")?;

    // Input data
    let uri = params.text_document_position_params.text_document.uri;
    let filepath = uri.to_file_path().ok().ok_or_else(|| anyhow!("Couldn't get filepath from [{:?}]", uri))?;
    let source_file = filepath.normalize()?.as_path().to_string_lossy().to_lowercase();
    let line_number = params.text_document_position_params.position.line + 1;

    // debug_log.write_all("Target File: ".as_bytes())?;
    // debug_log.write_all(source_file.as_bytes())?;
    // debug_log.write_all("\n".as_bytes())?;

    for exe_cache in &cache.exe_caches {
        let result = || -> anyhow::Result<GotoDefinitionResponse> {
            // Reparse PDB because Rust is stupid
            let pdb_file = File::open(&exe_cache.borrow_owner().pdb_path)?;
            let mut pdb = PDB::open(pdb_file)?;
            let address_map = pdb.address_map()?;

            // Find exe address range for (source_file, line_info)
            let line_infos = exe_cache
                .borrow_owner()
                .files
                .get(&source_file)
                .and_then(|lines| lines.get(&line_number))
                .ok_or_else(|| anyhow::anyhow!("Could not fine entry for [{source_file}]:[{line_number}]"))?;

            let mut source_locations: Vec<(String, u32)> = Default::default();
            for line_info in line_infos {
                let rva = line_info
                    .offset
                    .to_rva(&address_map)
                    .ok_or_else(|| anyhow!("Could not map line offset to RVA"))?;
                let start = rva.0;
                let end = rva.0 + line_info.length.unwrap_or_default();

                // Find calls made within line
                let pe = &exe_cache.borrow_dependent().borrow_owner().exe_parsed;
                let section = pe
                    .sections
                    .iter()
                    .find(|sec| sec.virtual_address <= start && start < sec.virtual_address + sec.virtual_size);
                if let Some(section) = section {
                    let offset = (start - section.virtual_address) as usize;
                    let size = (end - start) as usize;
                    let bytes = &exe_cache.borrow_owner().exe_bytes
                        [section.pointer_to_raw_data as usize + offset..section.pointer_to_raw_data as usize + offset + size];
                    let instructions = exe_cache.borrow_owner().exe_capstone.disasm_all(bytes, start as u64)?;

                    for instruction in instructions.iter() {
                        //println!("{}", instruction);
                        if instruction.mnemonic().unwrap_or_default() == "call" {
                            let source_loc = || -> anyhow::Result<(String, u32)> {
                                let op_str = instruction.op_str().ok_or_else(|| anyhow::anyhow!("No op str"))?;
                                let mut target_address = u64::from_str_radix(op_str.trim_start_matches("0x"), 16)?;

                                // lookup target instruction, may be jmp
                                let maybe_inst = exe_cache
                                    .borrow_dependent()
                                    .borrow_dependent()
                                    .exe_instructions_sorted
                                    .get(&target_address);
                                if let Some(instruction) = maybe_inst {
                                    if instruction.mnemonic().unwrap_or_default() == "jmp" {
                                        let op_str = instruction.op_str().ok_or_else(|| anyhow::anyhow!("No op str"))?;
                                        let new_target_address = u64::from_str_radix(op_str.trim_start_matches("0x"), 16)?;
                                        //println!("    Remapping call 0x{:x} to 0x{:x}", target_address, new_target_address);
                                        target_address = new_target_address;
                                    }
                                }

                                let symcache = &exe_cache.borrow_dependent().borrow_owner().symcache;
                                let m = symcache.lookup(target_address).collect::<Vec<_>>();
                                if m.len() == 0 {
                                    anyhow::bail!("Could not find function at address [0x{:x}]", target_address);
                                }

                                let source_loc = &m[0];
                                let path = source_loc
                                    .file()
                                    .map(|file| file.full_path())
                                    .ok_or_else(|| anyhow::anyhow!("<unknown file>"))?;

                                if let Ok(real_path) = PathBuf::from_str(&path).unwrap().normalize() {
                                    let line = source_loc.line();
                                    Ok((real_path.as_path().to_string_lossy().to_string(), line))
                                } else {
                                    anyhow::bail!("Could not resolve source file")
                                }
                            }();

                            if let Ok(sl) = source_loc {
                                source_locations.push(sl);
                            }
                        }
                    }
                }
            }

            source_locations = source_locations.into_iter().unique().collect();

            if source_locations.len() == 0 {
                anyhow::bail!("Failed to map file/line to anything");
            }

            let lsp_locations: Vec<_> = source_locations
                .iter()
                .filter_map(|sl| {
                    let file = &sl.0;
                    let line = sl.1;
                    let pos = Position::new(line - 1, 0); // lines start at 0?
                    url::Url::from_file_path(&file).ok().and_then(|uri| {
                        Some(lsp_types::Location {
                            uri: uri,
                            range: lsp_types::Range { start: pos, end: pos },
                        })
                    })
                })
                .collect();

            if lsp_locations.len() == 1 {
                return Ok(GotoDefinitionResponse::Scalar(lsp_locations[0].clone()));
            } else {
                return Ok(GotoDefinitionResponse::Array(lsp_locations));
            }
        }();

        if result.is_ok() {
            return result;
        }
    }

    anyhow::bail!("Failed to find [{:?}]:[{}] in any PDB", &filepath, line_number);
}

fn get_panic_msg(err: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(panic_msg) = err.downcast_ref::<&str>() {
        panic_msg.to_string()
    } else if let Some(panic_msg) = err.downcast_ref::<String>() {
        panic_msg.clone()
    } else {
        "Unknown panic".to_owned()
    }
}
