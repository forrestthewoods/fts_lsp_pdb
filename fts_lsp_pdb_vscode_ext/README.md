`fts-lsp-pdb` provides `goto definition` support for compiled languages that produce `PDB` debug symbols.

![](media/goto_definition_multilang.gif)

# Supported Platforms
Only runs on Windows and with projects that had a PDB file.

# Supported Languages
Any compiled language that produces `.pdb` debug symbols

Verified to work with: C, C++, Rust, Zig, Odin, Nim, Jai
Known Issues: D

# Configuration
Your project needs to be configured so that the extension knows what file types to consider and where `.pdb` files are located.

In `settings.json`:

```json
"fts_lsp_pdb.languages": ["cpp"],
"fts_lsp_pdb.file_patterns": [
    "**/*.zig", 
    "**/*.jai",
    "**/*.odin",
    "**/*.nim",
    "**/*.rs",
],
"fts_lsp_pdb.pdbs": [
    "path/to/foo.pdb",
    "path/to/some/other/bar.pdb",
],
```

You can find a list of supported language identifiers in the [VSCode documentation](https://code.visualstudio.com/docs/languages/identifiers).

# Known Limitations

The limitations of this extension are numerous:

* Only works with function calls
* Doesn't support inline functions or macros
* Only supports Windows and `.pdb` debug symbols
* Untested with `.dlls`
* Required making a full debug build to produce a `.pdb`
* Only tested on small projects
* Doesn't implement any LSP feature except `GotoDefinition`
