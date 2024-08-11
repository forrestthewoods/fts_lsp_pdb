/* --------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 * ------------------------------------------------------------------------------------------ */

import * as path from 'path';
import { workspace, ExtensionContext } from 'vscode';

import {
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: ExtensionContext) {
	// The server is implemented in node
	//const command = 'C:/source_control/fts_pdb_lsp/target/debug/fts_pdb_lsp.exe';
	const command = path.join(context.extensionPath, 'server', 'bin', 'fts_lsp_pdb_server.exe');

	// If the extension is launched in debug mode then the debug server options are used
	// Otherwise the run options are used
	const serverOptions: ServerOptions = {
		run: { command: command, transport: TransportKind.stdio },
		debug: {
			command: command,
			transport: TransportKind.stdio,
		}
	};

	// Options to control the language client
	const config = workspace.getConfiguration('fts_lsp_pdb');
	const clientOptions: LanguageClientOptions = {
		documentSelector: [
			...config.get<string[]>("languages", []).map(lang => ({ scheme: 'file', language: lang })),
			...config.get<string[]>("file_patterns", []).map(pattern => ({ scheme: 'file', pattern: pattern })),
		],
	};

	// Create the language client and start the client.
	client = new LanguageClient(
		'lsp_pdb',
		'Language Server via PDB',
		serverOptions,
		clientOptions
	);

	// Set up configuration change listener
	context.subscriptions.push(
		workspace.onDidChangeConfiguration(e => {
			if (e.affectsConfiguration('fts_lsp_pdb')) {
				const c = workspace.getConfiguration('fts_lsp_pdb');

				// Refresh LSP server
				client.sendNotification('workspace/updateConfig', {
					pdbs: c.get('pdbs')
				  });
			}
		})
	);

	// Start the client. This will also launch the server
	client.start();

	// send config data
	client.sendNotification('workspace/updateConfig', {
		pdbs: config.get('pdbs')
	  });
}

export function deactivate(): Thenable<void> | undefined {
	if (!client) {
		return undefined;
	}
	return client.stop();
}
