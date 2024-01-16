use clap::Parser;

use crate::{log, TSFSContext};

use super::Command;

/// Move to the specified folder
#[derive(Parser, Debug)]
pub struct CdArgs {
    folder: String,
}

pub struct CdCommand;

impl Command for CdCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match CdArgs::try_parse_from(args) {
            Ok(args) => {
                if let Some(keyring_tree) = &ctx.keyring_tree {
                    if args.folder == ".." {
                        if ctx.current_folder.len() > 0 {
                            ctx.current_folder.pop();
                        } else {
                            log::error("Can't move back, already in root");
                        }
                    } else {
                        let folder;

                        if let Some(current_folder) = ctx.current_folder.last() {
                            let current_folder = keyring_tree.get_file(&current_folder).unwrap();
                            folder = current_folder
                                .file
                                .keyring
                                .unwrap()
                                .get_file_by_name(&args.folder);
                        } else {
                            folder = keyring_tree.get_file_by_name(&args.folder);
                        }

                        if let Some(folder) = folder {
                            if !folder.file.is_folder() {
                                log::error("This is not a folder");
                                return;
                            }

                            ctx.current_folder.push(folder.file.id);
                        } else {
                            log::error("Folder not found");
                        }
                    }
                } else {
                    log::error("Missing Keyring Tree, not logged ?");
                }
            }

            Err(e) => {
                println!("{e}");
            }
        }
    }

    fn description(&self) -> String {
        "List the content of the current folder".into()
    }
}
