use clap::Parser;
use colored::Colorize;
use serde::Serialize;
use std::{
    fs::{self, create_dir_all},
    io::Write,
};

use crate::{log, TSFSContext};

use super::{download_file, Command};

#[derive(Serialize)]
pub struct DownloadFileRequest {
    file_uid: String,
}

/// Download a file
#[derive(Parser, Debug)]
pub struct DownloadArgs {
    name: String,
}

pub struct DownloadCommand;

impl Command for DownloadCommand {
    fn execute(&self, args: &Vec<String>, ctx: &mut TSFSContext) {
        match DownloadArgs::try_parse_from(args) {
            Ok(args) => {
                if let Some(keyring_tree) = &ctx.keyring_tree {
                    let mut current_folder = None;
                    if let Some(current_folder_id) = ctx.current_folder.last() {
                        current_folder = keyring_tree.get_file(current_folder_id);
                    };

                    let current_keyring = if let Some(folder) = &current_folder {
                        folder.file.keyring.as_ref().unwrap()
                    } else {
                        keyring_tree
                    };

                    if let Some(file) = current_keyring.get_file_by_name(&args.name) {
                        if let Some(file) = download_file(ctx, file) {
                            let dir_path = &format!(
                                "{}{}",
                                ctx.local_folder.as_ref().unwrap(),
                                ctx.get_path()
                            );

                            // Create all dirs
                            create_dir_all(dir_path).expect("Can't create directories");

                            // Create file
                            let file_path = format!("{}{}", dir_path, file.name);

                            log::info(&format!("Creating file at {}", file_path.green()));
                            let mut local_file =
                                fs::File::create(&file_path).expect("Can't create file");
                            local_file
                                .write_all(&file.data.unwrap())
                                .expect("Can't write to file");

                            log::info(&format!("File downloaded at {}", file_path.green()));
                        }
                    } else {
                        log::error(&format!("Can't find file {}", args.name.red()));
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
        "Download a file from the current folder".into()
    }
}
