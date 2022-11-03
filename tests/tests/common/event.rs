use crate::common::util::*;
use std::{
    env,
    path::{Path, PathBuf},
};

/// Events that drive the test.
#[derive(Debug, Clone)]
pub(crate) enum TestEvent {
    // Check the policy and runtime hash
    #[allow(dead_code)] // FIXME
    CheckHash,
    // Write a remote file
    WriteFile(String, PathBuf),
    // Append a remote file
    #[allow(dead_code)] // FIXME
    AppendFile(String, PathBuf),
    // Execute a remote file
    Execute(String),
    // Execute a pipeline
    Pipeline(String),
    // Read a remote file
    ReadFile(String),
    // Request to shutdown the runtime
    ShutDown,
}

impl TestEvent {
    /// Create a test event for provisioning program. The function adds the local and remote
    /// path prefices on the filename.
    pub(crate) fn write_program(filename: &str) -> TestEvent {
        TestEvent::WriteFile(runtime_program_dir(filename), program_dir(filename))
    }

    /// Create a test event for provisioning data. The function adds the local and remote
    /// path prefices on the filename.
    pub(crate) fn write_data(filename: &str) -> TestEvent {
        TestEvent::WriteFile(runtime_data_dir(filename), data_dir(filename))
    }

    /// Create a list of events for provisioning data files in the `local_dir_path`. The
    /// `local_dir_path` will be replaced by `remote_dir_path`.
    #[allow(dead_code)] // FIXME
    pub(crate) fn write_all<T: AsRef<Path>, K: AsRef<Path>>(
        dir_path: T,
        remote_dir_path: K,
    ) -> Vec<TestEvent> {
        TestEvent::input_list(dir_path, remote_dir_path)
            .into_iter()
            .map(|(remote, local)| TestEvent::WriteFile(remote, local))
            .collect()
    }

    /// Create a test event for executing a program. The function adds the remote
    /// path prefices on the filename.
    pub(crate) fn execute<T: AsRef<str>>(filename: T) -> TestEvent {
        TestEvent::Execute(runtime_program_dir(filename))
    }

    /// Create a test event for reading result.
    pub(crate) fn read_result<T: AsRef<str>>(filepath: T) -> TestEvent {
        TestEvent::ReadFile(String::from(filepath.as_ref()))
    }

    /// Create a test event for execute the pipeline of `pipeline_id`.
    pub(crate) fn pipeline<T: AsRef<str>>(pipeline_id: T) -> TestEvent {
        TestEvent::Pipeline(String::from(pipeline_id.as_ref()))
    }

    /// Function produces a vec of input lists. Each list corresponds to a round
    /// and is a vec of pairs of remote (des) file and local (src) file path,
    /// which corresponds to provisioning/appending the content of the local file to the remote file.
    #[allow(dead_code)] // FIXME
    pub(crate) fn batch_process_events<T: AsRef<Path>, K: AsRef<str>, Q: AsRef<str>>(
        local_dir_path: T,
        program_filename: K,
        result_path: Q,
    ) -> Vec<TestEvent> {
        // Load the remote input path, otherwise use default `/input/`
        let remote_dir_path = env::var("REMOTE_DATA_DIR").unwrap_or("/input/".to_string());

        // Construct the TestEvent gradually and append to this vec.
        let mut rst = Vec::new();

        // traverse the `local_dir_path`. Assume sub-directories are sorted,
        // e.g. `1` `2` `3` `4` `5`. Each sub-directory contains files provisioned to
        // the remote in each batch. Note that the provisioning use `append` request rather then
        // `write` request anf the remote path is of prefix `remote_dir_path`.
        // For example, in the previous example, if in the second batch, sub-directory `2`,
        // there is a file `local_dir_path/2/a.dat`,
        // then a TestEvent::Append('remote_dir_path/a.dat', `local_dir_path/2/a.dat`) will be
        // created.
        let mut dir_entries = local_dir_path
            .as_ref()
            .read_dir()
            .expect(&format!("invalid path: {:?}", local_dir_path.as_ref()))
            .filter_map(|e| e.map(|x| x.path()).ok())
            .collect::<Vec<_>>();
        dir_entries.sort();

        // borrow so the loop will not complain on the lifetime.
        let program_filename = program_filename.as_ref();
        let result_path = result_path.as_ref();

        // Add append, execute and read_result events in each round.
        for entry in dir_entries.iter() {
            // Add all the append requests.
            rst.append(
                &mut TestEvent::input_list(entry, &remote_dir_path)
                    .into_iter()
                    .map(|(remote, local)| TestEvent::AppendFile(remote, local))
                    .collect(),
            );
            // Add execute request.
            rst.push(TestEvent::execute(program_filename));
            rst.push(TestEvent::read_result(result_path));
        }

        rst
    }

    /// Function produces a vec of pairs of remote (des) file and local (src) file path,
    /// which corresponds to provisioning/overwriting the content of the local file to the remote file.
    /// Read all files and diretory in the path of 'dir_path' in the local machine and replace the prefix with 'remote_dir_path'.
    /// E.g. if call the function with '/local/path/' and '/remote/path/',
    /// the result could be [(/remote/path/a.txt, /local/path/a.txt), (/remote/path/b/c.txt, /local/path/b/c.txt), ... ].
    #[allow(dead_code)] // FIXME
    pub(crate) fn input_list<T: AsRef<Path>, K: AsRef<Path>>(
        dir_path: T,
        remote_dir_path: K,
    ) -> Vec<(String, PathBuf)> {
        let mut rst = Vec::new();
        let dir_path = dir_path.as_ref();

        // Traverse all files and directories.
        for entry in dir_path
            .read_dir()
            .expect(&format!("invalid path: {:?}", dir_path))
        {
            let entry = entry.expect("invalid entry").path();
            let remote_entry_path = remote_dir_path.as_ref().join(
                entry
                    .strip_prefix(dir_path)
                    .expect("Failed to strip entry prefix"),
            );

            if entry.is_dir() {
                // If it a directory traverse recursively.
                rst.append(&mut TestEvent::input_list(entry, remote_entry_path))
            } else if entry.is_file() {
                let entry_path = entry.to_str().expect("Failed to parse the entry path");
                rst.push((
                    remote_entry_path
                        .to_str()
                        .expect("Failed to parse remote entry path")
                        .to_string(),
                    PathBuf::from(entry_path),
                ))
            }
        }

        rst
    }
}
