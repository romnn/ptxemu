use color_eyre::eyre;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use testcontainers::core::WaitFor;

// nvidia/cuda:11.7.0-devel-ubuntu20.04
const NAME: &str = "nvidia/cuda";
const TAG: &str = "11.7.0-devel-ubuntu20.04";

const DIR: &str = "/data";
const CONSOLE_ADDRESS: &str = ":9001";

#[derive(Debug)]
pub struct CUDA {
    pub env: HashMap<String, String>,
    pub volumes: HashMap<String, String>,
}

impl CUDA {
    pub fn add_volume(&mut self, src: impl AsRef<Path>, dest: impl AsRef<Path>) -> &mut Self {
        let src = src.as_ref().to_string_lossy().to_string();
        let dest = dest.as_ref().to_string_lossy().to_string();
        self.volumes.insert(src, dest);
        self
    }
}
// pub struct CUDABuilder {
//     pub env: HashMap<String, String>,
//     pub volumes: HashMap<String, String>,
// }

impl Default for CUDA {
    fn default() -> Self {
        let env = HashMap::new();
        let volumes = HashMap::new();
        // env_vars.insert(
        //     "MINIO_CONSOLE_ADDRESS".to_owned(),
        //     CONSOLE_ADDRESS.to_owned(),
        // );

        Self { env, volumes }
    }
}

#[derive(Debug, Clone)]
pub struct CUDAContainerArgs {
    // pub dir: String,
    // pub certs_dir: Option<String>,
    // pub json_log: bool,
}

impl Default for CUDAContainerArgs {
    fn default() -> Self {
        Self {
            // dir: DIR.to_owned(),
            // certs_dir: None,
            // json_log: false,
        }
    }
}

impl testcontainers::ImageArgs for CUDAContainerArgs {
    fn into_iterator(self) -> Box<dyn Iterator<Item = String>> {
        // let mut args = vec!["server".to_owned(), self.dir.to_owned()];

        // if let Some(ref certs_dir) = self.certs_dir {
        //     args.push("--certs-dir".to_owned());
        //     args.push(certs_dir.to_owned())
        // }

        // if self.json_log {
        //     args.push("--json".to_owned());
        // }

        // Box::new(args.into_iter())
        Box::new(vec![].into_iter())
    }
}

// pub fn exec(&self, cmd: ExecCommand) {
//     let ExecCommand {
//         cmd,
//         ready_conditions,
//     } = cmd;

//     log::debug!("Executing command {:?}", cmd);

//     self.docker_client.exec(self.id(), cmd);

//     self.docker_client
//         .block_until_ready(self.id(), ready_conditions);
// }


// pub fn exec_in(image: impl testcontainers::Image) -> eyre::Result<()> {
//     use testcontainers::clients::Cli as DockerClient;
//     use testcontainers::core::ExecCommand;


//     image.add_volume(dir.path(), &dest);
//     image.add_volume(dir.path(), &dest);
//     let docker = DockerClient::default();
//     let container = docker.run(request);
// }

impl testcontainers::Image for CUDA {
    type Args = CUDAContainerArgs;

    fn name(&self) -> String {
        NAME.to_owned()
    }

    fn tag(&self) -> String {
        TAG.to_owned()
    }

    // todo: we can use volumes here to map something into the container

    fn ready_conditions(&self) -> Vec<WaitFor> {
        // container is ready immediately
        vec![]
        // vec![WaitFor::message_on_stdout("API:")]
    }

    // fn entrypoint(&self) -> Option<String> {
    //     Some("sleep infinity".to_string())
    // }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        // (&PathBuf, &PathBuf)
        // let volume_iter = self.volumes.iter().map(|(src, dest)| {
        //     (
        //         src.to_string_lossy().to_string().as_ref(),
        //         dest.to_string_lossy().to_string().as_ref(),
        //         // src.to_string_lossy().to_string().as_ref(),
        //         // dest.to_string_lossy().to_string().as_ref(),
        //     )
        // });
        Box::new(self.volumes.iter())
    }

    // fn env_vars(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
    //     Box::new(self.env_vars.iter())
    // }
}

impl CUDA {
    // copy_dir_to_container copies the contents of a directory to a parent path in the container. This parent path must exist in the container first
    // as we cannot create it
    pub async fn copy_dir_to_container(
        &self,
        host_dir: impl AsRef<Path>,
        container_parent: impl AsRef<Path>,
        mode: i64,
    ) -> eyre::Result<()> {
        // note: maybe using volumes is much easier and faster
        // we need access to the bollard docker client and then do manual api calls?

        // dir, err := isDir(hostDirPath)
        // if err != nil {
        //     return err
        // }

        // if !dir {
        //     // it's not a dir: let the consumer to handle an error
        //     return fmt.Errorf("path %s is not a directory", hostDirPath)
        // }

        // buff, err := tarDir(hostDirPath, fileMode)
        // if err != nil {
        //     return err
        // }

        // // create the directory under its parent
        // parent := filepath.Dir(containerParentPath)

        // return c.provider.client.CopyToContainer(ctx, c.ID, parent, buff, types.CopyToContainerOptions{})
        Ok(())
    }
}

// how can we get the docker connection from the testcontainer
// should we merge the copy file functions upstream

// CopyToContainer copies content into the container filesystem.
// Note that must be a Reader for a TAR archive

// func (cli *Client) CopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader, options types.CopyToContainerOptions) error {
// 	query := url.Values{}
// 	query.Set("path", filepath.ToSlash(dstPath)) // Normalize the paths used in the API.
// 	// Do not allow for an existing directory to be overwritten by a non-directory and vice versa.
// 	if !options.AllowOverwriteDirWithFile {
// 		query.Set("noOverwriteDirNonDir", "true")
// 	}

// 	if options.CopyUIDGID {
// 		query.Set("copyUIDGID", "true")
// 	}

// 	apiPath := "/containers/" + containerID + "/archive"

// 	response, err := cli.putRaw(ctx, apiPath, query, content, nil)
// 	defer ensureReaderClosed(response)
// 	if err != nil {
// 		return wrapResponseError(err, response, "container:path", containerID+":"+dstPath)
// 	}

// 	// TODO this code converts non-error status-codes (e.g., "204 No Content") into an error; verify if this is the desired behavior
// 	if response.statusCode != http.StatusOK {
// 		return fmt.Errorf("unexpected status code from daemon: %d", response.statusCode)
// 	}

// 	return nil
// }

/*
func (c *DockerContainer) Exec(ctx context.Context, cmd []string) (int, io.Reader, error) {
    cli := c.provider.client
    response, err := cli.ContainerExecCreate(ctx, c.ID, types.ExecConfig{
        Cmd:          cmd,
        Detach:       false,
        AttachStdout: true,
        AttachStderr: true,
    })
    if err != nil {
        return 0, nil, err
    }

    hijack, err := cli.ContainerExecAttach(ctx, response.ID, types.ExecStartCheck{})
    if err != nil {
        return 0, nil, err
    }

    var exitCode int
    for {
        execResp, err := cli.ContainerExecInspect(ctx, response.ID)
        if err != nil {
            return 0, nil, err
        }

        if !execResp.Running {
            exitCode = execResp.ExitCode
            break
        }

        time.Sleep(100 * time.Millisecond)
    }

    return exitCode, hijack.Reader, nil
}

type FileFromContainer struct {
    underlying *io.ReadCloser
    tarreader  *tar.Reader
}

func (fc *FileFromContainer) Read(b []byte) (int, error) {
    return (*fc.tarreader).Read(b)
}

func (fc *FileFromContainer) Close() error {
    return (*fc.underlying).Close()
}

func (c *DockerContainer) CopyFileFromContainer(ctx context.Context, filePath string) (io.ReadCloser, error) {
    r, _, err := c.provider.client.CopyFromContainer(ctx, c.ID, filePath)
    if err != nil {
        return nil, err
    }
    tarReader := tar.NewReader(r)

    // if we got here we have exactly one file in the TAR-stream
    // so we advance the index by one so the next call to Read will start reading it
    _, err = tarReader.Next()
    if err != nil {
        return nil, err
    }

    ret := &FileFromContainer{
        underlying: &r,
        tarreader:  tarReader,
    }

    return ret, nil
}

func (c *DockerContainer) CopyFileToContainer(ctx context.Context, hostFilePath string, containerFilePath string, fileMode int64) error {
    dir, err := isDir(hostFilePath)
    if err != nil {
        return err
    }

    if dir {
        return c.CopyDirToContainer(ctx, hostFilePath, containerFilePath, fileMode)
    }

    fileContent, err := ioutil.ReadFile(hostFilePath)
    if err != nil {
        return err
    }
    return c.CopyToContainer(ctx, fileContent, containerFilePath, fileMode)
}

// CopyToContainer copies fileContent data to a file in container
func (c *DockerContainer) CopyToContainer(ctx context.Context, fileContent []byte, containerFilePath string, fileMode int64) error {
    buffer, err := tarFile(fileContent, containerFilePath, fileMode)
    if err != nil {
        return err
    }

    return c.provider.client.CopyToContainer(ctx, c.ID, filepath.Dir(containerFilePath), buffer, types.CopyToContainerOptions{})
}
*/
