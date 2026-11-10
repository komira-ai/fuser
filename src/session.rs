//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::thread::{self};

use log::debug;
use log::error;
use log::info;
use log::warn;
use nix::fcntl::FcntlArg;
use nix::fcntl::FdFlag;
use nix::fcntl::OFlag;
use nix::fcntl::fcntl;
use nix::unistd::Uid;
use nix::unistd::geteuid;
use parking_lot::Mutex;

use crate::Errno;
use crate::Filesystem;
use crate::InitOutcome;
use crate::KernelConfig;
use crate::MountOption;
use crate::ReplyEmpty;
use crate::Request;
use crate::channel::Channel;
use crate::channel::ChannelSender;
use crate::dev_fuse::DevFuse;
use crate::ll;
use crate::ll::Operation;
use crate::ll::ResponseErrno;
use crate::ll::Version;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi as abi;
use crate::mnt::Mount;
use crate::mnt::mount_options::Config;
use crate::mnt::mount_options::check_option_conflicts;
use crate::notify::Notifier;
use crate::read_buf::FuseReadBuf;
use crate::reply::Reply;
use crate::reply::ReplyRaw;
use crate::reply::ReplySender;
use crate::request::RequestWithSender;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub(crate) const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Default, Debug, Eq, PartialEq, Clone, Copy)]
/// How requests should be filtered based on the calling UID.
pub enum SessionACL {
    /// Allow requests from any user. Corresponds to the `allow_other` mount option.
    All,
    /// Allow requests from root. Corresponds to the `allow_root` mount option.
    RootAndOwner,
    /// Allow requests from the owning UID. This is FUSE's default mode of operation.
    #[default]
    Owner,
}

impl SessionACL {
    /// Returns the mount option string for kernel/fusermount/libfuse paths.
    /// Both `All` and `RootAndOwner` map to `allow_other` - the kernel only
    /// understands `allow_other`, and fuser enforces the root-only restriction internally.
    #[allow(dead_code)]
    pub(crate) fn to_mount_option(self) -> Option<&'static str> {
        match self {
            SessionACL::All | SessionACL::RootAndOwner => Some("allow_other"),
            SessionACL::Owner => None,
        }
    }
}

/// Calls `destroy` on drop.
#[derive(Debug)]
pub(crate) struct FilesystemHolder<FS: Filesystem> {
    pub(crate) fs: Option<FS>,
}

impl<FS: Filesystem> FilesystemHolder<FS> {
    fn destroy(&mut self) {
        if let Some(mut fs) = self.fs.take() {
            fs.destroy();
        }
    }
}

impl<FS: Filesystem> Drop for FilesystemHolder<FS> {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[derive(Debug)]
struct UmountOnDrop {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl UmountOnDrop {
    fn umount(&self) -> io::Result<()> {
        if let Some(mount) = self.mount.lock().take() {
            mount.umount()?;
        }
        Ok(())
    }
}

impl Drop for UmountOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.umount() {
            warn!("Failed to umount filesystem: {}", e);
        }
    }
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations. None after `destroy` called.
    pub(crate) filesystem: FilesystemHolder<FS>,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: UmountOnDrop,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement `allow_root` and `auto_unmount`
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: Uid,
    /// Result of the INIT handshake: set when the init message is answered, or by
    /// `from_fd_initialized`.
    pub(crate) init_outcome: Option<InitOutcome>,
    /// Read end of the pipe that `SessionStopper` writes to, once one was requested.
    stop: Option<Arc<OwnedFd>>,
    pub(crate) config: Config,
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    /// # Errors
    /// Returns an error if the options are incorrect, or if the fuse device can't be mounted.
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &Config,
    ) -> io::Result<Session<FS>> {
        check_option_conflicts(options)?;

        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther, return an error
        // because fusermount needs allow_root or allow_other to handle the auto_unmount option
        if options.mount_options.contains(&MountOption::AutoUnmount)
            && options.acl == SessionACL::Owner
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("auto_unmount requires acl != Owner, got: {:?}", options.acl),
            ));
        }
        let (file, mount) = Mount::new(mountpoint, &options.mount_options, options.acl)?;

        let ch = Channel::new(file);

        let mut session = Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch,
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(Some(mount))),
            },
            allowed: options.acl,
            session_owner: geteuid(),
            init_outcome: None,
            stop: None,
            config: options.clone(),
        };

        session.handshake()?;

        Ok(session)
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(
        filesystem: FS,
        fd: OwnedFd,
        acl: SessionACL,
        config: Config,
    ) -> io::Result<Self> {
        let ch = Channel::new(Arc::new(DevFuse(File::from(fd))));
        let mut session = Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch,
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(None)),
            },
            allowed: acl,
            session_owner: geteuid(),
            init_outcome: None,
            stop: None,
            config,
        };

        session.handshake()?;

        Ok(session)
    }

    /// Wrap a /dev/fuse file descriptor of a connection that the kernel has already
    /// initialised, for example one inherited from a server that crashed or is being
    /// replaced. The kernel sends INIT once per mount, so no handshake is run and no
    /// request is consumed: the session starts serving at once, with `init` (the
    /// outcome recorded by [`Session::init_outcome`] when the connection was
    /// initialised) as the state of the connection.
    ///
    /// [`Filesystem::init`] is not called. This doesn't mount the filesystem anywhere.
    /// Use [`Notifier::resend`] to have the kernel queue again the requests the previous
    /// server had read and not answered.
    pub fn from_fd_initialized(
        filesystem: FS,
        fd: OwnedFd,
        acl: SessionACL,
        config: Config,
        init: InitOutcome,
    ) -> Self {
        Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch: Channel::new(Arc::new(DevFuse(File::from(fd)))),
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(None)),
            },
            allowed: acl,
            session_owner: geteuid(),
            init_outcome: Some(init),
            stop: None,
            config,
        }
    }

    /// The outcome of the INIT handshake, to record it for [`Session::from_fd_initialized`].
    /// Always `Some` for a session returned by `new`, `from_fd` or `from_fd_initialized`.
    pub fn init_outcome(&self) -> Option<InitOutcome> {
        self.init_outcome
    }

    /// Returns a handle that makes [`Session::run`] return once its event loops have
    /// stopped reading requests, without unmounting or aborting the connection. A
    /// request that was read has been passed to the filesystem; the filesystem is
    /// destroyed as at any end of the loop. The descriptor is made non-blocking, as
    /// the event loops poll it.
    /// # Errors
    /// Returns an error if the pipe the handle needs can't be created or the descriptor
    /// can't be made non-blocking.
    pub fn stopper(&mut self) -> io::Result<SessionStopper> {
        let write = match &self.stop {
            Some(_) => return Err(io::Error::other("stopper() was already called")),
            None => {
                let (read, write) = nix::unistd::pipe()?;
                for fd in [&read, &write] {
                    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
                }
                let flags = OFlag::from_bits_retain(fcntl(self.ch.as_fd(), FcntlArg::F_GETFL)?);
                fcntl(
                    self.ch.as_fd(),
                    FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
                )?;
                self.stop = Some(Arc::new(read));
                write
            }
        };
        Ok(SessionStopper(Arc::new(write)))
    }

    /// Run the session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        let sender = self.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *self.mount.mount.lock());
        let guard = thread::Builder::new()
            .name("fuser-bg".to_string())
            .spawn(move || self.run())?;
        Ok(BackgroundSession {
            guard,
            sender,
            mount,
        })
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    /// # Errors
    /// Returns any final error when the session comes to an end.
    pub fn run(self) -> io::Result<()> {
        let Session {
            filesystem,
            ch,
            mount: _do_not_umount_yet,
            allowed,
            session_owner,
            init_outcome: _,
            stop,
            config,
        } = self;

        let n_threads = config.n_threads.unwrap_or(1);

        if !cfg!(target_os = "linux") && n_threads != 1 {
            // TODO: check whether it works on macOS/FreeBSD and enable if it works.
            return Err(io::Error::other(
                "n_threads != 1 is only supported on Linux",
            ));
        }

        let Some(n_threads_minus_one) = n_threads.checked_sub(1) else {
            return Err(io::Error::other("n_threads"));
        };

        let mut filesystem = Arc::new(filesystem);

        let mut channels = Vec::with_capacity(n_threads);

        for _ in 0..n_threads_minus_one {
            if config.clone_fd {
                #[cfg(target_os = "linux")]
                {
                    channels.push(ch.clone_fd()?);
                    continue;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(io::Error::other("clone_fd is only supported on Linux"));
                }
            } else {
                channels.push(ch.clone());
            }
        }
        channels.push(ch);

        let mut threads = Vec::with_capacity(n_threads);

        for (i, ch) in channels.into_iter().enumerate() {
            let thread_name = format!("fuser-{i}");
            let event_loop = SessionEventLoop {
                thread_name: thread_name.clone(),
                filesystem: filesystem.clone(),
                ch,
                allowed,
                session_owner,
                stop: stop.clone(),
            };
            threads.push(
                thread::Builder::new()
                    .name(thread_name)
                    .spawn(move || event_loop.event_loop())?,
            );
        }

        let mut reply: io::Result<()> = Ok(());
        for thread in threads {
            let res = match thread.join() {
                Ok(res) => res,
                Err(_) => {
                    return Err(io::Error::other("event loop thread panicked"));
                }
            };
            if let Err(e) = res {
                if reply.is_ok() {
                    reply = Err(e);
                }
            }
        }

        let Some(filesystem) = Arc::get_mut(&mut filesystem) else {
            return Err(io::Error::other(
                "BUG: must have one refcount for filesystem",
            ));
        };

        filesystem.destroy();

        reply
    }

    fn handshake(&mut self) -> io::Result<()> {
        let mut buf = FuseReadBuf::new();
        let buf = buf.as_mut();

        loop {
            // Read the init request from the kernel
            let size = match self.ch.receive_retrying(buf) {
                Ok(size) => size,
                Err(nix::errno::Errno::ENODEV) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "FUSE device disconnected during handshake",
                    ));
                }
                Err(err) => return Err(err.into()),
            };

            // Parse the request
            let request = match ll::AnyRequest::try_from(&buf[..size]) {
                Ok(request) => request,
                Err(err) => {
                    error!("{err}");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()));
                }
            };

            // Extract the init operation
            let op = match request.operation() {
                Ok(op) => op,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to parse FUSE operation",
                    ));
                }
            };

            let init = match op {
                ll::Operation::Init(init) => init,
                _ => {
                    error!("Received non-init FUSE operation before init: {}", request);
                    // Send error response and return error - non-init during handshake is invalid
                    <ReplyRaw as Reply>::new(
                        request.unique(),
                        ReplySender::Channel(self.ch.sender()),
                    )
                    .send_ll(&ResponseErrno(ll::Errno::EIO));
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Received non-init FUSE operation during handshake",
                    ));
                }
            };

            let v = init.version();
            if v.0 > abi::FUSE_KERNEL_VERSION {
                // Kernel has a newer major version than we support.
                // Send our version and wait for a second INIT request with a compatible version.
                debug!(
                    "INIT: Kernel version {} > our version {}, sending our version and waiting for next init",
                    v.0,
                    abi::FUSE_KERNEL_VERSION
                );
                let response = init.reply_version_only();
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&response);
                continue;
            }

            // We don't support ABI versions before 7.6
            if v < Version(7, 6) {
                error!("Unsupported FUSE ABI version {v}");
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&ResponseErrno(ll::Errno::EPROTO));
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Unsupported FUSE ABI version {v}"),
                ));
            }

            let mut config = KernelConfig::new(init.capabilities(), init.max_readahead(), v);

            // Call filesystem init method and give it a chance to return an error
            let Some(filesystem) = &mut self.filesystem.fs else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Bug: filesystem must be initialized during handshake",
                ));
            };
            let res = filesystem.init(Request::ref_cast(request.header()), &mut config);
            if let Err(error) = res {
                let errno = Errno::from_i32(error.raw_os_error().unwrap_or(0));
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&ResponseErrno(errno));
                return Err(error);
            }

            // Remember the ABI version supported by kernel and mark the session initialized.
            self.init_outcome = Some(config.outcome());

            // Log capability status for debugging
            for bit in 0..64 {
                let bitflags = InitFlags::from_bits_retain(1 << bit);
                if bitflags == InitFlags::FUSE_INIT_EXT {
                    continue;
                }
                let bitflag_is_known = InitFlags::all().contains(bitflags);
                let kernel_supports = init.capabilities().contains(bitflags);
                let we_requested = config.requested.contains(bitflags);
                // On macOS, there's a clash between linux and macOS constants,
                // so we pick macOS ones (last).
                let name = if let Some((name, _)) = bitflags.iter_names().last() {
                    Cow::Borrowed(name)
                } else {
                    Cow::Owned(format!("(1 << {bit})"))
                };
                if we_requested && kernel_supports {
                    debug!("capability {name} enabled")
                } else if we_requested {
                    debug!("capability {name} not supported by kernel")
                } else if kernel_supports {
                    debug!("capability {name} not requested by client")
                } else if bitflag_is_known {
                    debug!("capability {name} not supported nor requested")
                }
            }

            // Reply with our desired version and settings.
            debug!(
                "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                abi::FUSE_KERNEL_VERSION,
                abi::FUSE_KERNEL_MINOR_VERSION,
                init.capabilities() & config.requested,
                config.max_readahead,
                config.max_write
            );

            let response = init.reply(&config);
            <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                .send_ll(&response);

            return Ok(());
        }
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        self.mount.umount()
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
    }
}

/// A thread-safe handle that stops the event loops of a session, see [`Session::stopper`].
#[derive(Debug, Clone)]
pub struct SessionStopper(Arc<OwnedFd>);

impl SessionStopper {
    /// Make the event loops of the session return. Calling it again has no further effect.
    /// # Errors
    /// Returns an error if the pipe can't be written.
    pub fn stop(&self) -> io::Result<()> {
        match nix::unistd::write(&*self.0, &[0]) {
            Ok(_) | Err(nix::errno::Errno::EAGAIN) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        if let Some(mount) = std::mem::take(&mut *self.mount.lock()) {
            mount.umount()?;
        }
        Ok(())
    }
}

pub(crate) struct SessionEventLoop<FS: Filesystem> {
    /// Cache thread name for faster `debug!`.
    pub(crate) thread_name: String,
    pub(crate) ch: Channel,
    pub(crate) filesystem: Arc<FilesystemHolder<FS>>,
    pub(crate) allowed: SessionACL,
    pub(crate) session_owner: Uid,
    stop: Option<Arc<OwnedFd>>,
}

impl<FS: Filesystem> SessionEventLoop<FS> {
    fn event_loop(&self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buf = FuseReadBuf::new();
        let buf = buf.as_mut();
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            let received = match &self.stop {
                None => self.ch.receive_retrying(buf).map(Some),
                Some(stop) => self.ch.receive_until_stopped(stop.as_fd(), buf),
            };
            match received {
                Ok(None) => return Ok(()),
                Ok(Some(size)) => match RequestWithSender::new(self.ch.sender(), &buf[..size]) {
                    // Dispatch request
                    Some(req) => {
                        if let Ok(Operation::Destroy(_)) = req.request.operation() {
                            req.reply::<ReplyEmpty>().ok();
                            return Ok(());
                        } else {
                            req.dispatch(self)
                        }
                    }
                    // Quit loop on illegal request
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid request",
                        ));
                    }
                },
                Err(nix::errno::Errno::ENODEV) => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
    }
}

/// The background session data structure
#[derive(Debug)]
pub struct BackgroundSession {
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    sender: ChannelSender,
    /// Ensures the filesystem is unmounted when the session ends
    mount: Option<Mount>,
}

impl BackgroundSession {
    /// Unmount the filesystem and join the background thread.
    pub fn umount_and_join(mut self) -> io::Result<()> {
        if let Some(mount) = self.mount.take() {
            mount.umount()?;
        }
        self.join()
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }

    /// Join the filesystem thread.
    pub fn join(self) -> io::Result<()> {
        self.guard
            .join()
            .map_err(|_panic: Box<dyn std::any::Any + Send>| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "filesystem background thread panicked",
                )
            })?
    }
}

#[cfg(test)]
mod test {
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    use super::*;
    use crate::FileHandle;
    use crate::INodeNo;
    use crate::ReplyAttr;

    /// The device end of a datagram socket pair stands in for /dev/fuse: like the device, it
    /// delivers one request per read and takes one reply per write.
    fn fake_device() -> (OwnedFd, UnixDatagram) {
        let (device, kernel) = UnixDatagram::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        (OwnedFd::from(device), kernel)
    }

    fn request(opcode: abi::fuse_opcode, unique: u64, body: &[u8]) -> Vec<u8> {
        let len = (size_of::<abi::fuse_in_header>() + body.len()) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&(opcode as u32).to_ne_bytes());
        buf.extend_from_slice(&unique.to_ne_bytes());
        buf.extend_from_slice(&1u64.to_ne_bytes()); // nodeid
        buf.extend_from_slice(&[0; 16]); // uid, gid, pid, padding
        buf.extend_from_slice(body);
        buf
    }

    fn getattr(unique: u64) -> Vec<u8> {
        request(abi::fuse_opcode::FUSE_GETATTR, unique, &[0; 16])
    }

    fn init(major: u32, minor: u32, flags: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&major.to_ne_bytes());
        body.extend_from_slice(&minor.to_ne_bytes());
        body.extend_from_slice(&65536u32.to_ne_bytes()); // max_readahead
        body.extend_from_slice(&(flags as u32).to_ne_bytes());
        body.extend_from_slice(&((flags >> 32) as u32).to_ne_bytes());
        body.extend_from_slice(&[0; 44]);
        request(abi::fuse_opcode::FUSE_INIT, 1, &body)
    }

    /// Returns the (error, unique) of the next message the session wrote, and its length.
    fn read_reply(kernel: &UnixDatagram) -> (i32, u64, usize) {
        let mut buf = [0u8; 256];
        let n = kernel.recv(&mut buf).unwrap();
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(len as usize, n);
        let error = i32::from_ne_bytes(buf[4..8].try_into().unwrap());
        let unique = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        (error, unique, n)
    }

    /// Answers `getattr` with `EBADF`, and records whether each request was a resend.
    #[derive(Default)]
    struct TestFs {
        resends: Arc<Mutex<Vec<bool>>>,
        init_calls: Arc<Mutex<u32>>,
        offered_resend: Arc<Mutex<Option<bool>>>,
        passthrough_depth: u32,
    }

    impl Filesystem for TestFs {
        fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
            *self.init_calls.lock() += 1;
            let resend = config.capabilities().contains(InitFlags::FUSE_HAS_RESEND);
            *self.offered_resend.lock() = Some(resend);
            if resend {
                config.add_capabilities(InitFlags::FUSE_HAS_RESEND).unwrap();
            }
            config.set_max_write(4096).unwrap();
            if self.passthrough_depth > 0 {
                config
                    .add_capabilities(InitFlags::FUSE_PASSTHROUGH)
                    .unwrap();
                config.set_max_stack_depth(self.passthrough_depth).unwrap();
            }
            Ok(())
        }

        fn getattr(&self, req: &Request, _ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
            self.resends.lock().push(req.unique().is_resend());
            reply.error(Errno::EBADF);
        }
    }

    fn flag_pair(flags: InitFlags) -> u64 {
        flags.bits() | InitFlags::FUSE_INIT_EXT.bits()
    }

    fn handshake(fs: TestFs, offered: InitFlags) -> (Session<TestFs>, UnixDatagram) {
        let (device, kernel) = fake_device();
        kernel.send(&init(7, 40, flag_pair(offered))).unwrap();
        let session = Session::from_fd(fs, device, SessionACL::All, Config::default()).unwrap();
        (session, kernel)
    }

    #[test]
    fn from_fd_runs_the_handshake_and_reports_its_outcome() {
        let fs = TestFs::default();
        let (init_calls, offered) = (fs.init_calls.clone(), fs.offered_resend.clone());
        let (session, kernel) =
            handshake(fs, InitFlags::FUSE_HAS_RESEND | InitFlags::FUSE_MAX_PAGES);

        let (error, unique, _) = read_reply(&kernel);
        assert_eq!((error, unique), (0, 1));
        assert_eq!(*init_calls.lock(), 1);
        assert_eq!(*offered.lock(), Some(true));
        let outcome = session.init_outcome().unwrap();
        assert_eq!(outcome.kernel_abi, Version(7, 40));
        assert_eq!(
            outcome.capabilities,
            InitFlags::FUSE_HAS_RESEND | InitFlags::FUSE_MAX_PAGES
        );
        assert!(outcome.flags.contains(InitFlags::FUSE_HAS_RESEND));
        assert!(!outcome.flags.contains(InitFlags::FUSE_INIT_EXT));
        assert_eq!(outcome.max_readahead, 65536);
        assert_eq!(outcome.max_write, 4096);
        assert_eq!(outcome.max_stack_depth, 0);
    }

    #[test]
    fn outcome_reports_the_stack_depth_only_with_passthrough() {
        let fs = TestFs {
            passthrough_depth: 2,
            ..TestFs::default()
        };
        let (session, _kernel) = handshake(fs, InitFlags::FUSE_PASSTHROUGH);
        let outcome = session.init_outcome().unwrap();
        assert!(outcome.flags.contains(InitFlags::FUSE_PASSTHROUGH));
        assert_eq!(outcome.max_stack_depth, 2);
    }

    #[test]
    fn from_fd_still_refuses_a_connection_that_is_already_initialised() {
        let (device, kernel) = fake_device();
        kernel.send(&getattr(9)).unwrap();
        let err = Session::from_fd(
            TestFs::default(),
            device,
            SessionACL::All,
            Config::default(),
        )
        .map(|_| ())
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let (error, unique, _) = read_reply(&kernel);
        assert_eq!((error, unique), (-libc::EIO, 9));
    }

    #[test]
    fn from_fd_initialized_serves_a_queued_request_without_init() {
        let (device, kernel) = fake_device();
        let fs = TestFs::default();
        let (resends, init_calls) = (fs.resends.clone(), fs.init_calls.clone());
        let (recorded, _kernel) = handshake(TestFs::default(), InitFlags::FUSE_HAS_RESEND);
        let recorded = recorded.init_outcome().unwrap();

        // The request is queued before the session exists, as it is when a job calls
        // while no server is reading.
        kernel.send(&getattr(5)).unwrap();
        let mut session =
            Session::from_fd_initialized(fs, device, SessionACL::All, Config::default(), recorded);
        assert_eq!(session.init_outcome(), Some(recorded));
        let stopper = session.stopper().unwrap();
        let server = thread::spawn(move || session.run());

        let (error, unique, _) = read_reply(&kernel);
        assert_eq!((error, unique), (-libc::EBADF, 5));
        stopper.stop().unwrap();
        server.join().unwrap().unwrap();
        assert_eq!(*resends.lock(), vec![false]);
        assert_eq!(*init_calls.lock(), 0);
    }

    #[test]
    fn a_resent_request_is_marked_and_answered_under_its_id() {
        let (device, kernel) = fake_device();
        let fs = TestFs::default();
        let resends = fs.resends.clone();
        let (recorded, _kernel) = handshake(TestFs::default(), InitFlags::empty());
        let recorded = recorded.init_outcome().unwrap();
        let mut session =
            Session::from_fd_initialized(fs, device, SessionACL::All, Config::default(), recorded);
        let stopper = session.stopper().unwrap();
        let server = thread::spawn(move || session.run());

        let unique = 7 | abi::FUSE_UNIQUE_RESEND;
        kernel.send(&getattr(unique)).unwrap();
        assert_eq!(read_reply(&kernel), (-libc::EBADF, unique, 16));
        kernel.send(&getattr(8)).unwrap();
        assert_eq!(read_reply(&kernel), (-libc::EBADF, 8, 16));

        stopper.stop().unwrap();
        server.join().unwrap().unwrap();
        assert_eq!(*resends.lock(), vec![true, false]);
    }

    #[test]
    fn resend_is_a_header_only_notification() {
        let (device, kernel) = fake_device();
        let (recorded, _kernel) = handshake(TestFs::default(), InitFlags::empty());
        let recorded = recorded.init_outcome().unwrap();
        let session = Session::from_fd_initialized(
            TestFs::default(),
            device,
            SessionACL::All,
            Config::default(),
            recorded,
        );

        session.notifier().resend().unwrap();
        // Notifications have unique 0 and the notify code in the error field.
        assert_eq!(read_reply(&kernel), (7, 0, 16));
    }

    #[test]
    fn a_stopper_ends_every_event_loop_and_leaves_the_device_open() {
        let (device, kernel) = fake_device();
        let (recorded, _kernel) = handshake(TestFs::default(), InitFlags::empty());
        let recorded = recorded.init_outcome().unwrap();
        let config = Config {
            n_threads: Some(if cfg!(target_os = "linux") { 3 } else { 1 }),
            ..Config::default()
        };
        let mut session = Session::from_fd_initialized(
            TestFs::default(),
            device,
            SessionACL::All,
            config,
            recorded,
        );
        let stopper = session.stopper().unwrap();
        assert!(session.stopper().is_err());
        let device = nix::unistd::dup(session.as_fd()).unwrap();
        let server = thread::spawn(move || session.run());

        stopper.stop().unwrap();
        stopper.clone().stop().unwrap();
        server.join().unwrap().unwrap();

        // The connection was not closed: the next server can read from the same device.
        kernel.send(&getattr(3)).unwrap();
        let mut buf = [0u8; 64];
        let flags = OFlag::from_bits_retain(fcntl(&device, FcntlArg::F_GETFL).unwrap());
        assert!(flags.contains(OFlag::O_NONBLOCK));
        assert_eq!(nix::unistd::read(&device, &mut buf).unwrap(), 56);
    }

    #[test]
    fn a_non_blocking_device_waits_for_requests() {
        let (device, kernel) = fake_device();
        let (recorded, _kernel) = handshake(TestFs::default(), InitFlags::empty());
        let recorded = recorded.init_outcome().unwrap();
        fcntl(&device, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        let session = Session::from_fd_initialized(
            TestFs::default(),
            device,
            SessionACL::All,
            Config::default(),
            recorded,
        );
        let server = thread::spawn(move || session.run());

        kernel.send(&getattr(4)).unwrap();
        assert_eq!(read_reply(&kernel), (-libc::EBADF, 4, 16));
        kernel
            .send(&request(abi::fuse_opcode::FUSE_DESTROY, 6, &[]))
            .unwrap();
        assert_eq!(read_reply(&kernel), (0, 6, 16));
        server.join().unwrap().unwrap();
    }

    #[test]
    fn a_backing_id_of_an_earlier_server_is_taken_without_unsafe() {
        let (device, _kernel) = fake_device();
        let (recorded, _kernel) = handshake(TestFs::default(), InitFlags::empty());
        let recorded = recorded.init_outcome().unwrap();
        let session = Session::from_fd_initialized(
            TestFs::default(),
            device,
            SessionACL::All,
            Config::default(),
            recorded,
        );
        // Giving it up again leaves the id open in the kernel, as the server that registered it did.
        assert_eq!(session.notifier().backing_id_from_raw(5).into_raw(), 5);
    }
}
