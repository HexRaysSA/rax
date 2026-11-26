//! Application- and framework-bundled XPC services in the closed guest.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::Arc;

use plist::Value;
use plist::stream::{Event, Reader};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::mach::ipc::{KObject, Port, Right, disp};
use crate::user::darwin::process::Proc;
use crate::user::darwin::signal::{Origin, SIGKILL};
use crate::user::darwin::syscall::Ctx;

use super::{MAX_DOMAIN_BYTES, MAX_DOMAIN_PATHS, MAX_NAME_BYTES, SERVICE_NOT_FOUND};

const MAX_MANIFEST: u64 = 256 << 10;

#[derive(Default)]
pub(super) struct Services {
    domains: BTreeMap<i32, BTreeSet<String>>,
    running: Vec<Service>,
}

struct Service {
    client: i32,
    pid: i32,
    name: String,
    configuration: Configuration,
    endpoint: Arc<Port>,
    checked_in: bool,
}

struct Configuration {
    service_type: String,
    run_loop: Option<String>,
    env: Vec<Vec<u8>>,
    join_session: bool,
}

pub(super) enum Request<'a> {
    Open {
        origin: Option<&'a str>,
        paths: Vec<&'a str>,
    },
    Scan(Vec<&'a str>),
    Resume,
    LookUp(&'a str),
    Info,
    CheckIn(&'a str),
}

pub(super) enum Reply {
    Empty,
    Scan,
    Info {
        name: String,
        service_type: String,
        run_loop: Option<String>,
    },
    Endpoint(Right, u32),
}

fn missing() -> i64 {
    SERVICE_NOT_FOUND
}

fn app_root(executable: &str) -> Option<&str> {
    let (bundle, name) = executable.rsplit_once("/Contents/MacOS/")?;
    (bundle.starts_with('/') && bundle.ends_with(".app") && component(name)).then_some(bundle)
}

fn component(name: &str) -> bool {
    !matches!(name, "" | "." | "..") && !name.contains(['/', '\0'])
}

fn read_manifest(data: &[u8]) -> Option<Value> {
    // Binary plists can reuse encoded objects. Bound the expanded tree as
    // well as the file, and limit the nesting of the recursive value builder.
    let mut budget = MAX_MANIFEST as usize * 2;
    let mut depth = 0usize;
    let mut events = Vec::new();
    for event in Reader::new(Cursor::new(data)) {
        let event = event.ok()?;
        let size = match &event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                depth += 1;
                (depth <= 24).then_some(0)?
            }
            Event::EndCollection => {
                depth = depth.checked_sub(1)?;
                0
            }
            Event::String(value) => value.len(),
            Event::Data(value) => value.len(),
            _ => 0,
        };
        budget = budget.checked_sub(size.checked_add(32)?)?;
        events.push(event);
    }
    if depth != 0 {
        return None;
    }
    let mut events = events.into_iter().map(Ok);
    let result = Value::from_events(&mut events).ok()?;
    events.next().is_none().then_some(result)
}

fn resolve(
    proc: &Proc,
    name: &str,
    services: &str,
    installed: bool,
) -> Result<Option<(String, Configuration)>, i64> {
    let files = proc.vfs.files().ok_or_else(missing)?;
    let Ok(entries) = files.children(services) else {
        return Ok(None);
    };
    let mut match_found = None;
    for (bundle, entry) in entries {
        if !bundle.ends_with(".xpc") || !entry.is_dir() {
            continue;
        }
        let contents = format!("{services}/{bundle}/Contents");
        let manifest = format!("{contents}/Info.plist");
        let Ok((canonical, entry)) = files.lookup(&manifest) else {
            continue;
        };
        if canonical != manifest
            || entry.len() > MAX_MANIFEST
            || (installed && !files.is_installed_entry(&entry))
        {
            continue;
        }
        let Some(manifest) = entry.bytes().ok().and_then(|bytes| read_manifest(&bytes)) else {
            continue;
        };
        let Some(manifest) = manifest.as_dictionary() else {
            continue;
        };
        if manifest
            .get("CFBundleIdentifier")
            .and_then(Value::as_string)
            != Some(name)
            || manifest
                .get("CFBundlePackageType")
                .and_then(Value::as_string)
                != Some("XPC!")
        {
            continue;
        }
        let executable = manifest
            .get("CFBundleExecutable")
            .and_then(Value::as_string)
            .filter(|path| component(path))
            .ok_or_else(missing)?;
        let properties = manifest
            .get("XPCService")
            .and_then(Value::as_dictionary)
            .ok_or_else(missing)?;
        let invalid = i64::from(Errno::EINVAL.0);
        let string_property = |name| {
            properties
                .get(name)
                .map(|value| value.as_string().ok_or(invalid))
                .transpose()
        };
        let service_type = string_property("ServiceType")?.unwrap_or("Application");
        let run_loop = string_property("RunLoopType")?;
        let join_session = properties
            .get("JoinExistingSession")
            .map(|value| value.as_boolean().ok_or(invalid))
            .transpose()?
            .unwrap_or(false);
        let valid_run_loop = matches!(run_loop, None | Some("dispatch_main" | "NSRunLoop"))
            || (installed && run_loop == Some("_NSApplicationMain"));
        if service_type != "Application" || !valid_run_loop || match_found.is_some() {
            return Err(i64::from(Errno::ENOTSUP.0));
        }
        let mut env: Vec<Vec<u8>> = proc
            .config
            .envp
            .iter()
            .filter(|value| !value.starts_with(b"XPC_"))
            .cloned()
            .collect();
        if let Some(variables) = properties.get("EnvironmentVariables") {
            for (key, value) in variables.as_dictionary().ok_or(invalid)? {
                let value = value.as_string().ok_or(invalid)?;
                if key.is_empty()
                    || key.contains(['=', '\0'])
                    || key.starts_with("XPC_")
                    || value.contains('\0')
                {
                    return Err(invalid);
                }
                env.retain(|item| item.split(|&byte| byte == b'=').next() != Some(key.as_bytes()));
                env.push(format!("{key}={value}").into_bytes());
            }
        }
        env.push(format!("XPC_SERVICE_NAME={name}").into_bytes());
        env.push(b"XPC_FLAGS=0x0".to_vec());
        // Keep the loader's initial vectors inside the same bound as exec.
        let environment_bytes: usize = env.iter().map(|value| value.len() + 9).sum();
        if environment_bytes > 128 << 10 {
            return Err(i64::from(Errno::E2BIG.0));
        }
        let executable = format!("{contents}/MacOS/{executable}");
        if installed
            && !files.lookup(&executable).is_ok_and(|(path, entry)| {
                path == executable && files.is_installed_entry(&entry) && !entry.is_dir()
            })
        {
            continue;
        }
        match_found = Some((
            executable,
            Configuration {
                service_type: service_type.to_owned(),
                run_loop: run_loop.map(str::to_owned),
                env,
                join_session,
            },
        ));
    }
    Ok(match_found)
}

fn open_origin(proc: &Proc) -> Option<&str> {
    app_root(&proc.config.exec_path).or_else(|| {
        proc.config.native_kernel_info.as_ref()?;
        let (parent, name) = proc.config.exec_path.rsplit_once('/')?;
        component(name).then_some(if parent.is_empty() { "/" } else { parent })
    })
}

fn remember_frameworks(
    proc: &Proc,
    frameworks: &mut BTreeSet<String>,
    paths: &[&str],
) -> Result<(), i64> {
    if proc.config.native_kernel_info.is_none() {
        return Ok(());
    }
    let selected: BTreeSet<_> = paths
        .iter()
        .filter_map(|path| crate::user::darwin::runtime_files::framework_service_directory(path))
        .filter(|path| !frameworks.contains(path))
        .collect();
    let bytes: usize = frameworks
        .iter()
        .chain(&selected)
        .map(|path| path.len())
        .sum();
    if frameworks.len() + selected.len() > MAX_DOMAIN_PATHS || bytes > MAX_DOMAIN_BYTES {
        return Err(i64::from(Errno::E2BIG.0));
    }
    frameworks.extend(selected);
    Ok(())
}

impl Services {
    fn reply(&mut self, proc: &Proc, request: &Request<'_>) -> Result<Reply, i64> {
        match request {
            Request::Open { origin, paths } => {
                if proc.config.native_kernel_info.is_none() && self.current(proc.pid).is_some() {
                    return Ok(Reply::Empty);
                }
                let root = open_origin(proc).ok_or_else(missing)?;
                if origin.is_some_and(|path| !path.is_empty() && path != root) {
                    return Err(i64::from(Errno::EINVAL.0));
                }
                remember_frameworks(proc, self.domains.entry(proc.pid).or_default(), paths)?;
                Ok(Reply::Empty)
            }
            Request::Scan(paths) => {
                let frameworks = self.domains.get_mut(&proc.pid).ok_or_else(missing)?;
                if proc.config.native_kernel_info.is_none()
                    && paths.as_slice() != [proc.config.exec_path.as_str()]
                {
                    return Err(i64::from(Errno::ENOTSUP.0));
                }
                remember_frameworks(proc, frameworks, paths)?;
                Ok(Reply::Scan)
            }
            Request::Resume
                if self.domains.contains_key(&proc.pid) || self.current(proc.pid).is_some() =>
            {
                Ok(Reply::Empty)
            }
            Request::LookUp(name) if self.domains.contains_key(&proc.pid) => {
                let service = self
                    .running
                    .iter()
                    .find(|service| {
                        service.client == proc.pid
                            && service.name == *name
                            && !service.endpoint.is_dead()
                    })
                    .ok_or_else(missing)?;
                service.endpoint.state.lock().unwrap().srights += 1;
                Ok(Reply::Endpoint(
                    Right::Send(service.endpoint.clone()),
                    disp::MOVE_SEND,
                ))
            }
            Request::Info => {
                let service = self.current(proc.pid).ok_or_else(missing)?;
                Ok(Reply::Info {
                    name: service.name.clone(),
                    service_type: service.configuration.service_type.clone(),
                    run_loop: service.configuration.run_loop.clone(),
                })
            }
            Request::CheckIn(name) => {
                let service = self.current(proc.pid).ok_or_else(missing)?;
                if service.name != *name || service.checked_in || service.endpoint.is_dead() {
                    return Err(i64::from(Errno::EINVAL.0));
                }
                service.checked_in = true;
                Ok(Reply::Endpoint(
                    Right::Receive(service.endpoint.clone()),
                    disp::MOVE_RECEIVE,
                ))
            }
            _ => Err(missing()),
        }
    }

    fn current(&mut self, pid: i32) -> Option<&mut Service> {
        self.running.iter_mut().find(|service| service.pid == pid)
    }

    pub(super) fn remove(&mut self, owner: i32) -> Vec<(i32, Arc<Port>)> {
        self.domains.remove(&owner);
        self.running
            .extract_if(.., |service| {
                service.pid == owner || service.client == owner
            })
            .map(|service| (service.pid, service.endpoint))
            .collect()
    }
}

pub(super) fn service_reply(ctx: &mut Ctx<'_>, request: Request<'_>) -> Result<Reply, i64> {
    let family = ctx.proc.family.clone().ok_or_else(missing)?;
    let result = family.bootstrap(|namespace| namespace.xpc.reply(ctx.proc, &request));
    let (Err(SERVICE_NOT_FOUND), Request::LookUp(name)) = (&result, request) else {
        return result;
    };
    if name.len() > MAX_NAME_BYTES
        || !component(name)
        || !family.bootstrap(|namespace| namespace.xpc.domains.contains_key(&ctx.proc.pid))
    {
        return result;
    }
    let mut candidate = None;
    if let Some(app) = app_root(&ctx.proc.config.exec_path) {
        candidate = resolve(
            ctx.proc,
            name,
            &format!("{app}/Contents/XPCServices"),
            false,
        )?;
    }
    if candidate.is_none() {
        let frameworks = family
            .bootstrap(|namespace| namespace.xpc.domains.get(&ctx.proc.pid).cloned())
            .ok_or_else(missing)?;
        for framework in frameworks {
            if let Some(service) = resolve(ctx.proc, name, &framework, true)? {
                if candidate.replace(service).is_some() {
                    return Err(i64::from(Errno::ENOTSUP.0));
                }
            }
        }
    }
    let (executable, mut configuration) = candidate.ok_or_else(missing)?;
    let pid = crate::user::darwin::exec::spawn_bootstrap_service(
        ctx,
        &executable,
        std::mem::take(&mut configuration.env),
        configuration.join_session,
    )
    .map_err(|error| i64::from(error.0))?;
    let endpoint = Port::new(KObject::None);
    endpoint.state.lock().unwrap().guest_service = true;
    family.bootstrap(|namespace| {
        namespace.xpc.running.push(Service {
            client: ctx.proc.pid,
            pid,
            name: name.to_owned(),
            configuration,
            endpoint,
            checked_in: false,
        });
        namespace.xpc.reply(ctx.proc, &Request::LookUp(name))
    })
}

pub(super) fn remove_owner(proc: &mut Proc, cancelled: Vec<(i32, Arc<Port>)>) {
    if let Some(family) = proc.family.clone() {
        for (pid, endpoint) in cancelled {
            super::kmsg::destroy_receive(proc, &endpoint);
            if pid != proc.pid {
                let origin = Origin::process(proc.pid, proc.creds.0);
                let _ = family.send_signal(pid, SIGKILL, origin);
            }
        }
    }
}
