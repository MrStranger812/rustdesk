use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/share/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/share/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()   
    } 
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
