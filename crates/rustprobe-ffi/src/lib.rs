use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use rustprobe_attrib::{
    queue_owner_query_runtime, register_flow_owner_runtime, selection_summary, set_monitoring_selection,
    sync_installed_apps, take_pending_owner_queries_runtime,
};
use rustprobe_capture::{
    is_capture_running, packets_seen, set_output_root, start_capture_from_fd, stop_capture,
};
use rustprobe_core::{AppIdentity, AppSelectionMode, FlowKey, FlowOwnerResolution};

fn as_jboolean(value: bool) -> jboolean {
    if value {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

fn parse_jstring(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<String, String> {
    env.get_string(&value)
        .map(|string| string.into())
        .map_err(|err| format!("failed to read java string: {err}"))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeStartCapture(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    fd: jint,
) -> jboolean {
    match start_capture_from_fd(fd) {
        Ok(started) => as_jboolean(started),
        Err(err) => {
            println!("rustprobe-ffi: failed to start capture: {err}");
            JNI_FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeStopCapture(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    stop_capture();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeIsCaptureRunning(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    as_jboolean(is_capture_running())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativePacketsSeen(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    packets_seen() as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeSyncInstalledApps(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    apps_json: JString<'_>,
) -> jboolean {
    let json = match parse_jstring(&mut env, apps_json) {
        Ok(value) => value,
        Err(err) => {
            println!("rustprobe-ffi: {err}");
            return JNI_FALSE;
        }
    };

    let apps: Vec<AppIdentity> = match serde_json::from_str(&json) {
        Ok(apps) => apps,
        Err(err) => {
            println!("rustprobe-ffi: failed to parse installed apps json: {err}");
            return JNI_FALSE;
        }
    };

    match sync_installed_apps(apps) {
        Ok(()) => JNI_TRUE,
        Err(err) => {
            println!("rustprobe-ffi: failed to sync installed apps: {err}");
            JNI_FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeSetMonitoringSelection(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    selection_json: JString<'_>,
) -> jboolean {
    let json = match parse_jstring(&mut env, selection_json) {
        Ok(value) => value,
        Err(err) => {
            println!("rustprobe-ffi: {err}");
            return JNI_FALSE;
        }
    };

    let selection: AppSelectionMode = match serde_json::from_str(&json) {
        Ok(selection) => selection,
        Err(err) => {
            println!("rustprobe-ffi: failed to parse selection json: {err}");
            return JNI_FALSE;
        }
    };

    match set_monitoring_selection(selection) {
        Ok(()) => JNI_TRUE,
        Err(err) => {
            println!("rustprobe-ffi: failed to set monitoring selection: {err}");
            JNI_FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeSetOutputDirectory(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    output_dir: JString<'_>,
) -> jboolean {
    let path = match parse_jstring(&mut env, output_dir) {
        Ok(value) => value,
        Err(err) => {
            println!("rustprobe-ffi: {err}");
            return JNI_FALSE;
        }
    };

    set_output_root(path);
    JNI_TRUE
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeRegisterOwnerResolution(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    resolution_json: JString<'_>,
) -> jboolean {
    let json = match parse_jstring(&mut env, resolution_json) {
        Ok(value) => value,
        Err(err) => {
            println!("rustprobe-ffi: {err}");
            return JNI_FALSE;
        }
    };

    let resolution: FlowOwnerResolution = match serde_json::from_str(&json) {
        Ok(resolution) => resolution,
        Err(err) => {
            println!("rustprobe-ffi: failed to parse owner resolution json: {err}");
            return JNI_FALSE;
        }
    };

    match register_flow_owner_runtime(resolution.key, resolution.uid) {
        Ok(()) => JNI_TRUE,
        Err(err) => {
            println!("rustprobe-ffi: failed to register owner resolution: {err}");
            JNI_FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeSelectionSummary(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let summary = selection_summary();
    env.new_string(summary)
        .expect("failed to allocate selection summary string")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeTakePendingOwnerQueries(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    limit: jint,
) -> jstring {
    let queries = take_pending_owner_queries_runtime(limit.max(0) as usize).unwrap_or_default();
    let json = serde_json::to_string(&queries).unwrap_or_else(|_| "[]".into());
    env.new_string(json)
        .expect("failed to allocate pending owner queries string")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_rustprobe_app_RustBridge_nativeQueueOwnerQuery(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    query_json: JString<'_>,
) -> jboolean {
    let json = match parse_jstring(&mut env, query_json) {
        Ok(value) => value,
        Err(err) => {
            println!("rustprobe-ffi: {err}");
            return JNI_FALSE;
        }
    };

    let key: FlowKey = match serde_json::from_str(&json) {
        Ok(key) => key,
        Err(err) => {
            println!("rustprobe-ffi: failed to parse owner query key json: {err}");
            return JNI_FALSE;
        }
    };

    match queue_owner_query_runtime(key) {
        Ok(()) => JNI_TRUE,
        Err(err) => {
            println!("rustprobe-ffi: failed to queue owner query: {err}");
            JNI_FALSE
        }
    }
}
