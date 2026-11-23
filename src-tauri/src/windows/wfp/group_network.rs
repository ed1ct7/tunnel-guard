use super::*;
use crate::process_groups::NetworkState;
use sha2::{Digest, Sha256};

const LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];
/// Top weight, like the kill switch, so no third-party sublayer outranks the
/// block. Blocks created by earlier versions keep their old weight.
const WEIGHT: u16 = u16::MAX;
const LEGACY_WEIGHT: u16 = 0xe100;

fn group_owner(id: &str) -> Result<[u8; 32]> {
    let storage = settings::storage_path()?;
    let mut hash = Sha256::new();
    hash.update(b"TunnelGuard group network v1\0");
    hash.update(storage.to_string_lossy().to_lowercase().as_bytes());
    hash.update(b"\0");
    hash.update(id.as_bytes());
    Ok(hash.finalize().into())
}

fn key(owner: &[u8; 32], index: u64) -> GUID {
    let mut hash = Sha256::new();
    hash.update(owner);
    hash.update(index.to_le_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    GUID::from_u128(u128::from_be_bytes(bytes))
}

fn filters(owner: &[u8; 32], paths: usize) -> impl Iterator<Item = (usize, GUID, GUID)> + '_ {
    (0..paths).flat_map(move |app| {
        LAYERS.into_iter().enumerate().map(move |(index, layer)| {
            let filter = key(owner, 1 + (app * LAYERS.len() + index) as u64);
            (app, layer, filter)
        })
    })
}

fn stored_paths(layer: &FWPM_SUBLAYER0) -> Result<Vec<String>> {
    let data = layer.providerData;
    if data.size == 0 || data.data.is_null() {
        return Err("Отсутствует список приложений заблокированной группы.".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(data.data, data.size as usize) };
    let paths: Vec<String> = serde_json::from_slice(bytes)
        .map_err(|_| "Не удалось прочитать список приложений заблокированной группы.")?;
    if paths.is_empty() {
        return Err("Список приложений заблокированной группы пуст.".into());
    }
    Ok(paths)
}

fn state(engine: &Engine, owner: &[u8; 32]) -> Result<NetworkState> {
    let layer_key = key(owner, 0);
    let Some(layer) = engine.sublayer(&layer_key)? else {
        return Ok(NetworkState::Off);
    };
    let layer = layer.get();
    let Ok(paths) = stored_paths(layer) else {
        return Ok(NetworkState::Partial);
    };
    let Ok(apps) = paths
        .iter()
        .map(|path| {
            let path = Path::new(path);
            if !path.is_file() {
                return Err("Указанный файл приложения больше не существует.".to_string());
            }
            application_id(path)
        })
        .collect::<Result<Vec<_>>>()
    else {
        return Ok(NetworkState::Partial);
    };
    if layer.flags & FWPM_SUBLAYER_FLAG_PERSISTENT == 0
        || (layer.weight != WEIGHT && layer.weight != LEGACY_WEIGHT)
    {
        return Ok(NetworkState::Partial);
    }
    for (app, expected_layer, filter) in filters(owner, paths.len()) {
        let Some(filter) = engine.filter(&filter)? else {
            return Ok(NetworkState::Partial);
        };
        let filter = filter.get();
        if filter.flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_DISABLED)
            != FWPM_FILTER_FLAG_PERSISTENT
            || filter.action.r#type != FWP_ACTION_BLOCK
            || !same_guid(filter.layerKey, expected_layer)
            || !same_guid(filter.subLayerKey, layer_key)
            || filter.numFilterConditions != 1
            || filter.filterCondition.is_null()
        {
            return Ok(NetworkState::Partial);
        }
        let condition = unsafe { &*filter.filterCondition };
        if !same_guid(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID)
            || condition.matchType != FWP_MATCH_EQUAL
            || condition.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
        {
            return Ok(NetworkState::Partial);
        }
        let Some(actual) = (unsafe { condition.conditionValue.Anonymous.byteBlob.as_ref() }) else {
            return Ok(NetworkState::Partial);
        };
        let expected = apps[app].get();
        if actual.data.is_null()
            || expected.data.is_null()
            || actual.size != expected.size
            || (unsafe {
                std::slice::from_raw_parts(actual.data, actual.size as usize)
                    != std::slice::from_raw_parts(expected.data, expected.size as usize)
            })
        {
            return Ok(NetworkState::Partial);
        }
    }
    Ok(NetworkState::Blocked)
}

pub(crate) fn status(id: &str) -> Result<NetworkState> {
    state(&Engine::open()?, &group_owner(id)?)
}

fn stage(engine: &Engine, owner: &[u8; 32], paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Err("Добавь хотя бы один полный путь к приложению.".into());
    }
    let apps: Vec<_> = paths
        .iter()
        .map(|path| application_id(Path::new(path)))
        .collect::<Result<_>>()?;
    let security = ObjectSecurity::new()?;
    let mut data = serde_json::to_vec(paths).map_err(|error| error.to_string())?;
    let mut name = wide(OsStr::new("Tunnel Guard – network block for process group"));
    let layer_key = key(owner, 0);
    let layer = FWPM_SUBLAYER0 {
        subLayerKey: layer_key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerData: FWP_BYTE_BLOB {
            size: u32::try_from(data.len()).map_err(|_| "Слишком большой список путей.")?,
            data: data.as_mut_ptr(),
        },
        weight: WEIGHT,
        ..Default::default()
    };
    check(
        unsafe { FwpmSubLayerAdd0(engine.0, &layer, security.0) },
        "создание блокировки группы",
    )?;

    for (app, layer, filter_key) in filters(owner, apps.len()) {
        let mut condition = condition(
            FWPM_CONDITION_ALE_APP_ID,
            FWP_MATCH_EQUAL,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 {
                byteBlob: apps[app].0.as_ptr(),
            },
        );
        let filter = FWPM_FILTER0 {
            filterKey: filter_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            layerKey: layer,
            subLayerKey: layer_key,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            numFilterConditions: 1,
            filterCondition: &mut condition,
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            ..Default::default()
        };
        check(
            unsafe { FwpmFilterAdd0(engine.0, &filter, security.0, null_mut()) },
            "блокировка приложения",
        )?;
    }
    Ok(())
}

pub(crate) fn block(id: &str, paths: &[String]) -> Result<()> {
    let owner = group_owner(id)?;
    let engine = Engine::open()?;
    let transaction = engine.write()?;
    match state(&engine, &owner)? {
        NetworkState::Blocked => {
            let layer = engine
                .sublayer(&key(&owner, 0))?
                .ok_or("Блокировка изменилась.")?;
            if stored_paths(layer.get())? == paths {
                return Ok(());
            }
            return Err("Сначала верни сети этой группе доступ.".into());
        }
        NetworkState::Partial => {
            return Err("Сначала сними частично применённую блокировку.".into())
        }
        NetworkState::Off => {}
    }
    stage(&engine, &owner, paths)?;
    if state(&engine, &owner)? != NetworkState::Blocked {
        return Err("Не удалось подтвердить фильтры группы.".into());
    }
    transaction.commit()
}

pub(crate) fn unblock(id: &str) -> Result<()> {
    let owner = group_owner(id)?;
    let engine = Engine::open()?;
    let transaction = engine.write()?;
    let layer_key = key(&owner, 0);
    let Some(layer) = engine.sublayer(&layer_key)? else {
        return Ok(());
    };
    let paths = stored_paths(layer.get())?;
    for (_, _, filter) in filters(&owner, paths.len()) {
        let code = unsafe { FwpmFilterDeleteByKey0(engine.0, &filter) };
        if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code, "удаление фильтра приложения")?;
        }
    }
    check(
        unsafe { FwpmSubLayerDeleteByKey0(engine.0, &layer_key) },
        "снятие блокировки группы",
    )?;
    transaction.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires administrator rights; staged filters are never committed"]
    fn windows_accepts_scoped_network_block_without_applying_it() {
        let engine = Engine::open().unwrap();
        let owner = group_owner("network_transaction_test").unwrap();
        assert_eq!(state(&engine, &owner).unwrap(), NetworkState::Off);
        let path = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        {
            let _transaction = engine.write().unwrap();
            stage(&engine, &owner, &[path]).unwrap();
            assert_eq!(state(&engine, &owner).unwrap(), NetworkState::Blocked);
        }
        assert_eq!(state(&engine, &owner).unwrap(), NetworkState::Off);
    }

    #[test]
    #[ignore = "requires administrator rights; only blocks the temporary test executable"]
    fn network_block_stops_local_tcp_and_can_be_removed() {
        use std::{
            net::{TcpListener, TcpStream},
            time::Duration,
        };
        let id = format!("loopback_fixture_{}", std::process::id());
        struct Cleanup<'a>(&'a str);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = unblock(self.0);
            }
        }
        let _cleanup = Cleanup(&id);
        let ipv4 = TcpListener::bind("127.0.0.1:0").unwrap();
        let ipv6 = TcpListener::bind("[::1]:0").unwrap();
        let endpoints = [ipv4.local_addr().unwrap(), ipv6.local_addr().unwrap()];
        let connect = |addr| TcpStream::connect_timeout(addr, Duration::from_millis(900));
        for address in &endpoints {
            assert!(connect(address).is_ok());
        }
        let path = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        block(&id, &[path]).unwrap();
        assert_eq!(status(&id).unwrap(), NetworkState::Blocked);
        for address in &endpoints {
            assert!(connect(address).is_err(), "blocked app reached {address}");
        }
        unblock(&id).unwrap();
        for address in &endpoints {
            assert!(connect(address).is_ok());
        }
    }
}
