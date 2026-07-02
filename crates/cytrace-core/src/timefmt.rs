//! 時間戳格式化（純函式、零依賴）。CLI 與 server（ADR-011 job 記錄）共用。

use std::time::{SystemTime, UNIX_EPOCH};

/// 目前的 Unix epoch 秒（時鐘異常時回 0，確定性優先於 panic）。
pub fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix epoch 秒 → ISO-8601 UTC 字串（純函式、零依賴；civil-from-days 演算法）。
pub fn epoch_to_iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant 的 civil_from_days（自 1970-01-01 起的天數）
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_to_iso_formats_utc() {
        assert_eq!(epoch_to_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso(1_609_459_200), "2021-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso(1_782_295_451), "2026-06-24T10:04:11Z");
    }
}
