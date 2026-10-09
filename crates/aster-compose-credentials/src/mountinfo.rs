use crate::{ComposeCredentialError, ComposeCredentialReason};

pub(crate) const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;

pub(crate) fn validate_read_only_mount(
    mountinfo: &[u8],
    target: &[u8],
) -> Result<(), ComposeCredentialError> {
    if mountinfo.len() > MAX_MOUNTINFO_BYTES {
        return Err(error(ComposeCredentialReason::TooLarge));
    }

    let mut matches = 0_u8;
    for line in mountinfo.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let (mountpoint, options) = parse_mountinfo_line(line)?;
        if mountpoint != target {
            continue;
        }
        matches = matches.checked_add(1).ok_or_else(invalid_mount)?;
        if matches != 1 || !has_option(options, b"ro") {
            return Err(invalid_mount());
        }
    }
    if matches == 1 {
        Ok(())
    } else {
        Err(invalid_mount())
    }
}

fn parse_mountinfo_line(line: &[u8]) -> Result<(Vec<u8>, &[u8]), ComposeCredentialError> {
    if line
        .iter()
        .any(|byte| byte.is_ascii_whitespace() && *byte != b' ')
    {
        return Err(invalid_mount());
    }
    let separator = line
        .windows(3)
        .position(|bytes| bytes == b" - ")
        .ok_or_else(invalid_mount)?;
    let left = line[..separator]
        .split(|byte| *byte == b' ')
        .collect::<Vec<_>>();
    let right = line[separator + 3..]
        .split(|byte| *byte == b' ')
        .collect::<Vec<_>>();
    if left.len() < 6
        || right.len() != 3
        || left.iter().chain(&right).any(|field| field.is_empty())
        || !is_positive_decimal(left[0])
        || !is_positive_decimal(left[1])
        || !is_device_number(left[2])
    {
        return Err(invalid_mount());
    }

    let root = decode_mount_field(left[3])?;
    let mountpoint = decode_mount_field(left[4])?;
    if !root.starts_with(b"/")
        || !mountpoint.starts_with(b"/")
        || !valid_options(left[5])
        || !left[6..].iter().all(valid_optional_field)
        || !valid_filesystem_type(right[0])
        || decode_mount_field(right[1])?.is_empty()
        || !valid_options(right[2])
    {
        return Err(invalid_mount());
    }
    Ok((mountpoint, left[5]))
}

fn is_positive_decimal(bytes: &[u8]) -> bool {
    parse_decimal(bytes).is_some_and(|value| value != 0)
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(10)?.checked_add(u64::from(
            byte.checked_sub(b'0').filter(|digit| *digit <= 9)?,
        ))
    })
}

fn is_device_number(bytes: &[u8]) -> bool {
    let mut fields = bytes.split(|byte| *byte == b':');
    let Some(major) = fields.next() else {
        return false;
    };
    let Some(minor) = fields.next() else {
        return false;
    };
    fields.next().is_none()
        && parse_decimal(major).is_some_and(|value| u32::try_from(value).is_ok())
        && parse_decimal(minor).is_some_and(|value| u32::try_from(value).is_ok())
}

fn valid_optional_field(field: &&[u8]) -> bool {
    if *field == b"unbindable" {
        return true;
    }
    [b"shared:".as_slice(), b"master:", b"propagate_from:"]
        .into_iter()
        .find_map(|prefix| field.strip_prefix(prefix))
        .is_some_and(is_positive_decimal)
}

fn valid_filesystem_type(field: &[u8]) -> bool {
    !field.is_empty()
        && field
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_options(field: &[u8]) -> bool {
    !field.is_empty()
        && field
            .split(|byte| *byte == b',')
            .all(|option| !option.is_empty())
}

fn decode_mount_field(encoded: &[u8]) -> Result<Vec<u8>, ComposeCredentialError> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        let escape = encoded
            .get(index + 1..index + 4)
            .ok_or_else(invalid_mount)?;
        let byte = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(invalid_mount()),
        };
        decoded.push(byte);
        index += 4;
    }
    Ok(decoded)
}

fn has_option(options: &[u8], expected: &[u8]) -> bool {
    options
        .split(|byte| *byte == b',')
        .any(|option| option == expected)
}

const fn error(reason: ComposeCredentialReason) -> ComposeCredentialError {
    ComposeCredentialError::new(reason)
}

const fn invalid_mount() -> ComposeCredentialError {
    error(ComposeCredentialReason::InvalidMountBoundary)
}
