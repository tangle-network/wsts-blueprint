use crate::keygen::KeygenError;

pub fn validate_parameters(n: u32, k: u32, t: u32) -> Result<(), KeygenError> {
    if k % n != 0 {
        return Err(KeygenError::SetupError(format!("k({k}) % n({n}) != 0")));
    }

    if k == 0 {
        return Err(KeygenError::SetupError(format!("k({k}) == 0")));
    }

    if n <= t {
        return Err(KeygenError::SetupError(format!("n({n}) <= t({t})")));
    }

    Ok(())
}

/// Returns a Vec of indices that denotes which indexes within the public key vector
/// are owned by which party.
///
/// E.g., if n=4 and k=10,
///
/// let party_key_ids: Vec<Vec<u32>> = [
///     [0, 1, 2].to_vec(),
///     [3, 4].to_vec(),
///     [5, 6, 7].to_vec(),
///     [8, 9].to_vec(),
/// ]
///
/// In the above case, we go up from 0..=9 possible key ids since k=10, and
/// we have 4 grouping since n=4. We need to generalize this below
pub fn generate_party_key_ids(n: u32, k: u32) -> Vec<Vec<u32>> {
    let mut result = Vec::with_capacity(n as usize);
    let ids_per_party = k / n;
    let mut start = 0;

    for _ in 0..n {
        let end = start + ids_per_party;
        let ids = (start..end).collect();
        result.push(ids);
        start = end;
    }

    result
}
