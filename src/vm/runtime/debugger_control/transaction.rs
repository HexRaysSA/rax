//! Compensate even a setter that mutates before returning an error.
pub(super) fn all_cpus<E: std::fmt::Display>(
    count: usize,
    insert: bool,
    mut apply: impl FnMut(usize, bool) -> Result<(), E>,
) -> Result<bool, String> {
    for index in 0..count {
        if let Err(original) = apply(index, insert) {
            let mut failures = Vec::new();
            for prior in (0..=index).rev() {
                if let Err(error) = apply(prior, !insert) {
                    failures.push(format!("CPU {prior}: {error}"));
                }
            }
            if failures.is_empty() {
                return Ok(false);
            }
            return Err(format!(
                "breakpoint setter failed ({original}); rollback failed ({}); CPU entry excluded",
                failures.join(", ")
            ));
        }
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_mutating_failure_is_compensated_including_the_failing_cpu() {
        for failure in 0..4 {
            let mut states = [false; 4];
            let result = all_cpus(4, true, |index, value| {
                states[index] = value;
                if value && index == failure {
                    Err("after mutation")
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Ok(false));
            assert_eq!(states, [false; 4]);
        }
    }
    #[test]
    fn failed_compensation_is_terminal_instead_of_a_recoverable_rejection() {
        let result = all_cpus(4, true, |index, value| {
            if (value && index == 2) || (!value && index == 1) {
                Err("SDK failure")
            } else {
                Ok(())
            }
        });
        assert!(result.unwrap_err().contains("CPU entry excluded"));
    }
    #[test]
    fn complete_publication_visits_every_cpu() {
        let mut states = [false; 4];
        assert_eq!(
            all_cpus(4, true, |index, value| {
                states[index] = value;
                Ok::<_, &str>(())
            }),
            Ok(true)
        );
        assert_eq!(states, [true; 4]);
    }
}
