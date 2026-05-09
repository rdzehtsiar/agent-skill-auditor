// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use thiserror::Error;

pub type AuditResult<T> = Result<T, AuditError>;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to walk {path}: {source}")]
    Walk {
        path: PathBuf,
        #[source]
        source: ignore::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse frontmatter in {path}: {source}")]
    Frontmatter {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
}
