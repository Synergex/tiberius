//! Builder pattern for configuring authentication.

use std::sync::Arc;

use crate::EncryptionLevel;

use super::env_provider::DefaultEnvChangeProvider;
use super::handler::TdsAuthHandler;
use super::traits::{EnvChangeProvider, FedAuthValidator, SqlAuthSource, SspiAcceptor};

/// Builder for composing authentication methods.
#[derive(Debug)]
pub struct AuthBuilder<P = DefaultEnvChangeProvider> {
    pub(super) env_provider: P,
    pub(super) encryption: EncryptionLevel,
    pub(super) sql_auth: Option<Arc<dyn SqlAuthSource>>,
    pub(super) sspi: Option<Arc<dyn SspiAcceptor>>,
    pub(super) fed_auth: Option<Arc<dyn FedAuthValidator>>,
    pub(super) allow_trust: bool,
}

impl Default for AuthBuilder<DefaultEnvChangeProvider> {
    fn default() -> Self {
        Self {
            env_provider: DefaultEnvChangeProvider::default(),
            encryption: EncryptionLevel::NotSupported,
            sql_auth: None,
            sspi: None,
            fed_auth: None,
            allow_trust: false,
        }
    }
}

impl<P> AuthBuilder<P>
where
    P: EnvChangeProvider + 'static,
{
    pub fn new(env_provider: P) -> Self {
        Self {
            env_provider,
            encryption: EncryptionLevel::NotSupported,
            sql_auth: None,
            sspi: None,
            fed_auth: None,
            allow_trust: false,
        }
    }

    pub fn encryption(mut self, encryption: EncryptionLevel) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn with_sql_auth(mut self, auth: Arc<dyn SqlAuthSource>) -> Self {
        self.sql_auth = Some(auth);
        self
    }

    pub fn with_sspi(mut self, acceptor: Arc<dyn SspiAcceptor>) -> Self {
        self.sspi = Some(acceptor);
        self
    }

    pub fn with_fed_auth(mut self, validator: Arc<dyn FedAuthValidator>) -> Self {
        self.fed_auth = Some(validator);
        self
    }

    pub fn allow_trust(mut self) -> Self {
        self.allow_trust = true;
        self
    }

    pub fn build(self) -> TdsAuthHandler<P> {
        TdsAuthHandler::from_builder(self)
    }
}
