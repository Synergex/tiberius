//! Authentication trait definitions.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::tds::codec::{TokenEnvChange, TokenFedAuthInfo, TokenFeatureExtAck, TokenLoginAck};
use crate::LoginMessage;

use super::error::{AuthResult, AuthSuccess};
use super::login_info::LoginInfo;
use crate::server::handler::TdsConnectionContext;

/// Validate SQL Server username/password authentication.
#[async_trait]
pub trait SqlAuthSource: Send + Sync + Debug {
    async fn authenticate(&self, login: &LoginInfo, password: &str) -> AuthResult<AuthSuccess>;
}

/// Validate FedAuth/AAD bearer tokens.
#[async_trait]
pub trait FedAuthValidator: Send + Sync + Debug {
    async fn validate(&self, login: &LoginInfo, token: &str) -> AuthResult<AuthSuccess>;
}

/// A single SSPI step response.
#[derive(Debug)]
pub struct SspiStep {
    pub response: Option<Vec<u8>>,
    pub complete: bool,
    pub session_user: Option<String>,
}

/// A stateful SSPI session for integrated authentication.
pub trait SspiSession: Send {
    fn step(&mut self, token: &[u8]) -> AuthResult<SspiStep>;
}

/// Result of initializing an SSPI session.
pub struct SspiStart {
    pub step: SspiStep,
    pub session: Option<Box<dyn SspiSession>>,
}

/// SSPI acceptor used to start integrated authentication.
pub trait SspiAcceptor: Send + Sync + Debug {
    fn start(&self, login: &LoginInfo, token: &[u8]) -> AuthResult<SspiStart>;
}

/// Supplies login ack and initial envchange tokens.
pub trait EnvChangeProvider: Send + Sync + Debug {
    fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck;

    fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
    where
        C: TdsConnectionContext;

    fn feature_ext_ack(&self, _login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
        None
    }

    fn fed_auth_info<C>(&self, _client: &C, _login: &LoginMessage<'_>) -> Option<TokenFedAuthInfo>
    where
        C: TdsConnectionContext,
    {
        None
    }
}
