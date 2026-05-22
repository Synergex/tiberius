//! TdsAuthHandler implementation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use futures_util::sink::SinkExt;

use crate::server::handler::{AuthHandler, TdsClient};
use crate::server::messages::{BackendToken, TdsBackendMessage};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{DoneStatus, TokenDone};
use crate::{EncryptionLevel, LoginMessage, Result};

use super::builder::AuthBuilder;
use super::env_provider::DefaultEnvChangeProvider;
use super::error::AuthError;
use super::login_info::LoginInfo;
use super::traits::{EnvChangeProvider, FedAuthValidator, SqlAuthSource, SspiAcceptor, SspiSession, SspiStep};

/// Maximum number of concurrent pending SSPI authentication sessions.
const MAX_PENDING_SSPI_SESSIONS: usize = 1000;

/// Maximum age for pending SSPI sessions before cleanup (in seconds).
const SSPI_SESSION_TTL_SECS: u64 = 60;

struct AuthSession {
    login: LoginMessage<'static>,
    info: LoginInfo,
    sspi: Box<dyn SspiSession>,
    created_at: Instant,
}

/// Auth handler that multiplexes SQL auth, SSPI, and FedAuth flows.
pub struct TdsAuthHandler<P = DefaultEnvChangeProvider> {
    env_provider: P,
    encryption: EncryptionLevel,
    sql_auth: Option<Arc<dyn SqlAuthSource>>,
    sspi: Option<Arc<dyn SspiAcceptor>>,
    fed_auth: Option<Arc<dyn FedAuthValidator>>,
    allow_trust: bool,
    sessions: Mutex<HashMap<SocketAddr, AuthSession>>,
}

impl<P> TdsAuthHandler<P>
where
    P: EnvChangeProvider + 'static,
{
    pub(super) fn from_builder(builder: AuthBuilder<P>) -> Self {
        Self {
            env_provider: builder.env_provider,
            encryption: builder.encryption,
            sql_auth: builder.sql_auth,
            sspi: builder.sspi,
            fed_auth: builder.fed_auth,
            allow_trust: builder.allow_trust,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Acquire the sessions lock, recovering from poison if needed.
    ///
    /// If the mutex is poisoned (another thread panicked while holding it),
    /// we recover the data and continue. SSPI session data is transient
    /// so this is safe.
    fn lock_sessions(&self) -> MutexGuard<'_, HashMap<SocketAddr, AuthSession>> {
        self.sessions.lock().unwrap_or_else(|poisoned| {
            // Mutex was poisoned - another thread panicked while holding it.
            // Recover and continue since SSPI sessions are transient.
            poisoned.into_inner()
        })
    }

    async fn finish_login<C>(
        &self,
        client: &mut C,
        login: &LoginMessage<'_>,
        info: &LoginInfo,
        session_user: Option<&str>,
    ) -> Result<()>
    where
        C: TdsClient,
    {
        client.set_tds_version(login.tds_version());
        info.apply_metadata(client, session_user);

        let mut tokens = Vec::new();
        tokens.push(BackendToken::LoginAck(self.env_provider.login_ack(login)));
        if let Some(feature) = self.env_provider.feature_ext_ack(login) {
            tokens.push(BackendToken::FeatureExtAck(feature));
        }
        if let Some(fed_auth) = self.env_provider.fed_auth_info(client, login) {
            tokens.push(BackendToken::FedAuthInfo(fed_auth));
        }
        for env in self.env_provider.env_changes(client, login) {
            tokens.push(BackendToken::EnvChange(env));
        }
        tokens.push(BackendToken::Done(TokenDone::default()));

        client.send(TdsBackendMessage::Tokens(tokens)).await?;
        client.set_packet_size(login.packet_size());
        client.set_state(TdsConnectionState::ReadyForQuery);
        Ok(())
    }

    async fn send_login_error<C>(
        &self,
        client: &mut C,
        login: Option<&LoginInfo>,
        err: AuthError,
    ) -> Result<()>
    where
        C: TdsClient,
    {
        let server = login
            .and_then(|info| info.server())
            .map(|s| s.to_string())
            .unwrap_or_else(|| client.socket_addr().ip().to_string());
        let token = crate::TokenError::new(
            err.code,
            err.state,
            err.class,
            err.message,
            server,
            "",
            1,
        );
        let done = TokenDone::with_status(DoneStatus::Error.into(), 0);

        client
            .send(TdsBackendMessage::Tokens(vec![
                BackendToken::Error(token),
                BackendToken::Done(done),
            ]))
            .await?;

        client.set_state(TdsConnectionState::Closed);
        Ok(())
    }

    async fn handle_sspi_step<C>(
        &self,
        client: &mut C,
        login: &LoginMessage<'_>,
        info: &LoginInfo,
        step: SspiStep,
    ) -> Result<()>
    where
        C: TdsClient,
    {
        if let Some(response) = step.response {
            client
                .send(TdsBackendMessage::Token(BackendToken::Sspi(
                    crate::tds::codec::TokenSspi::from_bytes(response),
                )))
                .await?;
        } else if !step.complete {
            client
                .send(TdsBackendMessage::Token(BackendToken::Sspi(
                    crate::tds::codec::TokenSspi::from_bytes(Vec::new()),
                )))
                .await?;
        }

        if step.complete {
            self.finish_login(client, login, info, step.session_user.as_deref())
                .await?;
        } else {
            client.set_state(TdsConnectionState::AuthenticationInProgress);
        }

        Ok(())
    }
}

fn negotiate_encryption(
    server_policy: EncryptionLevel,
    client_request: EncryptionLevel,
) -> EncryptionLevel {
    match server_policy {
        EncryptionLevel::NotSupported => EncryptionLevel::NotSupported,
        EncryptionLevel::Required => EncryptionLevel::Required,
        EncryptionLevel::On => match client_request {
            EncryptionLevel::Required | EncryptionLevel::On => EncryptionLevel::On,
            EncryptionLevel::Off => EncryptionLevel::Off,
            EncryptionLevel::NotSupported => EncryptionLevel::NotSupported,
        },
        EncryptionLevel::Off => match client_request {
            EncryptionLevel::NotSupported => EncryptionLevel::NotSupported,
            _ => EncryptionLevel::Off,
        },
    }
}

impl<P> AuthHandler for TdsAuthHandler<P>
where
    P: EnvChangeProvider + 'static,
{
    fn on_prelogin<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::tds::codec::PreloginMessage,
    ) -> crate::server::handler::BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let mut reply = crate::tds::codec::PreloginMessage::new();
            let negotiated = negotiate_encryption(self.encryption, message.encryption);
            reply.encryption = negotiated;
            reply.instance_name = None;
            reply.version = message.version;
            reply.sub_build = message.sub_build;
            reply.thread_id = 0;
            reply.fed_auth_required = message.fed_auth_required && self.fed_auth.is_some();
            reply.nonce = None;

            let prelogin_packet = match reply.encryption {
                EncryptionLevel::Off | EncryptionLevel::NotSupported => "tabular",
                _ => "prelogin",
            };
            client
                .connection_metadata_mut()
                .custom
                .insert("prelogin_packet_type".into(), prelogin_packet.into());

            client.set_encryption(reply.encryption);
            client.send(TdsBackendMessage::Prelogin(reply)).await?;
            client.set_state(TdsConnectionState::AwaitingLogin);
            Ok(())
        })
    }

    fn on_login<'a, C>(
        &'a self,
        client: &'a mut C,
        message: LoginMessage<'static>,
    ) -> crate::server::handler::BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let info = LoginInfo::from_login(client, &message);
            client.set_tds_version(message.tds_version());

            if let Some(token) = message.fed_auth_token() {
                let Some(validator) = self.fed_auth.as_ref() else {
                    return self
                        .send_login_error(
                            client,
                            Some(&info),
                            AuthError::login_failed(info.user()),
                        )
                        .await;
                };

                match validator.validate(&info, token).await {
                    Ok(success) => {
                        return self
                            .finish_login(
                                client,
                                &message,
                                &info,
                                success.session_user.as_deref(),
                            )
                            .await;
                    }
                    Err(err) => {
                        return self.send_login_error(client, Some(&info), err).await;
                    }
                }
            }

            if let Some(initial) = message.integrated_security_bytes() {
                let Some(acceptor) = self.sspi.as_ref() else {
                    return self
                        .send_login_error(
                            client,
                            Some(&info),
                            AuthError::login_failed(info.user()),
                        )
                        .await;
                };

                match acceptor.start(&info, initial) {
                    Ok(start) => {
                        if let Some(session) = start.session {
                            // Hold lock through cleanup + insertion to avoid TOCTOU race
                            let mut sessions = self.lock_sessions();

                            // Cleanup expired sessions within the same lock
                            let now = Instant::now();
                            let ttl = std::time::Duration::from_secs(SSPI_SESSION_TTL_SECS);
                            sessions.retain(|_addr, s| now.duration_since(s.created_at) < ttl);

                            // Enforce limit within same lock
                            while sessions.len() >= MAX_PENDING_SSPI_SESSIONS {
                                let oldest = sessions
                                    .iter()
                                    .min_by_key(|(_, s)| s.created_at)
                                    .map(|(addr, _)| *addr);
                                if let Some(addr) = oldest {
                                    sessions.remove(&addr);
                                } else {
                                    break;
                                }
                            }

                            sessions.insert(
                                client.socket_addr(),
                                AuthSession {
                                    login: message.clone(),
                                    info: info.clone(),
                                    sspi: session,
                                    created_at: now,
                                },
                            );
                        }

                        return self
                            .handle_sspi_step(client, &message, &info, start.step)
                            .await;
                    }
                    Err(err) => {
                        return self.send_login_error(client, Some(&info), err).await;
                    }
                }
            }

            if let Some(sql_auth) = self.sql_auth.as_ref() {
                let password = message.password_ref();
                match sql_auth.authenticate(&info, password).await {
                    Ok(success) => {
                        return self
                            .finish_login(
                                client,
                                &message,
                                &info,
                                success.session_user.as_deref(),
                            )
                            .await;
                    }
                    Err(err) => {
                        return self.send_login_error(client, Some(&info), err).await;
                    }
                }
            }

            if self.allow_trust {
                return self.finish_login(client, &message, &info, info.user()).await;
            }

            self.send_login_error(client, Some(&info), AuthError::login_failed(info.user()))
                .await
        })
    }

    fn on_sspi<'a, C>(
        &'a self,
        client: &'a mut C,
        token: crate::tds::codec::TokenSspi,
    ) -> crate::server::handler::BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let addr = client.socket_addr();
            let session = {
                let mut sessions = self.lock_sessions();
                sessions.remove(&addr)
            };

            let Some(mut session) = session else {
                return self
                    .send_login_error(
                        client,
                        None,
                        AuthError::login_failed(None),
                    )
                    .await;
            };

            let step = match session.sspi.step(token.as_ref()) {
                Ok(step) => step,
                Err(err) => {
                    return self.send_login_error(client, Some(&session.info), err).await;
                }
            };

            let login = session.login.clone();
            let info = session.info.clone();

            if !step.complete {
                // Re-insert session for next SSPI step (keeps original created_at)
                let mut sessions = self.lock_sessions();
                sessions.insert(addr, session);
            }

            self.handle_sspi_step(client, &login, &info, step)
                .await
        })
    }
}
