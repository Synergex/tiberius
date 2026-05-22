//! Login information extraction from LOGIN7 packets.

use std::net::SocketAddr;

use crate::server::handler::TdsConnectionContext;
use crate::tds::codec::FeatureLevel;
use crate::LoginMessage;

/// Authenticated login context derived from a LOGIN7 packet.
#[derive(Debug, Clone)]
pub struct LoginInfo {
    user: Option<String>,
    database: Option<String>,
    application: Option<String>,
    server: Option<String>,
    hostname: Option<String>,
    client_addr: SocketAddr,
    tds_version: FeatureLevel,
}

impl LoginInfo {
    pub fn from_login<C>(client: &C, login: &LoginMessage<'_>) -> Self
    where
        C: TdsConnectionContext,
    {
        let user = login.user_name_ref().trim();
        let database = login.db_name_ref().trim();
        let application = login.app_name_ref().trim();
        let server = login.server_name_ref().trim();
        let hostname = login.hostname_ref().trim();

        Self {
            user: if user.is_empty() { None } else { Some(user.to_string()) },
            database: if database.is_empty() {
                None
            } else {
                Some(database.to_string())
            },
            application: if application.is_empty() {
                None
            } else {
                Some(application.to_string())
            },
            server: if server.is_empty() {
                None
            } else {
                Some(server.to_string())
            },
            hostname: if hostname.is_empty() {
                None
            } else {
                Some(hostname.to_string())
            },
            client_addr: client.socket_addr(),
            tds_version: login.tds_version(),
        }
    }

    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    pub fn application(&self) -> Option<&str> {
        self.application.as_deref()
    }

    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    pub fn tds_version(&self) -> FeatureLevel {
        self.tds_version
    }

    pub(super) fn apply_metadata<C>(&self, client: &mut C, session_user: Option<&str>)
    where
        C: TdsConnectionContext,
    {
        let metadata = client.connection_metadata_mut();
        metadata.user = session_user.or(self.user()).map(|s| s.to_string());
        metadata.database = self.database().map(|s| s.to_string());
        metadata.application = self.application().map(|s| s.to_string());
        metadata.server = self.server().map(|s| s.to_string());
        metadata.hostname = self.hostname().map(|s| s.to_string());
    }
}
