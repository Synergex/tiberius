//! Default environment change provider implementation.

use crate::server::handler::TdsConnectionContext;
use crate::tds::codec::{
    FeatureAck, FedAuthAck, TokenEnvChange, TokenFeatureExtAck, TokenLoginAck,
};
use crate::{Collation, LoginMessage};

use super::traits::EnvChangeProvider;

/// Default login token provider (LoginAck + EnvChange + Done).
#[derive(Debug, Clone)]
pub struct DefaultEnvChangeProvider {
    pub program_name: String,
    pub server_version: u32,
    pub collation: Collation,
    pub default_database: String,
}

impl Default for DefaultEnvChangeProvider {
    fn default() -> Self {
        Self {
            program_name: "tiberius".to_string(),
            server_version: 0,
            collation: Collation::new(13632521, 52),
            default_database: "master".to_string(),
        }
    }
}

impl DefaultEnvChangeProvider {
    pub fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck {
        TokenLoginAck::new(1, login.tds_version(), &self.program_name, self.server_version)
    }

    pub fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
    where
        C: TdsConnectionContext,
    {
        let db_name = login.db_name_ref().trim();
        let db_name = if db_name.is_empty() {
            self.default_database.as_str()
        } else {
            db_name
        };

        vec![
            TokenEnvChange::Database(db_name.to_string(), String::new()),
            TokenEnvChange::PacketSize(login.packet_size(), client.packet_size()),
            TokenEnvChange::SqlCollation {
                old: None,
                new: Some(self.collation),
            },
        ]
    }

    pub fn feature_ext_ack(&self, login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
        if login.has_feature_ext() {
            let mut features = Vec::new();
            if login.fed_auth_token().is_some() {
                features.push(FeatureAck::FedAuth(FedAuthAck::SecurityToken {
                    nonce: login.fed_auth_nonce(),
                }));
            }

            Some(TokenFeatureExtAck { features })
        } else {
            None
        }
    }
}

impl EnvChangeProvider for DefaultEnvChangeProvider {
    fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck {
        self.login_ack(login)
    }

    fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
    where
        C: TdsConnectionContext,
    {
        self.env_changes(client, login)
    }

    fn feature_ext_ack(&self, login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
        self.feature_ext_ack(login)
    }
}
