//! GSSAPI/Kerberos authentication support.

use super::error::{AuthError, AuthResult};
use super::login_info::LoginInfo;
use super::traits::{SspiAcceptor, SspiSession, SspiStart, SspiStep};

use libgssapi::context::{SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::oid::{OidSet, GSS_MECH_KRB5};

#[derive(Debug, Default)]
pub struct GssapiAcceptor;

impl GssapiAcceptor {
    pub fn new() -> Self {
        Self
    }
}

impl SspiAcceptor for GssapiAcceptor {
    fn start(&self, _login: &LoginInfo, token: &[u8]) -> AuthResult<SspiStart> {
        let mut mechs = OidSet::new().map_err(|err| AuthError {
            code: 18456,
            state: 1,
            class: 14,
            message: format!("SSPI: {err}"),
        })?;
        mechs.add(&GSS_MECH_KRB5).map_err(|err| AuthError {
            code: 18456,
            state: 1,
            class: 14,
            message: format!("SSPI: {err}"),
        })?;

        let cred = Cred::acquire(None, None, CredUsage::Accept, Some(&mechs)).map_err(|err| {
            AuthError {
                code: 18456,
                state: 1,
                class: 14,
                message: format!("SSPI: {err}"),
            }
        })?;

        let mut ctx = ServerCtx::new(Some(cred));
        let response = ctx.step(token).map_err(|err| AuthError {
            code: 18456,
            state: 1,
            class: 14,
            message: format!("SSPI: {err}"),
        })?;

        let complete = ctx.is_complete();
        let session_user = if complete {
            ctx.source_name()
                .ok()
                .map(|name| name.to_string())
        } else {
            None
        };

        let step = SspiStep {
            response: response.map(|buf| buf.to_vec()),
            complete,
            session_user,
        };

        let session = if complete {
            None
        } else {
            Some(Box::new(GssapiSession { ctx }) as Box<dyn SspiSession>)
        };

        Ok(SspiStart { step, session })
    }
}

#[derive(Debug)]
struct GssapiSession {
    ctx: ServerCtx,
}

impl SspiSession for GssapiSession {
    fn step(&mut self, token: &[u8]) -> AuthResult<SspiStep> {
        let response = self.ctx.step(token).map_err(|err| AuthError {
            code: 18456,
            state: 1,
            class: 14,
            message: format!("SSPI: {err}"),
        })?;
        let complete = self.ctx.is_complete();
        let session_user = if complete {
            self.ctx
                .source_name()
                .ok()
                .map(|name| name.to_string())
        } else {
            None
        };

        Ok(SspiStep {
            response: response.map(|buf| buf.to_vec()),
            complete,
            session_user,
        })
    }
}
