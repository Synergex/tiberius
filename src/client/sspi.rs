//! Integrated authentication: the security-token exchange inside LOGIN7.

use crate::tds::codec::Encode;
use bytes::BytesMut;

/// One side of a multi-leg security exchange. `step` receives the server's
/// last token, or `None` to start, and returns the next token to send; an
/// empty token means there is nothing to send.
pub(crate) trait SspiClient {
    fn step(&mut self, input: Option<&[u8]>) -> crate::Result<Vec<u8>>;
}

/// An SSPI message body is the raw token, sized by the packet header.
pub(crate) struct SspiMessage(pub(crate) Vec<u8>);

impl Encode<BytesMut> for SspiMessage {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.extend_from_slice(&self.0);
        Ok(())
    }
}

#[cfg(all(windows, feature = "winauth"))]
pub(crate) use negotiate::Negotiate;

#[cfg(all(windows, feature = "winauth"))]
mod negotiate {
    use super::SspiClient;
    use std::{io, ptr, slice};
    use windows_sys::core::HRESULT;
    use windows_sys::Win32::Foundation::{
        SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED,
    };
    use windows_sys::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer,
        FreeCredentialsHandle, InitializeSecurityContextW, SecBuffer, SecBufferDesc,
        ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_CONNECTION, ISC_REQ_DELEGATE,
        ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH, ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT,
        NEGOSSP_NAME_W, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND,
        SECURITY_NATIVE_DREP,
    };
    use windows_sys::Win32::Security::Credentials::SecHandle;

    const FLAGS: u32 = ISC_REQ_ALLOCATE_MEMORY
        | ISC_REQ_CONFIDENTIALITY
        | ISC_REQ_CONNECTION
        | ISC_REQ_DELEGATE
        | ISC_REQ_INTEGRITY
        | ISC_REQ_MUTUAL_AUTH
        | ISC_REQ_REPLAY_DETECT
        | ISC_REQ_SEQUENCE_DETECT;

    /// SSPI's Negotiate package for the process identity: Kerberos when the
    /// SPN resolves to the server's account, otherwise NTLM.
    pub(crate) struct Negotiate {
        credentials: SecHandle,
        context: Option<SecHandle>,
        spn: Vec<u16>,
    }

    impl Negotiate {
        pub(crate) fn new(spn: &str) -> crate::Result<Self> {
            let mut credentials = SecHandle::default();
            let mut expiry = 0;
            let status = unsafe {
                AcquireCredentialsHandleW(
                    ptr::null(),
                    NEGOSSP_NAME_W,
                    SECPKG_CRED_OUTBOUND,
                    ptr::null(),
                    ptr::null(),
                    None,
                    ptr::null(),
                    &mut credentials,
                    &mut expiry,
                )
            };
            check(status)?;
            Ok(Self {
                credentials,
                context: None,
                spn: spn.encode_utf16().chain(Some(0)).collect(),
            })
        }
    }

    impl SspiClient for Negotiate {
        fn step(&mut self, input: Option<&[u8]>) -> crate::Result<Vec<u8>> {
            let mut in_buffer = SecBuffer {
                cbBuffer: input.map_or(0, |input| input.len() as u32),
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: input.map_or(ptr::null_mut(), |input| input.as_ptr() as *mut _),
            };
            let in_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut in_buffer,
            };
            let mut out_buffer = SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            };
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut out_buffer,
            };
            let mut context = self.context.unwrap_or_default();
            let mut attributes = 0;
            let mut expiry = 0;
            let mut status = unsafe {
                InitializeSecurityContextW(
                    &self.credentials,
                    self.context
                        .as_ref()
                        .map_or(ptr::null(), |context| context as *const _),
                    self.spn.as_ptr(),
                    FLAGS,
                    0,
                    SECURITY_NATIVE_DREP,
                    if input.is_some() {
                        &in_desc
                    } else {
                        ptr::null()
                    },
                    0,
                    &mut context,
                    &mut out_desc,
                    &mut attributes,
                    &mut expiry,
                )
            };
            if status >= 0 {
                self.context = Some(context);
                if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
                    status = unsafe { CompleteAuthToken(&context, &out_desc) };
                }
            }
            let token = if out_buffer.pvBuffer.is_null() {
                Vec::new()
            } else {
                let token = unsafe {
                    slice::from_raw_parts(
                        out_buffer.pvBuffer as *const u8,
                        out_buffer.cbBuffer as usize,
                    )
                }
                .to_vec();
                unsafe { FreeContextBuffer(out_buffer.pvBuffer) };
                token
            };
            match status {
                SEC_E_OK | SEC_I_CONTINUE_NEEDED => Ok(token),
                error => Err(io::Error::from_raw_os_error(error).into()),
            }
        }
    }

    impl Drop for Negotiate {
        fn drop(&mut self) {
            unsafe {
                if let Some(context) = &self.context {
                    DeleteSecurityContext(context);
                }
                FreeCredentialsHandle(&self.credentials);
            }
        }
    }

    fn check(status: HRESULT) -> crate::Result<()> {
        match status {
            SEC_E_OK => Ok(()),
            error => Err(io::Error::from_raw_os_error(error).into()),
        }
    }
}
