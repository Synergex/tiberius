use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// A handle to cancel an in-flight query from another task.
///
/// Obtained via [`Client::cancellation_token()`]. The token is `Clone` and
/// `Send + Sync`, so it can be shared across tasks freely.
///
/// Calling [`cancel()`](Self::cancel) causes the active [`QueryStream`] to
/// terminate cleanly at its next poll point by sending a TDS attention signal
/// to the server. After the stream ends, the connection is ready for new
/// queries with no manual cleanup required.
///
/// [`Client::cancellation_token()`]: crate::Client::cancellation_token
/// [`QueryStream`]: crate::QueryStream
///
/// # Example
///
/// ```no_run
/// # use tiberius::Config;
/// # use tokio_util::compat::TokioAsyncWriteCompatExt;
/// # use futures_util::stream::TryStreamExt;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let config = Config::new();
/// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
/// # tcp.set_nodelay(true)?;
/// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
/// let token = client.cancellation_token();
///
/// let mut stream = client.query("SELECT * FROM large_table", &[]).await?;
///
/// // In another task or after some condition:
/// token.cancel();
///
/// // The stream will terminate at the next poll:
/// while let Some(_item) = stream.try_next().await? {
///     // loop ends shortly after cancel() is called
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub(crate) fn new(flag: Arc<AtomicBool>) -> Self {
        Self { flag }
    }

    /// Request cancellation of the current operation.
    ///
    /// This is a non-blocking call that sets an internal flag. The actual
    /// attention signal is sent to the server the next time the associated
    /// stream is polled.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Returns `true` if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}
