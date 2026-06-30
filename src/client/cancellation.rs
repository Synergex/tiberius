use futures_util::task::AtomicWaker;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};

/// Shared cancellation state behind a [`CancellationToken`] and its
/// [`Connection`](crate::client::Connection).
///
/// Carries both the request flag and a waker so that [`CancellationToken::cancel`]
/// can wake a task parked in I/O — without the waker, a cancel issued while the
/// read loop is blocked on a packet-less statement (e.g. `WAITFOR DELAY`) would
/// never be observed until the statement completed on its own.
#[derive(Debug)]
pub(crate) struct CancellationState {
    requested: AtomicBool,
    waker: AtomicWaker,
}

impl CancellationState {
    pub(crate) fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    /// Returns `true` if cancellation has been requested.
    pub(crate) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// Clears the cancellation request flag.
    pub(crate) fn clear(&self) {
        self.requested.store(false, Ordering::Release);
    }

    /// Registers the current task to be woken when cancellation is requested.
    pub(crate) fn register_waker(&self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

/// A future that resolves once cancellation has been requested on the shared
/// [`CancellationState`], registering the current task's waker so a pending
/// read can be woken the instant [`CancellationToken::cancel`] is called.
///
/// Used to race a blocking token-byte read against cancellation; see
/// [`Connection::read_u8_or_cancel`](crate::client::Connection::read_u8_or_cancel).
pub(crate) struct CancelSignal(Arc<CancellationState>);

impl CancelSignal {
    pub(crate) fn new(state: Arc<CancellationState>) -> Self {
        Self(state)
    }
}

impl Future for CancelSignal {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.is_requested() {
            return Poll::Ready(());
        }

        self.0.register_waker(cx);

        // Re-check after registering to close the race where cancellation was
        // requested between the first check and the waker registration.
        if self.0.is_requested() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

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
    state: Arc<CancellationState>,
}

impl CancellationToken {
    pub(crate) fn new(state: Arc<CancellationState>) -> Self {
        Self { state }
    }

    /// Request cancellation of the current operation.
    ///
    /// This is a non-blocking call that sets an internal flag and wakes the
    /// task driving the associated stream, so a TDS attention signal is sent
    /// to the server promptly — even if that task is currently parked waiting
    /// for server output (as happens for a packet-less statement such as
    /// `WAITFOR DELAY`).
    pub fn cancel(&self) {
        self.state.requested.store(true, Ordering::Release);
        self.state.waker.wake();
    }

    /// Returns `true` if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.state.is_requested()
    }
}
