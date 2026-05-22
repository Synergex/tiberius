//! Optional smoke tests for the new RPC helpers against a real SQL Server
//! instance. Gated on `TIBERIUS_TEST_CONNECTION_STRING` — tests are marked
//! `#[ignore]` so a CI that forgets to set the env var sees "skipped"
//! rather than a silent "0 passed".

use futures_util::stream::TryStreamExt;
use std::env;
use tiberius::{Client, Config, CursorOpenOptions, Fetch, QueryItem};
use tokio_util::compat::TokioAsyncWriteCompatExt;

fn conn_str() -> String {
    env::var("TIBERIUS_TEST_CONNECTION_STRING")
        .expect("TIBERIUS_TEST_CONNECTION_STRING must be set (use `cargo test -- --ignored`)")
}

async fn connect() -> tiberius::Result<Client<tokio_util::compat::Compat<tokio::net::TcpStream>>> {
    let config = Config::from_ado_string(&conn_str())?;
    let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;
    Client::connect(config, tcp.compat_write()).await
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prepare_execute_unprepare() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let stmt = client
        .prepare("SELECT @P1 + @P2 AS s", "@P1 int, @P2 int")
        .await?;
    let first_handle = stmt.handle();

    for (a, b, expected) in [(1i32, 2i32, 3i32), (10, 20, 30), (-5, 5, 0)] {
        let row = stmt
            .query(&mut client, &[&a, &b])
            .await?
            .into_row()
            .await?
            .unwrap();
        assert_eq!(row.get::<i32, _>(0), Some(expected));
    }

    // Handle must be stable across executes — catches server-side slot-reuse bugs.
    assert_eq!(stmt.handle(), first_handle);

    stmt.unprepare(&mut client).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prep_exec_returns_handle_and_rows() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let (stmt, results) = client
        .prep_exec("SELECT @P1 AS v", "@P1 int", &[&42i32])
        .await?;
    let first_handle = stmt.handle();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].len(), 1);
    assert_eq!(results[0][0].get::<i32, _>(0), Some(42));

    // Reuse the handle.
    let row = stmt
        .query(&mut client, &[&99i32])
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), Some(99));
    assert_eq!(stmt.handle(), first_handle);

    stmt.unprepare(&mut client).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_open_fetch_close_cursor() -> tiberius::Result<()> {
    let mut client = connect().await?;

    let cursor = client
        .open_cursor(
            "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
            CursorOpenOptions::default(),
            "",
            &[],
        )
        .await?;

    let mut all = Vec::new();
    loop {
        let mut stream = cursor.fetch(&mut client, Fetch::Next { count: 10 }).await?;
        let mut got_any = false;
        while let Some(item) = stream.try_next().await? {
            if let QueryItem::Row(row) = item {
                got_any = true;
                all.push(row.get::<i32, _>(0).unwrap());
            }
        }
        if !got_any {
            break;
        }
    }
    assert_eq!(all, vec![1, 2, 3]);

    cursor.close(&mut client).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TIBERIUS_TEST_CONNECTION_STRING; run with --ignored"]
async fn live_prepared_across_table() -> tiberius::Result<()> {
    let mut client = connect().await?;

    // Use a temp table to exercise something more lifelike.
    client
        .simple_query(
            "IF OBJECT_ID('tempdb..##tiberius_rpc_helpers_live', 'U') IS NOT NULL \
             DROP TABLE ##tiberius_rpc_helpers_live; \
             CREATE TABLE ##tiberius_rpc_helpers_live (id int, name nvarchar(50))",
        )
        .await?
        .into_results()
        .await?;

    let insert = client
        .prepare(
            "INSERT INTO ##tiberius_rpc_helpers_live (id, name) VALUES (@P1, @P2)",
            "@P1 int, @P2 nvarchar(50)",
        )
        .await?;
    for (id, name) in [(1, "alpha"), (2, "beta"), (3, "gamma")] {
        insert.execute(&mut client, &[&id, &name]).await?;
    }
    insert.unprepare(&mut client).await?;

    let select = client
        .prepare(
            "SELECT id, name FROM ##tiberius_rpc_helpers_live WHERE id >= @P1 ORDER BY id",
            "@P1 int",
        )
        .await?;
    let rows = select
        .query(&mut client, &[&2i32])
        .await?
        .into_first_result()
        .await?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<i32, _>(0), Some(2));
    assert_eq!(rows[0].get::<&str, _>(1), Some("beta"));
    assert_eq!(rows[1].get::<i32, _>(0), Some(3));
    assert_eq!(rows[1].get::<&str, _>(1), Some("gamma"));
    select.unprepare(&mut client).await?;

    client
        .simple_query("DROP TABLE ##tiberius_rpc_helpers_live")
        .await?
        .into_results()
        .await?;
    Ok(())
}
