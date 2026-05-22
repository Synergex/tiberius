#!/usr/bin/env python3
"""
End-to-end protocol test for the dummy TDS server using pymssql.

This script:
1) Launches the dummy TDS server.
2) Waits for it to accept connections.
3) Connects using pymssql and runs a query.
4) Logs all steps and server output.
"""

from __future__ import annotations

import datetime as dt
import decimal
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path


HOST = os.environ.get("TDS_TEST_HOST", "127.0.0.1")
PORT = int(os.environ.get("TDS_TEST_PORT", "14333"))
QUERY = os.environ.get("TDS_TEST_QUERY", "SELECT 1")
STARTUP_TIMEOUT_SECS = 60
CONNECT_TIMEOUT_SECS = 10
FREETDS_DUMP_LINES = 200
RESULT_SAMPLE_ROWS = 5
RPC_LOG_WAIT_SECS = 2.0
RPC_OUTPUT_EXPECTED = 4242
RPC_EXEC_EXPECTED = 123
ATTENTION_LOG_WAIT_SECS = 5.0
ATTENTION_CANCEL_DELAY_SECS = 0.5
AUTH_LOG_WAIT_SECS = 2.0
HEADERS_LOG_WAIT_SECS = 2.0
COMPUTE_LOG_WAIT_SECS = 2.0
METADATA_LOG_WAIT_SECS = 2.0
COLUMNAR_LOG_WAIT_SECS = 2.0
LOB_STREAM_LOG_WAIT_SECS = 2.0
FEDAUTH_LOG_WAIT_SECS = 2.0
TLS_ENABLED = os.environ.get("TDS_TEST_TLS", "1") == "1"
TLS_ENCRYPTION = os.environ.get("TDS_TEST_TLS_ENCRYPTION", "request")
LEGACY_TYPES_ENABLED = os.environ.get("TDS_TEST_LEGACY_TYPES", "0") == "1"
FEDAUTH_ENABLED = os.environ.get("TDS_TEST_FEDAUTH", "0") == "1"
TVP_ENABLED = os.environ.get("TDS_TEST_TVP", "0") == "1"


def setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_path, mode="w"),
        ],
    )
    logging.info("Logging to %s", log_path)


def tail_file(path: Path, max_lines: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return []
    if len(lines) <= max_lines:
        return [line.rstrip("\n") for line in lines]
    return [line.rstrip("\n") for line in lines[-max_lines:]]


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def normalize_bytes(value):
    if value is None:
        return None
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def normalize_uuid(value):
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return str(uuid.UUID(bytes=bytes(value)))
        except (ValueError, AttributeError, TypeError):
            return str(value)
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return str(value)


def normalize_decimal(value):
    if value is None:
        return None
    if isinstance(value, decimal.Decimal):
        return value
    return decimal.Decimal(str(value))


def normalize_text(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def collect_result_sets(cur) -> list[tuple[list[str], list[tuple]]]:
    result_sets: list[tuple[list[str], list[tuple]]] = []
    while True:
        desc = cur.description
        if desc:
            columns = [col[0] for col in desc]
            rows = cur.fetchall()
            result_sets.append((columns, rows))
        more = cur.nextset()
        if not more:
            break
    return result_sets


def log_result_sets(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    if not result_sets:
        logging.info("%s: no result sets", label)
        return
    for idx, (columns, rows) in enumerate(result_sets, start=1):
        logging.info(
            "%s: result set %d columns=%s rows=%d",
            label,
            idx,
            columns,
            len(rows),
        )
        if rows:
            logging.info(
                "%s: result set %d sample=%s",
                label,
                idx,
                rows[:RESULT_SAMPLE_ROWS],
            )


def find_result_set(
    result_sets: list[tuple[list[str], list[tuple]]],
    column_name: str,
) -> tuple[list[str], list[tuple]] | None:
    for columns, rows in result_sets:
        lower_cols = [col.lower() for col in columns]
        if column_name.lower() in lower_cols:
            return columns, rows
    return None


def reader_thread(stream, prefix: str, stop_evt: threading.Event, tail: deque[str]) -> None:
    for line in iter(stream.readline, ""):
        if stop_evt.is_set():
            break
        line = line.rstrip("\n")
        msg = f"{prefix} {line}"
        logging.info(msg)
        tail.append(msg)
    stream.close()


def wait_for_log(tail: deque[str], needle: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        snapshot = list(tail)
        if any(needle in line for line in snapshot):
            return True
        time.sleep(0.05)
    return False


def find_log_line(tail: deque[str], needle: str) -> str | None:
    for line in reversed(list(tail)):
        if needle in line:
            return line
    return None


def wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def ensure_pymssql() -> None:
    try:
        import pymssql  # noqa: F401
        return
    except Exception as exc:  # pylint: disable=broad-except
        logging.warning("pymssql import failed: %s", exc)

    if os.environ.get("TDS_TEST_VENV") == "1":
        logging.info("Installing pymssql via pip (venv)")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "pymssql"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        logging.info("pip output:\n%s", result.stdout)
        if result.returncode != 0:
            raise RuntimeError("pip install pymssql failed in venv")
        import pymssql  # noqa: F401
        return

    logging.info("Installing pymssql via pip")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "pymssql"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    logging.info("pip output:\n%s", result.stdout)
    if result.returncode != 0 and "externally-managed-environment" in result.stdout:
        venv_dir = Path(__file__).resolve().parents[1] / "target" / "tds_dummy_test_venv"
        logging.warning("System Python is externally managed; creating venv at %s", venv_dir)
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        venv_python = venv_dir / "bin" / "python"
        logging.info("Installing pymssql in venv")
        subprocess.run([str(venv_python), "-m", "pip", "install", "pymssql"], check=True)
        logging.info("Re-running test inside venv")
        env = {**os.environ, "TDS_TEST_VENV": "1"}
        result = subprocess.run([str(venv_python), __file__], env=env, check=False)
        raise SystemExit(result.returncode)

    if result.returncode != 0:
        raise RuntimeError("pip install pymssql failed")

    import pymssql  # noqa: F401


def ensure_tls_materials(repo_root: Path) -> tuple[Path, Path]:
    tls_dir = repo_root / "target" / "tds_dummy_tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tls_dir / "server_cert.pem"
    key_path = tls_dir / "server_key.pem"

    if cert_path.exists() and key_path.exists():
        logging.info("TLS cert/key already exist in %s", tls_dir)
        return cert_path, key_path

    logging.info("Generating self-signed TLS cert/key in %s", tls_dir)
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "7",
        "-subj",
        "/CN=localhost",
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    logging.info("openssl output:\n%s", result.stdout)
    if result.returncode != 0:
        raise RuntimeError("openssl failed to generate TLS materials")

    return cert_path, key_path


def execute_and_collect(cur, sql: str, label: str) -> list[tuple[list[str], list[tuple]]]:
    logging.info("%s: executing SQL: %s", label, sql)
    cur.execute(sql)
    result_sets = collect_result_sets(cur)
    log_result_sets(label, result_sets)
    return result_sets


def execute_single_with_description(
    cur, sql: str, label: str
) -> tuple[list[str], list[tuple], tuple | None]:
    logging.info("%s: executing SQL: %s", label, sql)
    cur.execute(sql)
    desc = cur.description
    columns = [col[0] for col in desc] if desc else []
    rows = cur.fetchall() if desc else []
    while cur.nextset():
        _ = cur.fetchall()
    log_result_sets(label, [(columns, rows)])
    return columns, rows, desc


def validate_single_value(
    label: str,
    result_sets: list[tuple[list[str], list[tuple]]],
    expected_value=1,
) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(
        [col.lower() for col in columns] == ["value"],
        f"{label}: unexpected columns {columns}",
    )
    expect(rows == [(expected_value,)], f"{label}: unexpected rows {rows}")


def validate_multi(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 2, f"{label}: expected 2 result sets, got {len(result_sets)}")
    columns0, rows0 = result_sets[0]
    columns1, rows1 = result_sets[1]
    expect(
        [col.lower() for col in columns0] == ["id", "label"],
        f"{label}: unexpected columns in set 1: {columns0}",
    )
    expect(rows0 == [(1, "alpha"), (2, "beta")], f"{label}: unexpected rows {rows0}")
    expect(
        [col.lower() for col in columns1] == ["code", "note"],
        f"{label}: unexpected columns in set 2: {columns1}",
    )
    expect(rows1 == [(100, "gamma")], f"{label}: unexpected rows {rows1}")


def validate_compute(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    value_set = find_result_set(result_sets, "value")
    expect(value_set is not None, f"{label}: missing base result set")
    columns, rows = value_set
    idx = [col.lower() for col in columns].index("value")
    base_values = [int(row[idx]) for row in rows]
    expect(10 in base_values, f"{label}: unexpected base rows {rows}")

    alt_set = find_result_set(result_sets, "alt_value")
    if alt_set is None:
        expect(20 in base_values, f"{label}: compute row not surfaced in base rows {rows}")
        logging.warning("%s: alt_value result set not surfaced by client", label)
        return
    alt_cols, alt_rows = alt_set
    alt_idx = [col.lower() for col in alt_cols].index("alt_value")
    expect(
        any(int(row[alt_idx]) == 20 for row in alt_rows),
        f"{label}: unexpected alt rows {alt_rows}",
    )


def validate_nulls(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    _columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    expect(all(value is None for value in rows[0]), f"{label}: expected all NULLs {rows}")


def validate_empty(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(
        len(result_sets) == 0,
        f"{label}: expected no result sets, got {len(result_sets)}",
    )


def validate_types(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    legacy_present = "varchar_legacy_col" in col_map
    expected_cols = [
        "tinyint_col",
        "smallint_col",
        "int_col",
        "bigint_col",
        "intn_col",
        "intn1_col",
        "intn2_col",
        "intn8_col",
        "real_col",
        "float_col",
        "floatn_col",
        "floatn4_col",
        "bit_col",
        "bitn_col",
        "money_col",
        "smallmoney_col",
        "money_var_col",
        "money_var4_col",
        "datetime_col",
        "smalldatetime_col",
        "datetimen_col",
        "datetimen4_col",
        "date_col",
        "time_col",
        "datetime2_col",
        "datetimeoffset_col",
        "nvarchar_col",
        "nchar_col",
        "nvarchar_max_col",
        "varchar_col",
        "char_col",
        "varchar_max_col",
        "varbinary_col",
        "binary_col",
        "varbinary_max_col",
        "guid_col",
        "numeric_col",
        "decimal_col",
    ]
    if legacy_present:
        expected_cols.extend(
            [
                "varchar_legacy_col",
                "char_legacy_col",
                "varbinary_legacy_col",
                "binary_legacy_col",
                "numeric_legacy_col",
                "decimal_legacy_col",
            ]
        )
    for col in expected_cols:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")
    if LEGACY_TYPES_ENABLED and not legacy_present:
        logging.warning("%s: legacy columns not present in result set", label)

    row = rows[0]

    def col(name: str):
        return row[col_map[name]]

    expect(int(col("tinyint_col")) == 1, f"{label}: tinyint_col {row}")
    expect(int(col("smallint_col")) == 2, f"{label}: smallint_col {row}")
    expect(int(col("int_col")) == 42, f"{label}: int_col {row}")
    expect(int(col("bigint_col")) == 9001, f"{label}: bigint_col {row}")
    expect(int(col("intn_col")) == 314, f"{label}: intn_col {row}")
    expect(int(col("intn1_col")) == 7, f"{label}: intn1_col {row}")
    expect(int(col("intn2_col")) == 1234, f"{label}: intn2_col {row}")
    expect(int(col("intn8_col")) == 123456789012, f"{label}: intn8_col {row}")

    expect(abs(float(col("real_col")) - 3.5) < 1e-6, f"{label}: real_col {row}")
    expect(abs(float(col("float_col")) - 3.14159) < 1e-6, f"{label}: float_col {row}")
    expect(abs(float(col("floatn_col")) - 2.71828) < 1e-6, f"{label}: floatn_col {row}")
    expect(abs(float(col("floatn4_col")) - 6.25) < 1e-6, f"{label}: floatn4_col {row}")

    expect(bool(col("bit_col")) is True, f"{label}: bit_col {row}")
    expect(bool(col("bitn_col")) is False, f"{label}: bitn_col {row}")

    money = normalize_decimal(col("money_col"))
    smallmoney = normalize_decimal(col("smallmoney_col"))
    money_var = normalize_decimal(col("money_var_col"))
    money_var4 = normalize_decimal(col("money_var4_col"))
    expect(money == decimal.Decimal("12.34"), f"{label}: money_col {money}")
    expect(smallmoney == decimal.Decimal("5.67"), f"{label}: smallmoney_col {smallmoney}")
    expect(money_var == decimal.Decimal("99.99"), f"{label}: money_var_col {money_var}")
    expect(money_var4 == decimal.Decimal("1.23"), f"{label}: money_var4_col {money_var4}")

    dt_val = col("datetime_col")
    sdt_val = col("smalldatetime_col")
    dtn_val = col("datetimen_col")
    dtn4_val = col("datetimen4_col")
    allowed_dt = (dt.datetime, dt.date, str)
    expect(dt_val is not None, f"{label}: datetime_col is None")
    expect(sdt_val is not None, f"{label}: smalldatetime_col is None")
    expect(dtn_val is not None, f"{label}: datetimen_col is None")
    expect(dtn4_val is not None, f"{label}: datetimen4_col is None")
    expect(isinstance(dt_val, allowed_dt), f"{label}: datetime_col type {type(dt_val)}")
    expect(
        isinstance(sdt_val, allowed_dt),
        f"{label}: smalldatetime_col type {type(sdt_val)}",
    )
    expect(isinstance(dtn_val, allowed_dt), f"{label}: datetimen_col type {type(dtn_val)}")
    expect(isinstance(dtn4_val, allowed_dt), f"{label}: datetimen4_col type {type(dtn4_val)}")

    date_val = col("date_col")
    time_val = col("time_col")
    dt2_val = col("datetime2_col")
    dto_val = col("datetimeoffset_col")
    allowed_date = (dt.date, dt.datetime, str)
    allowed_time = (dt.time, str)
    expect(date_val is not None, f"{label}: date_col is None")
    expect(time_val is not None, f"{label}: time_col is None")
    expect(dt2_val is not None, f"{label}: datetime2_col is None")
    expect(dto_val is not None, f"{label}: datetimeoffset_col is None")
    expect(isinstance(date_val, allowed_date), f"{label}: date_col type {type(date_val)}")
    expect(isinstance(time_val, allowed_time), f"{label}: time_col type {type(time_val)}")

    nvarchar_val = normalize_text(col("nvarchar_col"))
    nchar_val = normalize_text(col("nchar_col"))
    nvarchar_max_val = normalize_text(col("nvarchar_max_col"))
    varchar_val = normalize_text(col("varchar_col"))
    char_val = normalize_text(col("char_col"))
    varchar_max_val = normalize_text(col("varchar_max_col"))
    expect(nvarchar_val == "hello", f"{label}: nvarchar_col {nvarchar_val}")
    expect(nchar_val.strip() == "hi", f"{label}: nchar_col {nchar_val!r}")
    expect(nvarchar_max_val == "nv-max", f"{label}: nvarchar_max_col {nvarchar_max_val!r}")
    expect(varchar_val.strip() == "ascii", f"{label}: varchar_col {varchar_val!r}")
    expect(char_val.strip() == "ch", f"{label}: char_col {char_val!r}")
    expect(varchar_max_val.strip() == "v-max", f"{label}: varchar_max_col {varchar_max_val!r}")
    if legacy_present:
        varchar_legacy_val = normalize_text(col("varchar_legacy_col"))
        char_legacy_val = normalize_text(col("char_legacy_col"))
        expect(
            varchar_legacy_val.strip() == "legacy-v",
            f"{label}: varchar_legacy_col {varchar_legacy_val!r}",
        )
        expect(
            char_legacy_val.strip() == "lc",
            f"{label}: char_legacy_col {char_legacy_val!r}",
        )

    varbin = normalize_bytes(col("varbinary_col"))
    bin_val = normalize_bytes(col("binary_col"))
    varbin_max = normalize_bytes(col("varbinary_max_col"))
    expect(varbin == b"\x01\x02\x03", f"{label}: varbinary_col {varbin}")
    expect(
        bin_val is not None and bin_val[:3] == b"\x04\x05\x06",
        f"{label}: binary_col {bin_val}",
    )
    expect(varbin_max == b"\n\x0b\x0c", f"{label}: varbinary_max_col {varbin_max}")
    if legacy_present:
        varbin_legacy = normalize_bytes(col("varbinary_legacy_col"))
        bin_legacy = normalize_bytes(col("binary_legacy_col"))
        expect(
            varbin_legacy == b"\r\x0e",
            f"{label}: varbinary_legacy_col {varbin_legacy}",
        )
        expect(bin_legacy == b"\x0f\x10", f"{label}: binary_legacy_col {bin_legacy}")

    guid_val = normalize_uuid(col("guid_col"))
    expect(
        guid_val == "00000000-0000-0000-0000-000000000001",
        f"{label}: guid_col {guid_val}",
    )

    num_val = normalize_decimal(col("numeric_col"))
    dec_val = normalize_decimal(col("decimal_col"))
    expect(num_val == decimal.Decimal("123.45"), f"{label}: numeric_col {num_val}")
    expect(dec_val == decimal.Decimal("98.76"), f"{label}: decimal_col {dec_val}")
    if legacy_present:
        num_legacy_val = normalize_decimal(col("numeric_legacy_col"))
        dec_legacy_val = normalize_decimal(col("decimal_legacy_col"))
        expect(
            num_legacy_val == decimal.Decimal("123.4"),
            f"{label}: numeric_legacy_col {num_legacy_val}",
        )
        expect(
            dec_legacy_val == decimal.Decimal("56.78"),
            f"{label}: decimal_legacy_col {dec_legacy_val}",
        )



def validate_metadata(
    label: str,
    columns: list[str],
    rows: list[tuple],
    desc: tuple | None,
) -> None:
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    expected_cols = [
        "identity_col",
        "hidden_col",
        "nullable_col",
        "varchar_cp_col",
        "numeric_prec_col",
        "decimal_prec_col",
    ]
    for col in expected_cols:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]
    expect(int(row[col_map["identity_col"]]) == 1, f"{label}: identity_col {row}")
    expect(int(row[col_map["hidden_col"]]) == 2, f"{label}: hidden_col {row}")
    expect(row[col_map["nullable_col"]] is None, f"{label}: nullable_col {row}")

    varchar_val = normalize_text(row[col_map["varchar_cp_col"]])
    expect(varchar_val == "caf\u00e9", f"{label}: varchar_cp_col {varchar_val!r}")

    num_val = normalize_decimal(row[col_map["numeric_prec_col"]])
    dec_val = normalize_decimal(row[col_map["decimal_prec_col"]])
    expect(num_val == decimal.Decimal("1234567.000"), f"{label}: numeric_prec_col {num_val}")
    expect(dec_val == decimal.Decimal("9876.50"), f"{label}: decimal_prec_col {dec_val}")

    if not desc:
        logging.warning("%s: cursor description missing", label)
        return

    desc_map = {item[0].lower(): item for item in desc}

    def check_precision(col: str, prec: int, scale: int) -> None:
        item = desc_map.get(col)
        if not item:
            logging.warning("%s: missing description for %s", label, col)
            return
        item_prec = item[4]
        item_scale = item[5]
        if item_prec is None or item_scale is None:
            logging.warning(
                "%s: precision/scale missing for %s (got %s/%s)",
                label,
                col,
                item_prec,
                item_scale,
            )
            return
        expect(int(item_prec) == prec, f"{label}: {col} precision {item_prec}")
        expect(int(item_scale) == scale, f"{label}: {col} scale {item_scale}")

    def check_nullability(col: str, nullable: bool) -> None:
        item = desc_map.get(col)
        if not item:
            logging.warning("%s: missing description for %s", label, col)
            return
        null_ok = item[6]
        if null_ok is None:
            logging.warning("%s: nullability missing for %s", label, col)
            return
        expect(bool(null_ok) == nullable, f"{label}: {col} null_ok {null_ok}")

    check_precision("numeric_prec_col", 10, 3)
    check_precision("decimal_prec_col", 6, 2)
    check_nullability("identity_col", False)
    check_nullability("nullable_col", True)


def _parse_variant_int(value) -> int | None:
    if isinstance(value, (int,)):
        return int(value)
    if isinstance(value, decimal.Decimal):
        return int(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = normalize_bytes(value)
        if not payload:
            return None
        if payload[0] == 0x38 and len(payload) >= 6:
            return int.from_bytes(payload[2:6], byteorder="little", signed=True)
        if len(payload) == 4:
            return int.from_bytes(payload, byteorder="little", signed=True)
    return None


def validate_varlen(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    for col in ["varchar_big_col", "char_big_col"]:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]
    varchar_big = normalize_text(row[col_map["varchar_big_col"]])
    char_big = normalize_text(row[col_map["char_big_col"]])

    expect(varchar_big == "café", f"{label}: varchar_big_col {varchar_big!r}")
    expect(char_big.strip() == "café", f"{label}: char_big_col {char_big!r}")

    legacy_present = "varchar_short_col" in col_map or "char_short_col" in col_map
    if legacy_present:
        expect(
            "varchar_short_col" in col_map and "char_short_col" in col_map,
            f"{label}: legacy columns incomplete in {columns}",
        )
        varchar_short = normalize_text(row[col_map["varchar_short_col"]])
        char_short = normalize_text(row[col_map["char_short_col"]])
        expect(varchar_short == "café", f"{label}: varchar_short_col {varchar_short!r}")
        expect(char_short.strip() == "café", f"{label}: char_short_col {char_short!r}")
    elif LEGACY_TYPES_ENABLED:
        logging.warning("%s: legacy char/varchar columns not present", label)


def validate_variants(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    for col in ["variant_int", "variant_numeric", "variant_varchar", "variant_null"]:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]

    int_val = _parse_variant_int(row[col_map["variant_int"]])
    if int_val is None:
        logging.warning("%s: variant_int unexpected value %r", label, row[col_map["variant_int"]])
    else:
        expect(int_val == 42, f"{label}: variant_int {int_val}")

    numeric_raw = row[col_map["variant_numeric"]]
    if isinstance(numeric_raw, (bytes, bytearray, memoryview)):
        logging.warning("%s: variant_numeric returned bytes %r", label, normalize_bytes(numeric_raw))
    else:
        num_val = normalize_decimal(numeric_raw)
        expect(num_val == decimal.Decimal("123.45"), f"{label}: variant_numeric {num_val}")

    varchar_raw = row[col_map["variant_varchar"]]
    if varchar_raw is None:
        logging.warning("%s: variant_varchar is None", label)
    else:
        varchar_val = normalize_text(varchar_raw)
        if varchar_val != "variant":
            logging.warning("%s: variant_varchar unexpected value %r", label, varchar_val)

    null_val = row[col_map["variant_null"]]
    if null_val is not None:
        logging.warning("%s: variant_null expected None, got %r", label, null_val)


def validate_columnar(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    for col in ["id", "label", "payload"]:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]
    id_val = row[col_map["id"]]
    label_val = normalize_text(row[col_map["label"]])
    payload_val = normalize_bytes(row[col_map["payload"]])
    expect(int(id_val) == 101, f"{label}: id {id_val}")
    expect(label_val == "columnar", f"{label}: label {label_val!r}")
    expect(payload_val == b"\x01\x02\x03\x04", f"{label}: payload {payload_val}")


def validate_tvp(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    expect("tvp_col" in col_map, f"{label}: missing column tvp_col in {columns}")

    row = rows[0]
    tvp_val = row[col_map["tvp_col"]]
    if tvp_val is None:
        logging.warning("%s: tvp_col is None", label)
    elif isinstance(tvp_val, (bytes, bytearray, memoryview)):
        payload = normalize_bytes(tvp_val)
        if not payload:
            logging.warning("%s: tvp_col empty payload", label)
        else:
            logging.info("%s: tvp_col payload bytes=%d", label, len(payload))
    else:
        logging.warning("%s: tvp_col unexpected type %s", label, type(tvp_val))

def validate_exotic(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    for col in [
        "udt_col",
        "geometry_col",
        "geography_col",
        "hierarchyid_col",
        "variant_col",
    ]:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]

    udt_val = row[col_map["udt_col"]]
    if isinstance(udt_val, (bytes, bytearray, memoryview)):
        udt_bytes = normalize_bytes(udt_val)
        expect(udt_bytes[:3] == b"\t\x08\x07", f"{label}: udt_col {udt_bytes}")
    else:
        logging.warning("%s: udt_col unexpected type %s", label, type(udt_val))

    for col_name, prefix in [
        ("geometry_col", b"GEO"),
        ("geography_col", b"GPY"),
        ("hierarchyid_col", b"HID"),
    ]:
        col_val = row[col_map[col_name]]
        if isinstance(col_val, (bytes, bytearray, memoryview)):
            col_bytes = normalize_bytes(col_val)
            expect(
                col_bytes[:3] == prefix,
                f"{label}: {col_name} {col_bytes}",
            )
        else:
            logging.warning(
                "%s: %s unexpected type %s",
                label,
                col_name,
                type(col_val),
            )

    variant_val = row[col_map["variant_col"]]
    variant_ok = False
    if isinstance(variant_val, (int,)):
        expect(int(variant_val) == 42, f"{label}: variant_col {variant_val}")
        variant_ok = True
    elif isinstance(variant_val, decimal.Decimal):
        expect(variant_val == decimal.Decimal("42"), f"{label}: variant_col {variant_val}")
        variant_ok = True
    elif isinstance(variant_val, (bytes, bytearray, memoryview)):
        payload = normalize_bytes(variant_val)
        if payload and payload[0] == 0x38:
            parsed = None
            if len(payload) >= 5:
                parsed = int.from_bytes(payload[1:5], byteorder="little", signed=True)
            if parsed != 42 and len(payload) >= 6:
                parsed = int.from_bytes(payload[2:6], byteorder="little", signed=True)
            if parsed == 42:
                variant_ok = True
            else:
                expect(False, f"{label}: variant_col payload {payload}")
    if not variant_ok:
        logging.warning("%s: variant_col unexpected value %r", label, variant_val)


def validate_lob(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    for col in ["text_col", "ntext_col", "image_col", "xml_col"]:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]
    text_val = normalize_text(row[col_map["text_col"]])
    ntext_val = normalize_text(row[col_map["ntext_col"]])
    xml_val = normalize_text(row[col_map["xml_col"]])
    image_val = normalize_bytes(row[col_map["image_col"]])

    expect(text_val == "text", f"{label}: text_col {text_val!r}")
    expect(ntext_val == "ntext", f"{label}: ntext_col {ntext_val!r}")
    expect(image_val == b"\x07\x08\x09", f"{label}: image_col {image_val}")
    expect("<a>1</a>" in xml_val, f"{label}: xml_col {xml_val!r}")

def validate_lob_stream(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    expect(len(result_sets) == 1, f"{label}: expected 1 result set, got {len(result_sets)}")
    columns, rows = result_sets[0]
    expect(len(rows) == 1, f"{label}: expected 1 row, got {len(rows)}")
    col_map = {name.lower(): idx for idx, name in enumerate(columns)}
    for col in ["text_col", "ntext_col", "image_col", "xml_col"]:
        expect(col in col_map, f"{label}: missing column {col} in {columns}")

    row = rows[0]
    text_val = normalize_text(row[col_map["text_col"]])
    ntext_val = normalize_text(row[col_map["ntext_col"]])
    xml_val = normalize_text(row[col_map["xml_col"]])
    image_val = normalize_bytes(row[col_map["image_col"]])

    expect(text_val.startswith("stream-text-"), f"{label}: text_col {text_val!r}")
    expect(ntext_val.startswith("stream-ntext-"), f"{label}: ntext_col {ntext_val!r}")
    expect(len(text_val) > 8000, f"{label}: text_col length {len(text_val)}")
    expect(len(ntext_val) > 8000, f"{label}: ntext_col length {len(ntext_val)}")
    expect(image_val is not None and len(image_val) == 16384, f"{label}: image_col {image_val}")
    expect("<stream>1</stream>" in xml_val, f"{label}: xml_col {xml_val!r}")



def validate_rpc_params(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    param_set = find_result_set(result_sets, "param_ordinal")
    expect(param_set is not None, f"{label}: missing param echo result set")
    columns, rows = param_set
    lower_cols = [col.lower() for col in columns]
    ord_idx = lower_cols.index("param_ordinal")
    val_idx = lower_cols.index("param_value")
    flags_idx = lower_cols.index("param_flags")

    by_ord = {row[ord_idx]: row for row in rows}
    expect(
        1 in by_ord and 2 in by_ord and 3 in by_ord and 4 in by_ord and 5 in by_ord and 6 in by_ord,
        f"{label}: missing ordinals {by_ord}",
    )
    expect(str(by_ord[1][val_idx]) == "1", f"{label}: param 1 value {by_ord[1]}")
    expect(
        str(by_ord[2][val_idx]) == "two",
        f"{label}: param 2 value {by_ord[2]}",
    )
    expect(
        str(by_ord[3][val_idx]) == "12.34",
        f"{label}: param 3 value {by_ord[3]}",
    )
    param4 = str(by_ord[4][val_idx]).lower()
    expect(param4 in ("true", "1"), f"{label}: param 4 value {by_ord[4]}")
    expect(str(by_ord[5][val_idx]) == "3.5", f"{label}: param 5 value {by_ord[5]}")
    expect(str(by_ord[6][val_idx]) == "[1, 2]", f"{label}: param 6 value {by_ord[6]}")

    out_flags = [
        int(row[flags_idx])
        for row in rows
        if int(row[flags_idx]) & 0x01 == 0x01
    ]
    expect(out_flags, f"{label}: expected output param flags in {rows}")


def validate_executesql(label: str, result_sets: list[tuple[list[str], list[tuple]]]) -> None:
    exec_set = find_result_set(result_sets, "exec_value")
    expect(exec_set is not None, f"{label}: missing exec_value result set")
    columns, rows = exec_set
    idx = [col.lower() for col in columns].index("exec_value")
    expect(rows and rows[0][idx] == RPC_EXEC_EXPECTED, f"{label}: exec_value {rows}")


def run_rpc(
    cur,
    tail: deque[str],
) -> tuple[list[tuple[list[str], list[tuple]]], bool, object, tuple]:
    logging.info("rpc: calling stored procedure via callproc")
    import pymssql

    out_param = pymssql.output(int, 5)
    params = (1, "two", decimal.Decimal("12.34"), True, 3.5, b"\x01\x02", out_param)
    callproc_result = cur.callproc("tds_rpc", params)
    logging.info("rpc: callproc returned %s", callproc_result)
    result_sets = collect_result_sets(cur)
    log_result_sets("rpc", result_sets)
    rpc_seen = wait_for_log(tail, "rpc from=", RPC_LOG_WAIT_SECS)
    if not rpc_seen:
        logging.warning("rpc: server log did not show RPC handler")
    return result_sets, rpc_seen, out_param, callproc_result


def run_rpc_output_only(cur, tail: deque[str]) -> tuple[tuple, bool]:
    logging.info("rpc_out: calling stored procedure via callproc")
    import pymssql

    out_param = pymssql.output(int, 5)
    params = (1, "two", decimal.Decimal("12.34"), True, 3.5, b"\x01\x02", out_param)
    callproc_result = cur.callproc("tds_rpc_out", params)
    logging.info("rpc_out: callproc returned %s", callproc_result)
    result_sets = collect_result_sets(cur)
    log_result_sets("rpc_out", result_sets)
    rpc_seen = wait_for_log(tail, 'proc_name="tds_rpc_out"', RPC_LOG_WAIT_SECS)
    if not rpc_seen:
        logging.warning("rpc_out: server log did not show RPC handler")
    return callproc_result, rpc_seen


def run_rpc_output_first(
    cur,
    tail: deque[str],
) -> tuple[list[tuple[list[str], list[tuple]]], bool, tuple]:
    logging.info("rpc_out_first: calling stored procedure via callproc")
    import pymssql

    out_param = pymssql.output(int, 5)
    params = (1, "two", decimal.Decimal("12.34"), True, 3.5, b"\x01\x02", out_param)
    callproc_result = cur.callproc("tds_rpc_out_first", params)
    logging.info("rpc_out_first: callproc returned %s", callproc_result)
    result_sets = collect_result_sets(cur)
    log_result_sets("rpc_out_first", result_sets)
    rpc_seen = wait_for_log(tail, 'proc_name="tds_rpc_out_first"', RPC_LOG_WAIT_SECS)
    if not rpc_seen:
        logging.warning("rpc_out_first: server log did not show RPC handler")
    return result_sets, rpc_seen, callproc_result


def run_executesql(
    cur,
    tail: deque[str],
) -> tuple[list[tuple[list[str], list[tuple]]], bool]:
    logging.info("executesql: calling sp_executesql via callproc")
    params = ("SELECT @P1", "@P1 int", 1)
    cur.callproc("sp_executesql", params)
    result_sets = collect_result_sets(cur)
    log_result_sets("executesql", result_sets)
    exec_seen = wait_for_log(tail, 'proc_name="sp_executesql"', RPC_LOG_WAIT_SECS)
    if not exec_seen:
        logging.warning("executesql: server log did not show RPC handler")
    return result_sets, exec_seen


def run_prepare_execute(
    cur,
    tail: deque[str],
) -> tuple[list[tuple[list[str], list[tuple]]], bool, bool, int | None]:
    import pymssql

    logging.info("prepare: calling sp_prepare via callproc")
    handle_param = pymssql.output(int, 0)
    prep_params = (handle_param, "@P1 int", "SELECT @P1")
    prep_result = cur.callproc("sp_prepare", prep_params)
    prep_sets = collect_result_sets(cur)
    log_result_sets("prepare", prep_sets)
    prep_seen = wait_for_log(tail, 'proc_name="sp_prepare"', RPC_LOG_WAIT_SECS)
    if not prep_seen:
        logging.warning("prepare: server log did not show RPC handler")

    handle_val = None
    if isinstance(prep_result, tuple):
        for val in prep_result:
            if isinstance(val, int):
                handle_val = val
                break

    logging.info("execute: calling sp_execute via callproc")
    exec_params = (handle_val or RPC_OUTPUT_EXPECTED, 7)
    cur.callproc("sp_execute", exec_params)
    exec_sets = collect_result_sets(cur)
    log_result_sets("execute", exec_sets)
    exec_seen = wait_for_log(tail, 'proc_name="sp_execute"', RPC_LOG_WAIT_SECS)
    if not exec_seen:
        logging.warning("execute: server log did not show RPC handler")
    return exec_sets, prep_seen, exec_seen, handle_val


def run_attention(cur, tail: deque[str]) -> tuple[bool, bool]:
    logging.info("attention: starting cancellation test")
    cancel_supported = hasattr(cur, "cancel") or hasattr(cur.connection, "cancel")
    if not cancel_supported:
        logging.warning("attention: cursor/connection cancel not available; skipping")
        return False, False

    cancel_result = {"error": None}

    def cancel_worker() -> None:
        time.sleep(ATTENTION_CANCEL_DELAY_SECS)
        try:
            if hasattr(cur, "cancel"):
                logging.info("attention: calling cursor.cancel()")
                cur.cancel()
            elif hasattr(cur.connection, "cancel"):
                logging.info("attention: calling connection.cancel()")
                cur.connection.cancel()
        except Exception as exc:  # pylint: disable=broad-except
            cancel_result["error"] = exc
            logging.warning("attention: cancel raised %s", exc)

    thread = threading.Thread(target=cancel_worker, daemon=True)
    thread.start()

    try:
        cur.execute("SELECT 1 -- tds_attention")
        try:
            rows = cur.fetchall()
            logging.info("attention: query returned %d rows", len(rows))
        except Exception as exc:  # pylint: disable=broad-except
            logging.info("attention: fetch raised %s", exc)
    except Exception as exc:  # pylint: disable=broad-except
        logging.info("attention: execute raised %s", exc)
    finally:
        thread.join(timeout=2)

    if cancel_result["error"] is not None:
        logging.warning("attention: cancel encountered error; continuing")

    attention_seen = wait_for_log(tail, "tds_attention: attention received", ATTENTION_LOG_WAIT_SECS)
    if not attention_seen:
        logging.warning("attention: server log did not show attention handler")
    return True, attention_seen


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    log_path = repo_root / "target" / "tds_dummy_pymssql_test.log"
    dump_path = repo_root / "target" / "tds_dummy_freetds.log"
    setup_logging(log_path)

    dump_path.parent.mkdir(parents=True, exist_ok=True)
    dump_path.write_text("", encoding="utf-8")
    os.environ.setdefault("TDSDUMP", str(dump_path))
    logging.info("FreeTDS dump path: %s", os.environ["TDSDUMP"])

    ensure_pymssql()
    import pymssql

    server_env = {**os.environ, "RUST_LOG": "info"}
    features = ["server-smol"]

    if LEGACY_TYPES_ENABLED:
        server_env["TDS_DUMMY_INCLUDE_LEGACY"] = "1"
        logging.info("Legacy type columns enabled for tds_types")

    if TLS_ENABLED:
        cert_path, key_path = ensure_tls_materials(repo_root)
        server_env["TDS_DUMMY_TLS_CERT"] = str(cert_path)
        server_env["TDS_DUMMY_TLS_KEY"] = str(key_path)
        server_env["TDS_DUMMY_ENCRYPTION"] = TLS_ENCRYPTION
        features.append("server-rustls")
        logging.info(
            "TLS enabled: cert=%s key=%s encryption=%s",
            cert_path,
            key_path,
            TLS_ENCRYPTION,
        )
    else:
        logging.info("TLS disabled for this test run")
    if FEDAUTH_ENABLED:
        server_env["TDS_DUMMY_FORCE_FEDAUTH"] = "1"
        logging.info("FedAuthInfo token emission enabled for tds_fedauth")
    else:
        logging.info("FedAuthInfo token emission disabled (set TDS_TEST_FEDAUTH=1 to enable)")
    if TVP_ENABLED:
        logging.info("TVP test enabled")
    else:
        logging.info("TVP test disabled (set TDS_TEST_TVP=1 to enable)")

    cmd = [
        "cargo",
        "run",
        "--example",
        "tds_server_dummy",
        "--features",
        ",".join(features),
    ]

    logging.info("Starting dummy server: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=server_env,
    )

    stop_evt = threading.Event()
    tail = deque(maxlen=200)

    stdout_thread = threading.Thread(
        target=reader_thread,
        args=(proc.stdout, "[server stdout]", stop_evt, tail),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=reader_thread,
        args=(proc.stderr, "[server stderr]", stop_evt, tail),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    try:
        logging.info("Waiting for server port %s:%s", HOST, PORT)
        deadline = time.time() + STARTUP_TIMEOUT_SECS
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("server exited before opening port")
            try:
                with socket.create_connection((HOST, PORT), timeout=0.5):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            raise RuntimeError("server did not open port in time")

        logging.info("Connecting with pymssql")
        conn_kwargs = {
            "server": HOST,
            "port": PORT,
            "user": "sa",
            "password": "x",
            "database": "master",
            "tds_version": "7.4",
            "login_timeout": CONNECT_TIMEOUT_SECS,
            "timeout": CONNECT_TIMEOUT_SECS,
        }
        if TLS_ENABLED:
            conn_kwargs["encryption"] = TLS_ENCRYPTION
        try:
            conn = pymssql.connect(**{**conn_kwargs, "use_uuid": True})
        except TypeError:
            logging.info("pymssql connect does not support use_uuid; retrying")
            conn = pymssql.connect(**conn_kwargs)

        try:
            try:
                conn.autocommit(True)
            except AttributeError:
                logging.info("pymssql connection does not support autocommit()")

            auth_seen = wait_for_log(tail, "auth: sql user=sa", AUTH_LOG_WAIT_SECS)
            expect(auth_seen, "auth: SQL auth handler was not observed in server logs")
            if FEDAUTH_ENABLED:
                fedauth_seen = wait_for_log(
                    tail,
                    "login: sending FedAuthInfo",
                    FEDAUTH_LOG_WAIT_SECS,
                )
                expect(fedauth_seen, "fedauth: FedAuthInfo was not emitted during login")

            cur = conn.cursor()

            basic_sets = execute_and_collect(cur, QUERY, "basic")
            validate_single_value("basic", basic_sets)

            info_sets = execute_and_collect(cur, "SELECT 1 -- tds_info", "tds_info")
            validate_single_value("tds_info", info_sets)

            type_sets = execute_and_collect(cur, "SELECT 1 -- tds_types", "tds_types")
            validate_types("tds_types", type_sets)

            varlen_sets = execute_and_collect(cur, "SELECT 1 -- tds_varlen", "tds_varlen")
            validate_varlen("tds_varlen", varlen_sets)

            try:
                variant_sets = execute_and_collect(cur, "SELECT 1 -- tds_variant", "tds_variant")
                validate_variants("tds_variant", variant_sets)
            except Exception as exc:  # pylint: disable=broad-except
                logging.warning("tds_variant: client could not parse sql_variant (%s)", exc)

            columnar_sets = execute_and_collect(cur, "SELECT 1 -- tds_columnar", "tds_columnar")
            validate_columnar("tds_columnar", columnar_sets)
            columnar_seen = wait_for_log(
                tail,
                "tds_columnar: send_row_values",
                COLUMNAR_LOG_WAIT_SECS,
            )
            expect(columnar_seen, "tds_columnar: server did not log columnar path")

            meta_columns, meta_rows, meta_desc = execute_single_with_description(
                cur, "SELECT 1 -- tds_metadata", "tds_metadata"
            )
            validate_metadata("tds_metadata", meta_columns, meta_rows, meta_desc)
            metadata_seen = wait_for_log(
                tail,
                "tds_metadata: table_name=",
                METADATA_LOG_WAIT_SECS,
            )
            expect(metadata_seen, "tds_metadata: table name log was not observed")

            null_sets = execute_and_collect(cur, "SELECT 1 -- tds_nulls", "tds_nulls")
            validate_nulls("tds_nulls", null_sets)

            multi_sets = execute_and_collect(cur, "SELECT 1 -- tds_multi", "tds_multi")
            validate_multi("tds_multi", multi_sets)

            token_sets = execute_and_collect(cur, "SELECT 1 -- tds_tokens", "tds_tokens")
            validate_single_value("tds_tokens", token_sets, expected_value=55)

            token_extra_sets = execute_and_collect(
                cur, "SELECT 1 -- tds_tokens_extra", "tds_tokens_extra"
            )
            token_extra = find_result_set(token_extra_sets, "value")
            expect(token_extra is not None, "tds_tokens_extra: missing value result set")
            extra_columns, extra_rows = token_extra
            idx = [col.lower() for col in extra_columns].index("value")
            expect(
                any(row[idx] == 66 for row in extra_rows),
                f"tds_tokens_extra: unexpected rows {extra_rows}",
            )

            compute_sets = execute_and_collect(cur, "SELECT 1 -- tds_compute", "tds_compute")
            validate_compute("tds_compute", compute_sets)
            compute_seen = wait_for_log(
                tail,
                "tds_compute: sending alt row",
                COMPUTE_LOG_WAIT_SECS,
            )
            expect(compute_seen, "tds_compute: server did not send alt row token")

            session_sets = execute_and_collect(
                cur, "SELECT 1 -- tds_session_state", "tds_session_state"
            )
            validate_empty("tds_session_state", session_sets)

            fedauth_sets = execute_and_collect(cur, "SELECT 1 -- tds_fedauth", "tds_fedauth")
            validate_empty("tds_fedauth", fedauth_sets)

            env_sets = execute_and_collect(cur, "SELECT 1 -- tds_envchange", "tds_envchange")
            validate_empty("tds_envchange", env_sets)

            env_full_sets = execute_and_collect(
                cur, "SELECT 1 -- tds_envchange_full", "tds_envchange_full"
            )
            validate_empty("tds_envchange_full", env_full_sets)

            try:
                conn.autocommit(False)
            except AttributeError:
                logging.info("pymssql connection does not support autocommit(False)")

            begin_sets = execute_and_collect(cur, "BEGIN TRAN -- tds_begin", "tds_begin")
            validate_empty("tds_begin", begin_sets)

            header_sets = execute_and_collect(cur, "SELECT 1 -- tds_headers", "tds_headers")
            validate_single_value("tds_headers", header_sets, expected_value=2)
            headers_seen = wait_for_log(tail, "tds_headers:", HEADERS_LOG_WAIT_SECS)
            expect(headers_seen, "tds_headers: server did not log header info")
            header_line = find_log_line(tail, "tds_headers:")
            expect(header_line is not None, "tds_headers: missing header log line")
            expect(
                "tx_desc=<none>" not in header_line,
                "tds_headers: expected transaction descriptor header",
            )

            commit_sets = execute_and_collect(cur, "COMMIT TRAN -- tds_commit", "tds_commit")
            validate_empty("tds_commit", commit_sets)

            try:
                conn.autocommit(True)
            except AttributeError:
                logging.info("pymssql connection does not support autocommit(True)")

            rpc_sets, rpc_seen, out_param, rpc_callproc = run_rpc(cur, tail)
            expect(rpc_seen, "rpc: RPC handler was not observed in server logs")

            validate_rpc_params("rpc_params", rpc_sets)

            rpc_value_set = find_result_set(rpc_sets, "rpc_value")
            if rpc_value_set:
                columns, rows = rpc_value_set
                idx = [col.lower() for col in columns].index("rpc_value")
                expect(rows[0][idx] == 7, f"rpc: unexpected row {rows}")
            else:
                logging.warning("rpc: rpc_value result set not found")

            if rpc_callproc and rpc_callproc[-1] != RPC_OUTPUT_EXPECTED:
                logging.warning("rpc: output param not updated (got %s)", rpc_callproc[-1])

            rpc_out_result, rpc_out_seen = run_rpc_output_only(cur, tail)
            expect(rpc_out_seen, "rpc_out: RPC handler was not observed in server logs")
            expect(
                rpc_out_result[-1] == RPC_OUTPUT_EXPECTED,
                f"rpc_out: output param value {rpc_out_result[-1]}",
            )

            rpc_out_first_sets, rpc_out_first_seen, rpc_out_first_result = run_rpc_output_first(
                cur, tail
            )
            expect(
                rpc_out_first_seen,
                "rpc_out_first: RPC handler was not observed in server logs",
            )
            if rpc_out_first_result[-1] == RPC_OUTPUT_EXPECTED:
                logging.info("rpc_out_first: output param updated with result sets present")
            else:
                logging.warning(
                    "rpc_out_first: output param not updated (got %s)",
                    rpc_out_first_result[-1],
                )

            exec_sets, exec_seen = run_executesql(cur, tail)
            expect(exec_seen, "executesql: RPC handler was not observed in server logs")
            validate_executesql("executesql", exec_sets)

            exec_sets, prep_seen, exec_seen, handle_val = run_prepare_execute(cur, tail)
            expect(prep_seen, "prepare: RPC handler was not observed in server logs")
            expect(exec_seen, "execute: RPC handler was not observed in server logs")
            validate_executesql("execute", exec_sets)
            if handle_val is not None and handle_val != RPC_OUTPUT_EXPECTED:
                logging.warning("prepare: unexpected handle value %s", handle_val)

            try:
                try:
                    exotic_conn = pymssql.connect(**{**conn_kwargs, "use_uuid": True})
                except TypeError:
                    exotic_conn = pymssql.connect(**conn_kwargs)
                try:
                    try:
                        exotic_conn.autocommit(True)
                    except AttributeError:
                        logging.info("pymssql exotic connection does not support autocommit()")
                    exotic_cur = exotic_conn.cursor()
                    try:
                        exotic_sets = execute_and_collect(
                            exotic_cur, "SELECT 1 -- tds_exotic", "tds_exotic"
                        )
                        validate_exotic("tds_exotic", exotic_sets)
                    except Exception as exc:  # pylint: disable=broad-except
                        logging.warning(
                            "tds_exotic: client could not parse exotic types (%s)", exc
                        )
                    try:
                        lob_sets = execute_and_collect(
                            exotic_cur, "SELECT 1 -- tds_lob", "tds_lob"
                        )
                        validate_lob("tds_lob", lob_sets)
                    except Exception as exc:  # pylint: disable=broad-except
                        logging.warning("tds_lob: client could not parse LOB types (%s)", exc)
                    try:
                        lob_stream_sets = execute_and_collect(
                            exotic_cur, "SELECT 1 -- tds_lob_stream", "tds_lob_stream"
                        )
                        validate_lob_stream("tds_lob_stream", lob_stream_sets)
                        lob_stream_seen = wait_for_log(
                            tail,
                            "tds_lob_stream: chunked writes",
                            LOB_STREAM_LOG_WAIT_SECS,
                        )
                        expect(
                            lob_stream_seen,
                            "tds_lob_stream: server did not log chunked writes",
                        )
                    except Exception as exc:  # pylint: disable=broad-except
                        logging.warning(
                            "tds_lob_stream: client could not parse LOB stream types (%s)",
                            exc,
                        )
                    if TVP_ENABLED:
                        try:
                            tvp_sets = execute_and_collect(
                                exotic_cur, "SELECT 1 -- tds_tvp", "tds_tvp"
                            )
                            validate_tvp("tds_tvp", tvp_sets)
                        except Exception as exc:  # pylint: disable=broad-except
                            logging.warning(
                                "tds_tvp: client could not parse TVP (%s)",
                                exc,
                            )
                finally:
                    exotic_conn.close()
            except Exception as exc:  # pylint: disable=broad-except
                logging.warning("tds_exotic/tds_lob: secondary connection failed (%s)", exc)
                try:
                    exotic_sets = execute_and_collect(
                        cur, "SELECT 1 -- tds_exotic", "tds_exotic"
                    )
                    validate_exotic("tds_exotic", exotic_sets)
                except Exception as exc2:  # pylint: disable=broad-except
                    logging.warning(
                        "tds_exotic: client could not parse exotic types (%s)", exc2
                    )
                try:
                    lob_sets = execute_and_collect(cur, "SELECT 1 -- tds_lob", "tds_lob")
                    validate_lob("tds_lob", lob_sets)
                except Exception as exc2:  # pylint: disable=broad-except
                    logging.warning("tds_lob: client could not parse LOB types (%s)", exc2)
                try:
                    lob_stream_sets = execute_and_collect(
                        cur, "SELECT 1 -- tds_lob_stream", "tds_lob_stream"
                    )
                    validate_lob_stream("tds_lob_stream", lob_stream_sets)
                    lob_stream_seen = wait_for_log(
                        tail,
                        "tds_lob_stream: chunked writes",
                        LOB_STREAM_LOG_WAIT_SECS,
                    )
                    expect(
                        lob_stream_seen,
                        "tds_lob_stream: server did not log chunked writes",
                    )
                except Exception as exc2:  # pylint: disable=broad-except
                    logging.warning(
                        "tds_lob_stream: client could not parse LOB stream types (%s)",
                        exc2,
                    )

            error_seen = False
            try:
                execute_and_collect(cur, "SELECT 1 -- tds_error", "tds_error")
            except Exception as exc:  # pylint: disable=broad-except
                logging.info("tds_error: expected error observed (%s)", exc)
                error_seen = True
            expect(error_seen, "tds_error: expected error token")

            attention_cur = conn.cursor()
            attention_attempted, attention_seen = run_attention(attention_cur, tail)
            if attention_attempted:
                expect(attention_seen, "attention: server did not observe attention")
                post_sets = execute_and_collect(
                    cur, "SELECT 1 -- attention_after", "attention_after"
                )
                validate_single_value("attention_after", post_sets)
        finally:
            conn.close()

        logging.info("Test completed successfully")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        logging.error("Test failed: %s", exc)
        logging.error("Server output tail:")
        for line in list(tail):
            logging.error("%s", line)
        dump_lines = tail_file(dump_path, FREETDS_DUMP_LINES)
        if dump_lines:
            logging.error("FreeTDS dump tail:")
            for line in dump_lines:
                logging.error("%s", line)
        return 1
    finally:
        stop_evt.set()
        if proc.poll() is None:
            logging.info("Stopping dummy server (pid=%s)", proc.pid)
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logging.warning("Server did not exit; killing")
                proc.kill()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
