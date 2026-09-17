// Минимальная разведка линковки boring на Linux CI (platform parity с локальной
// Windows/GNU пробой, docs/phase-reports/reality-boring-probe.md). Цель — не вся
// логика живого handshake, а гарантия, что объектники libcrypto+libssl BoringSSL
// реально втягиваются в линковку на linux/x86_64 (реальные вызовы, не пустой импорт)
// и бинарник исполняется.
use boring::sha::sha256;
use boring::ssl::{SslConnector, SslMethod};

fn main() {
    // libcrypto: настоящий вызов хеша — объектники не выкинутся мёртвым кодом.
    let d = sha256(b"aether-boring-probe-linux");
    println!("boring sha256[:8] = {:02x?}", &d[..8]);

    // libssl: сборка коннектора + ALPN (тот же паттерн, что в локальной пробе).
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("ssl builder");
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").expect("alpn");
    let connector = builder.build();
    println!("boring ssl ctx ok: TLS-коннектор собран, ALPN задан");
    let _ = connector; // держим живым до конца
    std::process::exit(0);
}
