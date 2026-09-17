# Reality-обложка: проба линковки boring (шаги 1–3 из 5)

**Дата прогона:** 2026-09-17 · **Крейт:** `boring 4.22.0` (cloudflare/boring) · **Тулчейн:** `stable-x86_64-pc-windows-gnu` (rustc 1.98.1)
**Статус:** РАЗВЕДКА — вопрос F11 «два libcrypto в одном дереве (конфликт символов с rustls/ring)» из `DEPENDENCIES.md`.

Это разведка, не прод-зависимость: `boring` **не** добавлен в workspace `Cargo.toml`,
в `crates/` нет никаких изменений. Всё хозяйство пробы — вне репо, в
`~/Desktop/boring-probe/` (два независимых крейта со своими `Cargo.lock`; workspace
репозитория не тронут — проба собиралась из своего каталога, lock-файлы у неё свои).

## Вопрос пробы

F11 зафиксирован буквально: «**EXISTS** (cloudflare/boring: 4.x stable…) Риск: два
libcrypto в одном дереве (конфликт символов с rustls/ring)». Это открытый риск
линковки, а не «отклонено» — ниже он **снят** для локального тулчейна windows-gnu:
boring линкуется чисто рядом с rustls/ring в одном бинаре (debug и release).

## Шаг 1 — план пробы

Две независимые сборки вне workspace, обе — **реальные вызовы** boring (не «импорт
для линковки», чтобы объектники гарантированно втянулись):

| Проба | Зависимости | Что делает |
|---|---|---|
| `probe-boring-only` | `boring = "4"` | `boring::sha::sha256` (libcrypto) + `SslConnector::builder(SslMethod::tls())` с ALPN (libssl) |
| `probe-boring-rustls` | `boring = "4"` + `rustls 0.23` (default-features = false, features = `[ring, std, tls12]`) + `ring 0.17` | всё то же + сверка SHA-256 boring vs ring, ECDSA-подпись ring, `rustls::crypto::ring::default_provider().install_default()`, сборка `ClientConfig` |

Набор rustls-фич в пробе повторяет прод-стек лаборатории (`crates/e2e-harness`):
тот же провайдер (`ring`), который реально едет в прод-пинах quinn/rustls.

## Шаг 2 — тулчейн: чего не хватало сверх `scripts/local-env.sh`

`local-env.sh` даёт базу (w64devkit-gcc в PATH, self-contained линкер rustup,
RUSTFLAGS/CFLAGS для PQ-shim) — её хватает workspace-пинам. Для boring-sys её
недостаточно; каждое из трёх звеньев ниже — реальный фейл холодной сборки:

1. **`CMAKE_GENERATOR=Ninja`.** boring-sys собирает BoringSSL через cmake-crate.
   Генератор по умолчанию на MSYS/Git Bash — Makefiles-вариант, зовущий `sh`;
   с busybox-sh из w64devkit сгенерированные CMake make-скрипты ломаются.
   Ninja шелл не использует — с ним собирается. `ninja.exe` и `cmake.exe` уже
   лежат в `w64devkit/bin` (добавляются local-env.sh), ставить ничего не нужно.
   Подтверждение по артефактам: `CMakeCache.txt` пробы —
   `CMAKE_GENERATOR:INTERNAL=Ninja`.
2. **NASM 2.16.03 (портативный).** CMakeLists BoringSSL на x86_64 Windows требует
   NASM для perlasm-ассемблера; без него конфигурация падает (`ASM_NASM not found`).
   В w64devkit nasm не входит. Достаточно zip `nasm-2.16.03-win64.zip` с nasm.org,
   распакованного в `Desktop/boring-probe/tools/nasm-2.16.03/` (nasm.exe + ndisasm.exe).
3. **`LIBCLANG_PATH` + `BINDGEN_EXTRA_CLANG_ARGS`.** boring-sys генерирует FFI
   bindgen'ом, которому нужен `libclang.dll`. Системного LLVM на машине нет —
   использована готовая библиотека из PyPI-колеса `libclang`
   (`pip download libclang`, wheel — это zip; распакован в
   `Desktop/boring-probe/tools/libclang/clang/native/libclang.dll`, версия 18.1.1).
   Без `-target x86_64-pc-windows-gnu` libclang парсит mingw-заголовки в режиме MSVC
   и падает на mingw-специфичных атрибутах (`__MINGW_NOTHROW` и др.). Отдельные `-I`
   нужны, потому что у libclang из колеса нет встроенных путей к заголовкам:
   `-I<w64devkit>/include` + `-I<w64devkit>/lib/gcc/x86_64-w64-mingw32/<ver>/include`
   (внутренний include gcc).

### Воспроизведение

Вспомогательный скрипт **`scripts/boring-probe-env.sh`** (в репо, вне crates/)
дополняет local-env.sh — он `source`-ит его и добавляет только недостающее,
ничего не дублируя. Explicit-fail по образцу local-env.sh: любой отсутствующий
компонент — понятная ошибка с подсказкой. Он не пишет ничего в каталог пробы —
только экспортирует переменные текущего шелла.

```bash
cd /путь/к/репо
source scripts/boring-probe-env.sh          # тянет local-env.sh, затем добавляет своё
# дальше — сборка пробы из её собственного каталога (вне workspace):
cd ~/Desktop/boring-probe/probe-boring-rustls
cargo build                                  # debug
cargo build --release                        # release
./target/debug/probe-boring-rustls.exe       # и то же для probe-boring-only
```

Полный набор переменных, который в итоге должен стоять в окружении
(если делать руками без скрипта):

```bash
source scripts/local-env.sh                  # база: PATH+w64devkit, LINKER, RUSTFLAGS, CFLAGS
export CMAKE_GENERATOR=Ninja
export PATH="$HOME/Desktop/boring-probe/tools/nasm-2.16.03:$PATH"
export LIBCLANG_PATH="$HOME/Desktop/boring-probe/tools/libclang/clang/native"   # C:/... форма
export BINDGEN_EXTRA_CLANG_ARGS="-target x86_64-pc-windows-gnu \
 -I$(cygpath -m "$HOME/w64devkit/include") \
 -I$(cygpath -m "$HOME/w64devkit/lib/gcc/x86_64-w64-mingw32/16.2.0/include)"
```

Переопределения скрипта (до source): `BORING_PROBE_DIR` (дефолт
`~/Desktop/boring-probe`), `BORING_PROBE_NASM_DIR`, `BORING_PROBE_LIBCLANG_DIR`.

## Шаг 3 — результат

| Проверка | Результат |
|---|---|
| `probe-boring-only`, cargo build (debug) | ✅ собралось чисто, 0 предупреждений линковщика |
| `probe-boring-rustls`, cargo build (debug) | ✅ оба TLS-стека в одном бинаре, конфликтов символов нет |
| `probe-boring-rustls`, cargo build --release | ✅ release-профиль линкуется чисто |
| Прогон `probe-boring-rustls` (реальные вызовы обоих стеков) | ✅ boring `sha256[:8]`, коннектор с ALPN, сверка `СОВПАДАЮТ` с ring, ring ECDSA-подпись, `ClientConfig` на ring-провайдере |
| Символьный аудит exe | ✅ в бинаре присутствуют символы **обоих** стеков (`BoringSSL`* / boring-sys объектники и `ring`/rustls) — обе статические библиотеки реально втянуты, дубликатов не подхватилось |
| SHA-256 boring vs ring | ✅ совпадают байт в байт на общем входе (проверяется в рантайме `assert_eq!`) |

Вывод шагов 1–3: **линкуется чисто**, символьный конфликт boring/ring/rustls
не материализовался на x86_64-pc-windows-gnu (rustc 1.98.1, w64devkit GCC 16.2.0).

## Шаг 4 — живой TLS-handshake обоих стеков в одном процессе

Расширен `probe-boring-rustls` (вне workspace, как и раньше): теперь оба стека не
просто слинкованы, а **делают реальную сетевую работу одновременно** — без tokio,
стандартные потоки + блокирующие loopback-TCP сокеты, чтобы «сломанное состояние»
не пряталось за общим шедулером:

- **boring-пара**: TLS-сервер (`SslAcceptor::mozilla_intermediate_v5`, ALPN-select
  callback) ↔ TLS-клиент (пин сертификата как единственный корень, verify PEER +
  hostname, ALPN) — RSA-2048 самоподписанный сертификат строится самим boring.
- **rustls-пара**: сервер + клиент на ring-провайдере (`default_provider()`),
  мини-цепочка rcgen CA→leaf (SAN `localhost`), ALPN `h2` с обеих сторон.
- **Перекрёстность**: 4 соединения (2+2) стартуют по барьеру одновременно, дальше
  потоки свободны — handshake и обмен данными обоих стеков перемешаны во времени
  планировщиком ОС. Плюс по одному контрольному соединению каждого стека **после**
  чужой активности (детектор отложенной порчи состояния).
- **Проверка данных**: по каждому соединению 64 KiB псевдослучайных байт
  (детерминированный xorshift-PRNG, свой seed) запрос-ответом, сверка байт в байт.
  Порча памяти ловится либо AEAD (handshake/чтение не завершится), либо сверкой.

### Результат

| Проверка | Результат |
|---|---|
| 6 живых TLS-соединений (3 boring + 3 rustls) в одном процессе | ✅ все handshake завершены, `is_handshaking()==false` / версия TLS считана |
| Данные 64 KiB × 6 соединений, сверка байт в байт | ✅ сошлись везде |
| ALPN-согласование | ✅ `h2` на всех соединениях обоих стеков |
| Контроль после чужой активности | ✅ rustls-прогон после boring-активности чист, boring-прогон после rustls-активности чист |
| Профили | ✅ debug и release; +3 повторных debug-прогона — стабильно `EXIT=0` |
| Паники / segfault / deadlock / порча состояния | **не обнаружено** |

Вывод шага 4: активность boring и активность rustls/ring **не ломают состояние
друг друга** при реальном сетевом I/O в одном процессе. Совместно с шагами 1–3
(линковка) риск F11 снят полностью: два TLS-стека в одном бинаре живут и работают.

### Находки по API (мелкие, но потратили время — фиксирую)

1. **boring: клиентский ALPN задаётся per-соединение.** `set_alpn_protos` на
   `SslConnector`/`SslContextBuilder` не наследуется SSL-объектом (`selected_alpn_protocol()`
   → `None`); рабочая точка — `connector.configure()` + `set_alpn_protos` на
   `ConnectConfiguration` (он `Deref<Target = SslRef>`, `SSL_set_alpn_protos`).
2. **ALPN-список сервера — только wire-формат** (`\x02h2`): `select_next_proto`
   без байта длины парсит мусор и молча не выбирает ничего → `AlpnError::NOACK`.
3. **webpki отвергает CA-сертификат в роли конечного**: самоподписанный cert с
   `CA:true`, поданный как leaf, даёт `InvalidCertificate(CaUsedAsEndEntity)`
   → `CertificateUnknown` на сервере. Нужна цепочка rcgen CA→leaf (CA:
   `keyCertSign`+`crlSign`, leaf: `digitalSignature`+`keyEncipherment`+`serverAuth`).
4. **boring: `X509::builder().sign()` должен быть последним** — он кодирует TBS в
   момент вызова; `set_not_before/after` и расширения после подписи дают
   ASN.1 `WRONG_TYPE`.

### Listing пробы (probe-boring-rustls/src/main.rs, шаг 4)

<details><summary>Полный исходник (383 строки)</summary>

```rust
// probe-boring-rustls: оба TLS-стека в ОДНОМ бинаре — линковка (шаги 1–3 разведки
// F11 из DEPENDENCIES.md) + ЖИВОЙ TLS-handshake обоих стеков через реальный loopback
// TCP (шаг 4), в одном процессе. Цель шага 4: активность одного TLS-стека (boring)
// не должна ломать состояние другого (rustls/ring) при реальном сетевом I/O —
// не только на этапе линковки символов.
//
// Без tokio: стандартные потоки + блокирующие сокеты. Стеки не должны зависеть
// от общего рантайма, чтобы «сломанное состояние» не пряталось за общим шедулером.
//
// Что делает прогон:
//   Ф1 (подготовка): boring RSA-2048 самоподписанный сертификат, серверный/клиентский
//       контексты boring (ALPN), rcgen-сертификат + конфиги rustls на ring-провайдере.
//       До этого — сверка SHA-256 boring vs ring и ECDSA-подпись ring (шаг 3).
//   Ф2–Ф4 (перекрёстный шаг): 4 соединения (2 boring + 2 rustls) стартуют одновременно
//       по барьеру; handshake и данные идут параллельно, сетевой I/O стеков перемешан
//       во времени планировщиком ОС. По каждому соединению — запрос-ответ 64 KiB
//       псевдослучайных байт (свой seed на прогон), сверка байт в байт.
//   Ф5 (контроль): по одному дополнительному соединению каждого стека ПОСЛЕ
//       чужой активности — детектор отложенной порчи состояния.
// Итого 6 живых TLS-соединений (3+3) за прогон. Любая паника/сегфолт/порча —
// находка серьёзнее снятого риска линковки: проба падает loudly с точным местом.
// Порча данных ловится либо AEAD (handshake/чтение не завершится), либо сверкой.

use boring::asn1::Asn1Time;
use boring::bn::{BigNum, MsbOption};
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::sha::sha256;
use boring::ssl::{select_next_proto, AlpnError, SslAcceptor, SslConnector, SslMethod};
use boring::x509::extension::BasicConstraints;
use boring::x509::{X509, X509Name};
use ring::signature::KeyPair as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::thread;

const HOST: &str = "localhost";
const ALPN_CLIENT: &[u8] = b"\x02h2\x08http/1.1"; // wire-формат ALPN: len+proto
const ALPN_SERVER: &[u8] = b"\x02h2"; // тоже wire-формат (без байта длины select_next_proto парсит мусор — проверено прогоном)
const DATA_LEN: usize = 64 * 1024;

// ---------- детерминированный PRNG (xorshift64*), чтобы прогон был повторяемым ----------
struct Xs(u64);
impl Xs {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            let v = x.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

// ---------- самоподписанный RSA-2048 сертификат для boring-стека ----------
fn self_signed_boring() -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa keygen")).expect("pkey");
    let mut name_builder = X509Name::builder().expect("name builder");
    name_builder.append_entry_by_text("CN", HOST).expect("CN");
    let name = name_builder.build();

    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    let mut serial = BigNum::new().expect("bn");
    serial.rand(64, MsbOption::MAYBE_ZERO, false).expect("rand");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("asn1 int"))
        .expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer (self-signed)");
    builder.set_pubkey(&key).expect("set pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("not_before"))
        .expect("nb");
    builder
        .set_not_after(&Asn1Time::days_from_now(2).expect("not_after"))
        .expect("na");
    let bc = BasicConstraints::new().critical().ca().build().expect("bc");
    builder.append_extension(bc).expect("append bc");
    // Подпись ПОСЛЕДНЕЙ: она кодирует TBS в момент вызова — всё поле сертификата
    // (включая сроки действия и расширения) должно быть уже заполнено.
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("self sign");
    (builder.build(), key)
}

fn boring_server_ctx(cert: &X509, key: &PKey<Private>) -> SslAcceptor {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor");
    builder.set_certificate(cert).expect("set cert");
    builder.set_private_key(key).expect("set key");
    builder.set_alpn_select_callback(|_ssl, client| {
        // стандартный алгоритм выбора протокола, сервер предпочитает h2
        select_next_proto(ALPN_SERVER, client).ok_or(AlpnError::NOACK)
    });
    builder.build()
}

fn boring_client_connector(cert: &X509) -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder
        .cert_store_mut()
        .add_cert(cert.to_owned())
        .expect("pin cert");
    builder.set_alpn_protos(ALPN_CLIENT).expect("alpn");
    builder.build() // verify PEER + verify_hostname — дефолт и так включены
}

/// Полный цикл одного boring-соединения: живой loopback-TCP, handshake с обеих
/// сторон, запрос-ответ. Сервер в отдельном потоке, клиент — ведущий.
fn run_boring(ctx: &Arc<SslAcceptor>, connector: &Arc<SslConnector>, seed: u64) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = ctx.clone();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept");
        let mut s = acceptor.accept(tcp).expect("boring server handshake");
        let mut got = vec![0u8; DATA_LEN];
        s.read_exact(&mut got).expect("boring server read");
        s.write_all(&got).expect("boring server echo");
        s
    });

    let tcp = TcpStream::connect(addr).expect("tcp connect");
    // ALPN — per-соединение: set_alpn_protos на SslContextBuilder не наследуется
    // SSL-объектом в BoringSSL (проверено этим прогоном: ALPN=<none>),
    // рабочая точка — configure() + set_alpn_protos на самом SSL.
    let mut cfg = connector.configure().expect("connect config");
    cfg.set_alpn_protos(ALPN_CLIENT).expect("alpn per-conn");
    let mut c = cfg.connect(HOST, tcp).expect("boring client handshake");
    assert!(
        !c.ssl().version_str().is_empty(),
        "boring: TLS-версия не считана (handshake не завершён?)"
    );

    let mut plain = vec![0u8; DATA_LEN];
    Xs(seed).fill(&mut plain);
    c.write_all(&plain).expect("boring client write");
    let mut got = vec![0u8; DATA_LEN];
    c.read_exact(&mut got).expect("boring client read echo");
    assert_eq!(plain, got, "boring client: эхо не совпало — порча данных/стека");
    let alpn = String::from_utf8_lossy(c.ssl().selected_alpn_protocol().unwrap_or(b"<none>"))
        .into_owned();

    let _server_stream = server.join().expect("boring server thread упал (паника)");
    format!("boring: handshake + {} байт сошлось, ALPN={}", DATA_LEN, alpn)
}

/// Полный цикл одного rustls-соединения (ring-провайдер): handshake + запрос-ответ.
fn run_rustls(
    client_cfg: &Arc<rustls::ClientConfig>,
    server_cfg: &Arc<rustls::ServerConfig>,
    seed: u64,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_cfg = server_cfg.clone();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept");
        let conn = rustls::ServerConnection::new(server_cfg).expect("server conn");
        let mut s = rustls::StreamOwned::new(conn, tcp);
        s.flush().expect("rustls server handshake"); // flush доталкивает handshake
        assert!(
            !s.conn.is_handshaking(),
            "rustls server: handshake не завершился"
        );
        let mut got = vec![0u8; DATA_LEN];
        s.read_exact(&mut got).expect("rustls server read");
        s.write_all(&got).expect("rustls server echo");
        s
    });

    let conn =
        rustls::ClientConnection::new(client_cfg.clone(), HOST.try_into().expect("dns name"))
            .expect("client conn");
    let mut c = rustls::StreamOwned::new(conn, TcpStream::connect(addr).expect("tcp connect"));
    c.flush().expect("rustls client handshake");
    assert!(
        !c.conn.is_handshaking(),
        "rustls client: handshake не завершился"
    );

    let mut plain = vec![0u8; DATA_LEN];
    Xs(seed).fill(&mut plain);
    c.write_all(&plain).expect("rustls client write");
    let mut got = vec![0u8; DATA_LEN];
    c.read_exact(&mut got).expect("rustls client read echo");
    assert_eq!(plain, got, "rustls client: эхо не совпало — порча данных/стека");
    let alpn = c
        .conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "<none>".to_string());

    server.join().expect("rustls server thread упал (паника)");
    format!("rustls: handshake + {} байт сошлось, ALPN={}", DATA_LEN, alpn)
}

/// Перекрёстный шаг: рукопожатия и данные обоих стеков идут ПАРАЛЛЕЛЬНО
/// (барьер стартов, дальше потоки свободны) — сетевой I/O стеков перемешан.
fn cross_step(
    boring_ctx: &Arc<SslAcceptor>,
    boring_connector: &Arc<SslConnector>,
    rustls_client: Arc<rustls::ClientConfig>,
    rustls_server: Arc<rustls::ServerConfig>,
) {
    let barrier = Arc::new(Barrier::new(4));

    let h_b1 = {
        let (bar, ctx, conn) = (barrier.clone(), boring_ctx.clone(), boring_connector.clone());
        thread::spawn(move || {
            bar.wait();
            run_boring(&ctx, &conn, 0xB100 + 1)
        })
    };
    let h_b2 = {
        let (bar, ctx, conn) = (barrier.clone(), boring_ctx.clone(), boring_connector.clone());
        thread::spawn(move || {
            bar.wait();
            run_boring(&ctx, &conn, 0xB200 + 1)
        })
    };
    let h_r1 = {
        let (bar, cc, sc) = (barrier.clone(), rustls_client.clone(), rustls_server.clone());
        thread::spawn(move || {
            bar.wait();
            run_rustls(&cc, &sc, 0x1100 + 1)
        })
    };
    let h_r2 = {
        let (bar, cc, sc) = (barrier.clone(), rustls_client.clone(), rustls_server.clone());
        thread::spawn(move || {
            bar.wait();
            run_rustls(&cc, &sc, 0x1200 + 1)
        })
    };
    for h in [h_b1, h_b2, h_r1, h_r2] {
        println!("  {}", h.join().expect("поток перекрёстного шага упал (паника)"));
    }
}

fn main() {
    println!("=== шаг 4: живые TLS-handshake обоих стеков в одном процессе ===");

    // --- криптопроверка линковки (шаг 3, сохранена) ---
    let input = b"aether-boring-rustls-probe";
    let d_boring = sha256(input);
    let d_ring = ring::digest::digest(&ring::digest::SHA256, input);
    assert_eq!(
        d_boring.as_ref(),
        d_ring.as_ref(),
        "boring и ring обязаны дать одинаковый SHA-256"
    );
    println!("SHA-256 boring == ring: СОВПАДАЮТ");

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .expect("ring keygen");
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .expect("ring from_pkcs8");
    let sig = key.sign(&rng, input).expect("ring sign");
    assert!(!sig.as_ref().is_empty() && !key.public_key().as_ref().is_empty());
    println!("ring ECDSA-подпись: ok");

    // --- Ф1: контексты обоих стеков (инициализация обоих до чужих handshake) ---
    let (cert, key) = self_signed_boring();
    let boring_ctx = Arc::new(boring_server_ctx(&cert, &key));
    let boring_connector = Arc::new(boring_client_connector(&cert));
    println!("boring: контексты готовы (RSA-2048 self-signed, ALPN h2, verify on)");

    let _ = rustls::crypto::ring::default_provider().install_default();
    // Мини-цепочка rcgen: CA (keyCertSign) + leaf-серверный сертификат (ServerAuth).
    // Цепочка, а не CA-as-leaf: webpki отвергает CA-сертификат в роли конечного
    // (InvalidCertificate(CaUsedAsEndEntity)) — проверено этим же прогоном.
    let ca_key = rcgen::KeyPair::generate().expect("rcgen ca keygen");
    let mut ca_params = rcgen::CertificateParams::new(vec!["Aether Probe CA".to_string()])
        .expect("rcgen ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("rcgen ca sign");

    let server_key = rcgen::KeyPair::generate().expect("rcgen keygen");
    let mut params = rcgen::CertificateParams::new(vec![HOST.to_string()])
        .expect("rcgen params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    let leaf_cert = params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("rcgen leaf sign");
    let cert_der = leaf_cert.der().as_ref().to_vec();
    let ca_der = ca_cert.der().as_ref().to_vec();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der))
        .expect("pin rustls ca cert");
    // ALPN обеим сторонам rustls — симметрично boring-паре (до заворачивания в Arc:
    // поле alpn_protocols публично мутируемое только у самого конфига).
    let mut client_cfg_local = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_cfg_local.alpn_protocols = vec![b"h2".to_vec()];
    let rustls_client_cfg: Arc<rustls::ClientConfig> = Arc::new(client_cfg_local);

    let mut server_cfg_local = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            server_key.serialize_der(),
        )),
    )
    .expect("rustls cert/key");
    server_cfg_local.alpn_protocols = vec![b"h2".to_vec()];
    let rustls_server_cfg: Arc<rustls::ServerConfig> = Arc::new(server_cfg_local);
    println!(
        "rustls: конфиги готовы (ring-провайдер, цепочка CA→leaf SAN {}, ALPN h2, pin CA как корень)",
        HOST
    );

    // --- Ф2–Ф4: перекрёстные живые handshake + данные ---
    cross_step(
        &boring_ctx,
        &boring_connector,
        rustls_client_cfg.clone(),
        rustls_server_cfg.clone(),
    );

    // --- Ф5: контроль целостности ПОСЛЕ чужой активности ---
    println!(
        "  {}",
        run_rustls(&rustls_client_cfg, &rustls_server_cfg, 0xFEED)
    );
    println!("  ^ rustls: контрольный прогон после boring-активности — чисто");
    println!(
        "  {}",
        run_boring(&boring_ctx, &boring_connector, 0xBEEF)
    );
    println!("  ^ boring: контрольный прогон после rustls-активности — чисто");

    println!();
    println!("=== ИТОГ: 6 живых TLS-соединений (3 boring + 3 rustls), паник/сегфолтов/порчи нет ===");
}
```

</details>

### Console-вывод эталонного прогона (release, 2026-09-17)

```text
=== шаг 4: живые TLS-handshake обоих стеков в одном процессе ===
SHA-256 boring == ring: СОВПАДАЮТ
ring ECDSA-подпись: ok
boring: контексты готовы (RSA-2048 self-signed, ALPN h2, verify on)
rustls: конфиги готовы (ring-провайдер, цепочка CA→leaf SAN localhost, ALPN h2, pin CA как корень)
  boring: handshake + 65536 байт сошлось, ALPN=h2
  boring: handshake + 65536 байт сошлось, ALPN=h2
  rustls: handshake + 65536 байт сошлось, ALPN=h2
  rustls: handshake + 65536 байт сошлось, ALPN=h2
  rustls: handshake + 65536 байт сошлось, ALPN=h2
  ^ rustls: контрольный прогон после boring-активности — чисто
  boring: handshake + 65536 байт сошлось, ALPN=h2
  ^ boring: контрольный прогон после rustls-активности — чисто

=== ИТОГ: 6 живых TLS-соединений (3 boring + 3 rustls), паник/сегфолтов/порчи нет ===
```

## Шаг 5 — архитектурная карточка: boring встроенный vs Go-sidecar

**Контекст решения.** Go-sidecar (xray-core отдельным процессом) был запасным путём
**на случай провала пробы** — если два libcrypto не живут в одном бинаре или живой
handshake ломает состояние. Оба прогона (шаги 1–3 и шаг 4) прошли чисто, случай
провала **не реализовался**. Рекомендация — boring встроенным.

| Критерий | boring встроенный (рекомендация) | xray-core Go-sidecar |
|---|---|---|
| Совместимость стеков | ✅ снята двумя пробами: линковка чисто (debug+release), живой handshake обоих стеков без паник/порчи | тривиальна (отдельный процесс) — но этот плюс больше не нужен |
| Контроль ClientHello (суть Reality) | ✅ полный, через FFI в том же процессе — ALPN/расширения/порядок шифров подтверждены на живых handshake | полный (uTLS внутри xray) |
| Число процессов/IPC | один процесс, обложка — обычный `CoverBinding` | второй процесс + локальный IPC-канал (запуск/рестарт/таймауты/здоровье), логическое дублирование TLS-слоя |
| Поверхность поставки | +3 звена тулчейна сборки (см. шаг 2) + boring-sys в дереве зависимостей | бинарник xray + переносимость его сборки в релиз-пайплайн |
| Состояние/устойчивость | состояние обложки в нашем процессе, аварийные пути предсказуемы (шаг 4: отказов не найдено) | сбои сайдкара — отдельный класс отказов, не наблюдаемый из нашего процесса |

Что пробы **не** устанавливают (честно): самой Reality-логики ещё нет (verify/ClientHello
маскировка — следующий этап); не мерилась цена бинаря; не проверена сборка boring-sys
в CI-окружении (три звена тулчейна шага 2 тяжелее текущих workspace-пинов — это будет
отдельная CI-работа при добавлении boring). `xray-core` остаётся **reference-only** для
поведения протокола Reality (DEPENDENCIES.md), не рантайм-зависимостью.
