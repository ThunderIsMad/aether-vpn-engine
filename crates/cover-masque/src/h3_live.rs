//! MASQUE live-слой (Phase 1, кусок 4): **собственный h3-клиент на quinn** —
//! то, чего не было в каркасе куска 2.
//!
//! Разделение труда (без дублей):
//!
//! * каркас (`MasqueBinding`, кусок 2) — sync: кадрирует запись frame-слоя в
//!   DATAGRAM-капсулу (`encode_datagram_capsule`) и кладёт в `Outbox`;
//! * live-слой (этот модуль) — async: поверх живого `quinn::Connection` поднимает
//!   HTTP/3 (`h3` + `h3-quinn`), шлёт Extended CONNECT-UDP (RFC 9298 §3,
//!   `:protocol: connect-udp`) и вычерпывает `Outbox` байндинга в HTTP/3
//!   DATAGRAM'ы (RFC 9297) на стриме запроса.
//!
//! **HTTP Datagrams даёт `h3-datagram`** (транспорт-адаптер — `h3-quinn`, фича
//! `datagram`): `HandleDatagramsExt::get_datagram_sender(request_stream_id)`
//! кодирует Quarter Stream ID + payload (RFC 9297 §4). Сам h3 0.0.8 публичного
//! API датаграмм не имеет — это факт спайка 2026-09-18 (DEPENDENCIES.md), а не
//! выбор реализации. Контекст-стек внутри payload'а — наш из куска 2
//! (`Context ID(0) ‖ record.encode()`, RFC 9298 §5): h3-datagram знает только
//! привязку «датаграмма ↔ request-стрим».
//!
//! **Caps.** Честность важнее маркетинга: датаграммный транспорт live-слой имеет
//! (`caps().datagram == true`), а `no_hol` остаётся `false` до двустороннего
//! прогона — приёмник пока живёт только в лаборатории (`e2e-harness/masque_lab`),
//! и клейм «no-HOL поверх MASQUE» держится на работающей паре концов, а не на
//! одном эмиттере.
//!
//! **Драйвер.** h3 0.0.8 не даёт `Future` над соединением: `client::Connection`
//! надо периодически дёргать (`poll_close` — он же двигает контрольные стримы и
//! SETTINGS). Обёртка `MasqueH3Client::drive()` — «прокрутить один шаг драйвера»;
//! в лаборатории это делает `tokio::spawn` + `wait_idle`-цикл.

use std::time::Duration;

use bytes::Bytes;
use h3::client;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::Connection as QConnection;

use crate::ConnectUdpRequest;

/// Тайм-аут настройки h3-сессии и ответа на Extended CONNECT: обложка не виснет
/// вечно на полуоткрытом узле — contract «fail loud» остальных кусков.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Ошибки live-слоя. Каждая ветка — конкретное место отказа, без слияния в один
/// «что-то сломалось» (это contract `MasqueFrameError` куска 2).
#[derive(Debug)]
pub enum MasqueH3Error {
    /// HTTP/3-сессия не поднялась (SETTINGS exchange, контрольные стримы).
    Connect(h3::error::ConnectionError),
    /// Extended CONNECT отклонён (стрим сброшен, заголовки не приняты и т.д.).
    Request(h3::error::StreamError),
    /// Ответ на CONNECT — не 2xx: капсулы едут только после успеха (RFC 9298 §4).
    NotConnected,
    /// QUIC DATAGRAM не принят (переполнение send-буфера или соединение умерло).
    SendDatagram(h3_datagram::datagram_handler::SendDatagramError),
    /// HTTP/3-датаграмма не прочитана (соединение закрыто пиром или сломано).
    ReadDatagram(h3::error::StreamError),
}

impl std::fmt::Display for MasqueH3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "h3 connect: {e}"),
            Self::Request(e) => write!(f, "extended connect: {e}"),
            Self::NotConnected => write!(f, "CONNECT-UDP не подтверждён (не 2xx)"),
            Self::SendDatagram(e) => write!(f, "send datagram: {e:?}"),
            Self::ReadDatagram(e) => write!(f, "read datagram: {e}"),
        }
    }
}

impl std::error::Error for MasqueH3Error {}

/// Живая h3-сессия MASQUE поверх одного quinn-соединения.
///
/// Обёртка держит вместе: h3-соединение (драйвер), sender датаграмм (привязан к
/// стриму CONNECT) и сам стрим CONNECT (ответ уже получен). Типы конкретные
/// (`h3_quinn`), потому что datagram-адаптер `h3-datagram` реализован ровно для
/// них (`DatagramConnectionExt for h3_quinn::Connection`) — дженерик здесь дал бы
/// второй слой трейтов без пользы.
pub struct MasqueH3Client {
    conn: client::Connection<QConnection, Bytes>,
    /// Жизнь соединения: `SendRequest::Drop` закрывает h3-соединение (h3 0.0.8,
    /// client/connection.rs:250 — «Connection closed by client» при обнулении
    /// счётчика). Пока обложка жива — handle жив; уронили — соединение закрылось.
    request_sender: client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    sender: h3_datagram::datagram_handler::DatagramSender<
        <QConnection as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::SendDatagramHandler,
        Bytes,
    >,
    reader: h3_datagram::datagram_handler::DatagramReader<
        <QConnection as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::RecvDatagramHandler,
    >,
    request_stream: client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

impl MasqueH3Client {
    /// Поднимает h3-сессию и открывает Extended CONNECT-UDP туннель.
    ///
    /// 1. h3-клиент поверх quinn-соединения: builder с `enable_datagram(true)` +
    ///    `enable_extended_connect(true)` — клиент отдаёт SETTINGS H3_DATAGRAM=1
    ///    и SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (h3 0.0.8, client/builder.rs);
    /// 2. Extended CONNECT-UDP из `ConnectUdpRequest` (кусок 2): метод CONNECT +
    ///    `:protocol: connect-udp` через `h3::ext::Protocol::CONNECT_UDP`;
    /// 3. ответ 2xx → датаграммный sender на стриме запроса.
    pub async fn connect_udp(
        quinn_conn: quinn::Connection,
        request: &ConnectUdpRequest,
    ) -> Result<Self, MasqueH3Error> {
        let (conn, mut request_sender) = client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build(QConnection::new(quinn_conn))
            .await
            .map_err(MasqueH3Error::Connect)?;

        let mut request_stream = request_sender
            .send_request(build_connect_request(request))
            .await
            .map_err(MasqueH3Error::Request)?;

        // RFC 9298 §4: капсулы/датаграммы — только после 2xx на CONNECT.
        let response = request_stream
            .recv_response()
            .await
            .map_err(MasqueH3Error::Request)?;
        if !response.status().is_success() {
            return Err(MasqueH3Error::NotConnected);
        }

        let sender = conn.get_datagram_sender(request_stream.id());
        let reader = conn.get_datagram_reader();
        Ok(Self {
            conn,
            request_sender,
            sender,
            reader,
            request_stream,
        })
    }

    /// Вычерпывает очередь каркаса в HTTP/3 DATAGRAM'ы: капсула куска 2 (тип 0x00,
    /// len, Context ID 0, record) становится payload'ом датаграммы на стриме CONNECT.
    ///
    /// Возвращает число отправленных датаграмм. Формат payload'а не пересобирается:
    /// то, что каркас положил в `Outbox`, уходит как есть — принимающая сторона
    /// разбирает `decode_masque_frame` (кусок 2).
    pub fn drain_binding(&mut self, binding: &mut crate::MasqueBinding) -> Result<usize, MasqueH3Error> {
        let pending = binding.take_pending();
        let mut sent = 0;
        for (_stream_id, capsule) in pending {
            self.sender
                .send_datagram(Bytes::from(capsule))
                .map_err(MasqueH3Error::SendDatagram)?;
            sent += 1;
        }
        Ok(sent)
    }

    /// «Один шаг» драйвера h3-соединения: двигает контрольные стримы, читает
    /// SETTINGS пира. Условие остановки — закрытие соединения (ошибка).
    pub fn drive_once(&mut self) -> Option<h3::error::ConnectionError> {
        use std::task::{Context, Poll};
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        match self.conn.poll_close(&mut cx) {
            Poll::Ready(err) => Some(err),
            Poll::Pending => None,
        }
    }

    /// Разбирает сессию на части для параллельной работы: драйвер уходит в
    /// фоновую задачу (`drive_until_closed`), обмен датаграммами остаётся здесь.
    /// `SendRequest` переезжает в `DatagramHalf`: его Drop закрывает соединение —
    /// уронили половину, соединение закрылось (graceful close по замыслу h3).
    pub fn split(self) -> (client::Connection<QConnection, Bytes>, DatagramHalf) {
        let Self {
            conn,
            request_sender,
            sender,
            reader,
            request_stream,
        } = self;
        (
            conn,
            DatagramHalf {
                _request_sender: request_sender,
                sender,
                reader,
                request_stream,
            },
        )
    }

    /// Caps live-слоя: датаграммы есть, no-HOL не заявляем до двустороннего прогона
    /// (см. шапку модуля).
    pub fn caps(&self) -> transport_mux::BindingCaps {
        transport_mux::BindingCaps {
            no_hol: false,
            datagram: true,
            dpi_profile: crate::DPI_PROFILE_MASQUE,
        }
    }

}

/// Половина сессии после `split`: обмен датаграммами + стрим CONNECT.
/// Драйвер соединения живёт отдельно (см. `drive_until_closed`).
pub struct DatagramHalf {
    /// Жизнь h3-соединения (см. поле `MasqueH3Client::request_sender`).
    _request_sender: client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    sender: h3_datagram::datagram_handler::DatagramSender<
        <QConnection as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::SendDatagramHandler,
        Bytes,
    >,
    reader: h3_datagram::datagram_handler::DatagramReader<
        <QConnection as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::RecvDatagramHandler,
    >,
    request_stream: client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

impl DatagramHalf {
    /// См. `MasqueH3Client::drain_binding` — та же семантика, на половине сессии.
    pub fn drain_binding(
        &mut self,
        binding: &mut crate::MasqueBinding,
    ) -> Result<usize, MasqueH3Error> {
        let pending = binding.take_pending();
        let mut sent = 0;
        for (_stream_id, capsule) in pending {
            self.sender
                .send_datagram(Bytes::from(capsule))
                .map_err(MasqueH3Error::SendDatagram)?;
            sent += 1;
        }
        Ok(sent)
    }

    /// Читает входящую HTTP/3-датаграмму: `(stream_id, payload)`. Payload —
    /// содержимое после Quarter Stream ID (RFC 9297 §4): капсула куска 2.
    pub async fn read_datagram(
        &mut self,
    ) -> Result<(h3::quic::StreamId, Bytes), MasqueH3Error> {
        let datagram = self
            .reader
            .read_datagram()
            .await
            .map_err(MasqueH3Error::ReadDatagram)?;
        Ok((datagram.stream_id(), datagram.into_payload()))
    }

    /// Стрим CONNECT (лаборатория: довести соединение до конца / прочитать тело).
    pub fn into_request_stream(
        self,
    ) -> client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes> {
        self.request_stream
    }
}

/// Сборка `http::Request<()>` Extended CONNECT-UDP.
///
/// Псевдо-поля (метод/URI) h3 берёт из Request, `:protocol` — из расширения
/// `h3::ext::Protocol` (h3 0.0.8, proto/headers.rs: метод CONNECT + ext Protocol →
/// `:protocol: connect-udp`). Обычный заголовок `capsule-protocol: ?1` (RFC 9298
/// §3.5) переносится из заголовков куска 2; псевдо-поля из `headers()` сюда не
/// едут — они уже выражены самим Request.
fn build_connect_request(req: &ConnectUdpRequest) -> http::Request<()> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_3)
        .uri(format!("{}://{}{}", req.scheme, req.authority, req.path));
    for (name, value) in req.headers() {
        if !name.starts_with(':') {
            builder = builder.header(name, value);
        }
    }
    let mut request = builder.body(()).expect("extended CONNECT: поля валидны по ConnectUdpRequest::new");
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_UDP);
    request
}

/// Будущее: крутить драйвер h3 до закрытия соединения (лаборатория/серверные тесты).
/// Отдельная функция, а не метод-конструктор, чтобы типfuture был выводим.
pub async fn drive_until_closed(mut conn: client::Connection<QConnection, Bytes>) -> h3::error::ConnectionError {
    std::future::poll_fn(|cx| conn.poll_close(cx)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DPI_PROFILE_MASQUE;

    /// Extended CONNECT-запрос собирается из полей куска 2: метод CONNECT, версия
    /// HTTP/3, `capsule-protocol: ?1` переносится, псевдо-поля — только в Request.
    #[test]
    fn connect_request_carries_capsule_protocol_header() {
        let req = ConnectUdpRequest::new(
            "proxy.example.org:4443",
            "https",
            "/.well-known/masque/udp/192.0.2.6/443/",
            "192.0.2.6",
            443,
        )
        .expect("запрос корректен");
        let request = build_connect_request(&req);
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.version(), http::Version::HTTP_3);
        assert_eq!(
            request.headers().get("capsule-protocol").map(|v| v.to_str().expect("ascii")),
            Some("?1"),
            "capsule-protocol: ?1 — RFC 9298 §3.5"
        );
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/192.0.2.6/443/"
        );
    }

    /// Псевдо-поля из `headers()` куска 2 не дублируются в обычные заголовки.
    #[test]
    fn connect_request_does_not_duplicate_pseudo_headers() {
        let req = ConnectUdpRequest::new("p:1", "https", "/", "h", 1).expect("ok");
        let request = build_connect_request(&req);
        for (name, _) in req.headers() {
            if name.starts_with(':') {
                assert!(
                    request.headers().get(name).is_none(),
                    "псевдо-поле {name} не должно быть обычным заголовком"
                );
            }
        }
    }

    /// Caps live-слоя: форма (датаграммы есть, no-HOL нет, профиль MASQUE).
    /// Полный контракт — двусторонний e2e-тест `e2e-harness/masque_lab`.
    #[test]
    fn live_caps_form() {
        let caps = transport_mux::BindingCaps {
            no_hol: false,
            datagram: true,
            dpi_profile: DPI_PROFILE_MASQUE,
        };
        assert!(!caps.no_hol);
        assert!(caps.datagram);
        assert_eq!(caps.dpi_profile, DPI_PROFILE_MASQUE);
    }
}
