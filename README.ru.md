# Xray-core (форк VLESS L3 / VPN)

[English](./README.md) · [Русский](./README.ru.md)

Это soft-форк [XTLS/Xray-core](https://github.com/XTLS/Xray-core), превращающий протокол VLESS из stream-прокси в полноценный VPN на уровне L3. Подключившийся клиент получает виртуальный IP внутри настраиваемой подсети, может обращаться к сервисам на хосте сервера через gateway-IP и общаться с другими клиентами peer-to-peer. Остальная часть Xray-core (REALITY, XHTTP, XUDP, routing, sniffing, балансировщики и т. д.) остаётся побайтово совместимой с upstream — стандартная конфигурация VLESS-REALITY запускается на этой сборке без каких-либо изменений в поведении.

> **Статус: тестирование.** Релизы тегаются как `v0.0.x-test`, пока стабилизируются протокольные расширения и формат на проводе. Деплоить вместе с обычными (без VPN) VLESS-клиентами на один и тот же inbound безопасно, но привязывать прод-юзеров к конкретному test-релизу пока не стоит.

## Что добавляет этот форк

| | Upstream Xray-core | Этот форк |
|---|---|---|
| VLESS как stream-прокси (TCP / UDP по соединению) | ✓ | ✓ |
| Виртуальный IPv4 на каждого клиента внутри подсети | — | ✓ |
| Kernel TUN-интерфейс на клиенте (Linux / Darwin) | — | ✓ |
| `ping` / ICMP сквозь туннель | — | ✓ |
| Peer-to-peer между подключёнными клиентами (10.0.0.x ↔ 10.0.0.y) | — | ✓ |
| Доступ к сервисам хоста VPS через gateway-IP (`curl http://10.0.0.1:port`) | — | ✓ |
| `inbound.Tag` пробрасывается на L3 sub-flow, чтобы правила `inboundTag:` работали | — | ✓ |

Видимая пользователю конфигурация — это один опциональный блок `virtualNetwork` на VLESS inbound (на сервере) и на VLESS outbound (на клиенте). Когда блок отсутствует, VLESS ведёт себя в точности как upstream.

## Как это работает (в одном абзаце)

При подключении клиент шлёт расширенный VLESS-запрос с UUID пользователя. IPAM на сервере выдаёт (или вспоминает) виртуальный IPv4 из настроенной подсети для этого UUID, отвечает 4-байтовой преамбулой `(назначенный_ip, gateway_ip, длина_префикса)`, и дальше обе стороны обмениваются сырыми IPv4-пакетами по тому же VLESS-стриму с 2-байтовой длиной префикса. На сервере пакеты попадают в userspace netstack [gVisor](https://github.com/google/gvisor): TCP/UDP, адресованные другим клиентам, форвардятся напрямую между их стримами, а TCP/UDP, адресованные на gateway, переписываются на loopback и идут через обычную outbound-цепочку Xray (routing-правила, freedom, blackhole, правила по `domain:` и т. д. — всё работает как раньше). На клиенте под Linux и macOS outbound поднимает kernel TUN-интерфейс (по умолчанию `xray0`), присваивает виртуальный IP и пробрасывает 1:1 пакеты в framed VLESS-стрим.

## Пример конфига сервера

Добавь блок `virtualNetwork` в свой VLESS inbound:

```jsonc
{
  "inbounds": [
    {
      "tag": "inbound-443",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "11111111-1111-1111-1111-111111111111", "email": "alice" },
          { "id": "22222222-2222-2222-2222-222222222222", "email": "bob"   }
        ],
        "decryption": "none",
        "virtualNetwork": {
          "enabled": true,
          "subnet": "10.0.0.0/24"
        }
      },
      "streamSettings": { /* REALITY / XHTTP / и т. д. — без изменений */ }
    }
  ]
}
```

| Поле | По умолчанию | Что делает |
|---|---|---|
| `enabled` | `false` | Главный выключатель. Если `false` — inbound ведёт себя как обычный VLESS upstream. |
| `subnet` | `10.0.0.0/24` | IPv4-подсеть, которую раздаёт IPAM. Первый адрес из подсети резервируется под gateway. |

IP-адреса выдаются по порядку и стабильны. Первому клиенту достаётся `10.0.0.2`, второму `10.0.0.3` и так далее — всегда выбирается самый низкий свободный адрес выше gateway. Связь `UUID → IP` записывается на диск (`<asset-dir>/virtualnet-ipam-<subnet>.json`), поэтому вернувшийся клиент всегда получает тот же адрес даже после рестарта xray. Если клиента удаляют из inbound’а (через панель или из `clients[]`, пока xray выключен) — его слот освобождается и достаётся следующему новому пользователю.

Gateway-IP (например, `10.0.0.1` для `10.0.0.0/24`) занят netstack'ом gVisor. Соединения, адресованные на gateway, переписываются на `127.0.0.1` хоста — чтобы попадали в сервисы, слушающие на `0.0.0.0` или loopback. Соединения на другие адреса внутри подсети сверяются с IPAM и форвардятся в стрим владельца этого IP (peer-to-peer). Соединения вне подсети идут через обычную outbound-цепочку Xray (routing-правила, freedom, blackhole, …).

## Пример конфига клиента (Linux / macOS)

Outbound на клиенте создаёт kernel TUN-устройство. **Нужен root** (или `cap_net_admin`).

```jsonc
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "vps.example.com",
          "port":    443,
          "users": [{
            "id":         "11111111-1111-1111-1111-111111111111",
            "encryption": "none",
            "flow":       ""
          }]
        }],
        "virtualNetwork": {
          "enabled":       true,
          "subnet":        "10.0.0.0/24",
          "interfaceName": "xray0",
          "mtu":           1420,
          "defaultRoute":  true
        }
      },
      "streamSettings": { /* REALITY / XHTTP / и т. д. */ }
    }
  ]
}
```

| Поле | По умолчанию | Что делает |
|---|---|---|
| `enabled` | `false` | Главный выключатель. Если `false` — outbound ведёт себя как обычный VLESS upstream. |
| `subnet` | `10.0.0.0/24` | Должна совпадать с серверной. |
| `interfaceName` | `xray0` | Имя kernel TUN-устройства, которое создаётся на хосте. |
| `mtu` | `1420` | MTU TUN-интерфейса. Дефолт оставляет запас под VLESS / TLS / IP-заголовки ниже. |
| `defaultRoute` | `true` | Если `true` — outbound меняет default route хоста через TUN, то есть **весь** трафик идёт через туннель. Поставь `false` для split-tunnel: через TUN ходит только подсеть, остальной трафик — по существующему default route. |

После `xray run` на хосте должно быть:

```
$ ip addr show xray0
xray0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>
    inet 10.0.0.45/24 scope global xray0

$ ping 10.0.0.1                # gateway (gVisor-стек на сервере)
$ curl http://10.0.0.1:8080    # сервис на хосте VPS на 0.0.0.0:8080
$ ping 10.0.0.46               # другой подключённый клиент (peer-to-peer)
$ curl https://example.com     # только если defaultRoute=true
```

## Расширения `vless://` ссылки

Парсер `vless://` URI в форке понимает три дополнительных query-параметра, чтобы одна share-ссылка несла в себе VPN-конфиг:

| Параметр | Что значит |
|---|---|
| `vnet=1` | Включить `virtualNetwork` на outbound. |
| `vnetSubnet=10.0.0.0/24` | Переопределить `subnet`. Слэш кодируй как `%2F`. |
| `vnetDefaultRoute=1` / `vnetDefaultRoute=0` | Переопределить `defaultRoute`. |

Полная share-ссылка выглядит так:

```
vless://<uuid>@vps.example.com:443?type=tcp&security=reality&pbk=...&fp=chrome&sni=...&sid=...&spx=%2F&vnet=1&vnetSubnet=10.0.0.0%2F24&vnetDefaultRoute=1#vps
```

Клиенты, которые не понимают новые параметры, просто их игнорируют и продолжают работать как обычный VLESS-прокси.

## 3x-ui (companion-форк)

Если хочется панель с UI для новых полей (тумблер `virtualNetwork` на каждый inbound, редактор подсети, генератор share-ссылок с параметрами `vnet*`) — есть companion-форк 3x-ui:

- https://github.com/sevaktigranyan305-netizen/3x-ui

В каждом релизном tarball-е лежит соответствующий бинарь Xray-core, поэтому одна команда `x-ui update` на сервере обновляет одновременно и панель, и core.

## Routing-правила

L3 sub-flow на стороне сервера оказываются в диспатчере Xray с тремя кусками контекста, которые routing-правила могут матчить:

- `sourceIP` — виртуальный IP клиента (например, `10.0.0.42`).
- `inboundTag` — tag исходного VLESS inbound, проброшенный с родительского соединения.
- `domain` (когда срабатывает sniffing) — снятый с HTTP/TLS как у любого другого inbound.

То есть правила вида `{"inboundTag":["inbound-443"], "domain":["geosite:cn"], "outboundTag":"direct"}` продолжают работать для туннельного трафика ровно так же, как и для обычного VLESS. Sniffing на L3 sub-flow запущен в режиме `RouteOnly` — снятые домены идут в роутинг, но не подменяют destination диспатча, поэтому gateway-IP rewrite и быстрый peer-to-peer путь остаются нетронутыми.

## Сборка

Сборка не отличается от upstream:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid=" -v ./main
```

Reproducible / кросс-платформенные сборки, вариант под Windows PowerShell и нюанс 32-битных MIPS такие же, как в upstream — полный набор смотри в [README upstream Xray-core](https://github.com/XTLS/Xray-core#one-line-compilation).

Готовые бинарники для каждого test-тега лежат в каждом [релизе](https://github.com/sevaktigranyan305-netizen/Xray-core/releases) (Linux / macOS / Windows / FreeBSD / Android — amd64, arm64, 386, arm, mips, mipsle, riscv64 и т. д., всего 22 ассета).

## Совместимость и ограничения

- **Платформы сервера:** любая платформа, которую поддерживает сам Xray-core — серверная часть работает только через gVisor и не трогает ядро.
- **Платформы клиента:** kernel TUN работает на Linux и macOS (Darwin). Windows / Android / iOS клиенты тоже подключаются, но TUN они поднимают через свою платформенную обвязку (например, через VPN-сервис Android) — смотри документацию своего клиента.
- **IPv6:** виртуальная подсеть только IPv4. Сам VLESS-транспорт (слой TLS / REALITY / XHTTP под ним) может ходить и по v4, и по v6.
- **NAT / port-forwarding из публичного интернета на пир:** вне области применения. Пиры могут общаться друг с другом и с хостом сервера, но извне они недоступны, если ты не публикуешь их сам.
- **Расширения `vless://` URI** (`vnet`, `vnetSubnet`, `vnetDefaultRoute`) — это договорённость уровня форка; share-ссылки, сгенерённые здесь, остаются валидными обычными VLESS-ссылками для клиентов, которые VPN-режим не поддерживают.

## Кредиты

- Upstream [Xray-core](https://github.com/XTLS/Xray-core) — всё, кроме пакета `proxy/vless/virtualnet/` и небольших dispatch-glue патчей в `proxy/vless/inbound`, `proxy/vless/outbound` и `infra/conf` — это upstream Xray-core под MPL-2.0.
- [gVisor](https://github.com/google/gvisor) — userspace netstack, на котором работает серверная часть.
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — обёртка над kernel TUN-устройством, используемая на клиенте.

## Лицензия

[Mozilla Public License 2.0](./LICENSE) — та же, что и в upstream Xray-core.
