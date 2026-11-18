# DPI Pilot

Компактный плагин Omarchy для обхода DPI через [zapret2](https://github.com/bol-van/zapret2). Один значок в баре, одно небольшое окно, никаких вкладок, списков и простыней настроек.

Плагин сам **генерирует стратегии**: собирает конфигурации `nfqws2` из примитивов (fake, multisplit, multidisorder, TTL, seq, QUIC), применяет их по очереди, проверяет YouTube, Discord и Google и оставляет ту, что реально работает быстрее. Готовые пресеты не используются.

Это отдельное решение, не форк и не надстройка над `omarchy-usque` или `omarchy-zapret2`. Кроме DPI-обхода есть необязательный **WARP** — свой генератор конфига для mihomo (MASQUE, без `wgcf` и без клиента Cloudflare).

## Что в интерфейсе

- **Тумблер** — включить или выключить обход.
- **WARP** — второй тумблер: туннель Cloudflare через MASQUE. При первом включении сам регистрирует устройство и собирает конфиг.
- **Доступность** — три точки: YouTube, Discord, Google. Зелёная — сайт открылся, красная — нет, пустая — ещё не проверяли.
- **Подобрать** — перебирает 12 сгенерированных стратегий и показывает прогресс прямо в попапе.
- **Проверить** — одна проверка текущего состояния, без перезапуска.
- **Сохранённые** — до трёх лучших вариантов, можно переключиться одним нажатием.
- **Дополнительно** — версия движка, обновление и удаление.

Правый клик по «DPI» включает и выключает обход, средний запускает проверку. Горячие клавиши в попапе: `G` — подбор, `C` — проверка, `W` — WARP, `R` — обновить, `Esc` — закрыть.

## Установка

Из локального каталога:

```bash
ln -s ~/Work/omarchy-dpi-pilot ~/.config/omarchy/plugins/kich.dpi-pilot
omarchy restart shell
omarchy bar put kich.dpi-pilot
```

Или как обычный плагин:

```bash
omarchy plugin add https://github.com/kichcloud/omarchy-dpi-pilot.git --enable --yes
```

Дальше — кнопка **Установить** в попапе. Установка скачивает официальный релиз `bol-van/zapret2`, сверяет `sha256` из GitHub и один раз спрашивает пароль через `pkexec`. Движок и системный юнит живут отдельно от других плагинов:

| Путь | Что |
| --- | --- |
| `/opt/kich-dpi/` | `nfqws2`, Lua-библиотеки, фейки, `mihomo` и копия менеджера |
| `/etc/systemd/system/kich-dpi.service` | служба обхода |
| `/etc/systemd/system/kich-dpi-warp.service` | служба WARP (mihomo) |
| `/etc/polkit-1/rules.d/49-kich-dpi.rules` | запуск/остановка без пароля |
| `/etc/sysctl.d/90-kich-dpi.conf` | `nf_conntrack_tcp_be_liberal=1` |
| `~/.config/kich-dpi/active.json` | выбранная стратегия |
| `~/.config/kich-dpi/strategies.json` | сохранённые варианты |
| `~/.config/kich-dpi/warp.yaml` | сгенерированный конфиг mihomo |
| `~/.local/share/kich-dpi/account.json` | ключи WARP-устройства (0600) |
| `~/.local/state/kich-dpi/` | результаты проверок и прогресс подбора |

Свои nftables-таблица `inet kich_dpi`, очередь `230` и метка `0x10000000` не пересекаются с `omarchy-zapret2`. Но два DPI-обходчика одновременно перехватывать один и тот же трафик не должны: попап предупредит, если `omarchy-zapret2.service` активен.

## Как работает подбор

`bin/kich-dpi generate` строит 12 конфигураций из комбинаций:

- fake + multisplit / multidisorder;
- fakedsplit / fakeddisorder;
- позиции `1`, `2`, `midsld`, `1,midsld`, `sld+1`;
- фулинг `tcp_md5`, `ip_ttl`, `tcp_seq`, `tcp_flags_unset=ack`;
- fake для TLS и QUIC, разное число повторов.

Для каждой стратегии служба перезапускается, затем три запроса `curl` измеряют код ответа и время. Сортировка: сначала число открывшихся сайтов, потом суммарное время. В конце применяется лучшая стратегия; если ни одна не лучше текущей, остаётся текущая. Всё это видно в попапе как «N / 12» и название текущей конфигурации.

Обход применяется ко всему TCP 80/443 и UDP 443, поэтому списки доменов не нужны. Пакеты внутри TUN (если рядом работает WARP) пропускаются правилом `meta oiftype 65534 return`, а адреса MASQUE-шлюзов Cloudflare исключены из очереди отдельно — иначе обход ломал бы рукопожатие самого туннеля. Отдельно пропускается метка `0x20000000`: её mihomo ставит на свои сокеты (`routing-mark`), и без этого desync применялся к прямому трафику из его userspace-стека — Госуслуги, например, переставали открываться.

## WARP (необязательно)

WARP здесь — не `wgcf` и не `warp-cli`, а свой генератор:

1. при первом включении менеджер создаёт ключ P-256 через `openssl` и регистрирует устройство напрямую в Cloudflare API с `tunnel_type=masque`;
2. собирает `~/.config/kich-dpi/warp.yaml` для mihomo: TUN `kichwarp`, MASQUE поверх HTTP/2, fake-IP DNS;
3. запускает `kich-dpi-warp.service` от вашего пользователя с `CAP_NET_ADMIN`.

Почему MASQUE, а не WireGuard: в российских сетях классический WG-WARP узнаётся и режется DPI, а MASQUE идёт по TCP 443. Почему mihomo, а не клиент Cloudflare: нужен конфиг с исключениями. Российские домены (Яндекс, VK, Госуслуги, банки, Ozon, Avito и другие), локальная сеть и частные подсети идут напрямую, остальное — через туннель. QUIC (UDP 443) тоже идёт через туннель: браузер пробует его первым, и напрямую он висит около десяти секунд, из-за чего страница выглядит мёртвой. Остальной UDP — звонки, игры, локальная сеть — остаётся напрямую. `warp-cli` так не умеет: consumer-клиент гонит в туннель весь трафик.

Шлюз один и закреплён — `162.159.198.2` (H2, тот же, что у клиентов WARP). Пул из четырёх адресов с выбором по задержке оказался хуже: `197.2` и `196.2` отвечают `alive: false`, а `.1`-двойники отдают другой ключ и падают на `x509: remote endpoint has a different public key`. Переключения между шлюзами срывали часть рукопожатий; с закреплённым шлюзом их не стало.

YouTube в России режется по IPv4, а WARP выходит из Москвы (`colo=DME`) — то есть в том же проблемном месте, и обычный туннель проблему не решает. Поэтому прокси просит IPv6 у DNS (`ip-version: ipv6-prefer`): YouTube уходит по IPv6 внутри туннеля. Замер: 7 из 15 запросов по IPv4 против 15 из 15 по IPv6; в реальном TUN с DPI — 29 из 30. Домены без AAAA автоматически идут по IPv4.

Оба движка работают одновременно, но с чужими туннелями WARP не уживается: если активен `omarchy-usque.service`, тумблер WARP покажет причину и не запустится — два TUN дерутся за маршрут по умолчанию.

## Команды

`bin/kich-dpi` — обычный исполняемый файл, все ответы в JSON:

```bash
bin/kich-dpi status            # состояние для панели
bin/kich-dpi on | off | toggle # включить/выключить
bin/kich-dpi check             # проверить три сайта
bin/kich-dpi generate          # сгенерировать и измерить стратегии
bin/kich-dpi strategies        # сохранённые варианты
bin/kich-dpi use <id>          # применить сохранённую
bin/kich-dpi doctor            # диагностика
bin/kich-dpi logs 100          # журнал службы
pkexec bin/kich-dpi setup      # поставить/обновить движок и mihomo
pkexec bin/kich-dpi remove [--purge]

bin/kich-dpi warp-on | warp-off | warp-toggle
bin/kich-dpi warp-register     # перерегистрировать аккаунт Cloudflare
bin/kich-dpi warp-check        # идёт ли трафик через WARP
```

IPC из шелла:

```bash
omarchy-shell kich.dpi-pilot toggle     # открыть попап
omarchy-shell kich.dpi-pilot service    # включить/выключить обход
omarchy-shell kich.dpi-pilot warp       # включить/выключить WARP
omarchy-shell kich.dpi-pilot check
omarchy-shell kich.dpi-pilot generate
```

## Диагностика

- `journalctl -u kich-dpi -f` — журнал `nfqws2` и менеджера.
- `journalctl -u kich-dpi-warp -f` — журнал mihomo.
- `bin/kich-dpi doctor` — движок, mihomo, аккаунт WARP, юниты, polkit, curl, nft, конфликты с `omarchy-zapret2` и `omarchy-usque`.
- Если служба падает сразу после старта, проверьте, что ядро поддерживает `nf_tables`/`NFQUEUE`, есть `/dev/net/tun` и что другой обход не держит очередь `230`.
- WARP не поднялся: `bin/kich-dpi warp-check` покажет `warp=on/off`, а `warp-register` пересоздаст аккаунт, если Cloudflare его отклонил.
- После смены сети подбор стоит повторить: у разных провайдеров работают разные комбинации.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Тесты собирают конфигурации, проверяют уникальность стратегий и, если найден `nfqws2`, прогоняют каждую через `--dry-run`. Конфиг WARP проверяется как YAML, а при наличии бинарника — через `mihomo -t`:

```bash
KICH_DPI_ENGINE_DIR=/opt/kich-dpi/engine/current \
KICH_DPI_MIHOMO=/opt/kich-dpi/mihomo \
python3 -m unittest discover -s tests -v
```

## Лицензия

Код плагина — MIT (см. `LICENSE`). Движок скачивается отдельно из [bol-van/zapret2](https://github.com/bol-van/zapret2); условия upstream-проекта смотрите в его репозитории.
