# DPI Pilot

Компактный плагин Omarchy для обхода DPI через [zapret2](https://github.com/bol-van/zapret2). Один значок в баре, одно небольшое окно, никаких вкладок, списков и простыней настроек.

Плагин сам **генерирует стратегии**: собирает конфигурации `nfqws2` из примитивов (fake, multisplit, multidisorder, TTL, seq, QUIC), применяет их по очереди, проверяет YouTube, Discord и Google и оставляет ту, что реально работает быстрее. Готовые пресеты не используются.

Это отдельное решение, не форк и не надстройка над `omarchy-usque` или `omarchy-zapret2`. WARP/туннеля здесь нет — только DPI-обход.

## Что в интерфейсе

- **Тумблер** — включить или выключить обход.
- **Доступность** — три точки: YouTube, Discord, Google. Зелёная — сайт открылся, красная — нет, пустая — ещё не проверяли.
- **Подобрать** — перебирает 12 сгенерированных стратегий и показывает прогресс прямо в попапе.
- **Проверить** — одна проверка текущего состояния, без перезапуска.
- **Сохранённые** — до трёх лучших вариантов, можно переключиться одним нажатием.
- **Дополнительно** — версия движка, обновление и удаление.

Правый клик по «DPI» включает и выключает обход, средний запускает проверку. Горячие клавиши в попапе: `G` — подбор, `C` — проверка, `R` — обновить, `Esc` — закрыть.

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
| `/opt/kich-dpi/` | `nfqws2`, Lua-библиотеки, фейки и копия менеджера |
| `/etc/systemd/system/kich-dpi.service` | служба обхода |
| `/etc/polkit-1/rules.d/49-kich-dpi.rules` | запуск/остановка без пароля |
| `/etc/sysctl.d/90-kich-dpi.conf` | `nf_conntrack_tcp_be_liberal=1` |
| `~/.config/kich-dpi/active.json` | выбранная стратегия |
| `~/.config/kich-dpi/strategies.json` | сохранённые варианты |
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

Обход применяется ко всему TCP 80/443 и UDP 443, поэтому списки доменов не нужны. Пакеты внутри TUN (если рядом работает WARP) пропускаются правилом `meta oiftype 65534 return`.

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
pkexec bin/kich-dpi setup      # поставить/обновить движок
pkexec bin/kich-dpi remove [--purge]
```

IPC из шелла:

```bash
omarchy-shell kich.dpi-pilot toggle     # открыть попап
omarchy-shell kich.dpi-pilot service    # включить/выключить обход
omarchy-shell kich.dpi-pilot check
omarchy-shell kich.dpi-pilot generate
```

## Диагностика

- `journalctl -u kich-dpi -f` — журнал `nfqws2` и менеджера.
- `bin/kich-dpi doctor` — движок, юнит, polkit, curl, nft, конфликт с `omarchy-zapret2`.
- Если служба падает сразу после старта, проверьте, что ядро поддерживает `nf_tables`/`NFQUEUE` и что другой обход не держит очередь `230`.
- После смены сети подбор стоит повторить: у разных провайдеров работают разные комбинации.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Тесты собирают конфигурации, проверяют уникальность стратегий и, если найден `nfqws2`, прогоняют каждую через `--dry-run`. Системные пути и сеть не трогаются.

## Лицензия

Код плагина — MIT (см. `LICENSE`). Движок скачивается отдельно из [bol-van/zapret2](https://github.com/bol-van/zapret2); условия upstream-проекта смотрите в его репозитории.
