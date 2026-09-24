# RouteVPN — полный гайд

RouteVPN — консольный VPN-клиент для Linux на базе mihomo. Он принимает обычные Clash/Mihomo YAML-подписки, списки `vless://`/`vmess://`/`ss://` и base64-подписки, маршрутизирует весь трафик через TUN, умеет выбирать узлы, задавать правила и раздавать интернет через Wi-Fi.

Команда клиента:

```bash
rvpn <команда>
```

Конфигурация хранится в `~/.config/routevpn` с правами `0600`.

HTTPS-подписки скачивает `curl`: это обходит несовместимость встроенного загрузчика mihomo с некоторыми серверами. При добавлении и команде `rvpn update` файл проверяется и сохраняется локально. Обновление сейчас запускается вручную.

## Установка

```bash
git clone https://github.com/zoemavo/route-vpn.git
cd route-vpn
python3 -m pip install --user PyYAML
chmod +x routevpn.py
ln -s "$PWD/routevpn.py" ~/.local/bin/rvpn
sudo ln -s "$PWD/routevpn.py" /usr/local/bin/rvpn
```

Установите `mihomo` из пакетов своего дистрибутива или положите официальный бинарник `mihomo` в каталог проекта. Также нужны `curl` и `iproute2`. Для точки доступа установите `iwd` либо `hostapd`, а также `dnsmasq` и `nftables`.

## Быстрый старт

```bash
rvpn sub add myvpn 'https://example.org/my-subscription'
rvpn uplink wlan0
sudo rvpn run
```

`run` занимает текущий терминал. Остановить VPN можно `Ctrl+C`. После запуска в другом терминале:

```bash
rvpn status
rvpn nodes
rvpn node 'имя узла'
rvpn update
```

Для обычного приложения прокси без изменения системных маршрутов: `rvpn run --proxy-only`. Прокси слушает `127.0.0.1:17890` и одновременно принимает HTTP и SOCKS5.

Важно: TUN требует root, поэтому используется именно `sudo rvpn run`. Если написать просто `rvpn run`, клиент покажет понятную ошибку.

## Подписки

```bash
rvpn sub add myvpn 'https://example.org/my-subscription'
rvpn sub add local /path/to/subscription.txt
rvpn sub list
rvpn sub use myvpn
rvpn sub remove local
rvpn update
```

HTTPS-ссылку клиент скачивает через `curl`, проверяет и сохраняет локально. Это нужно для подписок, которые не работают через встроенный загрузчик mihomo. `rvpn update` повторяет скачивание вручную. Автоматического фонового обновления пока нет.

Поддерживаются:

- Mihomo/Clash YAML;
- строки URI (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `tuic://`);
- base64, внутри которого находятся такие URI.

## Узлы и состояние

```bash
rvpn status
rvpn nodes
rvpn node '🇹🇷 Soda VPN | Турция'
```

`status` показывает активную подписку, выбранный узел и количество доступных узлов. `nodes` печатает имена узлов по одному на строку. При каждом `rvpn run` клиент переключается на `AUTO`, измеряет задержку серверов и использует самый быстрый доступный узел. Если ни один сервер не ответил, запуск прерывается и обычное соединение восстанавливается. `rvpn node ИМЯ` позволяет выбрать сервер вручную до следующего запуска.

Проверить внешний IP через локальный прокси:

```bash
curl --proxy http://127.0.0.1:17890 https://api.ipify.org
```

## Физический интерфейс выхода

```bash
rvpn uplink wlan0
rvpn uplink
rvpn uplink auto
```

`uplink wlan0` заставляет VPN подключаться к серверам через физический `wlan0`, обходя другой существующий VPN вроде Happ. `auto` возвращает автоматический выбор интерфейса. После изменения перезагрузите работающий конфиг:

```bash
sudo rvpn reload
```

## Подписки и правила

```bash
rvpn sub add backup /path/to/subscription.txt
rvpn sub use backup
rvpn route add suffix example.org direct
rvpn route add cidr 203.0.113.0/24 block
rvpn route add src-cidr 10.77.0.50/32 direct
rvpn route add dst-port 25 block
rvpn route add process firefox vpn
rvpn route list
rvpn route remove 1
sudo rvpn reload
```

Последнее правило всегда `MATCH,VPN`. Действия: `vpn`, `direct`, `block`. Типы: `domain`, `suffix`, `cidr`, `src-cidr`, `dst-port`, `process`. Правила проверяются сверху вниз. `src-cidr` особенно полезен для клиентов Wi-Fi-точки доступа.

Если подписка пуста, группа AUTO использует `REJECT`. Для DNS основного трафика настроен DoH через группу VPN; разрешение адреса самого VPN-сервера выполняется через публичный DNS `1.1.1.1` для начального подключения. Правила `process` действуют для процессов этого компьютера, а `cidr` в этой версии относится к IPv4.

## Локальная переадресация порта

```bash
rvpn port add web 8080 example.org:443 --network tcp
rvpn port add game 27015 game.example.org:27015 --network udp --listen 10.77.0.1
rvpn port list
rvpn port remove web
sudo rvpn reload
```

Порт `8080` слушает на самом компьютере и соединяется с `example.org:443` через выбранный VPN-узел. Для доступа со стороны локальной сети укажите её IP в `--listen`. Это не создаёт публичный входящий порт на сервере провайдера VPN: для него нужна поддержка проброса у провайдера или доступ к своему серверу.

## Раздача через Wi-Fi

Сначала в одном терминале запустите VPN:

```bash
sudo rvpn run
```

Затем во втором терминале включите раздачу через второй адаптер:

```bash
sudo rvpn hotspot run --iface wlan1 --ssid RouteVPN
```

Для совместного использования одного адаптера как клиента и точки доступа:

```bash
sudo rvpn hotspot run --iface rvpn_ap --virtual-from wlan0 --ssid RouteVPN
```

Пароль вводится без отображения. Его можно передать в файле с правами `0600`:

```bash
sudo rvpn hotspot run --iface rvpn_ap --virtual-from wlan0 --ssid RouteVPN \
  --password-file /root/routevpn-wifi-password
```

Клиентам выдаются адреса `10.77.0.50–200/24`, шлюз — `10.77.0.1`. Правило `nft` блокирует выход клиентов через любой интерфейс, кроме `rvpn0`, поэтому при падении VPN они теряют интернет вместо утечки в обычную сеть. `Ctrl+C` останавливает AP. Из другого терминала: `sudo rvpn hotspot stop`.

Один адаптер может одновременно работать в режиме клиента и AP только если драйвер это поддерживает и обе роли используют один канал. На этом компьютере виртуальный AP проверен на канале 36 одновременно с TUN и подключённым `wlan0`.

## Диагностика

```bash
rvpn status
ip -brief link
ip route get 1.1.1.1
rvpn nodes | wc -l
```

Ожидаемый TUN-интерфейс называется `rvpn0`. Для него маршрут должен показывать `dev rvpn0 table 2022`. Если нужно проверить только локальный прокси, используйте `rvpn run --proxy-only` и не запускайте второй экземпляр одновременно.

Частые ошибки:

- `TUN требует root` — запускайте `sudo rvpn run`.
- `rvpn: command not found` после `sudo` — создайте системную ссылку `/usr/local/bin/rvpn`, как показано в разделе установки, затем выполните `hash -r`.
- `address already in use` — уже запущен другой экземпляр; найдите его через `ps -C mihomo -o pid,uid,args`.
- нет узлов — выполните `rvpn update`, затем `rvpn status`.
- AP не стартует — проверьте, что адаптер поддерживает AP, и что `--virtual-from` использует подключённый интерфейс.

## Остановка и восстановление

Остановка VPN: `Ctrl+C` в терминале, где запущен `rvpn run`. Остановка точки доступа: `sudo rvpn hotspot stop`. Клиент удаляет `rvpn0`, временное правило `nft`, виртуальный AP и возвращает прежнее значение IPv4 forwarding.

## Зависимости

- Python 3 и PyYAML
- mihomo в `PATH` или исполняемый файл `mihomo` в каталоге проекта
- Для точки доступа: iwd (отдельный Wi-Fi адаптер) или hostapd (виртуальный AP), dnsmasq, nftables, iproute2

Официальная документация: [форматы подписок](https://wiki.metacubex.one/en/config/proxy-providers/content/), [TUN](https://wiki.metacubex.one/en/config/inbound/tun/), [правила](https://wiki.metacubex.one/en/config/rules/), [iwd AP](https://man.archlinux.org/man/iwd.ap.5).

Проверка: `python3 -m unittest discover -s tests -v`.
