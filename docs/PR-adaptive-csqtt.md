# Изменения для PR в anton48/vk-turn-proxy-ios

Исходная версия: `6c41641dd6fc200a568ef565cf9d202dc4ccf907`.

Обе функции относятся только к **CSQTT**. Они включаются отдельно в редакторе
сервера и по умолчанию выключены. Остальные режимы приложения и формат
протокола не меняются; обновление сервера не требуется.

## Что подготовлено

1. `codex/csqtt-auto-transport`: автоматический выбор UDP/TCP для новых
   соединений, ограничение времени запуска, резервный транспорт после
   сетевого отказа и сброс оценки при смене сети. Ручной выбор сохраняется.
2. `codex/csqtt-quality-scheduler`: оба изменения вместе. Второй коммит
   добавляет ограниченные очереди отправки и уменьшает долю соединений с
   медленной отправкой или накопившейся очередью.

Вторая ветка основана на первой. Самый простой вариант — один PR из второй
ветки с двумя содержательными коммитами. Если автор предпочитает два PR,
сначала отправить первый, а после его принятия перебазировать вторую ветку
на актуальный `main`. Не отправлять два независимых PR в `main`, скрывая,
что второй пока содержит изменения первого.

## Заголовок общего PR

Add opt-in adaptive transport and connection scheduling for CSQTT

## Описание общего PR

Adds two optional settings to CSQTT profiles:

- Automatic UDP/TCP selection for new sessions, with bounded startup,
  fallback after connectivity failures and a fresh policy after path changes.
- Bounded per-worker write queues and weighted chunk scheduling, so a blocked
  relay does not stall writes to healthy relays.

Both settings default to off and survive profile backup/restore. Manual
UDP/TCP selection and the other tunnel modes are unchanged. No server or
wire-format changes are required.

Transport selection uses GETCONF completion latency, not sustained throughput.
Scheduling uses local write backpressure, not inferred packet loss. Healthy
sessions are not interrupted just to compare transports. Queued packets from
an old allocation are discarded rather than sent through its replacement.

Tests cover fallback, manual modes, network changes, quota refusals, cancelled
TURN allocation, weighted scheduling, queue limits and a blocked writer next
to a healthy relay. Physical-device throughput, loaded latency and energy
measurements are still needed before enabling either setting by default.

## Если нужны два PR

Первый: **Add opt-in automatic UDP/TCP selection for CSQTT**.

New CSQTT sessions can select UDP or TCP automatically. Connectivity failures
temporarily penalize a transport, startup has a bounded budget, and a network
change clears previous samples. Manual selection remains available. The
setting defaults to off; no server changes are needed. Selection compares
GETCONF completion latency, not continuous download/upload speed.

Второй: **Keep slow CSQTT relays from blocking healthy connections**.

Adds optional bounded per-worker write queues and backpressure-weighted chunk
scheduling. Slow connections get shorter chunks without being starved; the
existing maximum chunk size is unchanged. Queues are limited by packet count
and bytes, and packets are tied to their allocation epoch. The option
defaults to off. A local blocked-relay test verifies that another relay can
still deliver traffic; real-device performance is not yet measured.

## Публикация

1. Создать свой fork именно `anton48/vk-turn-proxy-ios` на GitHub.
2. В терминале открыть каталог проекта:

   ```sh
   cd /Users/igor/Documents/ChatGPT/network/vk-turn-proxy-ios
   ```

3. Добавить адрес своего fork, заменив `YOUR_LOGIN` на свой логин:

   ```sh
   git remote add fork https://github.com/YOUR_LOGIN/vk-turn-proxy-ios.git
   git push -u fork codex/csqtt-auto-transport
   git push -u fork codex/csqtt-quality-scheduler
   ```

4. Для общего PR выбрать на GitHub: **base repository**
   `anton48/vk-turn-proxy-ios`, **base** `main`, **head repository** свой fork,
   **compare** `codex/csqtt-quality-scheduler`.
5. Вставить заголовок и описание выше. Разумно открыть как **Draft**, пока нет
   измерений на физическом iPhone.

Публикация на GitHub и установка на телефон в этой работе не выполнялись.

## Проверки

Команды из корня репозитория:

```sh
go test -race ./pkg/... -count=1 -timeout=180s
go vet ./pkg/...
./tools/swiftcheck/run.sh
```

В `WireGuardBridge`:

```sh
go test -race . -count=1 -timeout=120s
go vet .
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer make xcframework
```

Здесь используется `.`: сборка создаёт внутри `build/goroot` копию Go,
а `./...` ошибочно захватывает тестовые файлы самого компилятора.

Сборка приложения без подписи, из корня:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild \
  -project VKTurnProxy/VKTurnProxy.xcodeproj -scheme VKTurnProxy \
  -configuration Debug -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath /private/tmp/vkturn-adaptive-build \
  CODE_SIGNING_ALLOWED=NO build
```

Swift-проверки новых настроек проверяют проводку полей по исходникам;
это не UI-тест на устройстве и не самостоятельное доказательство поведения
реального экспорта/импорта. Полная сборка проверяет типы приложения.
Сценарии испытаний и ограничения: [csqtt-adaptive.md](csqtt-adaptive.md).
