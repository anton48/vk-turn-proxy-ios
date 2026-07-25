# VK TURN Proxy — iOS

Приложение для iOS, разработанное в исследовательских и образовательных целях, которое реализует туннель (VPN) между клиентским устройством и сервером. 

Для построения туннеля могут быть использованы несколько разновидностей протоколов, общей частью которых является работа через [TURN relay](https://www.rfc-editor.org/info/rfc8656/). По умолчанию используются relay [ВКонтакте](https://vk.com) или можно задать другой TURN relay в настройках. Использование TURN relay как промежуточного звена позволяет приложению работать в том числе в условиях фильтрации трафика в корпоративной сети или у сотового провайдера.

## Установка

Загрузите TestFlight из AppStore, затем откройте [ссылку](https://testflight.apple.com/join/ANm6cmDv) или самостоятельная загрузка IPA файла из раздела [Releases](https://github.com/anton48/vk-turn-proxy-ios/releases) на устройство (потребуется подписать его с помощью того или иного сервиса, подключение будет рабочим, но не будут работать статистика и логи).

## Документация

[Как это работает](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#как-это-работает)

[Что необходимо для работы](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#что-необходимо-для-работы)

[Режимы работы](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#режимы-работы)

[Настройки приложения](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#настройки-клиентского-приложения)

[Автоматические ссылки](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#автоматические-ссылки)

[Backup/Restore](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#backuprestore)

[Капча](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#капча)

[Ответы на частые вопросы, решение проблем](https://github.com/anton48/vk-turn-proxy-ios/blob/main/docs/setup.md#ответы-на-частые-вопросы-решение-проблем)

## Credits

Based on [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) by [cacggghp](https://github.com/cacggghp).

## License

[GNU General Public License v3.0](LICENSE) (GPL-3.0) — as a derivative of [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) (GPL-3.0).

Files that carry an `SPDX-License-Identifier` header are additionally available under the license named there (e.g. MIT); the project as a whole is GPL-3.0.
