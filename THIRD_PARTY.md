# Компоненты сторонних разработчиков

VPN4ik использует оригинальные компоненты без изменения их исходного кода.

| Компонент | Версия | Лицензия и исходники |
| --- | --- | --- |
| Xray-core | 26.10.21 | [MPL 2.0](licenses/Xray-MPL-2.0.txt), [исходники закреплённой версии](https://github.com/XTLS/Xray-core/tree/v26.10.21) |
| Wintun | из официального архива Xray | [Условия распространения](licenses/Wintun.txt), [официальный проект](https://www.wintun.net/) |
| WireGuard for Windows | 0.5.3 | [MIT](licenses/WireGuard-MIT.txt), [официальные исходники](https://github.com/WireGuard/wireguard-windows/tree/v0.5.3) |
| .NET Runtime / WPF | 8.0, версия в автономной сборке | MIT и уведомления поставщика; файлы LICENSE/THIRD-PARTY-NOTICES включены в архив сборки |

Движок Xray и Wintun загружаются скриптом `scripts/bootstrap-engine.ps1` из официального релиза. Перед использованием проверяются закреплённые SHA-256. WireGuard — подписанный исполняемый файл WireGuard LLC, встроенный как ресурс клиента.

Подписки, VPN-ключи и конфигурации серверов пользователей не входят в проект или релиз.

