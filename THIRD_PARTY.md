# Компоненты сторонних разработчиков

VPN4ik использует оригинальные компоненты без изменения их исходного кода.

| Компонент | Версия | Лицензия и исходники |
| --- | --- | --- |
| Xray-core | 26.10.21 | [MPL 2.0](licenses/Xray-MPL-2.0.txt), [исходники закреплённой версии](https://github.com/XTLS/Xray-core/tree/v26.10.21) |
| Hiddify Core / HiddifyCli | 5.0.3, официальный Windows x64 пакет | [Исходная лицензия поставщика с дополнительными условиями](licenses/Hiddify-Core.txt), [исходники](https://github.com/hiddify/hiddify-core/tree/v5.0.3), [официальный выпуск](https://github.com/hiddify/hiddify-core/releases/tag/v5.0.3) |
| Cronet / cronet-go | libcronet из официального комплекта Hiddify 5.0.3 | [Уведомление cronet-go](licenses/Cronet-Go.txt), [обвязка](https://github.com/SagerNet/cronet-go/tree/0d28acc44093), [Chromium/Cronet](https://chromium.googlesource.com/chromium/src/+/main/components/cronet/) |
| Wintun | из официального архива Xray | [Условия распространения](licenses/Wintun.txt), [официальный проект](https://www.wintun.net/) |
| WireGuard for Windows | 0.5.3 | [MIT](licenses/WireGuard-MIT.txt), [официальные исходники](https://github.com/WireGuard/wireguard-windows/tree/v0.5.3) |
| .NET Runtime / WPF | 8.0, версия в автономной сборке | MIT и уведомления поставщика; файлы LICENSE/THIRD-PARTY-NOTICES включены в архив сборки |

Движок Xray и Wintun загружаются скриптом `scripts/bootstrap-engine.ps1` из официального релиза. Перед использованием проверяются закреплённые SHA-256. WireGuard — подписанный исполняемый файл WireGuard LLC, встроенный как ресурс клиента.

Hiddify Core предоставлен проектом [Hiddify](https://github.com/hiddify/hiddify-core) без изменения его бинарных файлов. `scripts/bootstrap-hiddify.ps1` проверяет SHA-256 официального архива и каждого файла. Архив встроен в VPN4ik; компоненты распаковываются в `Engine/Hiddify` с повторной проверкой. Wintun в этой папке — копия того же проверенного драйвера, указанного выше. Наш код соединяет ядро с существующим протокольным процессом Xray и сохраняет управление через собственную службу. Описание изменений — [интеграция Hiddify](docs/HIDDIFY.md).

Лицензия Hiddify Core содержит GPLv3 и дополнительные положения об атрибуции, открытом исходном коде, производных работах и некоммерческом использовании. Оригинальный текст включён без изменений. Компоненты Hiddify распространяются без изменений, с исходной лицензией и ссылками на исходники закреплённой версии выше. VPN4ik имеет собственные название и дизайн; исходники интеграции доступны в этом репозитории. Выпуск предназначен для некоммерческого использования, рекламы нет. Условия поставщика продолжают действовать для его компонентов.

Подписки, VPN-ключи и конфигурации серверов пользователей не входят в проект или релиз.

