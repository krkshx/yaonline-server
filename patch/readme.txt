патч для yachat.exe
- меняет xmpp.yandex.ru -> 127.0.0.1
- меняет xmpp.yandex-team.ru -> 127.0.0.1
- меняет mobile.online.yandex.net -> 127.0.0.1
- меняет passport.yandex.ru -> 127.0.0.1
- патчит YaTokenAuth (0x644840) -> всегда 0 (skip)

запуск patch.py от админа скопирует оригинал и пропатчит
потом нужно прописать в реестре LocalServer32 путь к yachat_run\yachat.exe
и поставить skip_yandex_login=1

логин babaev/admin krksh/admin
