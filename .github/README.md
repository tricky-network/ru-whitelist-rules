# 🏳️ RU Whitelist Rules

Rule-set'ы для [mihomo](https://github.com/MetaCubeX/mihomo) с доменами и подсетями, которые российские мобильные операторы пропускают при включённых белых списках. Нужны для правила `DIRECT` выше `geosite-ru`: всё из этих списков идёт напрямую, а не через туннель.

Сборка запускается раз в сутки. Результат публикуется в ветку [`release`](../../tree/release):

## Подключение

```yaml
rule-providers:
  ru-whitelist-domain:
    type: http
    format: mrs
    behavior: domain
    url: https://raw.githubusercontent.com/tricky-network/ru-whitelist-rules/release/ru-whitelist-domain.mrs
    path: ./ruleset/ru-whitelist-domain.mrs
    interval: 86400
  ru-whitelist-ipcidr:
    type: http
    format: mrs
    behavior: ipcidr
    url: https://raw.githubusercontent.com/tricky-network/ru-whitelist-rules/release/ru-whitelist-ipcidr.mrs
    path: ./ruleset/ru-whitelist-ipcidr.mrs
    interval: 86400

rules:
  - RULE-SET,ru-whitelist-domain,DIRECT
  - RULE-SET,ru-whitelist-ipcidr,DIRECT,no-resolve
  # ниже: GEOSITE,ru,... и остальное
```

## Источники

- Домены: `whitelist.txt` из [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist), © 2025 hxehex.real, [лицензия MIT](https://github.com/hxehex/russia-mobile-internet-whitelist/blob/main/LICENSE). Её текст лежит рядом с артефактами в `LICENSE-upstream`.
- Подсети: `cidrwhitelist.txt` из того же репозитория. Старый `ipwhitelist.txt` (одиночные адреса) не используется.
- Фильтр подсетей: `geo/geoip/ru.list` из [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), [лицензия GPL-3.0](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE). Это текстовый вариант того же `geoip-ru`, что и `ru.mrs`. Сам он сюда не копируется, используется только пересечение с ним.

При каждой сборке оба апстрима фиксируются по SHA коммита, и эти SHA записываются в `meta.json`.

## Как обрабатываются данные

**Домены.** Обрезаются пробелы, всё приводится к нижнему регистру, IDN переводится в punycode. Невалидные строки и битый punycode отбрасываются, дубликаты убираются. Матчинг **точный, как в апстриме**, без `+.`. Если поддомен не попал в список, он просто уйдёт в туннель и откроется. А `+.` пустил бы напрямую поддомены, которых в белом списке нет, и при включённых белых списках они бы не открылись.

**Подсети.** Результат = `cidrwhitelist ∩ geoip-ru`, соседние и вложенные подсети агрегируются. Если подсеть частично вне РФ, она обрезается до пересечения. В апстриме много широких зарубежных префиксов (например, `7.64.0.0/12`, сети европейских операторов), и без обрезки всё в них уходило бы напрямую. Сколько подсетей взято целиком, сколько обрезано и сколько выкинуто, плюс топ-10 самых крупных выкинутых, записывается в `meta.json`.

**Сборка падает, и ничего не публикуется, если:**

- любой из списков пуст;
- размер любого списка изменился больше чем на ±30% относительно последней опубликованной версии. Порог задаётся в [`../config/build.properties`](../config/build.properties). Обойти гейт можно только ручным запуском workflow с флагом `allow_size_change`;
- апстрим принёс домен из [`../config/denylist.txt`](../config/denylist.txt): голые TLD, крупные зарубежные CDN и облака. Такой домен не вырезается молча, сборка падает с ошибкой.

Если сборка упала, в `release` остаётся предыдущая версия. Если с прошлой публикации ничего не изменилось, новая не создаётся. Изменения в одном `meta.json` публикацию не запускают, потому что `builtAt` меняется на каждой сборке. Чтобы опубликовать заново без изменений в списках, например обновить `meta.json`, запустите workflow вручную с флагом `force_publish`. Гейты при этом всё равно проверяются.

## Локальная сборка

Нужен JDK 25. Тесты и сборка запускаются одной командой:

```sh
./gradlew test run --args="--out build/out"
```

Без `--mihomo` получатся только `.txt` и `meta.json`. Чтобы собрать и `.mrs`, добавьте путь к бинарю mihomo: `--args="--out build/out --mihomo /path/to/mihomo"`. Гейт по размеру срабатывает, если передать каталог с прошлой версией: `--prev <dir>`.
