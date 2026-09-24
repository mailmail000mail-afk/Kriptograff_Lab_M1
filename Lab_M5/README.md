```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

После установки доступна команда `cryptocore`.

## Вычисление HMAC

```text
cryptocore dgst --algorithm sha256 --hmac --key KEY
                --input INPUT_FILE [--output OUTPUT_FILE]
```

- `--hmac` включает HMAC-SHA-256;
- `--key` задаёт секретный ключ в hex и обязателен вместе с `--hmac`;
- ключ может иметь произвольную длину, но hex-строка должна содержать целое число байт;
- `--input` задаёт файл или `-` для стандартного ввода;
- `--output` записывает результат в файл вместо консоли.

Пример:

```powershell
cryptocore dgst --algorithm sha256 --hmac `
  --key 00112233445566778899aabbccddeeff `
  --input message.txt
```

Формат результата:

```text
HMAC_VALUE INPUT_FILE_PATH
```

Значение HMAC содержит 64 строчных hex-символа. Программа читает файл в бинарном режиме блоками по 8192 байта.

### Запись HMAC в файл

```powershell
cryptocore dgst --algorithm sha256 --hmac `
  --key 00112233445566778899aabbccddeeff `
  --input message.txt --output message.hmac
```

Файл `message.hmac` содержит ту же строку, которая без `--output` появилась бы в консоли.

### Стандартный ввод

```powershell
cmd /c "type message.txt | cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input -"
```

## Проверка HMAC

Опция `--verify` читает ожидаемый HMAC из указанного файла. Имя файла после HMAC и лишние пробелы игнорируются.

```powershell
cryptocore dgst --algorithm sha256 --hmac `
  --key 00112233445566778899aabbccddeeff `
  --input message.txt --verify message.hmac
```

Успешная проверка:

```text
[OK] HMAC verification successful
```

Код возврата равен `0`. Если файл или ключ изменён, программа печатает:

```text
[ERROR] HMAC verification failed
```

Код возврата будет ненулевым. Сравнение выполняется без досрочного выхода по первому отличающемуся байту.

## Как устроен HMAC-SHA-256

Реализация находится в `hmac_sha256.py` и использует только собственный класс `SHA256`.

Для SHA-256 размер блока равен 64 байтам. Перед вычислением HMAC ключ обрабатывается так:

1. ключ длиннее 64 байт хешируется SHA-256;
2. короткий ключ дополняется нулевыми байтами до 64 байт;
3. вычисляются внутренний и внешний блоки с `ipad = 0x36` и `opad = 0x5c`;
4. итог равен `SHA256((K XOR opad) || SHA256((K XOR ipad) || message))`.

Файл не загружается целиком. `file_mac.py` последовательно передаёт блоки в объект HMAC, поэтому объём памяти не зависит от размера файла.

## Свойства безопасности

Обычный хеш позволяет заметить изменение, только если эталонное значение получено из доверенного источника. HMAC дополнительно использует общий секретный ключ. Злоумышленник без ключа не должен иметь возможности создать правильный код для изменённого сообщения.

HMAC не шифрует файл и не скрывает его содержимое. Секретный ключ нужно создавать криптографическим генератором, хранить отдельно от файла и не передавать по открытому каналу. Для HMAC-SHA-256 практично использовать случайный ключ длиной 32 байта.

## Обычное хеширование

Команды Sprint 4 не изменились:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
cryptocore dgst --algorithm sha3-256 --input archive.bin --output archive.sha3
```

Без `--hmac` параметры `--key` и `--verify` отклоняются.

## Шифрование из прошлых спринтов

```text
cryptocore --algorithm aes --mode {ecb,cbc,cfb,ofb,ctr}
           (--encrypt | --decrypt) [--key KEY] [--iv IV]
           --input INPUT [--output OUTPUT]
```

При шифровании ключ может создаваться автоматически. При расшифровании `--key` обязателен. CBC, CFB, OFB и CTR используют 16-байтный IV, который при обычном шифровании записывается перед шифротекстом.

## Тесты

```powershell
python -m unittest discover -s tests -v
```

Набор из 67 тестов проверяет:

- HMAC-SHA-256 test cases 1–4 из [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html);
- ключи короче, равные и длиннее 64 байт;
- пустой ввод и потоковую обработку входа больше 1 ГиБ;
- генерацию, `--output`, stdin и `--verify`;
- обнаружение изменённого файла и неправильного ключа;
- совпадение с OpenSSL;
- все тесты SHA, AES и CSPRNG из Sprint 1–4.

Подробные результаты находятся в [TESTING.md](TESTING.md).