```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

## Шифрование AES-GCM

```powershell
cryptocore --algorithm aes --mode gcm --encrypt `
  --key 00112233445566778899aabbccddeeff `
  --input plaintext.bin --output ciphertext.gcm `
  --aad aabbccddeeff
```

Параметр `--aad` содержит AAD в hex. Он необязателен; без него используется пустая строка. AAD проходит аутентификацию, но не включается в шифротекст.

При обычном шифровании программа создаёт новый случайный nonce длиной 12 байт. Формат выходного файла:

```text
nonce (12 байт) || ciphertext || tag (16 байт)
```

Для воспроизводимых тестовых векторов можно явно передать `--nonce` или его совместимый псевдоним `--iv`:

```powershell
cryptocore --algorithm aes --mode gcm --encrypt `
  --key feffe9928665731c6d6a8f9467308308 `
  --nonce cafebabefacedbaddecaf888 --aad "" `
  --input empty.bin --output vector.gcm
```

Явный nonce предназначен для тестирования. В реальном применении один nonce нельзя повторно использовать с тем же ключом.

## Расшифрование AES-GCM

Если nonce записан в первых 12 байтах входного файла, достаточно указать правильный ключ и AAD:

```powershell
cryptocore --algorithm aes --mode gcm --decrypt `
  --key 00112233445566778899aabbccddeeff `
  --input ciphertext.gcm --output restored.bin `
  --aad aabbccddeeff
```

Успешная проверка завершается сообщением:

```text
[SUCCESS] Decryption completed successfully
```

При работе с отдельным значением `ciphertext || tag` nonce можно передать параметром `--nonce`.

## Отказ при ошибке аутентификации

Перед расшифрованием программа заново вычисляет тег и сравнивает все его байты без раннего выхода. Проверка выполняется до возврата открытого текста и до записи выходного файла.

Неправильный AAD, ключ, nonce, шифротекст или тег приводят к сообщению:

```text
[ERROR] Authentication failed: AAD mismatch or ciphertext/tag tampered
```

Код возврата равен `1`. Новый выходной файл не создаётся, и частичный открытый текст не записывается.

## Как устроен GCM

Реализация находится в `src/cryptocore/modes/gcm.py`.

1. AES шифрует нулевой блок и создаёт подключ `H` для GHASH.
2. Для 12-байтного nonce начальный счётчик равен `nonce || 00000001`.
3. Открытый текст шифруется AES-CTR со счётчика `J0 + 1`.
4. GHASH обрабатывает AAD, шифротекст и 64-битные поля их длины.
5. AES от `J0` объединяется с GHASH и образует 128-битный тег.

Умножение GHASH выполняется в поле `GF(2^128)` с полиномом `x^128 + x^7 + x^2 + x + 1`. Класс `GHASH` принимает AAD и шифротекст частями. Функция `update_ghash_from_stream` читает поток блоками по 8192 байта, поэтому сам GHASH не требует загружать большой AAD целиком.

Для nonce длиной не 12 байт класс `GCM` строит `J0` через GHASH, как требует SP 800-38D. Командный формат файла использует рекомендуемый 12-байтный nonce, а библиотечные методы также проверены с nonce длиной 8 и 20 байт.

## Encrypt-then-MAC

Модуль `src/cryptocore/aead/encrypt_then_mac.py` показывает общую композицию AES-CTR и HMAC-SHA-256:

```text
C = AES-CTR(Ke, P)
T = HMAC-SHA-256(Km, IV || C || AAD)
output = IV || C || T
```

Ключи `Ke` и `Km` независимо выводятся из мастер-ключа с разными метками HMAC. При расшифровании HMAC проверяется до запуска AES-CTR.

```python
from cryptocore.aead import EncryptThenMAC

scheme = EncryptThenMAC(bytes.fromhex("00112233445566778899aabbccddeeff"))
encrypted = scheme.encrypt(b"message", b"metadata")
restored = scheme.decrypt(encrypted, b"metadata")
```

## Проверка OpenSSL

Команда `openssl enc` не поддерживает GCM и другие AEAD-режимы. Это прямо указано в [официальной документации OpenSSL](https://docs.openssl.org/3.5/man1/openssl-enc/). Локальный OpenSSL 3.5.6 возвращает `enc: AEAD ciphers not supported`.

Поэтому независимая проверка GCM выполнена по официальным [примерам NIST с промежуточными значениями] и через `Crypto.Cipher.AES.MODE_GCM` только в тестах. Исходный код GCM не использует готовый режим GCM.

## Команды прошлых спринтов

Обычные режимы AES:

```text
cryptocore --algorithm aes --mode {ecb,cbc,cfb,ofb,ctr}
           (--encrypt | --decrypt) [--key KEY] [--iv IV]
           --input INPUT [--output OUTPUT]
```

Хеши и HMAC:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
cryptocore dgst --algorithm sha3-256 --input archive.bin
cryptocore dgst --algorithm sha256 --hmac `
  --key 00112233445566778899aabbccddeeff `
  --input message.txt --verify message.hmac
```

## Тесты

```powershell
python -m unittest discover -s tests -v
```

Набор из 85 тестов проверяет:

- примеры AES-GCM 1-5 из материалов NIST;
- пустые и неполные блоки, разные длины AAD и nonce;
- совпадение с независимой реализацией GCM;
- полный цикл командной строки и формат `nonce || ciphertext || tag`;
- отказ без выходного файла при неправильном AAD, шифротексте или теге;
- уникальность 1000 случайных nonce;
- потоковую передачу AAD объёмом больше 1 ГиБ;
- разделение ключей и проверки Encrypt-then-MAC;
- все 67 тестов Sprint 1-5.

Подробный протокол находится в [TESTING.md](TESTING.md).
