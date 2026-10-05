```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

## Выработка ключа из пароля

Подкоманда `derive` принимает пароль, соль, число итераций и длину результата:

```powershell
cryptocore derive `
  --password "MySecurePassword123!" `
  --salt a1b2c3d4e5f601234567890123456789 `
  --iterations 100000 `
  --length 32 `
  --algorithm pbkdf2
```

Формат стандартного вывода:

```text
KEY_HEX SALT_HEX
```

Если `--salt` не указан, программа создаёт случайную 16-байтную соль через системный CSPRNG:

```powershell
cryptocore derive --password "AnotherPassword" --iterations 100000 --length 16
```

Соль не является секретом, но она нужна для повторной выработки того же ключа. Поэтому значение `SALT_HEX` следует сохранить рядом с параметрами защищаемых данных.

## Параметры derive

| Параметр | Назначение | Значение по умолчанию |
|---|---|---:|
| `--password PASSWORD` | пароль в UTF-8 | обязательный |
| `--salt SALT` | соль в виде hex-строки | случайные 16 байт |
| `--iterations COUNT` | число итераций PBKDF2 | `100000` |
| `--length LENGTH` | длина ключа в байтах | `32` |
| `--algorithm ALGORITHM` | алгоритм KDF | `pbkdf2` |
| `--output FILE` | файл для двоичного ключа | не создаётся |

Число итераций и длина должны быть положительными. Соль должна иметь чётное количество шестнадцатеричных символов.

## Запись двоичного ключа

```powershell
cryptocore derive `
  --password "app_key" `
  --salt 00112233445566778899aabbccddeeff `
  --iterations 10000 `
  --length 32 `
  --output app.key
```

Файл `app.key` содержит только 32 байта производного ключа. Соль в него не добавляется. Строка `KEY_HEX SALT_HEX` всё равно печатается в консоль.

## Как работает PBKDF2

PBKDF2 делит результат на 32-байтные блоки. Для каждого блока вычисляется цепочка HMAC-SHA256:

```text
U1 = HMAC-SHA256(password, salt || INT_32_BE(block_index))
Uj = HMAC-SHA256(password, Uj-1)
Ti = U1 XOR U2 XOR ... XOR Uc
DK = T1 || T2 || ...
```

Последний блок обрезается до длины, указанной в `--length`. Повторение HMAC увеличивает стоимость перебора паролей, а уникальная соль не позволяет заранее вычислить одну таблицу для разных пользователей.

## Иерархия ключей

Функция `derive_key` получает независимые ключи из одного мастер-ключа. Контекст обозначает назначение ключа и включается в каждый HMAC:

```python
from cryptocore.kdf import derive_key

master = bytes.fromhex("00112233445566778899aabbccddeeff")
encryption_key = derive_key(master, "encryption", 32)
authentication_key = derive_key(master, "authentication", 32)
```

Алгоритм вычисляет последовательные блоки `HMAC-SHA256(master_key, context || counter)` и обрезает их до нужной длины. Это учебная контекстная схема из задания, а не полная стандартизованная процедура HKDF.

## Проверка через OpenSSL

Для соли, заданной в CryptoCore как hex, в OpenSSL используется параметр `hexsalt`:

```powershell
openssl kdf -keylen 32 `
  -kdfopt digest:SHA256 `
  -kdfopt pass:test `
  -kdfopt hexsalt:1234567890abcdef `
  -kdfopt iter:1000 PBKDF2
```

После удаления двоеточий и перевода регистра результат OpenSSL должен совпасть с первым полем вывода CryptoCore.

## Замечание о векторах RFC 6070

RFC 6070 содержит тестовые векторы PBKDF2-HMAC-SHA1. В задании одновременно требуется PBKDF2-HMAC-SHA256, поэтому приведённые в PDF значения SHA-1 нельзя использовать как ожидаемый результат реализации SHA-256.

Тесты сохраняют параметры RFC 6070, но используют корректные ответы HMAC-SHA256. Они дополнительно сверяются с `hashlib.pbkdf2_hmac("sha256", ...)` и OpenSSL.

## AES-CMAC

AES-CMAC вычисляется командой `dgst` с флагом `--cmac`. Для него выбирается алгоритм `aes` и передаётся 128-битный ключ в виде 32 hex-символов:

```powershell
cryptocore dgst --algorithm aes --cmac `
  --key 2b7e151628aed2a6abf7158809cf4f3c `
  --input message.bin
```

Формат результата совпадает с форматом других MAC:

```text
CMAC_VALUE INPUT_FILE_PATH
```

Результат можно записать в файл и затем проверить:

```powershell
cryptocore dgst --algorithm aes --cmac `
  --key 2b7e151628aed2a6abf7158809cf4f3c `
  --input message.bin --output message.cmac

cryptocore dgst --algorithm aes --cmac `
  --key 2b7e151628aed2a6abf7158809cf4f3c `
  --input message.bin --verify message.cmac
```

Успешная проверка завершается кодом `0` и сообщает `[OK] CMAC verification successful`. Несовпадение тега завершается кодом `1`.

### Как работает AES-CMAC

Реализация следует NIST SP 800-38B и использует только AES-ECB как блочный примитив. Готовый модуль `Crypto.Hash.CMAC` в рабочем коде не применяется.

Сначала вычисляется `L = AES_K(0^128)`. Удвоение в поле `GF(2^128)` даёт подключи `K1` и `K2`; при переносе старшего бита выполняется XOR с константой `0x87`. Все блоки, кроме последнего, обрабатываются как CBC-MAC:

```text
X0 = 0^128
Xi = AES_K(Xi-1 XOR Mi)
```

Полный последний блок складывается по XOR с `K1`. Неполный или пустой блок дополняется битом `1` и нулями, затем складывается с `K2`. После последнего XOR выполняется ещё одно шифрование AES. Полученный 16-байтный блок является тегом CMAC.

Файлы читаются частями по 8192 байта. Реализация хранит только текущее состояние CBC и последний блок, поэтому объём памяти не зависит от размера файла.

## Рекомендации по безопасности

- Для новых данных создавайте случайную соль длиной не менее 16 байт.
- Не повторяйте одну соль намеренно для разных паролей.
- Значения меньше `100000` используйте только для тестовых векторов. `100000` является учебным минимумом этой работы; в реальном приложении число итераций выбирают по актуальной политике и допустимому времени выполнения.
- Пароль, переданный через командную строку, может быть виден другим средствам операционной системы. Подкоманда предназначена для учебного использования.
- Python не гарантирует полное удаление неизменяемых строк из памяти. Программа обнуляет собственную изменяемую копию пароля после вычисления, но это не является абсолютной защитой памяти процесса.

## Команды прошлых спринтов

Шифрование AES:

```text
cryptocore --algorithm aes --mode {ecb,cbc,cfb,ofb,ctr,gcm}
           (--encrypt | --decrypt) [--key KEY] [--iv IV]
           [--aad AAD] --input INPUT [--output OUTPUT]
```

Хеши и HMAC:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
cryptocore dgst --algorithm sha3-256 --input archive.bin
cryptocore dgst --algorithm sha256 --hmac `
  --key 00112233445566778899aabbccddeeff `
  --input message.txt --verify message.hmac

cryptocore dgst --algorithm aes --cmac `
  --key 2b7e151628aed2a6abf7158809cf4f3c `
  --input message.bin --verify message.cmac
```

## Тесты

```powershell
python -m unittest discover -s tests -v
```

Набор из 115 тестов проверяет:

- четыре вектора AES-CMAC и подключи `K1/K2` из NIST SP 800-38B;
- потоковую обработку AES-CMAC, `--output`, `--verify` и обнаружение подмены;
- известные ответы PBKDF2-HMAC-SHA256;
- длины производного ключа от 1 до 100 байт;
- произвольные длины пароля и соли;
- совпадение с OpenSSL и стандартной библиотекой только в тестах;
- двоичный `--output` и точный формат `KEY_HEX SALT_HEX`;
- 1000 случайных солей без повторов;
- детерминированность и разделение контекстов иерархии ключей;
- все 85 тестов Sprint 1-6.

Подробный протокол находится в [TESTING.md](TESTING.md).

## Структура проекта

```text
CryptoCore/
|-- src/cryptocore/
|   |-- kdf/
|   |   |-- pbkdf2.py
|   |   `-- hkdf.py
|   |-- aead/                # Encrypt-then-MAC Sprint 6
|   |-- modes/               # AES ECB, CBC, CFB, OFB, CTR и GCM
|   |-- mac/                 # HMAC-SHA-256 и AES-CMAC Sprint 5
|   |   |-- hmac_sha256.py
|   |   `-- cmac.py
|   |-- hashes/              # SHA-256 и SHA3-256 Sprint 4
|   |-- cli_parser.py
|   `-- main.py
|-- tests/
|   |-- test_cmac.py
|   |-- test_cmac_cli.py
|   |-- test_kdf.py
|   |-- test_derive_cli.py
|   `-- тесты предыдущих спринтов
|-- scripts/benchmark_pbkdf2.py
|-- README.md
|-- TESTING.md
|-- Инструкция.docx
`-- pyproject.toml
```
