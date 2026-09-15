```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

После установки команда `cryptocore` доступна.

## Параметры командной строки

```text
cryptocore --algorithm aes --mode {ecb,cbc,cfb,ofb,ctr}
           (--encrypt | --decrypt) --key KEY [--iv IV]
           --input INPUT [--output OUTPUT]
```

- `--algorithm aes` выбирает AES.
- `--mode` выбирает режим работы.
- Необходимо задать ровно один флаг: `--encrypt` или `--decrypt`.
- `--key` принимает 16-байтный ключ в виде 32 hex-символов.
- `--iv` принимает 16-байтный IV в виде 32 hex-символов. Он разрешён только при расшифровании в режимах CBC, CFB, OFB и CTR.
- `--input` задаёт входной файл.
- `--output` задаёт результат. Если параметр пропущен, к имени входного файла добавляется `.enc` или `.dec`.

## Режимы и формат данных

| Режим | Дополнение | Размер шифротекста | IV |
|---|---|---|---|
| ECB | PKCS#7 | Кратен 16 байтам | Не используется |
| CBC | PKCS#7 | Кратен 16 байтам | 16 байт |
| CFB | Нет | Равен размеру исходных данных | 16 байт |
| OFB | Нет | Равен размеру исходных данных | 16 байт |
| CTR | Нет | Равен размеру исходных данных | 16 байт |

При шифровании в новом режиме программа получает IV через `os.urandom(16)` и записывает результат в формате:

```text
<16-байтный IV><шифротекст>
```

При расшифровании без `--iv` первые 16 байт входного файла считаются IV. При явном `--iv` входной файл должен содержать только шифротекст, без префикса IV. Это нужно для файлов, созданных OpenSSL, и для заранее разделённых данных.

## Примеры использования

Шифрование CBC с автоматически созданным IV:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование файла CryptoCore, в котором IV находится в первых 16 байтах:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Расшифрование шифротекста без префикса с явно заданным IV:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input openssl_cipher.bin --output decrypted.bin
```

Для CFB, OFB и CTR команды имеют тот же вид: изменяется только значение `--mode`.

## Проверка полного цикла

```powershell
$key = "000102030405060708090a0b0c0d0e0f"
Set-Content -Encoding UTF8 plaintext.txt "Проверка CryptoCore Sprint 2"

foreach ($mode in "cbc", "cfb", "ofb", "ctr") {
    cryptocore --algorithm aes --mode $mode --encrypt --key $key --input plaintext.txt --output "$mode.bin"
    cryptocore --algorithm aes --mode $mode --decrypt --key $key --input "$mode.bin" --output "$mode.restored.txt"
    Write-Host $mode ((Get-FileHash plaintext.txt).Hash -eq (Get-FileHash "$mode.restored.txt").Hash)
}
```

Для каждого режима должно быть выведено `True`.

## Автоматические тесты

Полный набор тестов:

```powershell
python -m unittest discover -s tests -v
```

Он проверяет:

- требования Sprint 1 и работу ECB;
- известные векторы NIST для CBC, CFB-128, OFB и CTR;
- PKCS#7 для ECB и CBC;
- частичные последние блоки в потоковых режимах;
- случайную генерацию и добавление IV к файлу;
- расшифрование с IV из файла и из `--iv`;
- ошибки ключа, IV, конфликтующих флагов и слишком короткого файла;
- двустороннюю совместимость всех новых режимов с OpenSSL.

Только тесты совместимости:

```powershell
python -m unittest discover -s tests -p "test_openssl_interop.py" -v
```

Если OpenSSL не найден, эти два теста будут пропущены с пометкой `skipped`.

## Ручная проверка совместимости с OpenSSL

### CryptoCore шифрует, OpenSSL расшифровывает

Сначала создайте файл в любом новом режиме, например CBC:

```powershell
$key = "000102030405060708090a0b0c0d0e0f"
cryptocore --algorithm aes --mode cbc --encrypt --key $key --input plaintext.txt --output cipher_with_iv.bin
```

Отделите IV от шифротекста:

```powershell
$data = [IO.File]::ReadAllBytes("cipher_with_iv.bin")
$iv = [byte[]]$data[0..15]
$body = [byte[]]$data[16..($data.Length - 1)]
$ivHex = ([BitConverter]::ToString($iv)).Replace("-", "")
[IO.File]::WriteAllBytes("ciphertext_only.bin", $body)
```

Расшифруйте оставшийся шифротекст:

```powershell
openssl enc -aes-128-cbc -d -K $key -iv $ivHex -in ciphertext_only.bin -out openssl_restored.txt -nosalt
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash openssl_restored.txt).Hash
```

Для остальных режимов замените `cbc` в параметрах CryptoCore и OpenSSL на `cfb`, `ofb` или `ctr`.

### OpenSSL шифрует, CryptoCore расшифровывает

```powershell
$key = "000102030405060708090a0b0c0d0e0f"
$iv = "aabbccddeeff00112233445566778899"
openssl enc -aes-128-cbc -K $key -iv $iv -in plaintext.txt -out openssl_cipher.bin -nosalt
cryptocore --algorithm aes --mode cbc --decrypt --key $key --iv $iv --input openssl_cipher.bin --output cryptocore_restored.txt
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash cryptocore_restored.txt).Hash
```

Эта последовательность также применяется к `cfb`, `ofb` и `ctr` после замены названия режима в обеих командах.

