
Шифрование:

```
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Параметр `--output` можно не указывать. При шифровании программа добавит к имени `.enc`, при расшифровании — `.dec`.

## Проверка полного цикла

```
Set-Content -Encoding UTF8 plaintext.txt "Проверка CryptoCore"
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash decrypted.txt).Hash
```

Последняя команда должна вывести `True`.

## Тесты

```
python -m unittest discover -s tests -v
```

Набор проверяет известный тестовый вектор AES-128, PKCS#7, текстовые и бинарные данные, пустой файл, полный цикл CLI и ошибочные параметры.

## Сверка с OpenSSL

OpenSSL по умолчанию использует совместимое дополнение PKCS#7. Сравнить шифротексты можно так:

```
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.txt -out ciphertext_openssl.bin -nosalt
(Get-FileHash ciphertext.bin).Hash -eq (Get-FileHash ciphertext_openssl.bin).Hash
```

Результат сравнения должен быть `True`.


