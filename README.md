# PWM Terminal Password Manager

## A password manager in C that uses OpenSSL to encrypt your passwords

This password manager is a personnal project that can encrypt passwords in a file and read it back.

# How to use it

To use PWM, you just have to open your terminal and execute the pwm program.

``` console
pwm create <file> <password>
pwm add <file> <password> <key> <descr>
pwm get <file> <password>
```

# Quick Start

To start, you need to install `OpenSSL3`.

After that, you can copy and build the program:

``` console
git clone https://github.com/alikadev/pwm.git
cd pwm
make all 
```

# Format

If you want to know the format used by PWM, it is a private file format that I named `PWM0`. Here is the format of the `PWM0` files.

- Header

The header is used to recognize the file format and to check the password hash before decrypting the file.

| Name       | Size     | Description               |
| ---------- | -------- | ------------------------- |
| Magic      | 4 bytes  | ASCII "PWM0"              |
| PasswdHash | 32 bytes | The hash of the password with SHA256 |

- Element

The end of the file contains a list of all the element (key, description). Here's the format of a single element:

| Name        | Size      | Description                        |
| ----------- | --------- | ---------------------------------- |
| KeySize     | 4 bytes   | The size of the key                |
| KeyCipher   | KeySize   | The key encrypted with AES         |
| DescrSize   | 4 bytes   | The size of the key                |
| DescrCipher | DescrSize | The description encrypted with AES |

The AES password is password hash and the salt is predefined in the file:
