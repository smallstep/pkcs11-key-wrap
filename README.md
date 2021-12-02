# pkcs11-key-wrap
Wrap keys from HSM using CKM_RSA_AES_KEY_WRAP step by step.

## Usage

First we need to create an RSA public wrapping key, in our example this is going
to be `rsa.pub`. Then we need to get the object id of the key that we want to
wrap, `1000` in the following example. Finally run the wrapping tool like:

```shell
go run main.go --module /usr/local/lib/softhsm/libsofthsm2.so --pin xxxx \
    --key 1000 --wrapping-key rsa.pub > wrapped.key
```
