# 🔐 pkcs11-key-wrap

Wrap keys from HSM using CKM_RSA_AES_KEY_WRAP step by step.

This tool can be used for example for exporting keys from Amazon's CloudHSM and
importing it to Google's KMS or Microsoft Azure's Key Vault.

## Install

go install github.com/smallstep/pkcs11-key-wrap

## Usage

First we need to create an RSA public wrapping key, in our example this is going
to be `rsa.pub`. Then we need to get the object id or the label of the key that
we want to wrap, `1000` or `my-key` in the following example. Finally run the
wrapping tool like:

```sh
pkcs11-key-wrap --pin xxxx --id 1000 --wrapping-key rsa.pub > wrapped.key
# OR
pkcs11-key-wrap --pin xxxx --label my-key --wrapping-key rsa.pub > wrapped.key
```

Without the `--module` flag will try to load the softhsm2 module, from
`/usr/lib/softhsm/libsofthsm2.so` in a Linux environment and from
`/usr/local/lib/softhsm/libsofthsm2.so` in macOS.

If Amazon CloudHSM is used the flag `--cloudhsm` is required because the
standard `CKM_AES_KEY_WRAP_PAD` mechanism should be replaced by the custom
`CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD`. The usage in this case will be like:

```sh
pkcs11-key-wrap --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --cloudhsm \
    --pin user:password --id 1000 --wrapping-key rsa.pub > wrapped.key
# OR
pkcs11-key-wrap --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --cloudhsm \
    --pin user:password --label my-key --wrapping-key rsa.pub > wrapped.key
```

## CloudHSM troubleshooting

If you get an error running pkcs11-key-wrap on CloudHSM, the best way to know
what is going is to look at their logs. To retrieve them just run:

```sh
/opt/cloudhsm/bin/pkcs11_info
```

That command with place a file named `pkcs11-data.tar.gz` on `/tmp`. To look at
the actual logs run:

```sh
cd /tmp
tar xzvf pkcs11-data.tar.gz
less pkcs11-data/cloudhsm-pkcs11.log.*
```

A common error if you have just one CloudHSM is to get this error:

```
Key <handle#> does not meet the availability requirements - The key must be available on at least 2 HSMs before being used.
```

To remove that requirement we can run:

```sh
sudo /opt/cloudhsm/bin/configure-pkcs11 --disable-key-availability-check
```

But the keys might be re-created or imported, Amazon's `key_mgmt_util` might be
useful for these situations as they can wrap a key using `wrapKey` or
`exportPrivateKey` commands.
