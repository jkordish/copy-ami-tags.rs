# copy-ami-tags.rs
Take [Packer](https://github.com/hashicorp/packer/) generated manifest.json and copy the AMI tags to other accounts

### building from source
```shell
$ curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly
```

```shell
$ git clone https://github.com/jkordish/copy-ami-tags.rs.git
```

```shell
$ cd copy-ami-tags.rs
$ cargo build --release
```

Binary will be target/release/copy-ami-tags-rs

### simple install
```shell
$ curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly
```

```shell
$ cargo install --git https://github.com/jkordish/copy-ami-tags.rs.git 
```

### executing
```shell
$ copy-ami-tags <role_name> <source_account> <shared_accounts,shared_accounts,shared_accounts>
```
