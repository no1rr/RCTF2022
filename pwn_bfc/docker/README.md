

## Build

```bash
docker build -t "pwn_bfc" .
```



## Run

```bash
docker run -d -p "0.0.0.0:pub_port:9999" -h "pwn_bfc" --name="pwn_bfc" pwn_bfc
```

`pub_port` is the port you want to expose to the public network.

