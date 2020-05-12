# Peng

A simple **port scanner detector** library, with focus on **lightweight memory** usage.

### Description 
`Peng` uses a probabilistic algorithm to detect if you're under a port scan attack. Right now, it **only detects tcp opening
connection** packets (SYN flag only).

### Idea

The general idea is to use the **minimum amount of memory**, to store information regarding a possible port scan threat. 
The **data structure** that fits the most for this task is the **bitmap**. This bitmap is **divided into** an arbitrary number of 
**bin**, which can store **information** about **requested ports**. 
After an amount of time specified by the user, `Peng` will **calculate** the **entropy** of each bin and return the total entropy 
of the entire bitmap. With this result **we can estimate if we were under a port scan attack.** 

### Implementation

The algorithm uses: `hash function`, `entropy` and a `bitmap` as the only data structure.

#### Hash function

Used to spread a port unevenly in the bitmap.

```go
func hash(port uint16) (uint16, uint64) {
		portModuled := (port / uint16(cfg.NumberOfBin)) % uint16(cfg.SizeBitmap)
		index, bit := portModuled/uint16(cfg.NumberOfBits), uint64(portModuled)%uint64(cfg.NumberOfBits)
		return index, bit
	}
```

#### Entropy function
![entropy](doc/img/entropy.svg)

The implementation is a bit different. Before saving the entropy, there's a check on the number of bit set to 1
and the number of bit set at 0. ```If bitAt1 > bitAt0 then entropy = 2 - entropy```. With this little variation, we expand the
**range of entropy** from 0-1 to **0-2**. We can use this additional information to **understand how many bits** (hashed port) were
**filled in a specific bin** (2 = all bits set, 0 = no bits set).

[more info about entroy](https://rosettacode.org/wiki/Entropy) 

#### Bitmap data structure

The bitmap implementation is a slightly improved package made by [andy2046](https://github.com/andy2046/bitmap).

### Behavior

`Peng` after receiving a config struct will start **listening** at provided **network interface**. Each **packet** is **processed** by 
**inspection function**, that will add the port to the bitmap through the AddPort func call. After the user-configured 
**timeout** has triggered, `Peng` will **save** the data to **influxdb** and in a **csv file** (according to user configuration). 
**After** the **saving**, it will **reset** all the **bitmap** and **repeat** the entire **process until sigterm signal.**

### Note

- In order to use `peng` you have to run it with root privileges.
- `Peng` is a library which will add more user extensibility and generalization in future releases.
- User can also attach own hash function instead of default one, by simply pass their func in the creation of the 
PortBitmap.

## Requirements
`libpcap` `docker` and `influxDB 2.0`

##### Running Influx on Docker

> ```$ docker run --name influxdb -p 9999:9999 quay.io/influxdb/influxdb:2.0.0-beta```

To use `influx` cli, console into the `influxdb` Docker container:

```$ docker exec -it influxdb /bin/bash```

For more information visit: <https://v2.docs.influxdata.com/v2.0/get-started/>

##### Running Influx on Linux Binaries (64-bit)

> ```
> $ wget https://dl.influxdata.com/influxdb/releases/influxdb_2.0.0-beta.8_linux_amd64.tar.gz
> $ tar xvfz influxdb_2.0.0-beta.8_linux_amd64.tar.gz
> ```

##### Running Influx on Linux Binaries (ARM)

> ```
> $ wget https://dl.influxdata.com/influxdb/releases/influxdb_2.0.0-beta.8_linux_arm64.tar.gz
> $ tar xvfz influxdb_2.0.0-beta.8_linux_arm64.tar.gz
> ```

## Binaries

You can find `peng` binaries on the release tag

## Compile

```
$ go build ./cmd/main.go
```
## How to use

In order to use `peng` you have to run it with root privileges.

``` 
peng -timeFrame [1m] -bin [16] -size [1024] -bucket [my-influxdb-bucket] -org [my-influxdb-organization] -token [influxdb-auth-token] -verbose [0-3] -export [filepath] -network [interface-name]
```

Mandatory flags:
 - `network`

Default values:
 - host: `localhost`
 - influxUrl: `http://localhost`
 - influxPort: `9999`
 - size: `1024`
 - bin: `16`
 - timeFrame: `1m`
 - verbose: `1`
 
## Options

Type `$ peng -help`

```
Usage: sys-status [options]
  -bin uint
    	number of bin in your bitmap (default 16)
  -bucket string
    	bucket string for telegraf
  -export string
    	file path to save the peng result as csv
  -influxPort uint
    	influxPort number (default 9999)
  -influxUrl string
    	influx url (default "http://localhost")
  -interfaces
    	show the list of all your network interfaces
  -network string
    	name of your network interface
  -org string
    	organization string for telegraf
  -size uint
    	size of your bitmap (default 1024)
  -timeFrame string
    	interval time to detect scans. Number + (s = seconds, m = minutes, h = hours) (default "1m")
  -token string
    	auth token for influxdb
  -verbose uint
    	set verbose level (1-3)
  -version
    	output version

```

## Dependencies

[gopacket](https://github.com/google/gopacket) used for snmp requests

```
go get github.com/google/gopacket
```

[influxdb-client](https://github.com/influxdata/influxdb-client-go) used for influxdb request

```
github.com/influxdata/influxdb-client-go
```

## Create InfluxDB DashBoard

1. In the navigation menu on the left, select **Boards** (**Dashboards**).

![dashboard](doc/img/dash-button.png)

2. Click the **Create Dashboard** menu in the upper right and select **New Dashboard.**

3. Enter a name for your dashboard in the **Name this dashboard** field in the upper left.

Note: more info at [influxdb-doc](https://v2.docs.influxdata.com/v2.0/visualize-data/dashboards/) official doc
