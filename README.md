# PewSWITCH
A FreeSWITCH specific scanning and exploitation toolkit for CVE-2021-37624 and CVE-2021-41157.

> Related blog: https://0xinfection.github.io/posts/analyzing-freeswitch-vulns/

## Usage
The help statement of the tool is as below:
```groovy
$ ./pewswitch --help

     ___    .        ____       _ __      __
    / _ \___|\    __/ __/|   __(_) /_____/ /
   / ___/ -_) |/|/ /\ \| |/|/ / / __/ __/ _ \
  /_/   \__/|__,__/___/|__,__/_/\__/\__/_//_/  v0.1

       "where we pew pew pew freeswitch"

Usage of ./pewswitch:
  -cve string
        Specify a specific CVE to scan. Both vulns are tested by default.
  -delay int
        Delay in seconds between subsequent requests. (default 0)
  -events string
        Comma-separated list of events to be subscribed to. All events are monitored by default.
  -expires int
        Maximum value of the 'Expires' header for SUBSCRIBE requests. (default 60)
  -ext-file string
        Specify a file containing extensions instead of '-exts'.
  -exts string
        Comma separated list of extensions to scan.
  -msg-file string
        Specify a CSV file containing messages to be sent (if found vulnerable to CVE-2021-37624).
  -out-dir string
        Output directory to write the results to. (default "./pewswitch-results/")
  -out-format string
        Output format type of the results. Can be either 'json' or 'csv'. (default "json")
  -threads int
        Number of threads to use while scanning. (default 2)
  -user-agent string
        Custom user-agent string to use. (default "pewswitch/0.1")
```

### Scanning for a specific vulnerability
By default the tool scans for both vulnerabilites. If you want to test for a specific vulnerability, you can use the `-cve` flag to test for a specific vulnerability.

Example:
```groovy
./pewswitch -cve 'cve-2021-37624' -exts 1000 freeserver.voip.com
```

### Specifying extensions
To specify extensions, you can choose either of the methods:
- Specify a comma separated list of extensions via the `-exts` argument.

    Example:
    ```powershell
    ./pewswitch -exts 1000,1001 freeserver.voip.com freeserver1.voip.com:5060
    ```
    This will make the tool to test for combinations of pairs for each extension with every host. So the end targets that will be tested in the above command are: `1000@freeserver.voip.com`, `1001@freeserver.voip.com`, `1000@freeserver1.voip.com:5060` and `1001@freeserver1.voip.com:5060`.

- Specify a file containing extensions. Note that when using a file, you need to specify both user and host. This is especially useful when you have to test specific extensions on specific servers. An example of such a file (e.g. [`extensions-sample.txt`](extensions-sample.txt)) could look like this:
    ```
    1000@freeserver.voip.com
    1001@freeserver1.voip.com:5060
    1002@freeserver01.voip.com:5660
    ...
    ```

    Example:
    ```groovy
    ./pewswitch -ext-file extensions-sample.txt
    ```

Note that if any port is not specified with the host, port 5060 will be used by default as the destination port.

### Output
The tool can output in 2 different formats, namely JSON and CSV. The default output format is JSON. Output format can be changed using the `-out-format` switch.

Example:
```groovy
./pewswitch -exts 1000 -out-format csv freeserver.voip.com 
```

You can find samples of reports in [`json`](pewswitch-results/sample-report.json) as well as [`csv`](pewswitch-results/sample-report.csv) format in the `./pewswitch-results/` directory.

The destination output directory can be changed using the `-out-dir` argument. By default the output directory is `./pewswitch-results/` which is created in the current working directory while running the tool.

Example:
```groovy
./pewswitch -ext-file extensions-sample.txt -out-dir /tmp
```

### Request Specific Settings
There are some additional packet specific settings in the tool that allows customization of requests during vulnerability validation/exploitation.

#### MESSAGE packets
If a server is found _vulnerable_ to CVE-2021-37624, by default a sample message from name `FBI` and number `022-324-3000` is sent to the target extension. The contents of the message looks like this: `FBI here. Open your door!`

This behaviour can be changed by making use of the `-msg-file` argument. This accepts a CSV file containing the name of the sender, the phone number and lastly the message contents to be sent. An example of such a file is [`messages-sample.csv`](messages-sample.csv).
```
sender_name,sender_phone,message
FBI,022-324-3000,FBI here. Open your door!
0xInfection,000-000-0000,Hi. Just confirming the vulnerability.
SPAMMY SALESMAN,BAD-GUY-9999,BUY MY STUFF!
```
Example:
```groovy
./pewswitch -cve 'cve-2021-27624' -msg-file messages-sample.csv -exts 1000 freeserver.voip.com 
```

#### SUBSCRIBE requests
By default, the tool sends SUBSCRIBE requests with a `Expires` header set at 60 seconds. It is for the same time-frame the tool will continue to listen for NOTIFY messages from the server. The value can be changed by making use of the `-expires` flag. 

Example:
```groovy
./pewswitch -expires 600 -ext-file extensions-sample.txt
```

The tool also monitors for NOTIFY messages by subscribing to *__all__* events. A list of all events is below:
- `talk`
- `hold`
- `conference`
- `as-feature-event`
- `dialog`
- `line-seize`
- `call-info`
- `sla`
- `include-session-description`
- `presence`
- `presence.winfo`
- `message-summary`
- `refer`

This behaviour can be changed by the `-events` flag which takes a comma separated list of events to monitor. Example:
```groovy
./pewswitch -cve 'cve-2021-41157' -events message-summary,presence -exts 1000,1002 freeserver.voip.com
```

### Setup
You can make use of the pre-built binaries from the [Releases](https://github.com/0xInfection/PewSWITCH/releases) section. Or, if you prefer to compile the code yourself, you'll need Go > 1.13. To build the tool, you can run `go build` which will give you a binary to run.

### Version and License
The tool is available under MIT License. Feel free to do whatever you want to do with it. :)

Currently, PewSWITCH is at v0.1.

### Bugs and features requests
New requests and features? Feel free to create an [issue](https://github.com/0xInfection/pewswitch/issues/new/) or a [pull request](https://github.com/0xInfection/pewswitch/pulls).

If you have anything to discuss you can reach out to me via twitter/email on my profile.

> Created with ♡ by [Pinaki](https://twitter.com/0xInfection).