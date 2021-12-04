# PewSWITCH
A scanning and exploitation toolkit for CVE-2021-37624 and CVE-2021-41157 in FreeSWITCH.

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

#### Scanning for a specific vulnerability
By default the tool scans for both vulnerabilites. If you want to test for a specific vulnerability, you can use the `-cve` flag to test for a specific vulnerability.

Example:
```powershell
./pewswitch -cve cve-2021-37624 -exts 1000 freeserver.voip.com
```

#### Specifying extensions
To specify extensions, you can choose either of the methods:
- Specify a comma separated list of extensions via the `-exts` argument.

    Example:
    ```powershell
    ./pewswitch -exts 1000,1001,1002 freeserver.voip.com
    ```

- Specify a file containing extensions. Note that when using a file, you need to specify both user and host. An example of such a file (e.g. `extensions.txt`) could look like this:
    ```
    1000@freeserver.voip.com
    1001@freeserver1.voip.com:5062
    1002@freeserver01.voip.com:9009
    ```

    Example:
    ```powershell
    ./pewswitch -ext-file extensions.txt
    ```
###