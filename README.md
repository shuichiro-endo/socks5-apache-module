# socks5 apache module

socks5 proxy(apache module) and client with socks5 over tls

hide socks5 proxy in an http server


## How it works
```mermaid
sequenceDiagram
    participant A as socks5 client
    participant B as my client
    participant C as apache http server (my socks5 module)
    participant D as destination server
    loop 
        A->>+B: socks5 selection request (Socks5)
        B->>+C: HTTP GET Request (HTTP or HTTPS)
        C->>C: check HTTP Request Header Key and Value (e.g. socks5: socks5)
        note right of C: if the key and value do not match, do nothing
        note right of C: if value of tls key is on, send socks5 data with tls (Socks5 over TLS)
        C-->>B: OK
        alt socks5 over tls flag is on
        B->>+C: SSL connect
        C-->>-B: 
        end
        B->>+C: socks5 selection request (Socks5 or Socks5 over TLS)
        C-->>-B: socks5 selection response (Socks5 or Socks5 over TLS)
        B-->>-A: socks5 selection response (Socks5)
        alt socks5 server authentication method is username/password authentication
        A->>+B: socks5 username/password authentication request (Socks5)
        B->>+C: socks5 username/password authentication request (Socks5 or Socks5 over TLS)
        C->>C: check username and password
        C-->>-B: socks5 username/password authentication response (Socks5 or Socks5 over TLS)
        B-->>-A: socks5 username/password authentication response (Socks5)
        end
        A->>+B: socks5 socks request (Socks5)
        B->>+C: socks5 socks request (Socks5 or Socks5 over TLS)
        C->>+D: check connection
        D-->>-C:  
        C-->>-B: socks5 socks response (Socks5 or Socks5 over TLS)
        B-->>-A: socks5 socks response (Socks5)
        loop until communication ends
            A->>+B: request (Socks5)
            B->>+C: request (Socks5 or Socks5 over TLS)
            C->>+D: request
            D-->>-C: response
            C-->>-B: response (Socks5 or Socks5 over TLS)
            B-->>-A: response (Socks5)
        end
        C-->>-B: HTTP GET Response (HTTP or HTTPS)
    end
```

## Installation
### Install dependencies
- server
    - apache2 http server (and mod_ssl)
    - apxs - APache eXtenSion tool
    - openssl and libssl-dev
    ```
    sudo apt install apache2 apache2-dev openssl libssl-dev
    ```

- client
    - openssl and libssl-dev
    ```
    sudo apt install openssl libssl-dev
    ```

### Install
#### 1. download the latest [socks5 apache module](https://github.com/shuichiro-endo/socks5-apache-module)
```
git clone https://github.com/shuichiro-endo/socks5-apache-module.git
```
#### 2. build and install
- server
    1. build and install my module
    ```
    cd socks5-apache-module/server
    sudo apxs -i -a -c mod_socks5.c -lssl -lcrypto
    ```
    2. restart apache2
    ```
    sudo systemctl restart apache2
    ```

- client
    1. build
    ```
    cd socks5-apache-module/client
    make
    ```

## Usage
- server
    1. run apache http server
    ```
    sudo systemctl start apache2
    ```
    2. connect to my server from my client

- client
    1. copy ssl/tls server certificate to my client directory (if the client connects to the apache server with https)
    ```
    cp xxx.crt socks5-apache-module/client/server_https.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char serverCertificateFilenameHttps[256] = "server_https.crt";	// server certificate file name (HTTPS)
    char serverCertificateFileDirectoryPathHttps[256] = ".";	// server certificate file directory path (HTTPS)
    ```
    3. build (if you change the certificate filename or directory path)
    ```
    cd socks5-apache-module/client
    make
    ```
    4. run my client (if the client uses socks5 over tls, you need to change the privatekey and certificate. see [How to change socks5 server privatekey and certificate (for Socks5 over TLS)](https://github.com/shuichiro-endo/socks5-apache-module#how-to-change-socks5-server-privatekey-and-certificate-for-socks5-over-tls).)
    ```
    usage   : ./client -h listen_ip -p listen_port -H target_socks5server_domainname -P target_socks5server_port [-s (HTTPS)] [-t (Socks5 over TLS)]
    example : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 80
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 80 -t
            : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 443 -s
            : ./client -h 0.0.0.0 -p 9050 -H foobar.test -P 443 -s -t
    ```
    5. connect to my client from other clients(browser, proxychains, etc.)
    ```
    proxychains4 curl -v https://www.google.com
    curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
    ```

## Notes
### How to change HTTP Request Header Key and Value
- server
    1. modify mod_socks5.c file
    ```
    #define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
    #define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
    #define HTTP_REQUEST_HEADER_TLS_KEY "tls"
    #define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5
    #define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
    ```
    2. build and install my module
    ```
    cd socks5-apache-module/server
    sudo apxs -i -a -c mod_socks5.c -lssl -lcrypto
    ```
    3. restart apache2
    ```
    sudo systemctl restart apache2
    ```

- client
    1. modify client.c file
    ```
    #define HTTP_REQUEST_HEADER_SOCKS5_KEY "socks5"
    #define HTTP_REQUEST_HEADER_SOCKS5_VALUE "socks5"
    #define HTTP_REQUEST_HEADER_TLS_KEY "tls"
    #define HTTP_REQUEST_HEADER_TLS_VALUE1 "off"	// Socks5
    #define HTTP_REQUEST_HEADER_TLS_VALUE2 "on"	// Socks5 over TLS
    
    ...

    if(socks5OverTlsFlag == 0){	// Socks5
    	httpRequestLength = snprintf(httpRequest, BUFSIZ+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE1);
    }else{	// Socks5 over TLS
    	httpRequestLength = snprintf(httpRequest, BUFSIZ+1, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n%s: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", domainname, HTTP_REQUEST_HEADER_SOCKS5_KEY, HTTP_REQUEST_HEADER_SOCKS5_VALUE, HTTP_REQUEST_HEADER_TLS_KEY, HTTP_REQUEST_HEADER_TLS_VALUE2);
    }
    ```
    2. build
    ```
    cd socks5-apache-module/client
    make
    ```

### How to change socks5 server Authentication Method
- server
    1. modify mod_socks5.c file
    ```
    static char authenticationMethod = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
    static char username[256] = "socks5user";
    static char password[256] = "supersecretpassword";
    ```
    2. build and install my module
    ```
    cd socks5-apache-module/server
    sudo apxs -i -a -c mod_socks5.c -lssl -lcrypto
    ```
    3. restart apache2
    ```
    sudo systemctl restart apache2
    ```

### How to change socks5 server privatekey and certificate (for Socks5 over TLS)
- server
    1. generate server privatekey, publickey and certificate
    ```
    openssl ecparam -genkey -name prime256v1 -out server-key-pair.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -out server-private.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -pubout -out server-public.pem
    
    openssl req -new -sha256 -key server-key-pair.pem -out server.csr
    openssl x509 -days 3650 -req -signkey server-private.pem < server.csr > server.crt
    openssl x509 -text -noout -in server.crt
    ```
    2. copy the server privatekey and certificate
    ```
    cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END EC PRIVATE KEY-----\\n"\\/"-----END EC PRIVATE KEY-----\\n";/g'
    cat server.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
    ```
    3. paste the privatekey and certificate into serverkey.h file
    ```
    char serverPrivateKey[] = "-----BEGIN EC PRIVATE KEY-----\n"\
    "MHcCAQEEIPAB7VXkdlfWvOL1YKr+cxGLhx69g/eqUjncU1D9hkUdoAoGCCqGSM49\n"\
    "AwEHoUQDQgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9\n"\
    "O7kldBsGkxFXSbXcUfjk6wyrgarKndpK0A==\n"\
    "-----END EC PRIVATE KEY-----\n";

    char serverCertificate[] = "-----BEGIN CERTIFICATE-----\n"\
    "MIIBhTCCASsCFB47Pqx2Ko4ZXD5bCsGaaTP1Zjh8MAoGCCqGSM49BAMCMEUxCzAJ\n"\
    "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"\
    "dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMTE1MTIwODA3WhcNMzMwMTEyMTIwODA3\n"\
    "WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"\
    "SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"\
    "QgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9O7kldBsG\n"\
    "kxFXSbXcUfjk6wyrgarKndpK0DAKBggqhkjOPQQDAgNIADBFAiEAqknImSukXNY+\n"\
    "fkuuFbDFkte9mZM3Xy/ArE7kDIMt4nwCIHdlJRn0Cf18VQbpLessgklsk/gX59uo\n"\
    "jrsksbPHQ50h\n"\
    "-----END CERTIFICATE-----\n";
    ```
    4. build and install my module
    ```
    cd socks5-apache-module/server
    sudo apxs -i -a -c mod_socks5.c -lssl -lcrypto
    ```
    5. restart apache2
    ```
    sudo systemctl restart apache2
    ```

- client
    1. copy server.crt file to my client directory
    ```
    cp server.crt socks5-apache-module/client/server_socks5.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char serverCertificateFilenameSocks5[256] = "server_socks5.crt";	// server certificate file name (Socks5 over TLS)
    char serverCertificateFileDirectoryPathSocks5[256] = ".";	// server certificate file directory path (Socks5 over TLS)
    ```
    3. build (if you change the certificate filename or directory path)
    ```
    cd socks5-apache-module/client
    make
    ```

### How to change socks5 server cipher suite TLS1.2, TLS1.3 (for Socks5 over TLS)
- server
    1. select cipher suite(TLS1.2) and check
    ```
    openssl ciphers -v "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256"
    ```
    2. select cipher suite(TLS1.3) [https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html)
    ```
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
    ```
    3. modify mod_socks5.c file
    ```
    char cipherSuiteTLS1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
    char cipherSuiteTLS1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3
    ```
    4. build and install my module
    ```
    cd socks5-apache-module/server
    sudo apxs -i -a -c mod_socks5.c -lssl -lcrypto
    ```
    5. restart apache2
    ```
    sudo systemctl restart apache2
    ```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/socks5-apache-module/blob/main/LICENSE) file for details.

