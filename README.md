# leshan-bsserver-rotkey
A very simple LWM2M bootstrap server used to test key rotation.

# Build & Run
Build the test server with :

```
mvn clean install
```
Then to run it :

```
java -jar target/leshan-bsserver-rotkey-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```

# Output
Logs should help you to see what happened, e.g :
```
2021-02-03 16:13:57,576 INFO LeshanBootstrapServer - Bootstrap server started at coap://0.0.0.0/0.0.0.0:5683 coaps://0.0.0.0/0.0.0.0:5684
2021-02-03 16:14:10,886 INFO RotKeyServer$1 - Device try to connect using 'identity1' identity. (PSK expected 'AAAA')
2021-02-03 16:14:10,946 INFO RotKeyServer$2 - Try to apply new credentials 'identity2','BBBB'
2021-02-03 16:15:35,851 INFO RotKeyServer$1 - Device try to connect using 'identity1' identity. (PSK expected 'AAAA')
2021-02-03 16:15:35,858 INFO RotKeyServer$2 - Try to apply new credentials 'identity3','CCCC'
2021-02-03 16:17:43,029 INFO RotKeyServer$1 - Device try to connect using 'identity3' identity. (PSK expected 'CCCC')
2021-02-03 16:17:43,044 INFO RotKeyServer$2 - Try to apply new credentials 'identity4','DDDD'
2021-02-03 16:19:49,858 INFO RotKeyServer$1 - Device try to connect using 'identity4' identity. (PSK expected 'DDDD')
2021-02-03 16:19:49,869 INFO RotKeyServer$2 - Try to apply new credentials 'identity1','AAAA'
2021-02-03 16:21:56,760 INFO RotKeyServer$1 - Device try to connect using 'identity1' identity. (PSK expected 'AAAA')
2021-02-03 16:21:56,778 INFO RotKeyServer$2 - Try to apply new credentials 'identity2','BBBB'
2021-02-03 16:24:03,675 INFO RotKeyServer$1 - Device try to connect using 'identity2' identity. (PSK expected 'BBBB')
2021-02-03 16:24:03,696 INFO RotKeyServer$2 - Try to apply new credentials 'identity3','CCCC'
```

# Need to change default config
Config is hardcoded, change code directly. See [RotKeyServer](./src/main/java/org/eclipse/leshan/bsserver/rotkey/RotKeyServer.java)

# Need more logs
See change value in [logback.xml](./src/main/resources/logback.xml)