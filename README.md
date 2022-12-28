## Switch WS
A websocket client library that targets the nintendo switch. It uses [easywsclient](https://github.com/dhbaird/easywsclient) as reference.  You should be able to use this library on linux based operating systems too.

### Known issues
- The library doesn't verify the SSL certificates which might lead to security issues
- Only SSL secured websockets are supported(plaintext will be added back later)
- You currently can't open multiple sockets at once because the mbedtls variables are global (will be fixed once I have time, I did it like that for testing purposes)
### Example

```cpp
#include  <iostream>
#include  <switchws.hpp>

using switchws::WebSocket;
int main(int argc,  char* argv[]) {
	consoleInit(NULL);
	padConfigureInput(1, HidNpadStyleSet_NpadStandard);
	PadState pad;
	padInitializeDefault(&pad);
	socketInitializeDefault();
	WebSocket::pointer ws = WebSocket::from_url("wss://example.com");
	if(ws ==  NULL)
		goto exit;
	ws->send("test");
	while  (ws->getReadyState()  != WebSocket::CLOSED &&  appletMainLoop())
	{
		padUpdate(&pad);
		u64 kDown =  padGetButtonsDown(&pad);
		if  (kDown & HidNpadButton_Plus)
			break;
		ws->poll();
		ws->dispatch([ws](const std::string & message)  {
			std::cout << message << std::endl;
			consoleUpdate(NULL);
		});
		consoleUpdate(NULL);
	}
exit:
	socketExit();
	consoleExit(NULL);
	return  0;
}

delete ws;
```

