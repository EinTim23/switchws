#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#ifndef _SOCKET_T_DEFINED
    typedef int socket_t;
    #define _SOCKET_T_DEFINED
#endif
#ifndef INVALID_SOCKET
    #define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
    #define SOCKET_ERROR   (-1)
#endif
#define closesocket(s) ::close(s)
#include <errno.h>
#define socketerrno errno
#define SOCKET_EAGAIN_EINPROGRESS EAGAIN
#define SOCKET_EWOULDBLOCK EWOULDBLOCK
#include <vector>
#include <string>
#include "switchws.hpp"

using switchws::Callback_Imp;
using switchws::BytesCallback_Imp;
mbedtls_x509_crt cacert;
mbedtls_net_context net_context;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl_context;
mbedtls_ssl_config ssl_config;

namespace { 
class _DummyWebSocket : public switchws::WebSocket
{
  public:
    void poll(int timeout) { }
    void send(const std::string& message) { }
    void sendBinary(const std::string& message) { }
    void sendBinary(const std::vector<uint8_t>& message) { }
    void sendPing() { }
    void close() { } 
    readyStateValues getReadyState() const { return CLOSED; }
    void _dispatch(Callback_Imp & callable) { }
    void _dispatchBinary(BytesCallback_Imp& callable) { }
};


class _RealWebSocket : public switchws::WebSocket
{
  public:
    struct wsheader_type {
        unsigned header_size;
        bool fin;
        bool mask;
        enum opcode_type {
            CONTINUATION = 0x0,
            TEXT_FRAME = 0x1,
            BINARY_FRAME = 0x2,
            CLOSE = 8,
            PING = 9,
            PONG = 0xa,
        } opcode;
        int N0;
        uint64_t N;
        uint8_t masking_key[4];
    };

    std::vector<uint8_t> rxbuf;
    std::vector<uint8_t> txbuf;
    std::vector<uint8_t> receivedData;
    readyStateValues readyState;
    bool useMask;
    bool isRxBad;

    _RealWebSocket(bool useMask)
            : readyState(OPEN)
            , useMask(useMask)
            , isRxBad(false) {
    }

    readyStateValues getReadyState() const {
      return readyState;
    }

    void poll(int timeout) { 
        if (readyState == CLOSED) {
            if (timeout > 0) {
                timeval tv = { timeout/1000, (timeout%1000) * 1000 };
                select(0, NULL, NULL, NULL, &tv);
            }
            return;
        }
        if (timeout != 0) {
            fd_set rfds;
            fd_set wfds;
            timeval tv = { timeout/1000, (timeout%1000) * 1000 };
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_SET(net_context.fd, &rfds);
            if (txbuf.size()) { FD_SET(net_context.fd, &wfds); }
            select(net_context.fd + 1, &rfds, &wfds, 0, timeout > 0 ? &tv : 0);
        }
        while (true) {
            int N = rxbuf.size();
            ssize_t ret;
            rxbuf.resize(N + 1500);
            ret = mbedtls_ssl_read(&ssl_context, (unsigned char*)&rxbuf[0] + N, 1500);
            if (false) { }
            else if (ret < 0 && (socketerrno == SOCKET_EWOULDBLOCK || socketerrno == SOCKET_EAGAIN_EINPROGRESS)) {
                rxbuf.resize(N);
                break;
            }
            else if (ret <= 0) {
                rxbuf.resize(N);
                mbedtls_net_free(&net_context);
                mbedtls_ssl_free(&ssl_context);
                mbedtls_ssl_config_free(&ssl_config);
                mbedtls_ctr_drbg_free(&ctr_drbg);
                mbedtls_entropy_free(&entropy);
                readyState = CLOSED;
                fputs(ret < 0 ? "Connection error!\n" : "Connection closed!\n", stderr);
                break;
            }
            else {
                rxbuf.resize(N + ret);
            }
        }
        while (txbuf.size()) {
            int ret = mbedtls_ssl_write(&ssl_context, (const unsigned char*)&txbuf[0], txbuf.size());
            if (false) { } 
            else if (ret < 0 && (socketerrno == SOCKET_EWOULDBLOCK || socketerrno == SOCKET_EAGAIN_EINPROGRESS)) {
                break;
            }
            else if (ret <= 0) {
                mbedtls_net_free( &net_context );
                mbedtls_ssl_free( &ssl_context );
                mbedtls_ssl_config_free( &ssl_config );
                mbedtls_ctr_drbg_free( &ctr_drbg );
                mbedtls_entropy_free( &entropy );
                readyState = CLOSED;
                fputs(ret < 0 ? "Connection error!\n" : "Connection closed!\n", stderr);
                break;
            }
            else {
                txbuf.erase(txbuf.begin(), txbuf.begin() + ret);
            }
        }
        if (!txbuf.size() && readyState == CLOSING) {
            mbedtls_net_free( &net_context );
            mbedtls_ssl_free( &ssl_context );
            mbedtls_ssl_config_free( &ssl_config );
            mbedtls_ctr_drbg_free( &ctr_drbg );
            mbedtls_entropy_free( &entropy );
            readyState = CLOSED;
        }
    }
    virtual void _dispatch(Callback_Imp & callable) {
        struct CallbackAdapter : public BytesCallback_Imp
        {
            Callback_Imp& callable;
            CallbackAdapter(Callback_Imp& callable) : callable(callable) { }
            void operator()(const std::vector<uint8_t>& message) {
                std::string stringMessage(message.begin(), message.end());
                callable(stringMessage);
            }
        };
        CallbackAdapter bytesCallback(callable);
        _dispatchBinary(bytesCallback);
    }

    virtual void _dispatchBinary(BytesCallback_Imp & callable) {
        if (isRxBad) {
            return;
        }
        while (true) {
            wsheader_type ws;
            if (rxbuf.size() < 2) { return;  }
            const uint8_t * data = (uint8_t *) &rxbuf[0];
            ws.fin = (data[0] & 0x80) == 0x80;
            ws.opcode = (wsheader_type::opcode_type) (data[0] & 0x0f);
            ws.mask = (data[1] & 0x80) == 0x80;
            ws.N0 = (data[1] & 0x7f);
            ws.header_size = 2 + (ws.N0 == 126? 2 : 0) + (ws.N0 == 127? 8 : 0) + (ws.mask? 4 : 0);
            if (rxbuf.size() < ws.header_size) { return; }
            int i = 0;
            if (ws.N0 < 126) {
                ws.N = ws.N0;
                i = 2;
            }
            else if (ws.N0 == 126) {
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 8;
                ws.N |= ((uint64_t) data[3]) << 0;
                i = 4;
            }
            else if (ws.N0 == 127) {
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 56;
                ws.N |= ((uint64_t) data[3]) << 48;
                ws.N |= ((uint64_t) data[4]) << 40;
                ws.N |= ((uint64_t) data[5]) << 32;
                ws.N |= ((uint64_t) data[6]) << 24;
                ws.N |= ((uint64_t) data[7]) << 16;
                ws.N |= ((uint64_t) data[8]) << 8;
                ws.N |= ((uint64_t) data[9]) << 0;
                i = 10;
                if (ws.N & 0x8000000000000000ull) {
                    isRxBad = true;
                    printf( "ERROR: Frame has invalid frame length. Closing.\n");
                    close();
                    return;
                }
            }
            if (ws.mask) {
                ws.masking_key[0] = ((uint8_t) data[i+0]) << 0;
                ws.masking_key[1] = ((uint8_t) data[i+1]) << 0;
                ws.masking_key[2] = ((uint8_t) data[i+2]) << 0;
                ws.masking_key[3] = ((uint8_t) data[i+3]) << 0;
            }
            else {
                ws.masking_key[0] = 0;
                ws.masking_key[1] = 0;
                ws.masking_key[2] = 0;
                ws.masking_key[3] = 0;
            }

            if (rxbuf.size() < ws.header_size+ws.N) { return; }

            if (false) { }
            else if (
                   ws.opcode == wsheader_type::TEXT_FRAME 
                || ws.opcode == wsheader_type::BINARY_FRAME
                || ws.opcode == wsheader_type::CONTINUATION
            ) {
                if (ws.mask) { for (size_t i = 0; i != ws.N; ++i) { rxbuf[i+ws.header_size] ^= ws.masking_key[i&0x3]; } }
                receivedData.insert(receivedData.end(), rxbuf.begin()+ws.header_size, rxbuf.begin()+ws.header_size+(size_t)ws.N);
                if (ws.fin) {
                    callable((const std::vector<uint8_t>) receivedData);
                    receivedData.erase(receivedData.begin(), receivedData.end());
                    std::vector<uint8_t> ().swap(receivedData);
                }
            }
            else if (ws.opcode == wsheader_type::PING) {
                if (ws.mask) { for (size_t i = 0; i != ws.N; ++i) { rxbuf[i+ws.header_size] ^= ws.masking_key[i&0x3]; } }
                std::string data(rxbuf.begin()+ws.header_size, rxbuf.begin()+ws.header_size+(size_t)ws.N);
                sendData(wsheader_type::PONG, data.size(), data.begin(), data.end());
            }
            else if (ws.opcode == wsheader_type::PONG) { }
            else if (ws.opcode == wsheader_type::CLOSE) { close(); }
            else { printf( "ERROR: Got unexpected WebSocket message.\n"); close(); }

            rxbuf.erase(rxbuf.begin(), rxbuf.begin() + ws.header_size+(size_t)ws.N);
        }
    }

    void sendPing() {
        std::string empty;
        sendData(wsheader_type::PING, empty.size(), empty.begin(), empty.end());
    }

    void send(const std::string& message) {
        sendData(wsheader_type::TEXT_FRAME, message.size(), message.begin(), message.end());
    }

    void sendBinary(const std::string& message) {
        sendData(wsheader_type::BINARY_FRAME, message.size(), message.begin(), message.end());
    }

    void sendBinary(const std::vector<uint8_t>& message) {
        sendData(wsheader_type::BINARY_FRAME, message.size(), message.begin(), message.end());
    }

    template<class Iterator>
    void sendData(wsheader_type::opcode_type type, uint64_t message_size, Iterator message_begin, Iterator message_end) {
        const uint8_t masking_key[4] = { 0x12, 0x34, 0x56, 0x78 };
        if (readyState == CLOSING || readyState == CLOSED) { return; }
        std::vector<uint8_t> header;
        header.assign(2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) + (useMask ? 4 : 0), 0);
        header[0] = 0x80 | type;
        if (false) { }
        else if (message_size < 126) {
            header[1] = (message_size & 0xff) | (useMask ? 0x80 : 0);
            if (useMask) {
                header[2] = masking_key[0];
                header[3] = masking_key[1];
                header[4] = masking_key[2];
                header[5] = masking_key[3];
            }
        }
        else if (message_size < 65536) {
            header[1] = 126 | (useMask ? 0x80 : 0);
            header[2] = (message_size >> 8) & 0xff;
            header[3] = (message_size >> 0) & 0xff;
            if (useMask) {
                header[4] = masking_key[0];
                header[5] = masking_key[1];
                header[6] = masking_key[2];
                header[7] = masking_key[3];
            }
        }
        else { 
            header[1] = 127 | (useMask ? 0x80 : 0);
            header[2] = (message_size >> 56) & 0xff;
            header[3] = (message_size >> 48) & 0xff;
            header[4] = (message_size >> 40) & 0xff;
            header[5] = (message_size >> 32) & 0xff;
            header[6] = (message_size >> 24) & 0xff;
            header[7] = (message_size >> 16) & 0xff;
            header[8] = (message_size >>  8) & 0xff;
            header[9] = (message_size >>  0) & 0xff;
            if (useMask) {
                header[10] = masking_key[0];
                header[11] = masking_key[1];
                header[12] = masking_key[2];
                header[13] = masking_key[3];
            }
        }
        txbuf.insert(txbuf.end(), header.begin(), header.end());
        txbuf.insert(txbuf.end(), message_begin, message_end);
        if (useMask) {
            size_t message_offset = txbuf.size() - message_size;
            for (size_t i = 0; i != message_size; ++i) {
                txbuf[message_offset + i] ^= masking_key[i&0x3];
            }
        }
    }

    void close() {
        if(readyState == CLOSING || readyState == CLOSED) { return; }
        readyState = CLOSING;
        uint8_t closeFrame[6] = {0x88, 0x80, 0x00, 0x00, 0x00, 0x00}; 
        std::vector<uint8_t> header(closeFrame, closeFrame+6);
        txbuf.insert(txbuf.end(), header.begin(), header.end());
    }

};


switchws::WebSocket::pointer from_url(const std::string& url, bool useMask, const std::string& origin) {
    char host[512];
    int port;
    char path[512];
    if (url.size() >= 512) {
      printf( "ERROR: url size limit exceeded: %s\n", url.c_str());
      return NULL;
    }
    if (origin.size() >= 200) {
      printf( "ERROR: origin size limit exceeded: %s\n", origin.c_str());
      return NULL;
    }
    if (false) { }
    else if (sscanf(url.c_str(), "wss://%[^:/]:%d/%s", host, &port, path) == 3) {
    }
    else if (sscanf(url.c_str(), "wss://%[^:/]/%s", host, path) == 2) {
        port = 443;
    }
    else if (sscanf(url.c_str(), "wss://%[^:/]:%d", host, &port) == 2) {
        path[0] = '\0';
    }
    else if (sscanf(url.c_str(), "wss://%[^:/]", host) == 1) {
        port = 443;
        path[0] = '\0';
    }
    else {
        printf( "ERROR: Could not parse WebSocket url: %s\n", url.c_str());
        return NULL;
    }
    printf("switchws: connecting: host=%s port=%d path=/%s\n", host, port, path);
    mbedtls_net_init( &net_context );
    mbedtls_ssl_init( &ssl_context );
    mbedtls_ssl_config_init( &ssl_config );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    int ret;
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                            nullptr,
                            0) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return NULL;
    }
    
    if ((ret = mbedtls_net_connect(&net_context, host, std::to_string(port).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf( "[!] mbedtls_net_connect (-0x%X)\n", -ret);
        return NULL;
    }

    if ((ret = mbedtls_ssl_config_defaults(&ssl_config,
                                                MBEDTLS_SSL_IS_CLIENT,
                                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                                MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf( "[!] mbedtls_ssl_config_defaults failed to load default SSL config (-0x%X)\n", -ret);
        return NULL;
    }
    mbedtls_ssl_conf_max_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_authmode( &ssl_config, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_rng( &ssl_config, mbedtls_ctr_drbg_random, &ctr_drbg );
    if ((ret = mbedtls_ssl_setup(&ssl_context, &ssl_config)) != 0)
    {
        printf( "[!] mbedtls_ssl_setup failed to setup SSL context (-0x%X)\n", -ret);
        return NULL;
    }
    mbedtls_ssl_set_bio(&ssl_context, &net_context, mbedtls_net_send, mbedtls_net_recv, nullptr);
    if ((ret = mbedtls_ssl_set_hostname(&ssl_context, host)) != 0)
    {
        printf( "[!] mbedtls_ssl_set_hostname (-0x%X)\n", -ret);
        return NULL;
    }
    {
        char line[1024];
        int status;
        int i;
        snprintf(line, 1024, "GET /%s HTTP/1.1\r\n", path); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        if (port == 443) {
            snprintf(line, 1024, "Host: %s\r\n", host); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        }
        else {
            snprintf(line, 1024, "Host: %s:%d\r\n", host, port); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        }
        snprintf(line, 1024, "Upgrade: websocket\r\n"); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        snprintf(line, 1024, "Connection: Upgrade\r\n"); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        if (!origin.empty()) {
            snprintf(line, 1024, "Origin: %s\r\n", origin.c_str()); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        }
        snprintf(line, 1024, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        snprintf(line, 1024, "Sec-WebSocket-Version: 13\r\n"); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        snprintf(line, 1024, "\r\n"); mbedtls_ssl_write(&ssl_context, (const unsigned char*)line, strlen(line));
        for (i = 0; i < 2 || (i < 1023 && line[i-2] != '\r' && line[i-1] != '\n'); ++i) { if (mbedtls_ssl_read(&ssl_context, (unsigned char*)line+i, 1) == 0) { return NULL; } }
        line[i] = 0;
        if (i == 1023) { printf( "ERROR: Got invalid status line connecting to: %s\n", url.c_str()); return NULL; }
        printf("%s", line);
        if (sscanf(line, "HTTP/1.1 %d", &status) != 1 || status != 101) { printf( "ERROR: Got bad status connecting to %s: %s", url.c_str(), line); return NULL; }
        while (true) {
            for (i = 0; i < 2 || (i < 1023 && line[i-2] != '\r' && line[i-1] != '\n'); ++i) { if (mbedtls_ssl_read(&ssl_context, (unsigned char*)line+i, 1) == 0) { return NULL; } }
            if (line[0] == '\r' && line[1] == '\n') { break; }
        }
    }
    int flag = 1;
    setsockopt(net_context.fd, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(flag)); // Disable Nagle's algorithm
    fcntl(net_context.fd, F_SETFL, O_NONBLOCK);
    return switchws::WebSocket::pointer(new _RealWebSocket(useMask));
}

} 



namespace switchws {

WebSocket::pointer WebSocket::create_dummy() {
    static pointer dummy = pointer(new _DummyWebSocket);
    return dummy;
}


WebSocket::pointer WebSocket::from_url(const std::string& url, const std::string& origin) {
    return ::from_url(url, true, origin);
}

WebSocket::pointer WebSocket::from_url_no_mask(const std::string& url, const std::string& origin) {
    return ::from_url(url, false, origin);
}


} 
