#ifndef switchwsh
#define switchwsh
#include <string>
#include <vector>

//ssl dogshit
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

namespace switchws {

struct Callback_Imp { virtual void operator()(const std::string& message) = 0; };
struct BytesCallback_Imp { virtual void operator()(const std::vector<uint8_t>& message) = 0; };

class WebSocket {

  public:
    typedef WebSocket * pointer;
    typedef enum readyStateValues { CLOSING, CLOSED, CONNECTING, OPEN } readyStateValues;

    static pointer create_dummy();
    static pointer from_url(const std::string& url, const std::string& origin = std::string());
    static pointer from_url_no_mask(const std::string& url, const std::string& origin = std::string());

    virtual ~WebSocket() { }
    virtual void poll(int timeout = 0) = 0; 
    virtual void send(const std::string& message) = 0;
    virtual void sendBinary(const std::string& message) = 0;
    virtual void sendBinary(const std::vector<uint8_t>& message) = 0;
    virtual void sendPing() = 0;
    virtual void close() = 0;
    virtual readyStateValues getReadyState() const = 0;

    template<class Callable>
    void dispatch(Callable callable)
    { 
        struct _Callback : public Callback_Imp {
            Callable& callable;
            _Callback(Callable& callable) : callable(callable) { }
            void operator()(const std::string& message) { callable(message); }
        };
        _Callback callback(callable);
        _dispatch(callback);
    }

    template<class Callable>
    void dispatchBinary(Callable callable)
    { 
        struct _Callback : public BytesCallback_Imp {
            Callable& callable;
            _Callback(Callable& callable) : callable(callable) { }
            void operator()(const std::vector<uint8_t>& message) { callable(message); }
        };
        _Callback callback(callable);
        _dispatchBinary(callback);
    }

  protected:
    virtual void _dispatch(Callback_Imp& callable) = 0;
    virtual void _dispatchBinary(BytesCallback_Imp& callable) = 0;
};

} 

#endif 
