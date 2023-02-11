/**
 * @file network.hpp
 * @brief Network utils
 */

#pragma once

//
// Windows headers
//

#include "details/windows.hpp"


//
// STL headers
//

#include <vector>
#include <future>
#include <functional>


namespace cas::net {

/**
 * 
 */
using port_t = unsigned short;


/**
 * @brief Pretty macro to initialize WinSock2 library
 */
#define WSA_STARTUP(ws_major, ws_minor) \
   cas::net::WsaInit wsa_init_(ws_major, ws_minor);


/**
 * @brief Wrapper over WSAStartup and WSACleanup.
 */
class WsaInit final
{
public:
    /**
     * @brief Constructor. Calls WSAStartup.
     */
    explicit WsaInit(BYTE major, BYTE minor);

    /**
     * @brief Destructor. Calls WSACleanup.
     */
    ~WsaInit();

private:
    // Internal data
    WSADATA wsa_data_;
};


/**
 * 
 */
class Socket final
{
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&&)            = delete;
    Socket& operator=(Socket&&) = delete;

public:
    /**
     * 
     */
    explicit Socket();

    /**
     * 
     */
    explicit Socket(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocol_info, GROUP group, DWORD flags);

    /**
     * 
     */
    ~Socket();

    /**
     * 
     */
    operator SOCKET() const noexcept { return socket_; }

    /**
     * 
     */
    void Close() noexcept;

    /**
     * 
     */
    void Attach(SOCKET raw_socket) noexcept;

private:
    // Internal socket
    SOCKET socket_;
};


/**
 * 
 */
class TcpServer final
{
public:
    /**
     * 
     */
    using buffer_t = std::vector<char>;

    /**
     * 
     */
    using recv_handler_t = std::function<buffer_t(const buffer_t&)>;

public:
    /**
     * 
     */
    explicit TcpServer(port_t port);

    /**
     * 
     */
    ~TcpServer();

    /**
     * 
     */
    void Start(HANDLE stop, const recv_handler_t& recv_handler, int backlog = 10);

private:
    void AsyncAccept(HANDLE accept_event, Socket& client_socket);

    void HandleConnection(HANDLE stop, SOCKET client_socket, const recv_handler_t& recv_handler);

private:
    Socket socket_;
};

}  // namespace cas::net
