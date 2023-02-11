/**
 * @file network.hpp
 * @brief Network utils implementation
 */


#include "details/network.hpp"
#include "details/error.hpp"

#include <atlsync.h>


namespace cas::net {
namespace details {

[[noreturn]] void ThrowLast()
{
    error::Throw(WSAGetLastError());
}


class WsaEvent final
{
public:
    WsaEvent()
        : h_(WSACreateEvent())
    { }

    ~WsaEvent()
    {
        WSACloseEvent(h_);
    }

    operator WSAEVENT() const noexcept { return h_; }

private:
    WSAEVENT h_;
};

}  // namespace details


WsaInit::WsaInit(BYTE major, BYTE minor)
    : wsa_data_()
{
    if (0 != WSAStartup(MAKEWORD(major, minor), &wsa_data_))
    {
        details::ThrowLast();
    }
}


WsaInit::~WsaInit()
{
    WSACleanup();
}


Socket::Socket()
    : socket_(INVALID_SOCKET)
{ }


Socket::Socket(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocol_info, GROUP group, DWORD flags)
    : socket_(WSASocket(af, type, protocol, protocol_info, group, flags))
{
    if (INVALID_SOCKET == socket_)
    {
        details::ThrowLast();
    }
}


Socket::~Socket()
{
    Close();
}


void Socket::Close() noexcept
{
    if (socket_ != INVALID_SOCKET)
    {
        closesocket(std::exchange(socket_, INVALID_SOCKET));
    }
}


void Socket::Attach(SOCKET raw_socket) noexcept
{
    Close();
    socket_ = raw_socket;
}


TcpServer::TcpServer(port_t port)
    : socket_(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
          WSA_FLAG_OVERLAPPED /* Overlapped I/O will be used */)
{
    SOCKADDR_IN host     = {};
    host.sin_family      = AF_INET;
    host.sin_port        = htons(port);
    host.sin_addr.s_addr = 0;  // Use own IP

    if (0 != bind(socket_, reinterpret_cast<SOCKADDR*>(&host), static_cast<int>(sizeof(host))))
    {
        details::ThrowLast();
    }
}


TcpServer::~TcpServer() = default;


void TcpServer::Start(HANDLE stop, const recv_handler_t& recv_handler, int backlog /* = 10 */)
{
    if (!stop)
    {
        //
        // Stop event MUST be passed
        //

        error::Throw(ERROR_INVALID_PARAMETER);
    }

    //
    // Start listening
    //

    if (0 != listen(socket_, backlog))
    {
        details::ThrowLast();
    }

    //
    // And now accept connections
    //

    ATL::CEvent accept_event(TRUE, FALSE);

    while (true)
    {
        //
        // Asynchonously accept a next connection
        //

        Socket client_socket;
        AsyncAccept(accept_event, client_socket);

        const HANDLE waitables[]   = { accept_event, stop };
        const auto waitables_count = static_cast<DWORD>(std::size(waitables));

        const auto wait_result = WaitForMultipleObjects(waitables_count, waitables, FALSE, INFINITE);
        switch (wait_result)
        {
        case WAIT_OBJECT_0:
            //
            // New conection received
            //

            HandleConnection(stop, client_socket, recv_handler);
            break;

        case WAIT_OBJECT_0 + 1:
            //
            // Stop requested
            //

            return;

        case WAIT_FAILED:
            error::ThrowLast();
        }
    }
}


void TcpServer::AsyncAccept(HANDLE accept_event, Socket& client_socket)
{
    std::thread([this, accept_event, &client_socket] {
        SOCKADDR_IN client_addr = {};
        auto addr_len           = static_cast<int>(sizeof(client_addr));

        if (const auto raw_socket = accept(socket_, reinterpret_cast<SOCKADDR*>(&client_addr), &addr_len);
            INVALID_SOCKET != raw_socket)
        {
            client_socket.Attach(raw_socket);
        }

        SetEvent(accept_event);
    }).detach();
}


void TcpServer::HandleConnection(HANDLE stop, SOCKET client_socket, const recv_handler_t& recv_handler)
{
    //
    // Enough space for tasks, but in real life it probably
    // should be more precisely chosen...
    //

    static constexpr auto kBufferSize = 4096;

    details::WsaEvent event;

    WSAOVERLAPPED owl = {};
    owl.hEvent        = event;

    const WSAEVENT waitables[] = { event, stop };
    const auto waitables_count = static_cast<DWORD>(std::size(waitables));

    //
    // Start reading...
    //

    buffer_t raw_buffer(kBufferSize, 0);

    WSABUF buffer = {};
    buffer.len    = static_cast<ULONG>(raw_buffer.size());
    buffer.buf    = raw_buffer.data();

    //
    // TODO: WSARecv
    //

    raw_buffer = recv_handler(raw_buffer);

    //
    // TODO: WSASend
    //
}


}  // namespace cas::net
