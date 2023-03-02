/**
 * @file crypto.hpp
 * @brief CryptoAPI helpers
 */

#pragma once

//
// Windows headers
//

#include "windows.hpp"


//
// STL headers
//

#include <string>
#include <memory>
#include <vector>
#include <type_traits>


namespace cas::crypto {

/**
 * @brief Wraps an allocator and erases memory before its deallocation
 *        to protect sensitive data.
 */
template<typename WrappedAlloc>
class erasing_adaptor
{
    using wrapped_t = WrappedAlloc;
    using traits_t  = std::allocator_traits<wrapped_t>;

public:
    using allocator_type                         = wrapped_t;
    using value_type                             = typename traits_t::value_type;
    using size_type                              = typename traits_t::size_type;
    using difference_type                        = typename traits_t::difference_type;
    using pointer                                = typename traits_t::pointer;
    using const_pointer                          = typename traits_t::const_pointer;
    using void_pointer                           = typename traits_t::void_pointer;
    using const_void_pointer                     = typename traits_t::const_void_pointer;
    using propagate_on_container_copy_assignment = typename traits_t::propagate_on_container_copy_assignment;
    using propagate_on_container_move_assignment = typename traits_t::propagate_on_container_move_assignment;
    using propagate_on_container_swap            = typename traits_t::propagate_on_container_swap;
    using is_always_equal                        = typename traits_t::is_always_equal;

    template<typename Ty>
    struct rebind
    {
        using other = erasing_adaptor<typename traits_t::template rebind_alloc<Ty>>;
    };

    //
    // Check if we actually can erase allocated space safe
    //

    static_assert(std::is_scalar_v<value_type> || std::is_trivial_v<value_type> && std::is_standard_layout_v<value_type>,
        "[cas::crypto::erasing_adaptor]: wrapped allocator MUST be instantiated with a type, "
        "that can be zeroed before destruction.");

    /**
     * @brief Constructs a wrapped allocator from its constructor arguments.
     */
    template<typename... Tys>
    erasing_adaptor(Tys&&... args) noexcept(std::is_nothrow_constructible_v<wrapped_t, Tys...>)
        : wrapped_(std::forward<Tys>(args)...)
    { }

    erasing_adaptor(const erasing_adaptor&)            = default;
    erasing_adaptor& operator=(const erasing_adaptor&) = default;

    erasing_adaptor(erasing_adaptor&&)            = default;
    erasing_adaptor& operator=(erasing_adaptor&&) = default;

    /**
     * @brief Allocates uninitialized storage.
     */
    value_type* allocate(size_type n)
    {
        return traits_t::allocate(wrapped_, n);
    }

    /**
     * @brief Deallocates storage.
     */
    void deallocate(value_type* p, size_type n)
    {
        if (p)
        {
            //
            // That's the purpose of this adaptor!
            // Erase memory before deallocation
            //

            const auto n_bytes = n * sizeof(value_type);
            SecureZeroMemory(p, static_cast<SIZE_T>(n_bytes));
        }

        return traits_t::deallocate(wrapped_, p, n);
    }

    /**
     * @brief Constructs an object in allocated storage.
     */
    template<typename Ty, typename... Tys>
    void construct(Ty* p, Tys&&... args)
    {
        return traits_t::construct(wrapped_, p, std::forward<Tys>(args)...);
    }

    /**
     * @brief Destructs an object in allocated storage.
     */
    template<typename Ty>
    void destroy(Ty* p)
    {
        return traits_t::destroy(wrapped_, p);
    }

    /**
     * @brief Returns the largest supported allocation size.
     */
    constexpr size_type max_size() const
    {
        return traits_t::max_size(wrapped_);
    }

    /**
     * @brief Obtains the allocator to use after copying a standard container.
     */
    erasing_adaptor select_on_container_copy_construction() const
    {
        return erasing_adaptor(traits_t::select_on_container_copy_construction(wrapped_));
    }

    /**
     * @brief Returns a wrapped allocator.
     */
    wrapped_t& wrapped_allocator() noexcept { return wrapped_; }
    const wrapped_t& wrapped_allocator() const noexcept { return wrapped_; }

private:
    // Wrapped allocator
    wrapped_t wrapped_;
};


/**
 * @brief Compares two allocator instances.
 */
template<typename Al1, typename Al2>
constexpr bool operator==(const erasing_adaptor<Al1>& lhs, const erasing_adaptor<Al2>& rhs)
{
    return lhs.wrapped_allocator() == rhs.wrapped_allocator();
}


/**
 * @brief Compares two allocator instances.
 */
template<typename Al1, typename Al2>
constexpr bool operator!=(const erasing_adaptor<Al1>& lhs, const erasing_adaptor<Al2>& rhs)
{
    return !(lhs == rhs);
}


/**
 * @brief Secure version of std::vector.
 */
template<typename Ty, typename Alloc = std::allocator<Ty>>
using sec_vector = std::vector<Ty, erasing_adaptor<Alloc>>;


/**
 * @brief Wrapper over HCRYPTPROV. Frees handle at a scope exit.
 */
class Provider final
{
    Provider(const Provider&)            = delete;
    Provider& operator=(const Provider&) = delete;

    Provider(Provider&&)            = delete;
    Provider& operator=(Provider&&) = delete;

public:
    /**
     * @brief Constructor, that just forwards its arguments into CryptAcquireContext.
     */
    explicit Provider(LPCWSTR container_name, LPCWSTR provider_name, DWORD provider_type, DWORD flags = 0);

    /**
     * @brief The same constructor as the previous one, but accepts STL strings 
     * instead of C-style ones.
     */
    explicit Provider(const std::wstring& container_name, const std::wstring& provider_name, DWORD provider_type, DWORD flags = 0);

    /**
     * @brief The same as the previous one, but sets container name to nullptr.
     */
    explicit Provider(const std::wstring& provider_name, DWORD provider_type, DWORD flags = 0);

    /**
     * @brief Opens a default provider of given type.
     */
    explicit Provider(DWORD provider_type, DWORD flags = 0);

    /**
     * @brief Destructor. Just calls cas::Provider::Clear.
     */
    ~Provider();

    /**
     * @brief Frees a wrapped provider.
     */
    void Clear() noexcept;

    /**
     * @brief Get the internal key handle.
     */
    operator HCRYPTPROV() const noexcept { return provider_; }

private:
    HCRYPTPROV provider_; /**< Internal provider handle */
};


/**
 * @brief Wrapper over HCRYPTKEY. Destroys handle at a scope exit.
 */
class Key final
{
public:
    /**
     * @brief Generates a key.
     */
    explicit Key(HCRYPTPROV provider, ALG_ID algorithm, DWORD flags = 0);

    /**
     * @brief Imports a key from buffer.
     */
    explicit Key(HCRYPTPROV provider, const sec_vector<unsigned char>& buffer, HCRYPTKEY public_key = 0, DWORD flags = 0);

    /**
     * @brief Destructor. Just calls cas::Key::Clear.
     */
    ~Key();

    /**
     * @brief Duplicates a key.
     */
    Key(const Key& other);

    /**
     * @brief Duplicates a key.
     */
    Key& operator=(const Key& other);

    /**
     * @brief Destroys a wrapped key.
     */
    void Clear() noexcept;

    /**
     * @brief Exports wrapped key into a buffer.
     */
    sec_vector<unsigned char> Export(DWORD type);

    /**
     * @brief Exports wrapped key into a buffer using export key.
     */
    sec_vector<unsigned char> Export(HCRYPTKEY export_key, DWORD type);

    /**
     * @brief Sets a key parameter.
     */
    void SetParameter(DWORD parameter, const void* data, DWORD flags = 0);

    /**
     * @brief Get the internal key handle.
     */
    operator HCRYPTKEY() const noexcept { return key_; }

private:
    HCRYPTKEY key_; /**< Internal key descriptor */
};


/**
 * @brief Wrapper over HCRYPTHASH. Destroys handle at a scope exit.
 */
class Hash final
{
    Hash(const Hash&)            = delete;
    Hash& operator=(const Hash&) = delete;

    Hash(Hash&&)            = delete;
    Hash& operator=(Hash&&) = delete;

public:
    /**
     * @brief Constructor. Creates hash by calling CryptCreateHash.
     */
    explicit Hash(HCRYPTPROV provider, ALG_ID algid, HCRYPTKEY key = 0, DWORD flags = 0);

    /**
     * @brief Destructor. Just calls cas::Hash::Clear.
     */
    ~Hash();

    /**
     * @brief Frees a wrapped hash.
     */
    void Clear() noexcept;

    /**
     * @brief Get the internal hash handle.
     */
    operator HCRYPTHASH() const noexcept { return hash_; }

private:
    HCRYPTHASH hash_; /**< Internal hash descriptor */
};

}  // namespace cas::crypto
