/*
 * New cryptographic library (ncrypt.dll)
 *
 * Copyright 2016 Alex Henrie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "ncrypt.h"
#include "bcrypt.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ncrypt);

enum algid
{
    /* symmetric */
    AES,
    /* asymmetric */
    RSA,
    DSA,
    ECDSA,
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
};

enum object_type
{
    KEY,
    PROVIDER,
};

struct object_property
{
    WCHAR *key;
    DWORD  value_size;
    void  *value;
};

struct object
{
    enum object_type        type;
    LONG                    refs;
    DWORD                   num_properties;
    struct object_property *properties;
};

struct key
{
    struct object     obj;
    enum algid        algid;
    BCRYPT_KEY_HANDLE handle;
    WCHAR            *name;
    BOOL               persisted;
    BOOL               machine;
    BOOL               finalized;
};

struct provider
{
    struct object obj;
};

static SECURITY_STATUS map_ntstatus(NTSTATUS status);

struct key_blob_header
{
    DWORD magic;
    DWORD version;
    DWORD algid;
    DWORD blob_type;
    DWORD blob_size;
};

#define NC_KEY_MAGIC 0x59454b4e /* NKEY */
#define NC_KEY_VERSION 1
#define NC_BLOB_RSAFULLPRIVATE 1
#define NC_BLOB_ECCPRIVATE 2

static BOOL get_key_registry_path(const WCHAR *name, BOOL machine, WCHAR *path, DWORD path_size)
{
    static const WCHAR hex[] = L"0123456789abcdef";
    static const WCHAR user_prefix[] = L"Software\\Wine\\Crypto\\NCrypt\\User\\";
    static const WCHAR machine_prefix[] = L"Software\\Wine\\Crypto\\NCrypt\\Machine\\";
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    DWORD i, prefix_len = lstrlenW(machine ? machine_prefix : user_prefix);
    NTSTATUS status;

    if (!name || !*name || wcslen(name) > 255 || path_size < prefix_len + sizeof(digest) * 2 + 1)
        return FALSE;
    memcpy(path, machine ? machine_prefix : user_prefix, prefix_len * sizeof(WCHAR));
    if ((status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto done;
    if ((status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0))) goto done;
    if ((status = BCryptHashData(hash, (BYTE *)name, wcslen(name) * sizeof(WCHAR), 0))) goto done;
    if ((status = BCryptFinishHash(hash, digest, sizeof(digest), 0))) goto done;
    for (i = 0; i < sizeof(digest); i++)
    {
        path[prefix_len + i * 2] = hex[digest[i] >> 4];
        path[prefix_len + i * 2 + 1] = hex[digest[i] & 15];
    }
    path[prefix_len + sizeof(digest) * 2] = 0;
done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (status)
    {
        WARN("Failed to hash key name, status %#lx\n", status);
        return FALSE;
    }
    return TRUE;
}

static SECURITY_STATUS save_persisted_key(struct key *key)
{
    HKEY root = key->machine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, regkey;
    WCHAR path[128];
    struct key_blob_header *blob;
    const WCHAR *blob_type;
    DWORD size;
    LSTATUS reg_status;
    NTSTATUS status;

    if (!key->persisted) return ERROR_SUCCESS;
    if (!get_key_registry_path(key->name, key->machine, path, ARRAY_SIZE(path))) return NTE_INVALID_PARAMETER;
    if (key->algid == RSA) blob_type = BCRYPT_RSAFULLPRIVATE_BLOB;
    else if (key->algid == ECDSA_P256 || key->algid == ECDSA_P384 || key->algid == ECDSA_P521)
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
    else return NTE_NOT_SUPPORTED;
    if ((status = BCryptExportKey(key->handle, NULL, blob_type, NULL, 0, &size, 0)))
        return map_ntstatus(status);
    if (!(blob = malloc(sizeof(*blob) + size))) return NTE_NO_MEMORY;
    blob->magic = NC_KEY_MAGIC;
    blob->version = NC_KEY_VERSION;
    blob->algid = key->algid;
    blob->blob_type = key->algid == RSA ? NC_BLOB_RSAFULLPRIVATE : NC_BLOB_ECCPRIVATE;
    blob->blob_size = size;
    status = BCryptExportKey(key->handle, NULL, blob_type, (BYTE *)(blob + 1), size, &size, 0);
    if (status)
    {
        free(blob);
        return map_ntstatus(status);
    }
    reg_status = RegCreateKeyExW(root, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                                 &regkey, NULL);
    if (!reg_status)
    {
        reg_status = RegSetValueExW(regkey, L"PrivateKey", 0, REG_BINARY, (BYTE *)blob,
                                    sizeof(*blob) + size);
        RegCloseKey(regkey);
    }
    free(blob);
    if (reg_status == ERROR_ACCESS_DENIED) return NTE_PERM;
    if (reg_status) return NTE_INTERNAL_ERROR;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS free_key(struct key *key)
{
    SECURITY_STATUS status = map_ntstatus(BCryptDestroyKey(key->handle));
    free(key->name);
    key->name = NULL;
    return status;
}

static SECURITY_STATUS map_ntstatus(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_INVALID_HANDLE:    return NTE_INVALID_HANDLE;
    case STATUS_INVALID_SIGNATURE: return NTE_BAD_SIGNATURE;
    case STATUS_SUCCESS:           return ERROR_SUCCESS;
    case STATUS_INVALID_PARAMETER: return NTE_INVALID_PARAMETER;
    case STATUS_NO_MEMORY:         return NTE_NO_MEMORY;
    case STATUS_NOT_SUPPORTED:     return NTE_NOT_SUPPORTED;
    case NTE_BAD_DATA:             return NTE_BAD_DATA;
    case STATUS_BUFFER_TOO_SMALL:  return NTE_BUFFER_TOO_SMALL;
    default:
        FIXME("unhandled status %#lx\n", status);
        return NTE_INTERNAL_ERROR;
    }
}

static struct key *allocate_key(void)
{
    struct key *ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->obj.type = KEY;
    ret->obj.refs = 1;
    return ret;
}

static struct provider *allocate_provider(void)
{
    struct provider *ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->obj.type = PROVIDER;
    ret->obj.refs = 1;
    return ret;
}

static void provider_addref(NCRYPT_PROV_HANDLE handle)
{
    struct provider *provider = (struct provider *)handle;
    InterlockedIncrement(&provider->obj.refs);
}

static struct object_property *get_object_property(struct object *object, const WCHAR *name)
{
    unsigned int i;
    for (i = 0; i < object->num_properties; i++)
    {
        struct object_property *property = &object->properties[i];
        if (!lstrcmpW(property->key, name)) return property;
    }
    return NULL;
}

struct object_property *add_object_property(struct object *object, const WCHAR *name)
{
    struct object_property *property;

    if (!object->num_properties)
    {
        if (!(object->properties = malloc(sizeof(*property))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        property = &object->properties[object->num_properties++];
    }
    else
    {
        struct object_property *tmp;
        if (!(tmp = realloc(object->properties, sizeof(*property) * (object->num_properties + 1))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        object->properties = tmp;
        property = &object->properties[object->num_properties++];
    }

    memset(property, 0, sizeof(*property));
    if (!(property->key = wcsdup(name)))
    {
        ERR("Error allocating memory.\n");
        return NULL;
    }

    return property;
}

static SECURITY_STATUS set_object_property(struct object *object, const WCHAR *name, BYTE *value, DWORD value_size)
{
    struct object_property *property = get_object_property(object, name);
    void *tmp;
    BOOL added = FALSE;

    if (!property)
    {
        if (!(property = add_object_property(object, name))) return NTE_NO_MEMORY;
        added = TRUE;
    }
    if (!(tmp = malloc(value_size ? value_size : 1)))
    {
        if (added)
        {
            free(property->key);
            object->num_properties--;
        }
        return NTE_NO_MEMORY;
    }
    if (value_size) memcpy(tmp, value, value_size);

    free(property->value);
    property->value = tmp;
    property->value_size = value_size;

    return ERROR_SUCCESS;
}

static struct key *create_key_object(enum algid algid, NCRYPT_PROV_HANDLE provider)
{
    NCRYPT_SUPPORTED_LENGTHS supported_lengths = {512, 16384, 8, 1024};
    struct key *key;
    DWORD dw_value;

    if (!(key = allocate_key())) return NULL;

#define SET_PROP(name, value, size) do { if (set_object_property(&key->obj, name, (BYTE *)(value), size)) goto failed; } while (0)

    switch (algid)
    {
    case RSA:
        key->algid = RSA;
        SET_PROP(NCRYPT_ALGORITHM_PROPERTY, BCRYPT_RSA_ALGORITHM, sizeof(BCRYPT_RSA_ALGORITHM));
        SET_PROP(NCRYPT_ALGORITHM_GROUP_PROPERTY, BCRYPT_RSA_ALGORITHM, sizeof(BCRYPT_RSA_ALGORITHM));
        SET_PROP(NCRYPT_LENGTHS_PROPERTY, &supported_lengths, sizeof(supported_lengths));
        dw_value = 128;
        SET_PROP(NCRYPT_BLOCK_LENGTH_PROPERTY, &dw_value, sizeof(dw_value));
        dw_value = 128;
        SET_PROP(BCRYPT_SIGNATURE_LENGTH, &dw_value, sizeof(dw_value));
        break;

    case ECDSA_P256:
        key->algid = ECDSA_P256;
        SET_PROP(NCRYPT_ALGORITHM_PROPERTY, BCRYPT_ECDSA_P256_ALGORITHM, sizeof(BCRYPT_ECDSA_P256_ALGORITHM));
        SET_PROP(NCRYPT_ALGORITHM_GROUP_PROPERTY, BCRYPT_ECDSA_ALGORITHM, sizeof(BCRYPT_ECDSA_ALGORITHM));
        break;

    case ECDSA_P384:
        key->algid = ECDSA_P384;
        SET_PROP(NCRYPT_ALGORITHM_PROPERTY, BCRYPT_ECDSA_P384_ALGORITHM, sizeof(BCRYPT_ECDSA_P384_ALGORITHM));
        SET_PROP(NCRYPT_ALGORITHM_GROUP_PROPERTY, BCRYPT_ECDSA_ALGORITHM, sizeof(BCRYPT_ECDSA_ALGORITHM));
        break;

    case ECDSA_P521:
        key->algid = ECDSA_P521;
        SET_PROP(NCRYPT_ALGORITHM_PROPERTY, BCRYPT_ECDSA_P521_ALGORITHM, sizeof(BCRYPT_ECDSA_P521_ALGORITHM));
        SET_PROP(NCRYPT_ALGORITHM_GROUP_PROPERTY, BCRYPT_ECDSA_ALGORITHM, sizeof(BCRYPT_ECDSA_ALGORITHM));
        break;

    default:
        ERR("Invalid algid %#x\n", algid);
        goto failed;
    }

    dw_value = 0;
    SET_PROP(NCRYPT_EXPORT_POLICY_PROPERTY, &dw_value, sizeof(dw_value));
    dw_value = NCRYPT_ALLOW_ALL_USAGES;
    SET_PROP(NCRYPT_KEY_USAGE_PROPERTY, &dw_value, sizeof(dw_value));
    dw_value = 0;
    SET_PROP(NCRYPT_KEY_TYPE_PROPERTY, &dw_value, sizeof(dw_value));
    SET_PROP(NCRYPT_PROVIDER_HANDLE_PROPERTY, &provider, sizeof(provider));
    provider_addref(provider);
#undef SET_PROP
    return key;

failed:
#undef SET_PROP
    while (key->obj.num_properties)
    {
        struct object_property *prop = &key->obj.properties[--key->obj.num_properties];
        free(prop->key);
        free(prop->value);
    }
    free(key->obj.properties);
    free(key);
    return NULL;
}

SECURITY_STATUS WINAPI NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *handle,
                                                const WCHAR *algid, const WCHAR *name, DWORD keyspec, DWORD flags)
{
    struct key *key;
    DWORD bitlen;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE alg;
    HKEY root = flags & NCRYPT_MACHINE_KEY_FLAG ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, regkey;
    WCHAR path[128];
    LSTATUS reg_status;

    TRACE("(%#Ix, %p, %s, %s, %#lx, %#lx)\n", provider, handle, wine_dbgstr_w(algid), wine_dbgstr_w(name),
          keyspec, flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags & ~(NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_SILENT_FLAG)) return NTE_BAD_FLAGS;
    if (name && !get_key_registry_path(name, !!(flags & NCRYPT_MACHINE_KEY_FLAG), path, ARRAY_SIZE(path)))
        return NTE_INVALID_PARAMETER;
    if (name && !(flags & NCRYPT_OVERWRITE_KEY_FLAG))
    {
        reg_status = RegOpenKeyExW(root, path, 0, KEY_READ, &regkey);
        if (!reg_status)
        {
            RegCloseKey(regkey);
            return NTE_EXISTS;
        }
        if (reg_status != ERROR_FILE_NOT_FOUND) return reg_status == ERROR_ACCESS_DENIED ? NTE_PERM : NTE_INTERNAL_ERROR;
    }

    if (!wcsicmp(algid, BCRYPT_RSA_ALGORITHM))
    {
        if (!(key = create_key_object(RSA, provider))) return NTE_NO_MEMORY;
        alg = BCRYPT_RSA_ALG_HANDLE;
        bitlen = 1024;
    }
    else if (!wcsicmp(algid, BCRYPT_ECDSA_P256_ALGORITHM))
    {
        if (!(key = create_key_object(ECDSA_P256, provider))) return NTE_NO_MEMORY;
        alg = BCRYPT_ECDSA_P256_ALG_HANDLE;
        bitlen = 256;
    }
    else if (!wcsicmp(algid, BCRYPT_ECDSA_P384_ALGORITHM))
    {
        if (!(key = create_key_object(ECDSA_P384, provider))) return NTE_NO_MEMORY;
        alg = BCRYPT_ECDSA_P384_ALG_HANDLE;
        bitlen = 384;
    }
    else if (!wcsicmp(algid, BCRYPT_ECDSA_P521_ALGORITHM))
    {
        if (!(key = create_key_object(ECDSA_P521, provider))) return NTE_NO_MEMORY;
        alg = BCRYPT_ECDSA_P521_ALG_HANDLE;
        bitlen = 521;
    }
    else
    {
        FIXME("Algorithm not handled %s\n", wine_dbgstr_w(algid));
        return NTE_NOT_SUPPORTED;
    }

    if ((status = BCryptGenerateKeyPair(alg, &key->handle, bitlen, 0)))
    {
        NCryptFreeObject((NCRYPT_HANDLE)key);
        return map_ntstatus(status);
    }
    set_object_property(&key->obj, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bitlen, sizeof(bitlen));
    set_object_property(&key->obj, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&bitlen, sizeof(bitlen));
    if (name)
    {
        key->name = wcsdup(name);
        if (!key->name)
        {
            free_key(key);
            free(key);
            return NTE_NO_MEMORY;
        }
        /* Keep the historical transient-key behavior for algorithms not yet
         * supported by the persistent storage format. */
        key->persisted = TRUE;
        key->machine = !!(flags & NCRYPT_MACHINE_KEY_FLAG);
        set_object_property(&key->obj, NCRYPT_NAME_PROPERTY, (BYTE *)name, (lstrlenW(name) + 1) * sizeof(WCHAR));
    }

    *handle = (NCRYPT_KEY_HANDLE)key;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptDecrypt(NCRYPT_KEY_HANDLE handle, BYTE *input, DWORD insize, void *padding, BYTE *output,
                                     DWORD outsize, DWORD *result, DWORD flags)
{
    struct key *key = (struct key *)handle;
    NTSTATUS status;

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", handle, input, insize, padding, output, outsize, result, flags);

    if (key->obj.type != KEY) return NTE_INVALID_HANDLE;

    status = BCryptDecrypt(key->handle, input, insize, padding, NULL, 0, output, outsize, result, flags);
    return map_ntstatus(status);
}

SECURITY_STATUS WINAPI NCryptDeleteKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    struct key *obj = (struct key *)key;
    WCHAR path[128];
    LSTATUS status;

    TRACE("(%#Ix, %#lx)\n", key, flags);
    if (!obj || obj->obj.type != KEY) return NTE_INVALID_HANDLE;
    if (flags & ~NCRYPT_SILENT_FLAG) return NTE_BAD_FLAGS;
    if (obj->persisted)
    {
        if (!get_key_registry_path(obj->name, obj->machine, path, ARRAY_SIZE(path))) return NTE_INVALID_PARAMETER;
        status = RegDeleteKeyW(obj->machine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, path);
        if (status && status != ERROR_FILE_NOT_FOUND) return status == ERROR_ACCESS_DENIED ? NTE_PERM : NTE_INTERNAL_ERROR;
    }
    return NCryptFreeObject(key);
}

SECURITY_STATUS WINAPI NCryptEncrypt(NCRYPT_KEY_HANDLE handle, BYTE *input, DWORD insize, void *padding, BYTE *output,
                                     DWORD outsize, DWORD *result, DWORD flags)
{
    struct key *key = (struct key *)handle;
    NTSTATUS status;

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", handle, input, insize, padding, output, outsize, result, flags);

    if (flags & ~(NCRYPT_NO_PADDING_FLAG | NCRYPT_PAD_OAEP_FLAG | NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG))
    {
        FIXME("Flags %lx not supported\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (key->obj.type != KEY) return NTE_INVALID_HANDLE;

    status = BCryptEncrypt(key->handle, input, insize, padding, NULL, 0, output, outsize, result, flags);
    return map_ntstatus(status);
}

SECURITY_STATUS WINAPI NCryptEnumAlgorithms(NCRYPT_PROV_HANDLE provider, DWORD alg_ops,
                                            DWORD *alg_count, NCryptAlgorithmName **alg_list, DWORD flags)
{
    FIXME("(%#Ix, %#lx, %p, %p, %#lx): stub\n", provider, alg_ops, alg_count, alg_list, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptEnumKeys(NCRYPT_PROV_HANDLE provider, const WCHAR *scope,
                                      NCryptKeyName **key_name, PVOID *enum_state, DWORD flags)
{
    FIXME("(%#Ix, %p, %p, %p, %#lx): stub\n", provider, scope, key_name, enum_state, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE handle, DWORD flags)
{
    struct key *key = (struct key *)handle;
    DWORD key_length;
    struct object_property *prop;
    SECURITY_STATUS ret;
    NTSTATUS status;

    TRACE("(%#Ix, %#lx)\n", handle, flags);

    if (!key || key->obj.type != KEY) return NTE_INVALID_HANDLE;
    if (key->finalized) return NTE_INVALID_HANDLE;

    if (!(prop = get_object_property(&key->obj, NCRYPT_LENGTH_PROPERTY))) return NTE_INVALID_HANDLE;
    key_length = *(DWORD *)prop->value;
    status = BCryptSetProperty(key->handle, BCRYPT_KEY_LENGTH, (UCHAR *)&key_length, sizeof(key_length), 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error setting key length property\n");
        return map_ntstatus(status);
    }

    status = BCryptFinalizeKeyPair(key->handle, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error finalizing key pair\n");
        return map_ntstatus(status);
    }

    key->finalized = TRUE;
    if ((ret = save_persisted_key(key))) return ret;

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFreeBuffer(PVOID buf)
{
    FIXME("(%p): stub\n", buf);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE handle)
{
    struct object *object = (struct object *)handle;
    SECURITY_STATUS ret = STATUS_SUCCESS;
    unsigned int i;

    TRACE("(%#Ix)\n", handle);

    if (!object)
    {
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    switch (object->type)
    {
    case KEY:
    {
        struct key *key = (struct key *)object;
        ret = free_key(key);
        break;
    }
    case PROVIDER:
        if (InterlockedDecrement(&object->refs)) return 0;
        break;

    default:
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    for (i = 0; i < object->num_properties; i++)
    {
        if (!wcscmp(object->properties[i].key, NCRYPT_PROVIDER_HANDLE_PROPERTY))
            NCryptFreeObject(*(NCRYPT_HANDLE *)object->properties[i].value);

        free(object->properties[i].key);
        free(object->properties[i].value);
    }
    free(object->properties);
    free(object);
    return ret;
}

SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *output,
                                         DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *object = (struct object *)handle;
    const struct object_property *property;

    TRACE("(%#Ix, %s, %p, %lu, %p, %#lx)\n", handle, wine_dbgstr_w(name), output, outsize, result, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (!(property = get_object_property(object, name))) return NTE_INVALID_PARAMETER;

    *result = property->value_size;
    if (!output) return ERROR_SUCCESS;
    if (outsize < property->value_size) return NTE_BUFFER_TOO_SMALL;

    memcpy(output, property->value, property->value_size);
    if (!wcscmp(name, NCRYPT_PROVIDER_HANDLE_PROPERTY))
        provider_addref(*(NCRYPT_PROV_HANDLE*)property->value);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE decrypt_key,
                                       const WCHAR *type, NCryptBufferDesc *params, NCRYPT_KEY_HANDLE *handle,
                                       BYTE *data, DWORD datasize, DWORD flags)
{
    BCRYPT_KEY_BLOB *header = (BCRYPT_KEY_BLOB *)data;
    struct key *key;
    NTSTATUS status;
    ULONG bitlen;
    BCRYPT_ALG_HANDLE alg;
    WCHAR *import_name = NULL;
    BOOL have_curve = FALSE;
    BOOL private_key = FALSE;
    enum algid curve_algid = 0;
    BYTE *import_data = data;
    unsigned int i;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %p, %lu, %#lx)\n", provider, decrypt_key, wine_dbgstr_w(type),
          params, handle, data, datasize, flags);

    if (decrypt_key)
    {
        FIXME("Key blob decryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params && (params->ulVersion != NCRYPTBUFFER_VERSION || params->cBuffers > 16 ||
                   (params->cBuffers && !params->pBuffers)))
        return NTE_INVALID_PARAMETER;
    if (params)
    {
        for (i = 0; i < params->cBuffers; i++)
        {
            NCryptBuffer *buffer = &params->pBuffers[i];
            unsigned int chars, j;
            if (buffer->BufferType == NCRYPTBUFFER_ECC_CURVE_NAME)
            {
                if (!buffer->pvBuffer || buffer->cbBuffer < sizeof(WCHAR) ||
                    buffer->cbBuffer % sizeof(WCHAR) || have_curve)
                {
                    free(import_name);
                    return NTE_INVALID_PARAMETER;
                }
                chars = buffer->cbBuffer / sizeof(WCHAR);
                for (j = 0; j < chars && ((WCHAR *)buffer->pvBuffer)[j]; j++);
                if (j == chars)
                {
                    free(import_name);
                    return NTE_INVALID_PARAMETER;
                }
                TRACE("Import ECC curve %s\n", wine_dbgstr_w(buffer->pvBuffer));
                if (!wcsicmp(buffer->pvBuffer, L"nistP256") || !wcsicmp(buffer->pvBuffer, L"secp256r1") ||
                    !wcsicmp(buffer->pvBuffer, L"P-256")) curve_algid = ECDSA_P256;
                else if (!wcsicmp(buffer->pvBuffer, L"nistP384") || !wcsicmp(buffer->pvBuffer, L"secp384r1") ||
                         !wcsicmp(buffer->pvBuffer, L"P-384")) curve_algid = ECDSA_P384;
                else if (!wcsicmp(buffer->pvBuffer, L"nistP521") || !wcsicmp(buffer->pvBuffer, L"secp521r1") ||
                         !wcsicmp(buffer->pvBuffer, L"P-521")) curve_algid = ECDSA_P521;
                else
                {
                    free(import_name);
                    return NTE_NOT_SUPPORTED;
                }
                have_curve = TRUE;
                continue;
            }
            if (buffer->BufferType != NCRYPTBUFFER_PKCS_KEY_NAME)
            {
                FIXME("Import parameter type %lu not supported\n", buffer->BufferType);
                free(import_name);
                return NTE_NOT_SUPPORTED;
            }
            if (!buffer->pvBuffer || buffer->cbBuffer < sizeof(WCHAR) || buffer->cbBuffer % sizeof(WCHAR) || import_name)
            {
                free(import_name);
                return NTE_INVALID_PARAMETER;
            }
            chars = buffer->cbBuffer / sizeof(WCHAR);
            for (j = 0; j < chars && ((WCHAR *)buffer->pvBuffer)[j]; j++);
            if (j == chars)
            {
                free(import_name);
                return NTE_INVALID_PARAMETER;
            }
            import_name = wcsdup(buffer->pvBuffer);
            if (!import_name) return NTE_NO_MEMORY;
        }
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        free(import_name);
        return NTE_BAD_FLAGS;
    }
    if (!header || datasize < sizeof(*header))
    {
        free(import_name);
        return NTE_INVALID_PARAMETER;
    }

    if (header->Magic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC || header->Magic == BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC)
    {
        DWORD magic;

        if (!have_curve || datasize < sizeof(BCRYPT_ECCKEY_BLOB))
        {
            free(import_name);
            return NTE_INVALID_PARAMETER;
        }
        key = create_key_object(curve_algid, provider);
        if (!key)
        {
            free(import_name);
            return NTE_NO_MEMORY;
        }
        alg = curve_algid == ECDSA_P256 ? BCRYPT_ECDSA_P256_ALG_HANDLE :
              curve_algid == ECDSA_P384 ? BCRYPT_ECDSA_P384_ALG_HANDLE : BCRYPT_ECDSA_P521_ALG_HANDLE;
        bitlen = curve_algid == ECDSA_P256 ? 256 : curve_algid == ECDSA_P384 ? 384 : 521;
        magic = header->Magic == BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC ?
                (curve_algid == ECDSA_P256 ? BCRYPT_ECDSA_PRIVATE_P256_MAGIC :
                 curve_algid == ECDSA_P384 ? BCRYPT_ECDSA_PRIVATE_P384_MAGIC : BCRYPT_ECDSA_PRIVATE_P521_MAGIC) :
                (curve_algid == ECDSA_P256 ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC :
                 curve_algid == ECDSA_P384 ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC : BCRYPT_ECDSA_PUBLIC_P521_MAGIC);
        if (!(import_data = malloc(datasize)))
        {
            NCryptFreeObject((NCRYPT_HANDLE)key);
            free(import_name);
            return NTE_NO_MEMORY;
        }
        memcpy(import_data, data, datasize);
        ((BCRYPT_ECCKEY_BLOB *)import_data)->dwMagic = magic;
        private_key = header->Magic == BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC;
        goto import_blob;
    }

    switch (header->Magic)
    {
    case BCRYPT_RSAFULLPRIVATE_MAGIC:
    case BCRYPT_RSAPRIVATE_MAGIC:
    case BCRYPT_RSAPUBLIC_MAGIC:
    {
        BCRYPT_RSAKEY_BLOB *rsablob = (BCRYPT_RSAKEY_BLOB *)data;
        if (have_curve)
        {
            free(import_name);
            return NTE_INVALID_PARAMETER;
        }
        private_key = header->Magic != BCRYPT_RSAPUBLIC_MAGIC;
        if (!(key = create_key_object(RSA, provider)))
        {
            free(import_name);
            return NTE_NO_MEMORY;
        }
        alg = BCRYPT_RSA_ALG_HANDLE;
        bitlen = rsablob->BitLength;
        break;
    }
    case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
    case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
    {
        if (have_curve && curve_algid != ECDSA_P256)
        {
            free(import_name);
            return NTE_INVALID_PARAMETER;
        }
        private_key = header->Magic == BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        if (!(key = create_key_object(ECDSA_P256, provider)))
        {
            free(import_name);
            return NTE_NO_MEMORY;
        }
        alg = BCRYPT_ECDSA_P256_ALG_HANDLE;
        bitlen = 256;
        break;
    }
    case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
    case BCRYPT_ECDSA_PRIVATE_P384_MAGIC:
    {
        if (have_curve && curve_algid != ECDSA_P384)
        {
            free(import_name);
            return NTE_INVALID_PARAMETER;
        }
        private_key = header->Magic == BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        if (!(key = create_key_object(ECDSA_P384, provider)))
        {
            free(import_name);
            return NTE_NO_MEMORY;
        }
        alg = BCRYPT_ECDSA_P384_ALG_HANDLE;
        bitlen = 384;
        break;
    }
    case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
    case BCRYPT_ECDSA_PRIVATE_P521_MAGIC:
    {
        if (have_curve && curve_algid != ECDSA_P521)
        {
            free(import_name);
            return NTE_INVALID_PARAMETER;
        }
        private_key = header->Magic == BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
        if (!(key = create_key_object(ECDSA_P521, provider)))
        {
            free(import_name);
            return NTE_NO_MEMORY;
        }
        alg = BCRYPT_ECDSA_P521_ALG_HANDLE;
        bitlen = 521;
        break;
    }
    default:
        FIXME("Unhandled key magic %#lx\n", header->Magic);
        free(import_name);
        return NTE_INVALID_PARAMETER;
    }

import_blob:
    if ((status = BCryptImportKeyPair(alg, NULL, type, &key->handle, import_data, datasize, 0)))
    {
        NCryptFreeObject((NCRYPT_HANDLE)key);
        if (import_data != data) free(import_data);
        free(import_name);
        return map_ntstatus(status);
    }
    if (import_data != data) free(import_data);

    set_object_property(&key->obj, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bitlen, sizeof(bitlen));
    set_object_property(&key->obj, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&bitlen, sizeof(bitlen));
    if (import_name)
    {
        set_object_property(&key->obj, NCRYPT_NAME_PROPERTY, (BYTE *)import_name, (lstrlenW(import_name) + 1) * sizeof(WCHAR));
        if (private_key)
        {
            key->name = import_name;
            key->persisted = TRUE;
            key->finalized = TRUE;
            import_name = NULL;
            status = save_persisted_key(key);
            if (status)
            {
                NCryptFreeObject((NCRYPT_HANDLE)key);
                return status;
            }
        }
        free(import_name);
    }

    *handle = (NCRYPT_KEY_HANDLE)key;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptExportKey(NCRYPT_KEY_HANDLE handle, NCRYPT_KEY_HANDLE encrypt_key, const WCHAR *type,
                                       NCryptBufferDesc *params, BYTE *output, DWORD output_len, DWORD *ret_len,
                                       DWORD flags)
{
    struct key *key = (struct key *)handle;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %lu, %p, %#lx)\n", handle, encrypt_key, wine_dbgstr_w(type), params, output,
          output_len, ret_len, flags);

    if (encrypt_key)
    {
        FIXME("Key blob encryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }

    return map_ntstatus(BCryptExportKey(key->handle, NULL, type, output, output_len, ret_len, 0));
}

SECURITY_STATUS WINAPI NCryptIsAlgSupported(NCRYPT_PROV_HANDLE provider, const WCHAR *algid, DWORD flags)
{
    static const ULONG supported = BCRYPT_CIPHER_OPERATION |\
                                   BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |\
                                   BCRYPT_SIGNATURE_OPERATION |\
                                   BCRYPT_SECRET_AGREEMENT_OPERATION;
    BCRYPT_ALGORITHM_IDENTIFIER *list;
    ULONG i, count;
    NTSTATUS status;

    TRACE("(%#Ix, %s, %#lx)\n", provider, wine_dbgstr_w(algid), flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!lstrcmpiW(BCRYPT_RSA_SIGN_ALGORITHM, algid)) return NTE_NOT_SUPPORTED;

    status = BCryptEnumAlgorithms(supported, &count, &list, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error retrieving algorithm list %#lx\n", status);
        return map_ntstatus(status);
    }

    status = STATUS_NOT_SUPPORTED;
    for (i = 0; i < count; i++)
    {
        if (!lstrcmpiW(list[i].pszName, algid))
        {
            status = STATUS_SUCCESS;
            break;
        }
    }

    BCryptFreeBuffer(list);
    return map_ntstatus(status);
}

BOOL WINAPI NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    FIXME("(%#Ix): stub\n", hKey);
    return FALSE;
}

SECURITY_STATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                     const WCHAR *name, DWORD keyspec, DWORD flags)
{
    HKEY regkey;
    WCHAR path[128];
    BYTE *blob;
    DWORD size, type;
    LSTATUS reg_status;
    struct key_blob_header *header;
    struct key *obj;
    NTSTATUS status;
    unsigned int bitlen;
    enum algid algid;
    BCRYPT_ALG_HANDLE alg;
    const WCHAR *blob_type;
    BOOL machine = !!(flags & NCRYPT_MACHINE_KEY_FLAG);

    TRACE("(%#Ix, %p, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(name), keyspec, flags);
    if (!provider || ((struct object *)provider)->type != PROVIDER || !key) return NTE_INVALID_HANDLE;
    if (!name || !*name) return NTE_INVALID_PARAMETER;
    if (flags & ~(NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG)) return NTE_BAD_FLAGS;
    if (keyspec) return NTE_NOT_SUPPORTED;
    if (!get_key_registry_path(name, machine, path, ARRAY_SIZE(path))) return NTE_INVALID_PARAMETER;
    reg_status = RegOpenKeyExW(machine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, path, 0, KEY_QUERY_VALUE, &regkey);
    if (reg_status == ERROR_FILE_NOT_FOUND) return NTE_BAD_KEYSET;
    if (reg_status) return reg_status == ERROR_ACCESS_DENIED ? NTE_PERM : NTE_INTERNAL_ERROR;
    reg_status = RegQueryValueExW(regkey, L"PrivateKey", NULL, &type, NULL, &size);
    if (reg_status || type != REG_BINARY || size < sizeof(*header))
    {
        RegCloseKey(regkey);
        return NTE_BAD_DATA;
    }
    if (!(blob = malloc(size)))
    {
        RegCloseKey(regkey);
        return NTE_NO_MEMORY;
    }
    reg_status = RegQueryValueExW(regkey, L"PrivateKey", NULL, &type, blob, &size);
    RegCloseKey(regkey);
    if (reg_status)
    {
        free(blob);
        return NTE_BAD_DATA;
    }
    header = (struct key_blob_header *)blob;
    if (header->magic != NC_KEY_MAGIC || header->version != NC_KEY_VERSION ||
        header->blob_size != size - sizeof(*header))
    {
        free(blob);
        return NTE_BAD_DATA;
    }
    algid = header->algid;
    if (header->blob_type == NC_BLOB_RSAFULLPRIVATE && algid == RSA)
    {
        if (header->blob_size < sizeof(BCRYPT_RSAKEY_BLOB))
        {
            free(blob);
            return NTE_BAD_DATA;
        }
        blob_type = BCRYPT_RSAFULLPRIVATE_BLOB;
        alg = BCRYPT_RSA_ALG_HANDLE;
        bitlen = ((BCRYPT_RSAKEY_BLOB *)(header + 1))->BitLength;
    }
    else if (header->blob_type == NC_BLOB_ECCPRIVATE && algid == ECDSA_P256)
    {
        if (header->blob_size < sizeof(BCRYPT_ECCKEY_BLOB))
        {
            free(blob);
            return NTE_BAD_DATA;
        }
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
        alg = BCRYPT_ECDSA_P256_ALG_HANDLE;
        bitlen = 256;
    }
    else if (header->blob_type == NC_BLOB_ECCPRIVATE && algid == ECDSA_P384)
    {
        if (header->blob_size < sizeof(BCRYPT_ECCKEY_BLOB))
        {
            free(blob);
            return NTE_BAD_DATA;
        }
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
        alg = BCRYPT_ECDSA_P384_ALG_HANDLE;
        bitlen = 384;
    }
    else if (header->blob_type == NC_BLOB_ECCPRIVATE && algid == ECDSA_P521)
    {
        if (header->blob_size < sizeof(BCRYPT_ECCKEY_BLOB))
        {
            free(blob);
            return NTE_BAD_DATA;
        }
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
        alg = BCRYPT_ECDSA_P521_ALG_HANDLE;
        bitlen = 521;
    }
    else
    {
        free(blob);
        return NTE_BAD_DATA;
    }
    if (!(obj = create_key_object(algid, provider)))
    {
        free(blob);
        return NTE_NO_MEMORY;
    }
    status = BCryptImportKeyPair(alg, NULL, blob_type, &obj->handle,
                                 (BYTE *)(header + 1), header->blob_size, 0);
    free(blob);
    if (status)
    {
        NCryptFreeObject((NCRYPT_HANDLE)obj);
        return map_ntstatus(status);
    }
    set_object_property(&obj->obj, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bitlen, sizeof(bitlen));
    set_object_property(&obj->obj, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&bitlen, sizeof(bitlen));
    obj->name = wcsdup(name);
    if (!obj->name)
    {
        NCryptFreeObject((NCRYPT_HANDLE)obj);
        return NTE_NO_MEMORY;
    }
    obj->persisted = TRUE;
    obj->machine = machine;
    obj->finalized = TRUE;
    set_object_property(&obj->obj, NCRYPT_NAME_PROPERTY, (BYTE *)name, (lstrlenW(name) + 1) * sizeof(WCHAR));
    *key = (NCRYPT_KEY_HANDLE)obj;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *handle, const WCHAR *name, DWORD flags)
{
    struct provider *provider;

    FIXME("(%p, %s, %#lx): stub\n", handle, wine_dbgstr_w(name), flags);

    if (!(provider = allocate_provider()))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }
    *handle = (NCRYPT_PROV_HANDLE)provider;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *input, DWORD insize, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %s, %p, %lu, %#lx)\n", handle, wine_dbgstr_w(name), input, insize, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (!wcscmp(name, NCRYPT_PROVIDER_HANDLE_PROPERTY)) return NTE_NOT_SUPPORTED;
    return set_object_property(object, name, input, insize);
}

SECURITY_STATUS WINAPI NCryptSignHash(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *value, DWORD value_len,
                                      BYTE *sig, DWORD sig_len, DWORD *ret_len, DWORD flags)
{
    struct key *key = (struct key *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, value, value_len, sig, sig_len, flags);
    if (flags & NCRYPT_SILENT_FLAG) FIXME("Silent flag not implemented\n");

    if (!key || key->obj.type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptSignHash(key->handle, padding, value, value_len, sig, sig_len, ret_len,
                                       flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptVerifySignature(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *hash, DWORD hash_size,
                                             BYTE *signature, DWORD signature_size, DWORD flags)
{
    struct key *key = (struct key *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, hash, hash_size, signature,
          signature_size, flags);

    if (!hash_size || !signature_size) return NTE_INVALID_PARAMETER;
    if (!hash || !signature) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (!handle || key->obj.type != KEY) return NTE_INVALID_HANDLE;

    if (key->algid < RSA)
    {
        FIXME("Symmetric keys not supported.\n");
        return NTE_NOT_SUPPORTED;
    }

    return map_ntstatus(BCryptVerifySignature(key->handle, padding, hash, hash_size, signature, signature_size, flags));
}
