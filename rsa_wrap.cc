
#if __cplusplus
extern "C" {
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "lua.h"
#include "lauxlib.h"

#define RSA_PRIVATE_KEY_METATABLE "___RSA_PRIVATE_KEY_METATABLE___"
#define RSA_PUBLIC_KEY_METATABLE "___RSA_PUBLIC_KEY_METATABLE___"


static int free_rsa_key(lua_State *L)
{
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey) {return 0;}
	if(*ppKey)
	{
		RSA_free(*ppKey);
	}
	return 0;
}

static int rsa_private_encrypt_block_size(lua_State *L)
{
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey || !(*ppKey)) {return 0;}
	
	lua_pushinteger(L, RSA_size(*ppKey) - 11);
	return 1;
}
static int rsa_public_encrypt_block_size(lua_State *L)
{
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey || !(*ppKey)) {return 0;}
	int padding = lua_isnumber (L, 3)?lua_tointeger(L, 3):RSA_PKCS1_PADDING;
	if (padding == RSA_NO_PADDING)
	{
		lua_pushinteger(L, RSA_size(*ppKey));
	}
	else if(padding == RSA_PKCS1_OAEP_PADDING)
	{
		lua_pushinteger(L, RSA_size(*ppKey) - 41);
	}
	else// PKCS #1 v1.5 based padding modes
	{
		lua_pushinteger(L, RSA_size(*ppKey) - 11);
	}
	return 1;
}

static int rsa_public_encrypt(lua_State *L)
{
	int nLen = 0;
	unsigned char* buffer = 0;
	size_t text_len = 0;
	int out_len = 0;
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey) {return 0;}
	const char* text=lua_tolstring(L, 2, &text_len);
	if (!text || text_len == 0) {return 0;}
	

	nLen = RSA_size(*ppKey);
	buffer = (unsigned char*)malloc(nLen + 1);
	out_len = RSA_public_encrypt(text_len, (const unsigned char*)text, buffer, *ppKey, lua_isnumber (L, 3)?lua_tointeger(L, 3):RSA_PKCS1_PADDING);
	if (out_len != -1)
	{
		lua_pushlstring(L, (const char*)buffer, out_len);
		free(buffer);
		return 1;
	}
	else
	{
		free(buffer);
		return 0;
	}
}

static int rsa_public_decrypt(lua_State *L)
{
	int nLen = 0;
	unsigned char* buffer = 0;
	size_t text_len = 0;
	int out_len = 0;
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey) {return 0;}
	const char* text=lua_tolstring(L, 2, &text_len);
	if (!text || text_len == 0) {return 0;}
	

	nLen = RSA_size(*ppKey);
	buffer = (unsigned char*)malloc(nLen + 1);
	out_len = RSA_public_decrypt(text_len, (const unsigned char*)text, buffer, *ppKey, lua_isnumber (L, 3)?lua_tointeger (L, 3):RSA_PKCS1_PADDING);
	if (out_len != -1)
	{
		lua_pushlstring(L, (const char*)buffer, out_len);
		free(buffer);
		return 1;
	}
	else
	{
		free(buffer);
		return 0;
	}
}

static int rsa_private_encrypt(lua_State *L)
{
	int nLen = 0;
	unsigned char* buffer = 0;
	size_t text_len = 0;
	int out_len = 0;
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey) {return 0;}
	const char* text=lua_tolstring(L, 2, &text_len);
	if (!text || text_len == 0) {return 0;}
	

	nLen = RSA_size(*ppKey);
	buffer = (unsigned char*)malloc(nLen + 1);
	out_len = RSA_private_encrypt(text_len, (const unsigned char*)text, buffer, *ppKey, lua_isnumber (L, 3)?lua_tointeger (L, 3):RSA_PKCS1_PADDING);
	if (out_len != -1)
	{
		lua_pushlstring(L, (const char*)buffer, out_len);
		free(buffer);
		return 1;
	}
	else
	{
		free(buffer);
		return 0;
	}
}

static int rsa_private_decrypt(lua_State *L)
{
	int nLen = 0;
	unsigned char* buffer = 0;
	size_t text_len = 0;
	int out_len = 0;
	RSA ** ppKey = (RSA **)lua_touserdata (L, 1);
	if (!ppKey) {return 0;}
	const char* text=lua_tolstring(L, 2, &text_len);
	if (!text || text_len == 0) {return 0;}
	
	nLen = RSA_size(*ppKey);
	buffer = (unsigned char*)malloc(nLen + 1);
	out_len = RSA_private_decrypt(text_len, (const unsigned char*)text, buffer, *ppKey, lua_isnumber (L, 3)?lua_tointeger (L, 3):RSA_PKCS1_PADDING);
	if (out_len != -1)
	{
		lua_pushlstring(L, (const char*)buffer, out_len);
		free(buffer);
		return 1;
	}
	else
	{
		free(buffer);
		return 0;
	}
}

static RSA* create_private_rsa(const char* key_str,size_t key_len, const char* password)
{
	RSA* pKey = 0;
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio){ printf("rsa out of memory!\n"); return 0;}
	BIO_write(bio, key_str, key_len);
	pKey = PEM_read_bio_RSAPrivateKey(bio, 0, 0, (void*)password);
	BIO_free(bio);
	return pKey;
}
static RSA* create_public_rsa(const char* key_str,size_t key_len, const char* password)
{
	RSA* pKey = 0;
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio){ printf("rsa out of memory!\n"); return 0;}
	BIO_write(bio, key_str, key_len);
/*
The PEM routines are meant to send or store over practically any
channel. The DER routines are meant to send/store over any 8-bit
clean channel, which many socket protocols also do. (TCP/IP itself
and a plain socket does, but some protocols built on top of TCP/IP
like SMTP and HTTP don't, while some like FTP do.)

Either pair should work, but mixing them should not. The RSAPublicKey
routines use the "raw" PKCS#1 format, and the RSA_PUBKEY routines use
the generic X.509 PublicKeyInfo format which *contains* the PKCS#1.
Although semantically equivalent, these are not the same thing.

But if you get this (or pretty much anything else) wrong, the read
routine shouldn't crash. It should return null with error information
stored in the error queue; this is not the same as either crashing
or reading endlessly. In fact reading endlessly wouldn't crash either
by my definition so I can't guess what you mean actually happens. 
*/
	pKey = PEM_read_bio_RSA_PUBKEY(bio, 0, 0, (void*)password);
	BIO_free(bio);
	return pKey;
}

static int set_private_key_meta (lua_State *L) {
        if(luaL_newmetatable (L, RSA_PRIVATE_KEY_METATABLE) != 0)
		{
			lua_newtable(L);
			lua_pushcfunction (L, rsa_private_encrypt);
			lua_setfield(L, -2, "encrypt");
			lua_pushcfunction (L, rsa_private_decrypt);
			lua_setfield(L, -2, "decrypt");
			lua_pushcfunction (L, rsa_private_encrypt_block_size);
			lua_setfield(L, -2, "get_encrypt_block_size");

			lua_setfield(L, -2, "__index");
			lua_pushcfunction (L, free_rsa_key);
			lua_setfield (L, -2, "__gc");
		}
        return 1;
}

static int set_public_key_meta (lua_State *L) {
        if(luaL_newmetatable (L, RSA_PUBLIC_KEY_METATABLE) != 0)
		{
			lua_newtable(L);
			lua_pushcfunction (L, rsa_public_encrypt);
			lua_setfield(L, -2, "encrypt");
			lua_pushcfunction (L, rsa_public_decrypt);
			lua_setfield(L, -2, "decrypt");
			lua_pushcfunction (L, rsa_public_encrypt_block_size);
			lua_setfield(L, -2, "get_encrypt_block_size");

			lua_setfield(L, -2, "__index");
			lua_pushcfunction (L, free_rsa_key);
			lua_setfield (L, -2, "__gc");
		}
        return 1;
}

static int l_rsa_load_private_key(lua_State *L)
{
	RSA* pKey = 0;

	size_t key_str_len=0;
	size_t pl=0;
	const char* key_str=lua_tolstring(L, 1,&key_str_len);
	if (!key_str || key_str_len == 0 ) {return 0;}

	const char* password=lua_tolstring(L, 2, &pl);

	pKey = create_private_rsa(key_str, key_str_len, password);

	if(pKey)
	{
		RSA** ud = (RSA**)lua_newuserdata(L, sizeof(RSA*));
		*ud = pKey;
		set_private_key_meta (L);
		lua_setmetatable (L, -2);
		return 1;
	}
	else
	{
		printf("rsa private key loading failed!\n");
		return 0;
	}
}

static int l_rsa_load_private_key_file(lua_State *L)
{
	RSA* pKey = 0;

	size_t fl=0;
	size_t pl=0;
	const char* filename=lua_tolstring(L, 1, &fl);
	if (!filename || fl == 0 ) {return 0;}
	const char* password=lua_tolstring(L, 2, &pl);

	FILE * f=0;
	f=fopen(filename, "rb");
	if(!f)
	{
		return 0;
	}
	fseek(f, 0, SEEK_END);
	size_t fsize = ftell(f);
	fseek(f, 0, SEEK_SET);  //same as rewind(f);

	char *key_buff = (char*)malloc(fsize);
	fread(key_buff, fsize, 1, f);
	fclose(f);
	pKey = create_private_rsa(key_buff, fsize, password);
	//pKey = PEM_read_RSAPrivateKey(f, 0, 0, (void*)password);
	free(key_buff);

	if(pKey)
	{
		RSA** ud = (RSA**)lua_newuserdata(L, sizeof(RSA*));
		*ud = pKey;
		set_private_key_meta (L);
		lua_setmetatable (L, -2);
		return 1;
	}
	else
	{
		printf("rsa private key file loading failed!\n");
		return 0;
	}
}

static int l_rsa_load_public_key(lua_State *L)
{
	RSA* pKey = 0;

	size_t key_str_len=0;
	size_t pl=0;
	const char* key_str=lua_tolstring(L, 1,&key_str_len);
	if (!key_str || key_str_len == 0 ) {return 0;}

	const char* password=lua_tolstring(L, 2, &pl);

	pKey = create_public_rsa(key_str, key_str_len, password);

	if(pKey)
	{
		RSA** ud = (RSA**)lua_newuserdata(L, sizeof(RSA*));
		*ud = pKey;
		set_public_key_meta (L);
		lua_setmetatable (L, -2);
		return 1;
	}
	else
	{
		printf("rsa public key loading failed!\n");
		return 0;
	}
}

static int l_rsa_load_public_key_file(lua_State *L)
{
	RSA* pKey = 0;

	size_t fl=0;
	size_t pl=0;
	const char* filename=lua_tolstring(L, 1, &fl);
	if (!filename || fl == 0 ) {return 0;}
	const char* password=lua_tolstring(L, 2, &pl);

	FILE * f=0;
	f=fopen(filename, "rb");
	if(!f)
	{
		return 0;
	}
	
	fseek(f, 0, SEEK_END);
	size_t fsize = ftell(f);
	fseek(f, 0, SEEK_SET);  //same as rewind(f);

	char *key_buff = (char*)malloc(fsize);
	fread(key_buff, fsize, 1, f);
	fclose(f);
	pKey = create_public_rsa(key_buff, fsize, password);
	free(key_buff);

	//pKey = PEM_read_RSA_PUBKEY(f, 0, 0, (void*)password);

	if(pKey)
	{
		RSA** ud = (RSA**)lua_newuserdata(L, sizeof(RSA*));
		*ud = pKey;
		set_public_key_meta (L);
		lua_setmetatable (L, -2);
		return 1;
	}
	else
	{
		printf("rsa public key file loading failed!\n");
		return 0;
	}
}

#ifdef _WIN32
#define LUA_LIB_API __declspec(dllexport)
#else
#define LUA_LIB_API extern
#endif
LUA_LIB_API int luaopen_rsa(lua_State* L)
{
	const luaL_Reg lua_rsa_modules[] = {
		{"load_private_key",   l_rsa_load_private_key},
		{"load_public_key",   l_rsa_load_public_key},
		{"load_private_key_file",   l_rsa_load_private_key_file},
		{"load_public_key_file",   l_rsa_load_public_key_file},
		{NULL, NULL}
	};
	luaL_register(L, "rsa", lua_rsa_modules);
	return 1;
}

#if __cplusplus
}
#endif