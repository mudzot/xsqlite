/*
The MIT License (MIT)

Copyright (c) 2013 mudzot

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

/* Include the amalgamation file */
#include "sqlite3.c"

#ifdef SQLITE_HAS_CODEC

#include "crypto/mbedtls/arc4.h"
#include "crypto/mbedtls/sha1.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encryption support for sqlite using the high level codec interface
 * This implementation uses AES 128 bit in CBC mode
 */

#define BLOCKSIZE 16

#pragma pack(push, 1)
/**
 * The CBC cipher context
 */
typedef union
{
    unsigned char key[8];
    uint64_t num;
} SQLiteCipherContext;
#define KEYSIZE 8

#pragma pack(pop)

/**
 * Data encryption
 * @param ctx
 * @param in
 * @param out
 * @param size
 */
void SQLiteEncrypt(SQLiteCipherContext *ctx, const char *in, char *out,
                   int size)
{
    if (ctx->num) {
        mbedtls_arc4_context cryptCtx;
        mbedtls_arc4_init(&cryptCtx);
        mbedtls_arc4_setup(&cryptCtx, ctx->key, KEYSIZE);
        mbedtls_arc4_crypt(&cryptCtx, size, in, out);
    }
}

/**
 * Data decryption
 * @param ctx
 * @param in
 * @param out
 * @param size
 */
void SQLiteDecrypt(SQLiteCipherContext *ctx, const char *in, char *out,
                   int size)
{
    SQLiteEncrypt(ctx, in, out, size);
}

/**
 * Crypto block associating with each sqlite Pager
 */
typedef struct
{
    Pager *pager;                  /* Pager this crypto block belongs to */
    int32_t pageSize;              /* Size of pages */
    SQLiteCipherContext *readCtx;  /* CipherContext for reading */
    SQLiteCipherContext *writeCtx; /* CipherContext for writing */
    uint8_t *cryptBuffer; /* Buffer for encrypted and/or decrypted data */
} CodecCryptBlock;

/**
 * Create new cipher context
 * Key and IV are derived from the pass phrase using SHA256
 * The context should be freed with sqlite3_free when done
 * @param passPhrase
 * @param length
 * @return
 */
SQLiteCipherContext *CipherContextNew(const uint8_t *passphrase, int length)
{
    uint8_t hash[64];
    if (passphrase == NULL || length <= 0) {
        return NULL;
    }
    SQLiteCipherContext *ctx =
        (SQLiteCipherContext *)sqlite3_malloc(sizeof(SQLiteCipherContext));
    if (ctx == NULL) {
        return NULL;
    }

    if (passphrase != NULL && length > 0) {
        mbedtls_sha1_context hashCtx;
        mbedtls_sha1_init(&hashCtx);
        mbedtls_sha1_starts(&hashCtx);
        mbedtls_sha1_update(&hashCtx, passphrase, length);
        mbedtls_sha1_finish(&hashCtx, hash);

        memset(ctx->key, 0, sizeof(ctx->key));
        memcpy(ctx->key, hash, KEYSIZE);
    } else {
        ctx->num = 0;
    }

    return ctx;
}

/**
 * Duplicate a cipher context
 * @param org
 * @return
 */
SQLiteCipherContext *CipherContextClone(SQLiteCipherContext *org)
{
    SQLiteCipherContext *ctx =
        (SQLiteCipherContext *)sqlite3_malloc(sizeof(SQLiteCipherContext));
    if (ctx != NULL) {
        memcpy(ctx, org, sizeof(SQLiteCipherContext));
    }
    return ctx;
}

/**
 * Create or update existing crypto block
 * @param ctx cipher context to be used
 * @param pager sqlite Pager to be associated with
 * @param pageSize current page size (to be updated if changed)
 * @param existed existing crypt block to be updated if any
 * @return
 */
CodecCryptBlock *CreateCodeCryptBlock(SQLiteCipherContext *ctx, Pager *pager,
                                      int32_t pageSize,
                                      CodecCryptBlock *existing)
{
    CodecCryptBlock *block = existing;
    if (existing == NULL) {
        block = (CodecCryptBlock *)sqlite3_malloc(sizeof(CodecCryptBlock));
        if (block == NULL) {
            return NULL;
        }
        block->readCtx = ctx;
        block->writeCtx = ctx;
        block->cryptBuffer = NULL;
        block->pageSize = 0;
    }
    if (pageSize == -1) {
        pageSize = pager->pageSize;
    }

    block->pager = pager;
    if (block->pageSize != pageSize) {
        block->pageSize = pageSize;
        if (block->cryptBuffer) {
            sqlite3_free(block->cryptBuffer);
        }
        block->cryptBuffer = sqlite3_malloc(pageSize);
        if (block->cryptBuffer == NULL) {
            return NULL;
        }
    }
    return block;
}

/**
 * Destroy the crypto block created with CreateCodecCryptBlock
 * @param block
 */
void FreeCodecCryptBlock(CodecCryptBlock *block)
{
    if (block->cryptBuffer) {
        sqlite3_free(block->cryptBuffer);
        block->cryptBuffer = NULL;
    }

    /* Destroy the read key if there is one */
    if (block->readCtx) {
        sqlite3_free(block->readCtx);
    }
    if (block->writeCtx != NULL && block->writeCtx != block->readCtx) {
        sqlite3_free(block->writeCtx);
    }
    block->readCtx = NULL;
    block->writeCtx = NULL;

    sqlite3_free(block);
}

/**
 * Destroy crypto block callback
 * @param pv
 */
static void SQLite3CodecFreeCallback(void *pv)
{
    CodecCryptBlock *block = (CodecCryptBlock *)pv;
    FreeCodecCryptBlock(block);
}

/**
 * Page size changed callback
 * @param pArg the associated crypto block
 * @param pageSize updated pageSize
 * @param reservedSize
 */
void SQLite3CodecSizeChangedCallback(void *pArg, int pageSize, int reservedSize)
{
    CodecCryptBlock *block = (CodecCryptBlock *)pArg;
    if (block->pageSize != pageSize) {
        block->pageSize = pageSize;
    }
}

/**
 * Encrypting or decrypting a page callback
 * to be called by CODEC1 and CODEC2 in pager.c
 *
 * Note:
 * Decrypting is called via CODEC1 and doesn't care about returned value
 * (therefore need to replace input data)
 * Encrypting is called via CODEC2, taking returned value as buffer data to
 * write (DO NOT replace input data)
 * @param pArg the associated crypto block
 * @param data data to be encrypted/decrypted
 * @param nPageNum page number
 * @param nMode
 * @return
 */
void *SQLite3CodecCallback(void *pArg, void *data, Pgno nPageNum, int nMode)
{
    CodecCryptBlock *block = (CodecCryptBlock *)pArg;
    if (!block)
        return data;
    char *retVal = data;
    int32_t pageSize = block->pageSize;

    switch (nMode) {
    case 0: /* Undo a "case 7" journal file encryption */
    case 2: /* Reload a page */
    case 3: /* Load a page */
        if (!block->readCtx)
            break;
        SQLiteDecrypt(block->readCtx, data, data, pageSize);
        break;
    case 6: /* Encrypt a page for the main database file */
        if (!block->writeCtx)
            break;
        SQLiteEncrypt(block->writeCtx, data, block->cryptBuffer, pageSize);
        retVal = block->cryptBuffer;
        break;
    case 7: /* Encrypt a page for the journal file */
        /* Under normal circumstances, the readkey is the same as the writekey.
        However,
        when the database is being rekeyed, the readkey is not the same as the
        writekey.
        The rollback journal must be written using the original key for the
        database file because it is, by nature, a rollback journal.
        Therefore, for case 7, when the rollback is being written, always
        encrypt using
        the database's readkey, which is guaranteed to be the same key that was
        used to
        read the original data.
        */
        if (!block->readCtx)
            break;
        SQLiteEncrypt(block->readCtx, data, block->cryptBuffer, pageSize);
        retVal = block->cryptBuffer;
        break;
    }

    return retVal;
}

/**
 * Called to attach a key to a database
 * in (attach.c)
 * @param db
 * @param nDb
 * @param pKey
 * @param nKeyLen
 * @return
 */
int sqlite3CodecAttach(sqlite3 *db, int nDb, const void *pKey, int nKeyLen)
{
    int rc = SQLITE_ERROR;
    SQLiteCipherContext *ctx = NULL;

    /* No key specified, could mean either use the main db's encryption or no
     * encryption */
    if (pKey == NULL || nKeyLen == 0) {
        if (nDb == 0) {
            /* Main database, no key specified so not encrypted */
            return SQLITE_OK;
        } else {
            /*
             * Attached database, use the main database's key
             * Get the encryption block for the main database and attempt to
             * duplicate the key
             * for use by the attached database
             */
            Pager *pager = sqlite3BtreePager(db->aDb[0].pBt);
            CodecCryptBlock *pBlock =
                (CodecCryptBlock *)sqlite3PagerGetCodec(pager);

            if (!pBlock)
                return SQLITE_OK; /* Main database is not encrypted so neither
                                     will be any attached database */
            if (!pBlock->readCtx)
                return SQLITE_OK; /* Not encrypted */

            ctx = CipherContextClone(pBlock->readCtx);
            if (ctx == NULL) {
                return SQLITE_NOMEM;
            }
        }
    } else { /* User-supplied passphrase, so create a cryptographic key out of
                it */
        ctx = CipherContextNew(pKey, nKeyLen);
        if (ctx == NULL) {
            return SQLITE_NOMEM;
        }
    }

    /* Create a new encryption block and assign the codec to the new attached
     * database */
    if (ctx != NULL) {
        Pager *pager = sqlite3BtreePager(db->aDb[nDb].pBt);
        CodecCryptBlock *block = CreateCodeCryptBlock(ctx, pager, -1, NULL);
        if (!block) {
            return SQLITE_NOMEM;
        }

        sqlite3PagerSetCodec(pager, SQLite3CodecCallback,
                             SQLite3CodecSizeChangedCallback,
                             SQLite3CodecFreeCallback, block);

        rc = SQLITE_OK;
    }
    return rc;
}

/**
 * Get the stored crypto key
 * Once a password has been supplied and a key created, we don't keep the
 * original password for security purposes.  Therefore return NULL.
 * @param db
 * @param nDb
 * @param ppKey
 * @param pnKeyLen
 */
void sqlite3CodecGetKey(sqlite3 *db, int nDb, void **ppKey, int *pnKeyLen)
{
    Btree *pbt = db->aDb[0].pBt;
    Pager *p = sqlite3BtreePager(pbt);
    CodecCryptBlock *pBlock = (CodecCryptBlock *)sqlite3PagerGetCodec(p);

    if (ppKey != NULL) {
        *ppKey = 0;
    }
    if (pnKeyLen != NULL && pBlock != NULL) {
        *pnKeyLen = 1;
    }
}

/**
 * Deprecated. Use sqlite3_key_v2.
 *
 * @param db
 * @param pKey
 * @param nKey
 * @return
 */
SQLITE_API int sqlite3_key(sqlite3 *db, /* Database to be rekeyed */
                           const void *pKey, int nKey /* The key */
                           )
{
    return sqlite3_key_v2(db, NULL, pKey, nKey);
}

/**
 * Specify the key for an encrypted database.  This routine should be called
 * right after sqlite3_open().
 *
 * The code to implement this API is not available in the public release
 * of SQLite.
 * @param db
 * @param pKey
 * @param nKey
 * @return
 */
SQLITE_API int sqlite3_key_v2(sqlite3 *db,         /* Database to be rekeyed */
                              const char *zDbName, /* Name of the database */
                              const void *pKey, int nKey /* The key */
                              )
{
    return sqlite3CodecAttach(db, 0, pKey, nKey);
}

/**
 * Deprecated. Use sqlite3_rekey_v2.
 */
SQLITE_API int sqlite3_rekey(sqlite3 *db, /* Database to be rekeyed */
                             const void *pKey, int nKey /* The new key */
                             )
{
    return sqlite3_rekey_v2(db, NULL, pKey, nKey);
}

/**
 * Change the key on an open database.
 *
 * If the current database is not encrypted, this routine will encrypt it. If
 * pNew==0 or nNew==0, the database is decrypted.
 *
 * The code to implement this API is not available in the public release of
 * SQLite.
 * @param db
 * @param pKey
 * @param nKey
 * @return
 */
SQLITE_API int sqlite3_rekey_v2(sqlite3 *db, /* Database to be rekeyed */
                                const char *zDbName, /* Name of the database */
                                const void *pKey, int nKey /* The new key */
                                )
{
    Btree *pbt = db->aDb[0].pBt;
    Pager *p = sqlite3BtreePager(pbt);
    CodecCryptBlock *block = (CodecCryptBlock *)sqlite3PagerGetCodec(p);
    SQLiteCipherContext *ctx = NULL;
    int rc = SQLITE_ERROR;

    ctx = CipherContextNew(pKey, nKey);

    /* To rekey a database, we change the writekey for the pager.  The readkey
     * remains the same */

    if (block == NULL) /* Encrypt an unencrypted database */
    {
        block = CreateCodeCryptBlock(ctx, p, -1, NULL);
        if (block == NULL)
            return SQLITE_NOMEM;

        block->readCtx = NULL; /* Original database is not encrypted */
        sqlite3PagerSetCodec(sqlite3BtreePager(pbt), SQLite3CodecCallback,
                             SQLite3CodecSizeChangedCallback,
                             SQLite3CodecFreeCallback, block);
    } else {
        /* Change the writekey for an already-encrypted database */
        block->writeCtx = ctx;
    }

    /* Rewrite the whole database to ensure new writekey is used */
    sqlite3_mutex_enter(db->mutex);

    /* Start a transaction */
    rc = sqlite3BtreeBeginTrans(pbt, 1);

    if (rc == SQLITE_OK) {
        /* Rewrite all the pages in the database using the new encryption key */
        Pgno nPage;
        Pgno nSkip = PAGER_MJ_PGNO(p);
        DbPage *pPage;
        Pgno n;
        int count;

        sqlite3PagerPagecount(p, &count);
        nPage = (Pgno)count;

        for (n = 1; n <= nPage; n++) {
            if (n == nSkip)
                continue;
            rc = sqlite3PagerGet(p, n, &pPage, 0);
            if (!rc) {
                rc = sqlite3PagerWrite(pPage);
                sqlite3PagerUnref(pPage);
            }
        }
    }

    /* If we succeeded, try and commit the transaction */
    if (rc == SQLITE_OK) {
        rc = sqlite3BtreeCommit(pbt);
    } else {
        /* If we failed, rollback */
        sqlite3BtreeRollback(pbt, SQLITE_OK, 1);
    }

    /* If we succeeded, destroy any previous read key this database used and
     * make the readkey equal to the writekey */
    if (rc == SQLITE_OK) {
        if (block->readCtx != NULL) {
            sqlite3_free(block->readCtx);
        }
        block->readCtx = block->writeCtx;
    }
    /* We failed.  Destroy the new writekey (if there was one) and revert it
       back to the original readkey */
    else {
        if (block->writeCtx != NULL) {
            sqlite3_free(block->writeCtx);
        }
        block->writeCtx = block->readCtx;
    }

    /* If the readkey and writekey are both empty, there's no need for a codec
     * on this pager anymore. Remove the codec from the pager.
     * sqlite3PagerSetCodec calls FreeCodecCryptBlock for this block
     */
    if (block->readCtx == NULL && block->writeCtx == NULL) {
        sqlite3PagerSetCodec(p, NULL, NULL, NULL, NULL);
    }
    
    sqlite3_mutex_leave(db->mutex);

    return rc;
}

/**
 * Specify the activation key for a SEE database.  Unless
 * activated, none of the SEE routines will work.
 */
SQLITE_API void
sqlite3_activate_see(const char *zPassPhrase /* Activation phrase */
                     )
{
}

#ifdef __cplusplus
} /* end of the 'extern "C"' block */
#endif

#endif /* SQLITE_HAS_CODEC */