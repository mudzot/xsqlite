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

#ifndef SQLITEWRAPPER_H
#define SQLITEWRAPPER_H

#include <cstdint>
#include <iostream>
#include <map>
#include <sqlite3.h>

/**
 * A thin C++ wrapper around sqlite C interface
 */
namespace sqlitewrapper {

class SQLiteStatement;

typedef enum {
    TYPE_UNKNOWN = 0,
    TYPE_INTEGER = 1,
    TYPE_FLOAT = 2,
    TYPE_TEXT = 3,
    TYPE_BLOB = 4,
    TYPE_NULL = 5
} SQLiteDataType;

class SQLiteDatabase;

class SQLiteStatement
{
    friend SQLiteDatabase;

public:
    ~SQLiteStatement()
    {
        int rc = sqlite3_finalize(_stmt);
        if (rc != SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << "Last error: " << sqlite3_errstr(rc) << std::endl;
        }
        _stmt = NULL;
    }

    /// Reset the execution result, NOT the binding data
    int reset()
    {
        _clearRowData();
        int rc = sqlite3_reset(_stmt);
        if (rc != SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << "Last error: " << sqlite3_errstr(rc) << std::endl;
        }
        return rc;
    }

    /// Clear binding data
    int clearBindings()
    {
        return sqlite3_clear_bindings(_stmt);
    }

    /// Bind NULL
    int bind(int oneBasedIndex)
    {
        int rc = sqlite3_bind_null(_stmt, oneBasedIndex);
        return rc;
    }

    /// Bind BLOB
    int bind(int oneBasedIndex, const void *data, int length)
    {
        int rc = sqlite3_bind_blob(_stmt, oneBasedIndex, data, length,
                                   SQLITE_TRANSIENT);
        return rc;
    }

    /// Bind DOUBLE
    int bind(int oneBasedIndex, double d)
    {
        int rc = sqlite3_bind_double(_stmt, oneBasedIndex, d);
        return rc;
    }

    /// Bind INT
    int bind(int oneBasedIndex, int32_t i)
    {
        int rc = sqlite3_bind_int(_stmt, oneBasedIndex, i);
        return rc;
    }

    /// Bind INT64
    int bind(int oneBasedIndex, int64_t i64)
    {
        int rc = sqlite3_bind_int64(_stmt, oneBasedIndex, i64);
        return rc;
    }

    /// Bind TEXT
    int bind(int oneBasedIndex, const std::string &text)
    {
        int rc = sqlite3_bind_text(_stmt, oneBasedIndex, text.data(),
                                   text.length(), SQLITE_STATIC);
        return rc;
    }

    /// Bind UTF16 TEXT
    int bind(int oneBasedIndex, const std::wstring &text)
    {
        int rc = sqlite3_bind_text16(_stmt, oneBasedIndex, text.data(),
                                     2 * text.length(), SQLITE_STATIC);
        return rc;
    }

    /// Execute the statement
    bool execute()
    {
        _hasRow = false;
        _columnCount = 0;
        int rc = sqlite3_step(_stmt);
        if (rc == SQLITE_DONE) {
            // Should reset to execute another before step again
            reset();
            return true;
        } else if (rc == SQLITE_ROW) {
            // Have returned data, step again to retrieve more row(s)
            _columnCount = sqlite3_column_count(_stmt);
            for (int i = 0; i < _columnCount; ++i) {
                const char *ptr = sqlite3_column_name(_stmt, i);
                if (ptr) {
                    _rowNameIndex[std::string(ptr)] = i;
                }
            }
            _hasRow = true;
            return true;
        } else {
            // Error occurred
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << "Error: " << sqlite3_errstr(rc) << std::endl;
            reset();
            return false;
        }
    }

    /// Indicate whether there currently is a result row (after execute or next)
    bool hasRow()
    {
        return _hasRow;
    }

    /// Iterate to next result row (then check with hasRow)
    void next()
    {
        int rc = sqlite3_step(_stmt);
        if (rc == SQLITE_DONE) {
            // Should reset to execute another before step again
            _hasRow = false;
            reset();
        } else if (rc == SQLITE_ROW) {
            // Have returned data, step again to retrieve more row(s)
            _columnCount = sqlite3_column_count(_stmt);
            _hasRow = true;
        } else {
            // Error occurred
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << "Error: " << sqlite3_errstr(rc) << std::endl;
            reset();
        }
    }

    SQLiteDataType getColumnType(int zeroBasedColIndex)
    {
        if (_hasRow) {
            return TYPE_UNKNOWN;
        }
        int dataType = sqlite3_column_type(_stmt, zeroBasedColIndex);
        if (dataType < 0 || dataType > TYPE_NULL) {
            dataType = 0;
        }
        return (SQLiteDataType)dataType;
    }

    int getDouble(double &_return, int zeroBasedColIndex)
    {
        if (!_hasRow || zeroBasedColIndex < 0 ||
            zeroBasedColIndex >= _columnCount) {
            return SQLITE_MISUSE;
        }
        _return = sqlite3_column_double(_stmt, zeroBasedColIndex);
        return SQLITE_OK;
    }

    int getDouble(double &_return, const std::string &colName)
    {
        std::map<std::string, int>::const_iterator it =
            _rowNameIndex.find(colName);
        if (it != _rowNameIndex.end()) {
            return getDouble(_return, it->second);
        } else {
            return SQLITE_NOTFOUND;
        }
    }

    int getInt(int &_return, int zeroBasedColIndex)
    {
        if (!_hasRow || zeroBasedColIndex < 0 ||
            zeroBasedColIndex >= _columnCount) {
            return SQLITE_MISUSE;
        }
        _return = sqlite3_column_int(_stmt, zeroBasedColIndex);
        return SQLITE_OK;
    }

    int getInt(int &_return, const std::string &colName)
    {
        std::map<std::string, int>::const_iterator it =
            _rowNameIndex.find(colName);
        if (it != _rowNameIndex.end()) {
            return getInt(_return, it->second);
        } else {
            return SQLITE_NOTFOUND;
        }
    }

    int64_t getInt64(int64_t _return, int zeroBasedColIndex)
    {
        if (!_hasRow || zeroBasedColIndex < 0 ||
            zeroBasedColIndex >= _columnCount) {
            return SQLITE_MISUSE;
        }
        _return = sqlite3_column_int64(_stmt, zeroBasedColIndex);
        return SQLITE_OK;
    }

    int64_t getInt64(int64_t _return, const std::string &colName)
    {
        std::map<std::string, int>::const_iterator it =
            _rowNameIndex.find(colName);
        if (it != _rowNameIndex.end()) {
            return getInt64(_return, it->second);
        } else {
            return SQLITE_NOTFOUND;
        }
    }

    int getString(std::string &_return, int zeroBasedColIndex)
    {
        if (!_hasRow || zeroBasedColIndex < 0 ||
            zeroBasedColIndex >= _columnCount) {
            _return = "";
            return SQLITE_MISUSE;
        }
        const char *ptr =
            (const char *)sqlite3_column_text(_stmt, zeroBasedColIndex);
        if (ptr != NULL) {
            _return = std::string(ptr);
            return SQLITE_OK;
        } else {
            _return = "";
            return SQLITE_ERROR;
        }
    }

    int getString(std::string &_return, const std::string &colName)
    {
        std::map<std::string, int>::const_iterator it =
            _rowNameIndex.find(colName);
        if (it != _rowNameIndex.end()) {
            return getString(_return, it->second);
        } else {
            return SQLITE_NOTFOUND;
        }
    }

    int getString(std::wstring &_return, int zeroBasedColIndex)
    {
        if (!_hasRow || zeroBasedColIndex < 0 ||
            zeroBasedColIndex >= _columnCount) {
            _return = L"";
            return SQLITE_MISUSE;
        }
        const void *ptr = sqlite3_column_text(_stmt, zeroBasedColIndex);
        if (ptr != NULL) {
            _return = std::wstring((const wchar_t *)ptr);
            return SQLITE_OK;
        } else {
            _return = L"";
            return SQLITE_ERROR;
        }
    }

    int getString(std::wstring &_return, const std::string &colName)
    {
        std::map<std::string, int>::const_iterator it =
            _rowNameIndex.find(colName);
        if (it != _rowNameIndex.end()) {
            return getString(_return, it->second);
        } else {
            return SQLITE_NOTFOUND;
        }
    }

private:
    sqlite3_stmt *_stmt;
    // Query data
    bool _hasRow;
    int _columnCount;
    std::map<std::string, int> _rowNameIndex;

private:
    SQLiteStatement(sqlite3_stmt *stmt)
        : _stmt(stmt), _hasRow(false), _columnCount(0)
    {
    }
    void _clearRowData()
    {
        _hasRow = false;
        _columnCount = 0;
        _rowNameIndex.clear();
    }
};

class SQLiteDatabase
{
public:
    SQLiteDatabase() : _dbConn(NULL)
    {
    }
    virtual ~SQLiteDatabase()
    {
        close();
    }
    /// Open a database
    int open(const std::string &name)
    {
        int rc = sqlite3_open(name.c_str(), &_dbConn);
        if (rc != SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << sqlite3_errmsg(_dbConn) << std::endl;
            ;
        }
        return rc;
    }

    int open(const std::wstring &name)
    {
        int rc = sqlite3_open16(name.c_str(), &_dbConn);
        if (rc != SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << sqlite3_errmsg(_dbConn) << std::endl;
            ;
        }
        return rc;
    }
    /// Close a database
    void close()
    {
        if (_dbConn) {
            sqlite3_close(_dbConn);
            _dbConn = NULL;
        }
    }
    /// Prepare a statement (allocated with new, need delete when done)
    SQLiteStatement *prepareStatement(const std::string &sql)
    {
        if (!_dbConn) {
            return NULL;
        }
        sqlite3_stmt *stmt;
        int rc =
            sqlite3_prepare_v2(_dbConn, sql.c_str(), sql.length(), &stmt, NULL);
        if (rc == SQLITE_OK) {
            return new SQLiteStatement(stmt);
        } else {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << sqlite3_errmsg(_dbConn) << std::endl;
            return NULL;
        }
    }
    /// Prepare a statement (allocated with new, need delete when done)
    SQLiteStatement *prepareStatement(const std::wstring &sql)
    {
        if (!_dbConn) {
            return NULL;
        }
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare16_v2(_dbConn, sql.c_str(), sql.length(), &stmt,
                                      NULL);
        if (rc == SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << sqlite3_errstr(rc) << std::endl;
            ;
            return new SQLiteStatement(stmt);
        } else {
            return NULL;
        }
    }

    /// Begin a transaction
    void begin()
    {
        directExecute("BEGIN");
    }

    /// Commit a transaction
    void commit()
    {
        directExecute("COMMIT");
    }

    /// Rollback a transaction
    void rollback()
    {
        directExecute("ROLLBACK");
    }

    /// Directly execute a string statement
    int directExecute(const std::string &stmt)
    {
        if (!_dbConn) {
            return SQLITE_ERROR;
        }
        char *errMsg = NULL;
        int rc = sqlite3_exec(_dbConn, stmt.c_str(), NULL, NULL, &errMsg);
        if (rc != SQLITE_OK) {
            if (errMsg != NULL) {
                std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]" << errMsg
                          << std::endl;
                sqlite3_free(errMsg);
            }
        }
        return rc;
    }
#ifdef SQLITE_HAS_CODEC
    /// Assign a key to use with encrypted database (call right after open)
    int key(const std::string &passPhrase)
    {
        int rc = sqlite3_key(_dbConn, passPhrase.data(), passPhrase.length());
        if (rc != SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << sqlite3_errstr(rc) << std::endl;
        }
        return rc;
    }
    /**
     * Re-assign a key to a database
     */
    int rekey(const std::string &passPhrase)
    {
        int rc = sqlite3_rekey(_dbConn, passPhrase.data(), passPhrase.length());
        if (rc != SQLITE_OK) {
            std::cerr << "[" << __FILE__ << ":" << __LINE__ << "]"
                      << sqlite3_errmsg(_dbConn) << std::endl;
        }
        return rc;
    }
#endif

    inline sqlite3 *dbConn()
    {
        return _dbConn;
    }

private:
    sqlite3 *_dbConn;
};
}

/**

//Sample usage

int main(int argc, char** argv)
{
    SQLiteDatabase db;
    int rc = db.open("test.sqlite");
    rc = db.directExecute("DROP TABLE IF EXISTS Test");
    rc = db.directExecute("CREATE TABLE Test (id INTEGER PRIMARY KEY NOT NULL,
num INTEGER, str TEXT)");

    SQLiteStatement* stmt = db.prepareStatement("INSERT INTO Test(id,num,str)
VALUES(?,?,?)");
    stmt->bind(1, 7);
    stmt->bind(2, 150);
    stmt->bind(3, "string data");
    rc = stmt->execute();

    stmt->bind(1, 8);
    stmt->bind(2, 1600);
    stmt->bind(3, "more string data");
    rc = stmt->execute();
    delete stmt;

    stmt = db.prepareStatement("SELECT id,num,str FROM Test");
    if (stmt->execute()) {
        while (stmt->hasRow()) {
            int id;
            rc = stmt->getInt(id, 0);
            int num;
            rc = stmt->getInt(num, "num");
            std::string str;
            rc = stmt->getString(str, 2);
            std::cout << id << " | " << num << " | " << str << std::endl;
            stmt->next();
        }
    }
    delete stmt;

    return 0;
}


 */

#endif /* SQLITEWRAPPER_H */
