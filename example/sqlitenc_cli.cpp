#include <iostream>
#include <string>
#include "../SQLiteWrapper.h"

using namespace sqlitewrapper;

int main(int argc, char **argv)
{
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " sqlite_file passphrase enc|dec" << std::endl;
        return 1;
    }
    std::string input(argv[1]);
    std::string pwd(argv[2]);
    std::string op(argv[3]);

    SQLiteDatabase db;
    int rc = db.open(input);
    int error = -1;

    if (op == "enc") {
        error = db.rekey(pwd);
    } else if (op == "dec") {
        int error = db.key(pwd);
        if (error) {
            std::cerr << "Failed to open with given passphrase" << std::endl;
            return 1;
        }
        std::string empty;
        error = db.rekey(empty);
        if (error) {
            std::cerr << "Failed to decrypt with given passphrase" << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Unknown op " << op << std::endl;
        return 1;
    }
    return 0;
}
