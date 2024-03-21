#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <openssl/evp.h>
#include <algorithm>

using namespace std;

struct PasswordEntry {
    string application;
    string username;
    vector<unsigned char> password;
};

vector<unsigned char> encryptPassword(const vector<unsigned char>& password, const string& key) {
    vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    vector<unsigned char> encrypted;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), iv.data());

    int max_output_len = password.size() + EVP_MAX_BLOCK_LENGTH;
    encrypted.resize(max_output_len);
    int encrypted_len;
    EVP_EncryptUpdate(ctx, encrypted.data(), &encrypted_len, password.data(), password.size());
    int final_len;
    EVP_EncryptFinal_ex(ctx, encrypted.data() + encrypted_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);

    encrypted.resize(encrypted_len + final_len);

    return encrypted;
}

vector<unsigned char> decryptPassword(const vector<unsigned char>& encryptedPassword, const string& key) {
    vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    vector<unsigned char> decrypted;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), iv.data());

    int max_output_len = encryptedPassword.size() + EVP_MAX_BLOCK_LENGTH;
    decrypted.resize(max_output_len);
    int decrypted_len;
    EVP_DecryptUpdate(ctx, decrypted.data(), &decrypted_len, encryptedPassword.data(), encryptedPassword.size());
    int final_len;
    EVP_DecryptFinal_ex(ctx, decrypted.data() + decrypted_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);

    decrypted.resize(decrypted_len + final_len);

    return decrypted;
}

void savePasswordsToVault(const vector<PasswordEntry>& new_pass, const string& filename, const string& key) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Unable to open vault file for writing." << endl;
        return;
    }

    for (const auto& entry : new_pass) {
        vector<unsigned char> encryptedPassword = encryptPassword(entry.password, key);
        file << entry.application << endl;
        file << entry.username << endl;
        file.write(reinterpret_cast<const char*>(encryptedPassword.data()), encryptedPassword.size());
        file << endl;
    }
    cout << "Passwords saved to vault: " << filename << endl;
}

void addPassword(vector<PasswordEntry>& new_pass, const string& key) {
    PasswordEntry entry;
    cout << "Enter the application: ";
    cin >> entry.application;
    cout << "Enter username: ";
    cin >> entry.username;
    cout << "Enter password: ";
    string password;
    cin >> password;
    vector<unsigned char> passwordVector(password.begin(), password.end());
    entry.password = passwordVector;
    new_pass.push_back(entry);
}

void getPassword(const vector<PasswordEntry>& passwordDatabase, const string& application) {
    bool found = false;
    for (const auto& entry : passwordDatabase) {
        if (entry.application == application) {
            cout << "Username: " << entry.username << endl;
            cout << "Password: " << string(entry.password.begin(), entry.password.end()) << endl;
            found = true;
            break;
        }
    }
    if (!found) {
        cout << "Password entry not found for this application: " << application << endl;
    }
}


void deletePassword(vector<PasswordEntry>& new_pass, const string& application) {
    auto it = remove_if(new_pass.begin(), new_pass.end(),
                           [&application](const PasswordEntry& entry) { return entry.application == application; });
    if (it != new_pass.end()) {
        new_pass.erase(it, new_pass.end());
        cout << "Password entry deleted successfully for this application: " << application << endl;
    } else {
        cout << "Password entry not found for this application: " <<application << endl;
    }
}

void changePassword(vector<PasswordEntry>& new_pass, const string& application, const string& key) {
    for (auto& entry : new_pass) {
        if (entry.application == application) {
            cout << "Enter new password: ";
            string newPassword;
            cin >> newPassword;
            entry.password = vector<unsigned char>(newPassword.begin(), newPassword.end());
            cout << "Password changed successfully for this application: " << application << endl;
            savePasswordsToVault(new_pass, "vault.bin", key);
            return;
        }
    }
    cout << "Password entry not found for this application: " <<application << endl;
}

void displayAllPasswords(const vector<PasswordEntry>& new_pass) {
    if (new_pass.empty()) {
        cout << "No passwords stored." << endl;
        return;
    }
    cout << "Stored Passwords:" << endl;
    for (const auto& entry : new_pass) {
        cout << "Website: " << entry.application << ", Username: " << entry.username << ", Password: ";

        string passwordString(entry.password.begin(), entry.password.end());
        cout << passwordString << endl;
    }
}

vector<PasswordEntry> loadPasswordsFromVault(const string& filename, const string& key) {
    vector<PasswordEntry> passwordDatabase;
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Unable to open vault file for reading." << endl;
        return passwordDatabase;
    }

    string application, username, encryptedPassword;
    while (getline(file, application) && getline(file, username) && getline(file, encryptedPassword)) {
        vector<unsigned char> decryptedPassword = decryptPassword(
            vector<unsigned char>(encryptedPassword.begin(), encryptedPassword.end()), key);
        passwordDatabase.push_back({application, username, decryptedPassword});
    }
    cout << "Passwords loaded from vault: " << filename << endl;
    return passwordDatabase;
}


int main() {
    vector<PasswordEntry> new_pass;

    string key;
    cout << "Enter encryption key: ";
    cin >> key;

    new_pass = loadPasswordsFromVault("vault.bin", key);

    while (true) {
        cout << "\nPassword Manager\n";
        cout << "1. Add Password\n";
        cout << "2. Get Password\n";
        cout << "3. Delete Password\n";
        cout << "4. Change Password\n";
        cout << "5. Display All Passwords\n";
        cout << "6. Save Passwords to Vault\n";
        cout << "7. Exit\n";
        cout << "Enter your choice: ";

        int choice;
        cin >> choice;

        switch (choice) {
            case 1:
                addPassword(new_pass, key);
                break;
             case 2: {
    string application;
    cout << "Enter the application: ";
    cin >> application;
    getPassword(new_pass, application);
    break;
}

            case 3: {
                                string application;
                cout << "Enter application to delete: ";
                cin >> application;
                deletePassword(new_pass, application);
                break;
            }
            case 4: {
                string application;
                cout << "Enter the application to change password: ";
                cin >> application;
                changePassword(new_pass, application, key);
                break;
            }
            case 5:
                displayAllPasswords(new_pass);
                break;
            case 6:
                savePasswordsToVault(new_pass, "vault.bin", key);
                break;
            case 7:
                cout << "Exiting...\n";
                return 0;
            default:
                cerr << "Invalid choice! Please try again.\n";
        }
    }

    return 0;
}
