/*
 * LIBS USED (latest releases from 2024 Q4)
 *  - https://github.com/yhirose/cpp-httplib
 *  - https://github.com/openssl/openssl
 *  - https://github.com/nlohmann/json
 *
 * made by https://github.com/const-fn (DO NOT REDISTRIBUTE)
 */

#include <iostream>
#include <fstream>

#include <filesystem>
namespace fs = std::filesystem;

#include <thread>
#include <functional>

#include <chrono>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <incbin.h>

#include <json.hpp>

#include <winsock2.h>

#define SERVER_DOMAIN "discovery.pokemod.dev"
#define HEARTBEAT_DELAY 60

INCBIN(lite_modules, "C:/.../resources/lite-modules.json")
INCBIN(pro_modules, "C:/.../resources/pro-modules.json")

namespace
{
    char base_directory[256]{};
    std::string internal_base_directory;

    const char* local_ip;

    uint32_t active_sessions;
    std::time_t last_heartbeat;

    bool locked_modules;

    httplib::SSLServer* server;

    bool setup();

    void serviceRoutine();

    bool readKey(const char* path, EVP_PKEY*& key);
    void writeKey(const char* path, EVP_PKEY* key);
    bool generateKey(EVP_PKEY*& key);

    bool readCertificate(const char* path, X509*& certificate);
    void writeCertificate(const char* path, X509* certificate);
    bool generateCertificate(const char* domain, uint32_t numeric_local_ip, EVP_PKEY* key, X509*& certificate);

    bool readFile(const char* directory, const char* file_name, char*& data, size_t& size);
    void writeFile(const char* directory, const char* file_name, const char* data, size_t size);

    std::unique_ptr<char[]> bytesToHex(const uint8_t* data, size_t size);
}

int main()
{
    SetConsoleTitleA("Pokemod Server v1.0");

    {
        const size_t max_size = sizeof(base_directory);

        size_t required_size;
        getenv_s(&required_size, base_directory, max_size, "USERPROFILE");

        if (required_size >= max_size - 1)
        {
            std::cout << "Windows user name too long! " << required_size << "\n";
            return EXIT_FAILURE;
        }

        memcpy(base_directory + required_size - 1, "\\.pokemod\\\0", 11);
    }

    if (fs::create_directory(base_directory))
    {
        std::string command("explorer ");
        command.append(base_directory);

        system(command.c_str());
    }

    {
        std::string agent_directory = std::string(base_directory).append("agents\\");

        if (fs::create_directory(agent_directory))
        {
            writeFile(
                agent_directory.c_str(),
                "lite-modules.json.disabled",
                reinterpret_cast<const char*>(lite_modules_data),
                lite_modules_size
            );

            writeFile(
                agent_directory.c_str(),
                "pro-modules.json.disabled",
                reinterpret_cast<const char*>(pro_modules_data),
                pro_modules_size
            );
        }
    }

    internal_base_directory = std::string(base_directory).append("internal\\");
    fs::create_directory(internal_base_directory);

    if (!setup())
    {
        Sleep(1000);
        return EXIT_FAILURE;
    }

    std::thread* service = nullptr;

    std::function<bool()> start_service = [&service]()
    {
        if (service) return false;

        service = new std::thread(serviceRoutine);

        return true;
    };

    std::function<bool()> stop_service = [&service]()
    {
        if (!service) return false;

        server->stop();
        service->join();

        delete server;
        server = nullptr;

        delete service;
        service = nullptr;

        return true;
    };

    while (true)
    {
        std::cout << "==> ";

        std::string line;
        std::getline(std::cin, line);

        if (line == "exit")
        {
            std::cout << "Closing...";
            Sleep(1000);
            break;
        }

        if (line == "help")
        {
            std::cout
            << "\n"
            << "# help       | displays this overview of commands\n"
            << "# exit       | closes the application fully\n"
            << "# restart    | restarts the application\n"
            << "# start      | starts the actual pokemod service\n"
            << "# stop       | stops the actual pokemod service\n"
            << "# status     | prints status of the pokemod service and number of active sessions\n"
            << "# regenerate | deletes certifications and restarts application\n"
            << "# clear      | clear console\n"
            << "\n";

            continue;
        }

        if (line == "restart")
        {
            stop_service();

            if (!setup())
            {
                Sleep(1000);
                return EXIT_FAILURE;
            }

            continue;
        }

        if (line == "start" || line == "start locked")
        {
            if (!start_service())
            {
                std::cout << "The service is already online!\n";
                continue;
            }

            if (line == "start locked")
                locked_modules = true;

            std::cout << "The service has now started.\n";
            continue;
        }

        if (line == "stop")
        {
            locked_modules = false;

            if (!stop_service())
            {
                std::cout << "The service is not even online.\n";
                continue;
            }

            std::cout << "The service has been shutdown.\n";
            continue;
        }

        if (line == "status")
        {
            std::cout << "The service is currently ";

            if (service)
            {
                using namespace std::chrono;

                if((system_clock::to_time_t(system_clock::now()) - last_heartbeat) > (HEARTBEAT_DELAY * 2))
                    active_sessions = 0;

                std::cout << "online with " << active_sessions << " active session" << (active_sessions != 1 ? "s" : "");
            }
            else {
                std::cout << "offline";
            }

            std::cout << ".\n";

            continue;
        }

        if (line == "regenerate")
        {
            stop_service();
            fs::remove(std::string(internal_base_directory).append("certificate.pem"));

            if (!setup())
            {
                Sleep(1000);
                return EXIT_FAILURE;
            }

            std::cout << "A new certificate has been generated! Please check the server directory.\n";

            continue;
        }

        if (line == "clear")
        {
            system("cls");
            continue;
        }
    }

    stop_service();

    return EXIT_SUCCESS;
}

namespace
{
    bool setup()
    {
        system("cls");

        {
            WSADATA wsa_data;
            WSAStartup(MAKEWORD(2, 2), &wsa_data);

            PADDRINFOA domain_lookup = nullptr;

            ADDRINFOA hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            if (GetAddrInfoA("www.google.com", "http", &hints, &domain_lookup))
            {
                std::cout << "Failed to resolve domain \"www.google.com\"!\n";
                return false;
            }

            SOCKET socket_ = socket(
                domain_lookup->ai_family,
                domain_lookup->ai_socktype,
                domain_lookup->ai_protocol
            );

            sockaddr_in local_address{};

            bool failure = false;

            if (!connect(socket_, domain_lookup->ai_addr, static_cast<int>(domain_lookup->ai_addrlen)))
            {
                int length = sizeof(local_address);
                failure = getsockname(socket_, reinterpret_cast<sockaddr*>(&local_address), &length);
            }

            closesocket(socket_);

            WSACleanup();

            if (local_address.sin_family != AF_INET)
                failure = true;

            char* buffer = static_cast<char*>(malloc(INET_ADDRSTRLEN));

            if (!inet_ntop(AF_INET, &local_address.sin_addr, buffer, INET_ADDRSTRLEN))
                failure = true;

            if (failure)
            {
                std::cout << "Failed to get systems local IP!\n";
                return false;
            }

            free(const_cast<char*>(local_ip));
            local_ip = buffer;
        }

        std::cout << "Currently using local IP " << local_ip << "!\n";

        EVP_PKEY* key = nullptr;
        {
            const std::string private_key_path = std::string(internal_base_directory).append("private.pem");

            if (!fs::exists(private_key_path))
            {
                if (!generateKey(key))
                {
                    std::cout << "Failed to generate encryption keys!\n";
                    return false;
                }

                writeKey(private_key_path.c_str(), key);
            }
            else {
                if (!readKey(private_key_path.c_str(), key))
                {
                    std::cout << "Failed to read private key!\n";
                    return false;
                }
            }
        }

        {
            uint32_t numeric_local_ip = 0;
            inet_pton(AF_INET, local_ip, &numeric_local_ip);

            const std::string internal_certificate_path = std::string(internal_base_directory).append("certificate.pem");

            if (!fs::exists(internal_certificate_path))
            {
                {
                    X509* certificate = nullptr;

                    if (!generateCertificate(SERVER_DOMAIN, numeric_local_ip, key, certificate))
                    {
                        std::cout << "Failed to generate certificate!\n";
                        return false;
                    }

                    writeCertificate(internal_certificate_path.c_str(), certificate);

                    X509_free(certificate);
                }

                const std::string certificate_path = std::string(base_directory).append("spoofing.crt");
                fs::copy(internal_certificate_path, certificate_path, fs::copy_options::overwrite_existing);

                const std::string hosts_path = std::string(base_directory).append("hosts.txt");
                std::ofstream outfile(hosts_path);

                outfile << "127.0.0.1 localhost\n0.0.0.0 faults.pokemod.dev\n" << local_ip << " " << SERVER_DOMAIN;

                outfile.close();
            }
            else {
                X509* certificate = nullptr;

                if (!readCertificate(internal_certificate_path.c_str(), certificate))
                {
                    std::cout << "Failed to read internal certificate!\n";
                    return false;
                }

                int crit = 0;
                int idx = -1;

                auto general_names = static_cast<GENERAL_NAMES*>(
                        X509_get_ext_d2i(certificate, NID_subject_alt_name, &crit, &idx)
                );

                if (crit || !general_names)
                {
                    std::cout << "Unable to extract certification details! It may be corrupted.";
                }
                else {
                    bool dns_invalid = true, ip_invalid = true;

                    int num_of_entries = sk_GENERAL_NAME_num(general_names);

                    for (int i = 0; i < num_of_entries; i++)
                    {
                        auto general_name = static_cast<GENERAL_NAME*>(sk_GENERAL_NAME_value(general_names, i));

                        int type = 0;
                        void* value = GENERAL_NAME_get0_value(general_name, &type);

                        if (!value || !type) continue;

                        const unsigned char* data = ASN1_STRING_get0_data(static_cast<ASN1_STRING*>(value));

                        switch (general_name->type)
                        {
                            case GEN_DNS:
                            {
                                if (!strcmp(reinterpret_cast<const char*>(data), SERVER_DOMAIN))
                                    dns_invalid = false;

                                break;
                            }
                            case GEN_IPADD:
                            {
                                uint32_t numeric_ip = *reinterpret_cast<const uint32_t*>(data);

                                if (numeric_local_ip == numeric_ip)
                                    ip_invalid = false;
                            }
                        }
                    }

                    if (dns_invalid || ip_invalid)
                        std::cout << "Certificate outdated! Please regenerate it via command.\n";
                }
            }
        }

        EVP_PKEY_free(key);

        std::cout << "Enter \"help\" to get an overview of all commands.\n";

        return true;
    }

    void serviceRoutine()
    {
        const std::string certificate = std::string(internal_base_directory).append("certificate.pem");
        const std::string private_key = std::string(internal_base_directory).append("private.pem");

        if (!fs::exists(certificate) || !fs::exists(private_key))
        {
            std::cout << "\rSome internal files missing. Do not mess with them!\n";

            Sleep(1000);
            exit(EXIT_FAILURE);
        }

        using namespace httplib;
        using namespace nlohmann;

        server = new SSLServer(certificate.c_str(), private_key.c_str());

        const char* const terminator = "\n==> ";

        server->Post("/hal/auth/login", [](const Request& req, Response& res)
        {
            res.set_content(R"({"auth_token":"0","refresh_token":"0"})", "application/json");
        });

        server->Post("/hal/user/logout", [](const Request& req, Response& res)
        {
            res.set_content(R"({"message":"Success"})", "application/json");
        });

        server->Get("/hal/user/getProfile", [](const Request& req, Response& res)
        {
            res.set_content(R"({"email":"User@example.com","tier_name":"Spoofed"})", "application/json");
        });

        uint32_t session_counter = 0;

        server->Get("/hal/auth/heartbeat",
            [&session_counter](const Request& req, Response& res)
        {
            using namespace std::chrono;

            std::time_t heartbeat = system_clock::to_time_t(system_clock::now());

            session_counter++;

            if (!last_heartbeat || (heartbeat - last_heartbeat) >= HEARTBEAT_DELAY)
            {
                last_heartbeat = heartbeat;

                active_sessions = session_counter;

                session_counter = 0;
            }

            res.set_content(R"({"message":"Success"})", "application/json");
        });

        const std::string agent_directory = std::string(base_directory).append("agents\\");

        std::function<std::unique_ptr<char[]>(char*&, size_t&)> readModules([agent_directory](char*& data, size_t& size)
        {
            for (const auto& entry : fs::directory_iterator(agent_directory))
            {
                if (entry.is_directory() || entry.path().extension() != ".json")
                    continue;

                std::string file_path = entry.path().string();

                if (!readFile(file_path.c_str(), "", data, size))
                    continue;

                size_t path_length = file_path.size() + 1;

                std::unique_ptr<char[]> path_copy(new char[path_length]);
                memcpy(path_copy.get(), file_path.c_str(), path_length);

                return path_copy;
            }

            return std::unique_ptr<char[]>(nullptr);
        });

        server->Get("/hal/modules/getMyModules", [readModules, terminator](const Request& req, Response& res)
        {
            char* data;
            size_t size;

            if (!readModules(data, size))
            {
                std::cout << "\rERROR: Unable to find any module lists." << terminator;
                return;
            }

            res.set_content(data, size, "application/json");

            free(data);
        });

        std::function<bool(char*, size_t, json&, json*&)> parseModules(
            [terminator](char* data, size_t size, json& module_object, json*& module_list)
        {
            module_object = json::parse(
                data,
                data + size,
                nullptr,
                false,
                true
            );

            if (module_object.is_discarded())
            {
                std::cout << "\rERROR: Unable to parse module lists." << terminator;
                return false;
            }

            auto module_iterator = module_object.find("modules");

            if (!module_object.is_object() || module_iterator == module_object.end() || !module_iterator.value().is_array())
            {
                std::cout << "\rERROR: Invalid module list." << terminator;
                return false;
            }

            module_list = &module_iterator.value();

            return true;
        });

        server->Post("/hal/modules/setMyModules",
             [readModules, parseModules, terminator](const Request& req, Response& res)
        {
            if (locked_modules)
                return;

            std::unique_ptr<char[]> file_name;

            json module_object;
            json* module_list;

            {
                char* data;
                size_t size;

                file_name = readModules(data, size);

                if (!file_name)
                {
                    std::cout << "\rERROR: Unable to find any module lists." << terminator;
                    return;
                }

                bool result = parseModules(data, size, module_object, module_list);

                free(data);

                if (!result)
                    return;
            }

            for (auto& item : *module_list)
            {
                auto state_iterator = item.find("enabled_by_user");

                if(state_iterator == item.end())
                    continue;

                state_iterator.value() = false;
            }

            for (const auto& [key, value] : req.params)
            {
                if (key != "modules")
                    continue;

                for (auto& item : *module_list)
                {
                    auto name_iterator = item.find("name");

                    if(name_iterator == item.end() || name_iterator.value() != value)
                        continue;

                    auto state_iterator = item.find("enabled_by_user");

                    if (state_iterator == item.end())
                        continue;

                    state_iterator.value() = true;
                }
            }

            std::string modules_out = nlohmann::to_string(module_object);

            writeFile(
                file_name.get(),
                "",
                modules_out.c_str(),
                modules_out.size()
            );

            res.set_content(R"({"message":"Success"})", "application/json");
        });

        std::function<bool(json&, bool&)> readAgentKeys(
            [readModules, parseModules, terminator](json& keys, bool& vpgp_active)
        {
            keys = json::array();

            json module_object;
            json* module_list;

            {
                char* data;
                size_t size;

                if (!readModules(data, size))
                {
                    std::cout << "\rERROR: Unable to find any module lists." << terminator;
                    return false;
                }

                bool result = parseModules(data, size, module_object, module_list);

                free(data);

                if (!result)
                    return false;
            }

            vpgp_active = false;

            for (const auto& item : *module_list)
            {
                auto state_iterator = item.find("enabled_by_user");

                if (state_iterator == item.end() || !state_iterator.value())
                    continue;

                auto key_iterator = item.find("agent_key");

                if (key_iterator == item.end())
                    continue;

                std::string key = key_iterator.value();

                if (key == "Vpgp")
                {
                    vpgp_active = true;
                    continue;
                }

                keys.push_back(key);
            }

            return true;
        });

        const std::string main_agent_path = std::string(agent_directory).append("main_agent");
        const std::string vpgp_agent_path = std::string(agent_directory).append("vpgp_agent");

        server->Get("/hal/modules/getAgentHash",
            [main_agent_path, vpgp_agent_path, readAgentKeys, terminator](const Request& req, Response& res)
        {
            if (!fs::exists(main_agent_path))
            {
                std::cout << "\rERROR: Unable to find \"main_agent\"." << terminator;
                return;
            }

            uint8_t main_agent_hash[SHA_DIGEST_LENGTH]{};
            {
                char* data;
                size_t size;

                if (!readFile(main_agent_path.c_str(), "", data, size))
                {
                    std::cout << "\rERROR: Unable to read \"main_agent\"." << terminator;
                    return;
                }

                SHA1(reinterpret_cast<unsigned char*>(data), size, main_agent_hash);

                free(data);
            }

            uint8_t* vpgp_agent_hash = nullptr;
            {
                char* data;
                size_t size;

                if (readFile(vpgp_agent_path.c_str(), "", data, size))
                {
                    vpgp_agent_hash = static_cast<uint8_t*>(alloca(SHA_DIGEST_LENGTH));

                    SHA1(reinterpret_cast<unsigned char*>(data), size, vpgp_agent_hash);

                    free(data);
                }
            }

            json response = json::parse(R"({"agent_hash":"","vpgp_agent_hash":"","agent_keys":[]})");

            response["agent_hash"] = bytesToHex(main_agent_hash, SHA_DIGEST_LENGTH).get();

            json keys;
            bool vpgp_active;

            if (!readAgentKeys(keys, vpgp_active))
                return;

            response["agent_keys"] = keys;

            if (vpgp_active)
            {
                if (vpgp_agent_hash)
                {
                    response["vpgp_agent_hash"] = bytesToHex(vpgp_agent_hash, SHA_DIGEST_LENGTH).get();
                }
                else {
                    std::cout << "\rWARNING: Unable to read \"vpgp_agent\". Skipping!" << terminator;
                }
            }

            res.set_content(nlohmann::to_string(response), "application/json");
        });

        server->Get("/hal/modules/getMyAgent",
            [main_agent_path, vpgp_agent_path, readAgentKeys, terminator](const Request& req, Response& res)
        {
            if (!fs::exists(main_agent_path))
            {
                std::cout << "\rERROR: Unable to find \"main_agent\"." << terminator;
                return;
            }

            json response = json::parse(R"({"content":"","vpgp_content":"","agent_keys":[]})");

            {
                char* data;
                size_t size;

                if (!readFile(main_agent_path.c_str(), "", data, size))
                {
                    std::cout << "\rERROR: Unable to read \"main_agent\"." << terminator;
                    return;
                }

                response["content"] = std::string(data, size);

                free(data);
            }

            json keys;
            bool vpgp_active;

            if (!readAgentKeys(keys, vpgp_active))
                return;

            response["agent_keys"] = keys;

            if (vpgp_active)
            {
                char* data;
                size_t size;

                if (!readFile(vpgp_agent_path.c_str(), "", data, size))
                {
                    std::cout << "\rWARNING: Unable to read \"vpgp_agent\". Skipping!" << terminator;
                }
                else {
                    response["vpgp_content"] = std::string(data, size);
                    free(data);
                }
            }

            res.set_content(nlohmann::to_string(response), "application/json");
        });

        server->set_error_handler([terminator](const Request& req, Response& res)
        {
            std::cout << "\r" << req.method << " | " << req.path << " <- ERROR: Unknown request." << terminator;
        });

        server->listen(local_ip, 443);
    }

    bool readKey(const char* path, EVP_PKEY*& key)
    {
        FILE* file = fopen(path, "r");

        if (!file) return false;

        PEM_read_PrivateKey(file, &key, nullptr, nullptr);

        fclose(file);

        return true;
    }

    void writeKey(const char* path, EVP_PKEY* key)
    {
        FILE* file = fopen(path, "w");

        if (!file) return;

        PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr);

        fclose(file);
    }

    bool generateKey(EVP_PKEY*& key)
    {
        EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

        if (!context)
            return false;

        if (EVP_PKEY_keygen_init(context) <= 0)
            goto cleanup;

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0)
            goto cleanup;

        if (EVP_PKEY_keygen(context, &key) <= 0)
            goto cleanup;

        return true;

        cleanup:
        EVP_PKEY_CTX_free(context);
        return false;
    }

    bool readCertificate(const char* path, X509*& certificate)
    {
        FILE* file = fopen(path, "r");

        if (!file) return false;

        PEM_read_X509(file, &certificate, nullptr, nullptr);

        fclose(file);

        return true;
    }

    void writeCertificate(const char* path, X509* certificate)
    {
        FILE* file = fopen(path, "w");

        if (!file) return;

        PEM_write_X509(file, certificate);

        fclose(file);
    }

    bool generateCertificate(const char* domain, uint32_t numeric_local_ip, EVP_PKEY* key, X509*& certificate)
    {
        certificate = X509_new();

        if (!certificate)
            return false;

        X509_gmtime_adj(X509_get_notBefore(certificate), 0);
        X509_gmtime_adj(X509_get_notAfter(certificate), 31536000L);

        if (!X509_set_pubkey(certificate, key))
           return false;

        X509_NAME* name = X509_get_subject_name(certificate);

        if (!name) return false;

        X509_NAME_add_entry_by_NID(
            name,
            NID_countryName,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("US"),
            -1,
            -1,
            0
        );

        X509_NAME_add_entry_by_NID(
            name,
            NID_commonName,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("Pokemod"),
            -1,
            -1,
            0
        );

        X509_NAME_add_entry_by_NID(
            name,
            NID_organizationName,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("The Pokemod Group"),
            -1,
            -1,
            0
        );

        if (!X509_set_issuer_name(certificate, name))
            return false;

        GENERAL_NAMES* general_names = sk_GENERAL_NAME_new_null();

        {
            ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
            ASN1_STRING_set(ia5, domain, static_cast<int>(strlen(domain)));

            GENERAL_NAME* gn_domain = GENERAL_NAME_new();
            GENERAL_NAME_set0_value(gn_domain, GEN_DNS, ia5);

            sk_GENERAL_NAME_push(general_names, gn_domain);
        }

        {
            ASN1_OCTET_STRING* octet = ASN1_OCTET_STRING_new();
            ASN1_STRING_set(octet, &numeric_local_ip, sizeof(numeric_local_ip));

            GENERAL_NAME* gn_ip = GENERAL_NAME_new();
            GENERAL_NAME_set0_value(gn_ip, GEN_IPADD, octet);

            sk_GENERAL_NAME_push(general_names, gn_ip);
        }

        int result = X509_add1_ext_i2d(
            certificate,
            NID_subject_alt_name,
            general_names,
            0,
            X509V3_ADD_DEFAULT
        );

        sk_GENERAL_NAME_pop_free(general_names, GENERAL_NAME_free);

        if (result != 1) return false;

        BASIC_CONSTRAINTS* constraints = BASIC_CONSTRAINTS_new();
        constraints->ca = true;
        constraints->pathlen = nullptr;

        X509_EXTENSION* extension = X509V3_EXT_i2d(NID_basic_constraints, 0, constraints);
        X509_add_ext(certificate, extension, -1);

        X509_EXTENSION_free(extension);
        BASIC_CONSTRAINTS_free(constraints);

        return X509_sign(certificate, key, EVP_sha256());
    }

    bool readFile(const char* directory, const char* file_name, char*& data, size_t& size)
    {
        std::string path = std::string(directory);
        path.append(file_name);

        std::ifstream file(path, std::ios::binary);

        if(!file.is_open())
            return false;

        size_t file_size = fs::file_size(path);
        char* file_data = static_cast<char*>(malloc(file_size));

        if (!file_data)
        {
            file.close();
            return false;
        }

        file.read(file_data, static_cast<std::streamsize>(file_size));

        data = file_data;
        size = file_size;

        file.close();

        return true;
    }

    void writeFile(const char* directory, const char* file_name, const char* data, size_t size)
    {
        std::ofstream file;

        file.open(std::string(directory).append(file_name), std::ios_base::binary);
        file.write(data, static_cast<std::streamsize>(size));
        file.close();
    }

    std::unique_ptr<char[]> bytesToHex(const uint8_t* data, size_t size)
    {
        const char* const characters = "0123456789abcdef";

        std::unique_ptr<char[]> hex(new char[size * 2 + 1]);

        for (size_t i = 0; i < size; i++)
        {
            uint8_t entry = data[i];

            size_t hex_index = i * 2;

            hex[hex_index] = characters[entry >> 4];
            hex[hex_index + 1] = characters[entry & 0x0F];
        }

        hex[size * 2] = '\0';

        return hex;
    }
}
