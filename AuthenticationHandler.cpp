#define CURL_STATICLIB
#include <curl\curl.h>
#include "AuthenticationHandler.h"
#include <iostream>
#include <string>
#include <cjson/cJSON.h>
#include "AuthSettings.h"


size_t write_data(void* buffer, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)buffer, size * nmemb);
    return size * nmemb;
}

int AuthenticationHandler::Login(std::string username, std::string password) {
    try
    {
        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl)
        {
            std::string url = "https://authify.biz/api/uni_handler.php?type=login";
            std::string data = "&username=" + username + "&password=" + password + "&program_key=" + AuthSettings::program_key + "&api_key=" + AuthSettings::api_key;

            curl_easy_setopt(curl, CURLOPT_URL, url.append(data).c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla Authify");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, AuthSettings::pub_key);
            res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
                curl_easy_cleanup(curl);
                return false;
            }

        }
        curl_easy_cleanup(curl);
        cJSON* root = cJSON_Parse(readBuffer.c_str());
        cJSON* response = cJSON_GetObjectItem(root, "response");
        if (response->valuestring)
        {
            std::string responseString = response->valuestring;
            responseString.erase(std::remove(responseString.begin(), responseString.end(), '"'), responseString.end());
            if (responseString == "logged_in")
            {
                cJSON_Delete(root);
                return 1;
            }
            else if (responseString == "no_sub")
            {
                cJSON_Delete(root);
                return 2;
            }
        }
        cJSON_Delete(root);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Request failed, error: " << e.what() << '\n';
    }
}

bool AuthenticationHandler::Register(std::string username, std::string password, std::string email, std::string token) {
    try
    {
        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl)
        {
            std::string url = "https://authify.biz/api/uni_handler.php?type=register";
            std::string data = "&username=" + username + "&password=" + password + "&email=" + email + "&token=" + token + "&program_key=" + AuthSettings::program_key + "&api_key=" + AuthSettings::api_key;
            curl_easy_setopt(curl, CURLOPT_URL, url.append(data).c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla Authify");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, AuthSettings::pub_key);
            res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
                curl_easy_cleanup(curl);
                return false;
            }
            curl_easy_cleanup(curl);
        }
        curl_easy_cleanup(curl);
        cJSON* root = cJSON_Parse(readBuffer.c_str());
        cJSON* response = cJSON_GetObjectItem(root, "response");
        if (response->valuestring)
        {
            std::string responseString = response->valuestring;
            responseString.erase(std::remove(responseString.begin(), responseString.end(), '"'), responseString.end());
            if (responseString == "success")
            {
                cJSON_Delete(root);
                return true;
            }
        }
        cJSON_Delete(root);
        return false;

    }
    catch (const std::exception& e)
    {
        std::cerr << "Request failed, error: " << e.what() << '\n';
    }
}