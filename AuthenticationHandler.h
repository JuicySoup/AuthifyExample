#pragma once
#include <string>

class AuthenticationHandler
{
public:
	int Login(std::string username, std::string password);
	bool Register(std::string username, std::string password, std::string email, std::string token);
};

