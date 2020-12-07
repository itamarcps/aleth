#include "KeyAux.h"

#include <iostream>
#include <string>
#include <vector>
#include <libethcore/KeyManager.h>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/options_description.hpp>
#include <libdevcore/LoggingProgramOptions.h>


// The structure of this program is very simple, when running it we will check if an default wallet already exists, if nots we will ask the user to create an new one
// If it does, we ask the user if he wants to load their default wallet or create/load from an different place
// After loading, we will store his wallet in an dev::eth:KeyManager variable, we use this variable to call different functions for the wallet, as looking up an address, or signing an transaction
// The variable is used on the "else if" block below, that selects which action the user will try to do.
// Check KeyAux.h for more information on what does what.
// Notice: some features may not exist or be buggy, take caution

int main () {

	std::cout << "Hello! Welcome to the TAEX CLI wallet" << std::endl;
	
	// Setup logging options to default so we don't have thousands of debug strings when using this program
	dev::LoggingOptions loggingOptions;
	dev::setupLogging(loggingOptions);
	
	std::cout << "Loading wallet..." << std::endl;
	dev::eth::KeyManager wallet = LoadWallet();
	std::cout << "Wallet loaded." << std::endl;

	while (true) {
		std::cout << "What you are looking to do today?\n" <<
			"1 - List accounts and ETH balances\n" <<
			"2 - List accounts and TAEX balances\n" <<
			"3 - Send an ETH Transaction\n" << 
			"4 - Send an TAEX Transaction\n" <<
			"5 - Create an new account\n" <<
			"6 - Erase account\n" <<
			"7 - Create private key from Word/Phrase" << std::endl;
		// Cin.clear and fflush to clean input, remove these and you will see some stupid bugs that happens
		cin.clear();
		fflush(stdin);
		int userinput;
		std::cin >> userinput;
		if (userinput == 1) {
			ListETHAddresses(wallet);
		} else if (userinput == 2) {
			ListTAEXAddresses(wallet);
		} else if (userinput == 3) {
			SignETHTransaction(wallet);
		} else if (userinput == 4) {
			SignTAEXTransaction(wallet);
		} else if (userinput == 5) {
			std::string m_name;
			std::cout << "Please inform an account name" << std::endl;
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			std::getline(std::cin, m_name);
			CreateNewAccount(wallet, m_name);
			std::cout << "Reloading account..." << std::endl;
			wallet = LoadWallet();
		} else if (userinput == 6) {
			EraseAccount(wallet);
			std::cout << "Reloading account..." << std::endl;
			wallet = LoadWallet();
		} else if (userinput == 7) {
			std::string my_passphrase;
			std::cout << "Please input the passphrase for the wallet" << std::endl;
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			std::getline(std::cin, my_passphrase);
			CreateFromPassphrase(my_passphrase);
		} else if (userinput == 8) {
			break;
		} else {
			std::cout << "Wrong input, please check again" << std::endl;
		}


	}
	
	
	


	return 0;
}