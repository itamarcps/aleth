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

	std::cout << "Hello! Welcome to the ProcProc CLI wallet" << std::endl;
	
	// Setup logging options to default so we don't have thousands of debug strings when using this program
	dev::LoggingOptions loggingOptions;
	dev::setupLogging(loggingOptions);
	
	std::cout << "Loading wallet..." << std::endl;
	dev::eth::KeyManager wallet = LoadWallet();
	std::cout << "Wallet loaded." << std::endl;

	std::vector<boost::thread> MiningThreads;
	MiningStatus currentStatus;
	ListETHAddresses(wallet);
	wallet = LoadWallet();
	while (true) {
		std::cout << "What you are looking to do today?\n" <<
			"1 - List accounts and ETH balances\n" <<
			"2 - List accounts and ProcProc balances\n" <<
			"3 - Send an ETH Transaction\n" << 
			"4 - Send an ProcProc Transaction\n" <<
			"5 - Start Mining\n" <<
			"6 - Stop Mining\n" <<
			"7 - Print mining Status\n" <<
			"8 - Exit Wallet\n";

		std::string userinput;
		std::getline(std::cin, userinput);
		if (userinput == "1") {
			ListETHAddresses(wallet);
		} else if (userinput == "2") {
			ListProcProcAddresses(wallet);
		} else if (userinput == "3") {
			SignETHTransaction(wallet);
		} else if (userinput == "4") {
			SignProcProcTransaction(wallet);
		} else if (userinput == "5") {
			StartMining(wallet, currentStatus);
		} else if (userinput == "6") {
			stop_thread = true;
			std::cout << "Mining Stopped... please wait few second before trying to mine again!" << std::endl;
		} else if (userinput == "7") {
			currentStatus.statusLock.lock();
			std::cout << "Cores running: " << currentStatus.CoresRunning << std::endl;
			std::cout << "Average Hashrate: " << boost::lexical_cast<double>(currentStatus.AverageHash) * currentStatus.CoresRunning << " H/s" << std::endl;
			std::cout << "Solutions Found: " << currentStatus.solutionsFound << std::endl;
			currentStatus.statusLock.unlock();
		} else if (userinput == "8") {
			break;
		} else {
			std::cout << "Wrong input, please check again" << std::endl;
		}


	}
	
	
	


	return 0;
}