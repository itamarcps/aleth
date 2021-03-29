// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2015-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

/// @file
/// CLI module for key management.
#pragma once

#include <libdevcore/CommonIO.h>
#include <libdevcore/FileSystem.h>
#include <libdevcore/SHA3.h>
#include <libethcore/KeyManager.h>
#include <libethcore/TransactionBase.h>
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iosfwd>
#include <thread>
#include <boost/thread.hpp>
#include <mutex>
#include <atomic>
#include <boost/lexical_cast.hpp>
#include <json_spirit/JsonSpiritHeaders.h>
using namespace std;
using namespace dev;
using namespace dev::eth;
using namespace boost::algorithm;

boost::filesystem::path m_walletPath;
boost::filesystem::path m_secretsPath;


class BadArgument: public Exception {};
unique_ptr<SecretStore> m_secretStore;
unique_ptr<KeyManager> m_keyManager;

std::atomic_bool stop_thread(false);
std::atomic_bool target_changed(false);
std::atomic_bool work_changed(false);
std::atomic_bool work_submitted(false);

int64_t hashes_timer = 1000000;

json_spirit::mValue objectItem(
  const json_spirit::mValue element, const std::string name
) {
  return element.get_obj().at(name);
}

json_spirit::mValue arrayItem(
  const json_spirit::mValue element, size_t index
) {
  return element.get_array().at(index);
}

template <typename ElemT>
struct HexTo {
  ElemT value;
  operator ElemT() const { return value; }
  friend std::istream& operator>>(std::istream& in, HexTo& out) {
    in >> std::hex >> out.value;
    return in;
  }
};

class safeWork {
    public:
        void get(std::string& setMe) {
            safeWork_lock.lock();
            setMe = safeWork_;
            safeWork_lock.unlock();
        }

        void set(const std::string setThis) {
            safeWork_lock.lock();
            safeWork_ = setThis;
            safeWork_lock.unlock();
        }
    private:
        std::string safeWork_ = "";
        std::mutex safeWork_lock;
};

class MiningStatus {
	public:
		std::mutex statusLock;
		int CoresRunning = 0;
		std::string AverageHash = "0.0";
		u256 solutionsFound = 0;
};

class safeTarget {
    public:
        void get(u256& setMe) {
            safeTarget_lock.lock();
            setMe = safeTarget_;
            safeTarget_lock.unlock();
        }

        void set(const u256 setThis) {
            safeTarget_lock.lock();
            safeTarget_ = setThis;
            safeTarget_lock.unlock();
        }
    private:
        u256 safeTarget_ = 0;
        std::mutex safeTarget_lock;
};

// Select the appropriate address stored in the KeyManager from user input string.

Address userToAddress(std::string const& _s, KeyManager myWallet)
{
	if (h128 u = fromUUID(_s))
		return myWallet.address(u);
	DEV_IGNORE_EXCEPTIONS(return toAddress(_s));
	for (Address const& a: myWallet.accounts())
		if (myWallet.accountName(a) == _s)
			return a;
	return Address();
}

// Loads the SecretStore
// SecretStore (as far I understood) is an place inside the KeyManager variable that contains all secrets for the addresses contained on the KeyManager variable.

SecretStore& secretStore(KeyManager myWallet)
{
	return myWallet.store();
}

// Loads the secret key for an designed address from the KeyManager wallet variable.

Secret getSecret(std::string const& _signKey, KeyManager myWallet)
{
	string json = contentsString(_signKey);
	if (!json.empty())
		return Secret(secretStore(myWallet).secret(secretStore(myWallet).readKeyContent(json), [&](){ return getPassword("Enter passphrase for key: "); }));
	else
	{
		if (h128 u = fromUUID(_signKey))
			return Secret(secretStore(myWallet).secret(u, [&](){ return getPassword("Enter passphrase for key: "); }));
		Address a;
		try
		{
			a = toAddress(_signKey);
		}
		catch (...)
		{
			for (Address const& aa: myWallet.accounts())
				if (myWallet.accountName(aa) == _signKey)
				{
					a = aa;
					break;
				}
		}
		if (a)
			return myWallet.secret(a, [&](){ return getPassword("Enter passphrase for key (hint:" + myWallet.passwordHint(a) + "): "); });
		cerr << "Bad file, UUID or address: " << _signKey << endl;
		exit(-1);
	}
}

string createPassword(std::string const& _prompt)
{
	string ret;
	while (true)
	{
		ret = getPassword(_prompt);
		string confirm = getPassword("Please confirm the passphrase by entering it again: ");
		if (ret == confirm)
			break;
		cout << "Passwords were different. Try again." << endl;
	}
	return ret;
//	cout << "Enter a hint to help you remember this passphrase: " << flush;
//	cin >> hint;
//	return make_pair(ret, hint);
}

// Simple create an key from an random string of characters. look at FixedHash.h for more info.

KeyPair makeKey()
{
	KeyPair k(Secret::random());
	k = KeyPair(Secret(sha3(k.secret().ref())));

	return k;
}

// We use etherscan API to do everything related to transactions and balances, the function below is an simple boost::asio http GET function.

std::string httpGetRequest(std::string httpquery) {
	std::string server_answer;
	using boost::asio::ip::tcp;
	using namespace std;
    try
    {
        boost::asio::io_service io_service;
        string ipAddress = "api-ropsten.etherscan.io"; //"localhost" for loop back or ip address otherwise, i.e.- www.boost.org;       
        string portNum = "80"; //"8000" for instance;
        string hostAddress;
        if (portNum.compare("80") != 0) // add the ":" only if the port number is not 80 (proprietary port number).
        {
             hostAddress = ipAddress + ":" + portNum;
        }
        else 
        { 
            hostAddress = ipAddress;
        }
        //string wordToQuery = "aha";
        //string queryStr = argv[3]; //"/api/v1/similar?word=" + wordToQuery;

        // Get a list of endpoints corresponding to the server name.
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(ipAddress, portNum);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        // Try each endpoint until we successfully establish a connection.
        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);

        // Form the request. We specify the "Connection: close" header so that the
        // server will close the socket after transmitting the response. This will
        // allow us to treat all data up until the EOF as the content.
        boost::asio::streambuf request;
        std::ostream request_stream(&request);
        request_stream << "GET " << httpquery << " HTTP/1.1\r\n";  // note that you can change it if you wish to HTTP/1.0
        request_stream << "Host: " << hostAddress << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";

        // Send the request.
        boost::asio::write(socket, request);

        // Read the response status line. The response streambuf will automatically
        // grow to accommodate the entire line. The growth may be limited by passing
        // a maximum size to the streambuf constructor.
        boost::asio::streambuf response;
        boost::asio::read_until(socket, response, "\r\n");

        // Check that response is OK.
        std::istream response_stream(&response);
        std::string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        std::string status_message;
        std::getline(response_stream, status_message);
        if (!response_stream || http_version.substr(0, 5) != "HTTP/")
        {
            std::cout << "Invalid response\n";
            return "CANNOT GET BALANCE";
        }
        if (status_code != 200)
        {
            std::cout << "Response returned with status code " << status_code << "\n";
            return "CANNOT GET BALANCE";
        }

        // Read the response headers, which are terminated by a blank line.
        boost::asio::read_until(socket, response, "\r\n\r\n");

        // Process the response headers.
        std::string header;
        while (std::getline(response_stream, header) && header != "\r")
        {}

        // Write whatever content we already have to output.
        if (response.size() > 0)
        {
			std::stringstream answer_buffer;
            answer_buffer << &response;
			server_answer = answer_buffer.str();
        }

        // Read until EOF, writing data to output as we go.
        boost::system::error_code error;
        while (boost::asio::read(socket, response,boost::asio::transfer_at_least(1), error))
        {
              std::cout << &response;
        }

        if (error != boost::asio::error::eof)
        {
              throw boost::system::system_error(error);
        }
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << "\n";
    }
	return server_answer;

}


// My very stupid JSON Parser to select the appropriate value from the Etherscan API.

std::vector<std::string> GetJSONValue(std::string myJson, std::string myValue) {
	std::vector<std::string> jsonInputs;
	std::vector<std::string> resultValue;
	std::string value;
	bool found = false;
	for (std::size_t i = 0; i < myJson.size(); ++i) {
		if (myJson[i] == ',') {
			jsonInputs.push_back(value);
			value = "";
			continue;
		}
		if (myJson[i] == '}') {
			jsonInputs.push_back(value);
			continue;
		}
		if (myJson[i] == '{') {
			continue;
		}
		value += myJson[i];
	}
	for (std::size_t i = 0; i < jsonInputs.size(); ++i) {
		if(jsonInputs[i].find(myValue) != std::string::npos) {
			found = true;
		    resultValue.push_back(jsonInputs[i]);
		}
	}
	
	if (!found) {
		for (std::size_t i = 0; i < jsonInputs.size(); ++i) {
			if(jsonInputs[i].find("message") != std::string::npos) {
				found = true;
			    resultValue.push_back(jsonInputs[i]);
			}
		}
	}
	
	return resultValue;
}

// In BTC, you have 8 decimal digits, but in the code you don't have an decimal point, they are considered an full integer.
// Example 1.0 BTC = 100000000 in the code
// ETH have 18 digits, so to make better for the user to view their balance, we need to convert from this many digits value
// to an more human friendly one.

std::string convertToFixedPointString(std::string amount, size_t digits) {
	std::string result;
	if (amount.size() <= digits) {
		size_t ValueToPoint = digits - amount.size();
		result += "0.";
		for (size_t i = 0; i < ValueToPoint; ++i)
			result += "0";
		result += amount;
	} else {
		result = amount;
		size_t pointToPlace = result.size() - digits;
		result.insert(pointToPlace, ".");
	}

	return result;
}

// Simply get the balance from the Etherscan API

std::string GetETHBalance (std::string myAddress) {
	std::string balance;
	
	std::stringstream query;
	
	query << "/api?module=account&action=balance&address=";
	query << myAddress;
	query << "&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	balance = httpGetRequest(query.str());

	std::vector<std::string> jsonResult = GetJSONValue(balance, "result");
	balance = jsonResult[0];
	
	balance.pop_back();
	balance.erase(0,10);
	
	balance = convertToFixedPointString(balance, 18);

	return balance;
}


// Loads and show to the user the addresses that his wallet contains
// Also asks for the Etherscan API to get the balances from these addresses.

std::string GetProcProcBalance (std::string myAddress) {
	std::string balance;
	
	std::stringstream query;
	
	query << "/api?module=account&action=tokenbalance&contractaddress=0x407DcE91060Ee45dE7b8B7013Ea1f323ec4285FC&address=";
	query << myAddress;
	query << "&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	balance = httpGetRequest(query.str());

	std::vector<std::string> jsonResult = GetJSONValue(balance, "result");
	balance = jsonResult[0];
	
	balance.pop_back();
	balance.erase(0,10);
	
	balance = convertToFixedPointString(balance, 18);

	return balance;
}

// Here is were it starts to become tricky, tokens needs to be loaded differently and from their proper contract address, beside the wallet address.

void ListProcProcAddresses(KeyManager mywallet) {
	
	std::vector<std::string> WalletList;
	std::vector<std::string> AddressList;
	if (mywallet.store().keys().empty())
	{
		cout << "No keys found." << endl;
	} else {
		vector<u128> bare;
			AddressHash got;
			for (auto const& u: mywallet.store().keys())
				if (Address a = mywallet.address(u))
				{
					std::stringstream buffer;
					std::stringstream addressbuffer;
					got.insert(a);
					buffer << toUUID(u) << " " << a.abridged();
					buffer << " " << "0x" << a << " ";
					addressbuffer << "0x" << a;
					buffer << " " << mywallet.accountName(a);
					WalletList.push_back(buffer.str());
					AddressList.push_back(addressbuffer.str());
				}
				else
					bare.push_back(u);
			for (auto const& u: bare)
				cout << toUUID(u) << " (Bare)" << endl;
	}
	
	for (std::size_t i = 0; i < AddressList.size(); ++i) {
		WalletList[i] += GetProcProcBalance(AddressList[i]);
		WalletList[i] += "\n";
	}
	
	for (auto a : WalletList)
		std::cout << a;
	std::cout << std::endl;

	return;
}


// Create an new Account (Address) on the user wallet, and encrypts it


void CreateNewAccount(KeyManager myWallet, std::string m_name) {

	std::string m_lock;
	std::string m_lockHint;
	m_lock = createPassword("Enter a passphrase with which to secure this account");
	auto k = makeKey();
	bool usesMaster = m_lock.empty();
	h128 u = usesMaster ? myWallet.import(k.secret(), m_name) : myWallet.import(k.secret(), m_name, m_lock, m_lockHint);
	cout << "Created key " << toUUID(u) << endl;
	cout << "  Name: " << m_name << endl;
	if (usesMaster)
		cout << "  Uses master passphrase." << endl;
	else
		cout << "  Password hint: " << m_lockHint << endl;
	cout << "  Address: " << k.address().hex() << endl;
	

}

void ListETHAddresses(KeyManager mywallet) {
	
	std::vector<std::string> WalletList;
	std::vector<std::string> AddressList;
	if (mywallet.store().keys().empty())
	{
		cout << "No account found. Creating an new Miner wallet." << std::endl;
		CreateNewAccount(mywallet, "Miner");
	} else {
		vector<u128> bare;
			AddressHash got;
			for (auto const& u: mywallet.store().keys())
				if (Address a = mywallet.address(u))
				{
					std::stringstream buffer;
					std::stringstream addressbuffer;
					got.insert(a);
					buffer << toUUID(u) << " " << a.abridged();
					buffer << " " << "0x" << a << " ";
					addressbuffer << "0x" << a;
					buffer << " " << mywallet.accountName(a);
					WalletList.push_back(buffer.str());
					AddressList.push_back(addressbuffer.str());
				}
				else
					bare.push_back(u);
			for (auto const& u: bare)
				cout << toUUID(u) << " (Bare)" << endl;
	}
	
	for (std::size_t i = 0; i < AddressList.size(); ++i) {
		WalletList[i] += GetETHBalance(AddressList[i]);
		WalletList[i] += "\n";
	}
	
	for (auto a : WalletList)
		std::cout << a;
	std::cout << std::endl;

	return;
}

KeyManager CreateNewWallet(bool default_wallet) {
	boost::filesystem::path m_walletPath = KeyManager::defaultPath();
        boost::filesystem::path m_secretsPath = SecretStore::defaultPath();
	dev::eth::KeyManager wallet(m_walletPath, m_secretsPath);
	// default_wallet is an bool variable to create more safety and select what should show to the user appropriately 
	if (!default_wallet) {
		std::cout << "No default wallet found!\n Would you like to create an new wallet or load an existing one?\n1 - Create new wallet in default location \n2 - Load an existing one in different location\n3 - Create new wallet in different location" << std::endl;
	} else {
		std::cout << "Please inform what you are looking to do with your wallet\n2 - Load an existing one in different location\n3 - Create new wallet in different location" << std::endl;
	}
	std::string user_answer;
	std::getline(std::cin, user_answer);
	std::string m_masterPassword;
	if (user_answer == "1" && !default_wallet) {
		
		
		if (m_masterPassword.empty())
			m_masterPassword = createPassword("Please enter a MASTER passphrase to protect your key store (make it strong!): ");
		try
		{
			wallet.create(m_masterPassword);
		}
		catch (Exception const& _e)
		{
			cerr << "unable to create wallet" << endl << boost::diagnostic_information(_e);
		}

	} else if (user_answer == "2") {
		std::cout << "Please inform the full path for your wallet" << std::endl;
		std::string wallet_path;
		std::getline(std::cin, wallet_path);
		std::cout << "Please infor the full path for your wallet secrets" << std::endl;
		std::string wallet_secret_path;
		std::getline(std::cin, wallet_secret_path);
		
		m_walletPath = wallet_path;
		m_secretsPath = wallet_secret_path;
		KeyManager new_wallet(m_walletPath, m_secretsPath);
		wallet = new_wallet;
		
	} else if (user_answer == "3") {
		std::cout << "Please inform the full path for your wallet" << std::endl;
		std::string wallet_path;
		std::getline(std::cin, wallet_path);
		std::cout << "Please infor the full path for your wallet secrets" << std::endl;
		std::string wallet_secret_path;
		std::getline(std::cin, wallet_secret_path);
		
		m_walletPath = wallet_path;
		m_secretsPath = wallet_secret_path;
		KeyManager new_wallet(m_walletPath, m_secretsPath);
		wallet = new_wallet;
		
		if (m_masterPassword.empty())
		m_masterPassword = createPassword("Please enter a MASTER passphrase to protect your key store (make it strong!): ");
		try
		{
			wallet.create(m_masterPassword);
		}
		catch (Exception const& _e)
		{
			cerr << "unable to create wallet" << endl << boost::diagnostic_information(_e);
		}
		
	}
	return wallet;
}

// Function that hashes the Phrase from the user to create an new address based on this phrase
// It is easier to hash since hashing creates the 256 bits variable that the private key will use.

void CreateFromPassphrase(std::string my_passphrase) {
	std::string shahash = dev::sha3(my_passphrase, false);
	
	for (auto i = 0; i < 1048577; ++i)
		shahash = dev::sha3(shahash, false);
	
	KeyPair k(Secret::fromString(shahash));
	k = KeyPair(Secret(sha3(k.secret().ref())));
	
	std::cout << "Wallet generated..." << "Address: " << k.address().hex() << std::endl;
	
	std::cout << "Hashed: " << shahash << "Size: " << shahash.size() << std::endl;
	return;	
}

void EraseAccount (KeyManager myWallet) {
	
	std::string address;
	std::cout << "Please inform which address you are looking to delete" << std::endl;

	std::getline(std::cin, address);
	
	if (Address a = userToAddress(address, myWallet)) {
		myWallet.kill(a);
		std::cout << "Key " << address << " Deleted" << std::endl;
	} else {
 		std::cout << "Couldn't kill " << address << "; not found." << endl;
	}

	return;
}

// As talked previously, you also need to convert the Fixed Point value that the user provided back to the 18 digits value that the code will use to create an proper transaction.


std::string FixedPointToWei(std::string amountStr, int digits) {
	
	double amount = 0;
	std::stringstream ssi;
	ssi.precision(digits);
	ssi << std::fixed << amountStr;
	ssi >> amount;
	
	std::stringstream ss;
	ss.precision(digits);
	ss << std::fixed << amount;

	std::string valuestr = ss.str();

	valuestr.erase(std::remove(valuestr.begin(), valuestr.end(), '.'), valuestr.end());
	while (valuestr[0] == '0') {
		valuestr.erase(0,1);
	}

	return valuestr;
}

// Send the ETH Transaction using Etherscan API

std::string SendETHTransaction(std::string txidHex) {
	
	std::stringstream txidquery;
	
	txidquery << "/api?module=proxy&action=eth_sendRawTransaction&hex=";
	txidquery << txidHex;
	txidquery << "&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";

	std::string txid = httpGetRequest(txidquery.str());

	std::vector<std::string> txidJsonResult = GetJSONValue(txid, "result");
	std::string transactionLink = "https://ropsten.etherscan.io/tx/";
	std::string tmptxid = txidJsonResult[0];
	tmptxid.pop_back();
	tmptxid.erase(0,10);
	transactionLink += tmptxid;
	
	return transactionLink;
}
	
void SignETHTransaction(KeyManager myWallet) {
	std::string password;
	std::string m_signKey;
	std::string destwallet;
	std::string txgas;
	std::string txgasprice;
	std::string txvalue;
	TransactionSkeleton m_toSign;

	std::cout << "Please provide from which wallet you will be sending, provide the wallet address!" << std::endl;
	std::getline(std::cin, m_signKey);
	
	std::cout << "Please provide the destination wallet address" << std::endl;
	std::getline(std::cin, destwallet);
	
	std::cout << "Do you want to set your own fee or use an automatic fee?\n1 - Automatic\n2 - Set my own" << std::endl;
	std::string userinput;
	std::getline(std::cin, userinput);
	if (userinput == "2") {
			// TODO
	} else {
		txgas = "70000";
		txgasprice = "2500000000";
	}
	
	std::cout << "Please provide how much ETH you are looking to send." << std::endl;
	std::getline(std::cin, txvalue);
	
	
	txvalue = FixedPointToWei(txvalue, 18);
	int TxNonce;
	std::stringstream query;
	
	query << "/api?module=proxy&action=eth_getTransactionCount&address=";
	query << m_signKey;
	query << "&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	std::string nonceRequest = httpGetRequest(query.str());

	std::vector<std::string> jsonResult = GetJSONValue(nonceRequest, "result");
	jsonResult[0].pop_back();
	jsonResult[0].erase(0,10);

	std::stringstream nonceStrm;
	nonceStrm << std::hex << jsonResult[0];
	
	nonceStrm >> TxNonce;

	if (TxNonce == 0)
		++TxNonce;
	
	m_toSign.nonce = TxNonce;
	m_toSign.creation = false;
	m_toSign.to = toAddress(destwallet);
	m_toSign.gas = u256(txgas);
	m_toSign.gasPrice = u256(txgasprice);
	m_toSign.value = u256(txvalue);
	
	Secret s = getSecret(m_signKey, myWallet);
	
	std::stringstream txHexBuffer;
	std::cout << "Signing transaction" << std::endl;
	try
	{
		TransactionBase t = TransactionBase(m_toSign);
		t.setNonce(TxNonce);
		t.sign(s);
		txHexBuffer << toHex(t.rlp());
	}
	catch (Exception& ex)
	{
		cerr << "Invalid transaction: " << ex.what() << endl;
	}
	
	std::string transactionHex = txHexBuffer.str();
	

	std::cout << "Transaction signed, broadcasting" << std::endl;
	
	std::string transactionLink = SendETHTransaction(transactionHex);
	
	while (transactionLink.find("Transaction nonce is too low")  != std::string::npos || transactionLink.find("Transaction with the same hash was already imported")  != std::string::npos || transactionLink.find("There is another transaction with same nonce") != std::string::npos) {
		std::cout << "Transaction nonce is too low. trying again with higher..." << std::endl;
		txHexBuffer.str(std::string());
		std::cout << "TxNonce: " << TxNonce << std::endl;
		++TxNonce;
		m_toSign.nonce = TxNonce;
		try
		{
			TransactionBase t = TransactionBase(m_toSign);
			t.setNonce(TxNonce);
			t.sign(s);
			txHexBuffer << toHex(t.rlp());
		}
		catch (Exception& ex)
		{
			cerr << "Invalid transaction: " << ex.what() << endl;
		}
		std::string transactionHex = txHexBuffer.str();
		std::string transactionLink = SendETHTransaction(transactionHex);
	}
	
	
	std::cout << "Transaction signed! Link: " << transactionLink << std::endl;
	
	return;
}

// TO send tokens you need to build an transaction data.

 std::string BuildTXData(std::string txvalue, std::string destwallet) {
	std::string txdata;
	// Hex and padding that will call the "send" function of the address
	std::string sendpadding = "a9059cbb000000000000000000000000";
	// Padding for the value variable of the "send" function
	std::string valuepadding = "0000000000000000000000000000000000000000000000000000000000000000";

	txdata += sendpadding;
	
	if(destwallet[0] == '0' && destwallet[1] == 'x')
		destwallet.erase(0,2);
	
	txdata += destwallet;
	 
	// Convert to HEX
	
	u256 intValue;
	std::stringstream ss;
	ss << txvalue;
	ss >> intValue;
	std::stringstream ssi;
	ssi << std::hex << intValue;
	std::string amountStrHex = ssi.str();

	for (auto& c : amountStrHex)
		if(std::isupper(c))
			c = std::tolower(c);

	for (size_t i = (amountStrHex.size() - 1), x = (valuepadding.size() - 1), counter = 0; counter < amountStrHex.size(); --i, --x, ++counter)
		valuepadding[x] = amountStrHex[i];

	txdata += valuepadding;
	 
	return txdata;

}
void SignWorkTransaction(Secret &s, std::string m_signKey, std::string solution) {
	std::string password;
	std::string contractwallet = "407DcE91060Ee45dE7b8B7013Ea1f323ec4285FC";
	std::string txgas;
	std::string txgasprice;
	std::string txvalue;
	TransactionSkeleton m_toSign;
	
	txgas = "75000";
	txgasprice = "20000000000";
	
	int TxNonce;
	std::stringstream query;
	
	query << "/api?module=proxy&action=eth_getTransactionCount&address=0x";
	query << m_signKey;
	query << "&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	std::string nonceRequest = httpGetRequest(query.str());

	std::vector<std::string> jsonResult = GetJSONValue(nonceRequest, "result");
	jsonResult[0].pop_back();
	jsonResult[0].erase(0,10);

	std::stringstream nonceStrm;
	nonceStrm << std::hex << jsonResult[0];
	
	nonceStrm >> TxNonce;
	
	m_toSign.nonce = TxNonce;
	m_toSign.creation = false;
	m_toSign.to = toAddress(contractwallet);
	m_toSign.data = fromHex("0xc4c11523" + solution);
	m_toSign.gas = u256(txgas);
	m_toSign.gasPrice = u256(txgasprice);
	m_toSign.value = u256(0);
	
	std::stringstream txHexBuffer;
	std::cout << "Signing transaction" << std::endl;
	try
	{
		TransactionBase t = TransactionBase(m_toSign);
		t.setNonce(TxNonce);
		t.sign(s);
		txHexBuffer << toHex(t.rlp());
	}
	catch (Exception& ex)
	{
		cerr << "Invalid transaction: " << ex.what() << endl;
	}
	
	std::string transactionHex = txHexBuffer.str();
	
	std::string transactionLink = SendETHTransaction(transactionHex);
	
	while (transactionLink.find("Transaction nonce is too low")  != std::string::npos || transactionLink.find("Transaction with the same hash was already imported")  != std::string::npos || transactionLink.find("There is another transaction with same nonce") != std::string::npos) {
		txHexBuffer.str(std::string());
		++TxNonce;
		m_toSign.nonce = TxNonce;
		try
		{
			TransactionBase t = TransactionBase(m_toSign);
			t.setNonce(TxNonce);
			t.sign(s);
			txHexBuffer << toHex(t.rlp());
		}
		catch (Exception& ex)
		{
			cerr << "Invalid transaction: " << ex.what() << endl;
		}
		std::string transactionHex = txHexBuffer.str();
		std::string transactionLink = SendETHTransaction(transactionHex);
	}
	
	
	std::cout << "Transaction signed! Link: " << transactionLink << std::endl;
	
	return;
}


void SignProcProcTransaction(KeyManager myWallet) {
	std::string password;
	std::string m_signKey;
	std::string destwallet;
	std::string contractwallet = "407DcE91060Ee45dE7b8B7013Ea1f323ec4285FC";
	std::string txgas;
	std::string txgasprice;
	std::string txvalue;
	TransactionSkeleton m_toSign;
	std::cout << "Please provide from which wallet you will be sending, provide the wallet address!" << std::endl;
	std::getline(std::cin, m_signKey);
	
	std::cout << "Please provide the destination wallet address" << std::endl;
	std::getline(std::cin, destwallet);
	
	std::cout << "Do you want to set your own fee or use an automatic fee?\n1 - Automatic\n2 - Set my own" << std::endl;
	std::string userinput;
	std::getline(std::cin, userinput);
	if (userinput == "2") {
			// TODO
	} else {
		txgas = "70000";
		txgasprice = "2500000000";
	}
	
	std::cout << "Please provide how much ProcProc you are looking to send. remember max 4 digits!" << std::endl;
	std::getline(std::cin, txvalue);
	
	
	txvalue = FixedPointToWei(txvalue, 18);
	int TxNonce;
	std::stringstream query;
	
	query << "/api?module=proxy&action=eth_getTransactionCount&address=";
	query << m_signKey;
	query << "&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	std::string nonceRequest = httpGetRequest(query.str());

	std::vector<std::string> jsonResult = GetJSONValue(nonceRequest, "result");
	jsonResult[0].pop_back();
	jsonResult[0].erase(0,10);

	std::stringstream nonceStrm;
	nonceStrm << std::hex << jsonResult[0];
	
	nonceStrm >> TxNonce;

	if (TxNonce == 0)
		++TxNonce;
	
	m_toSign.nonce = TxNonce;
	m_toSign.creation = false;
	m_toSign.to = toAddress(contractwallet);
	m_toSign.data = fromHex(BuildTXData(txvalue, destwallet));
	m_toSign.gas = u256(txgas);
	m_toSign.gasPrice = u256(txgasprice);
	m_toSign.value = u256(0);
	
	Secret s = getSecret(m_signKey, myWallet);
	
	std::stringstream txHexBuffer;
	try
	{
		TransactionBase t = TransactionBase(m_toSign);
		t.setNonce(TxNonce);
		t.sign(s);
		txHexBuffer << toHex(t.rlp());
	}
	catch (Exception& ex)
	{
		cerr << "Invalid transaction: " << ex.what() << endl;
	}
	
	std::string transactionHex = txHexBuffer.str();

	
	std::string transactionLink = SendETHTransaction(transactionHex);
	
	while (transactionLink.find("Transaction nonce is too low")  != std::string::npos || transactionLink.find("Transaction with the same hash was already imported")  != std::string::npos || transactionLink.find("There is another transaction with same nonce") != std::string::npos) {
		std::cout << "Transaction nonce is too low. trying again with higher..." << std::endl;
		txHexBuffer.str(std::string());
		std::cout << "TxNonce: " << TxNonce << std::endl;
		++TxNonce;
		m_toSign.nonce = TxNonce;
		try
		{
			TransactionBase t = TransactionBase(m_toSign);
			t.setNonce(TxNonce);
			t.sign(s);
			txHexBuffer << toHex(t.rlp());
		}
		catch (Exception& ex)
		{
			cerr << "Invalid transaction: " << ex.what() << endl;
		}
		std::string transactionHex = txHexBuffer.str();
		std::string transactionLink = SendETHTransaction(transactionHex);
	}
	
	return;
}

KeyManager LoadWallet() {
	std::string m_masterPassword;
	boost::filesystem::path m_walletPath = KeyManager::defaultPath();
	boost::filesystem::path m_secretsPath = SecretStore::defaultPath();

	dev::eth::KeyManager wallet(m_walletPath, m_secretsPath);
	
	// Checks if an default wallet already exists, and call CreateNewWallet appropriately.
	if(!boost::filesystem::exists(m_walletPath)) {
		wallet = CreateNewWallet(false);
	} else {
		std::cout << "Default wallet found, do you still want to load or create an different wallet?\n1 - No\n2 - Yes" << std::endl;
		std::string user_answer;
		std::getline(std::cin, user_answer);
		if (user_answer == "2") {
			wallet = CreateNewWallet(true);
		}
	}
	return wallet;
}

std::string GetMinerAddress(KeyManager mywallet) {
	for (auto const& u: mywallet.store().keys()) {
		AddressHash got;
		if (Address a = mywallet.address(u)) {
			got.insert(a);
			std::cout << a << std::endl;
			return boost::lexical_cast<std::string>(a);
		}
	}
	return "";
}

std::string getnNonceHex(u256 nNonce) {
	std::string nNonceHex = "0000000000000000000000000000000000000000000000000000000000000000";
	std::string tmpnNonceHex;
	std::stringstream ss;
	ss << std::hex << nNonce;
	tmpnNonceHex = ss.str();
	
	for (auto &c : tmpnNonceHex) {
		if (std::isupper(c)) {
			c = std::tolower(c);
		}
	}
	
	for (size_t i = (tmpnNonceHex.size() - 1), x = (nNonceHex.size() -1), counter = 0; counter < tmpnNonceHex.size(); --i, --x, ++counter) {
		nNonceHex[x] = tmpnNonceHex[i];
	}
	
	return nNonceHex;
}

double diffclock(std::clock_t clock1,std::clock_t clock2)
{
    int64_t diffticks=clock1-clock2;
    double diffms=(diffticks)/(CLOCKS_PER_SEC/1000);
    return diffms;
}

void miner(safeTarget &currentTarget, safeWork &currentWork, MiningStatus &currentStatus, Secret s, std::string minerAddress, int threadID) {
	std::cout << "Starting Miner: " << threadID << std::endl;
	
	u256 nNonce = 0;
	u256 solution;
	int64_t hashes = 0;
	u256 myTarget;
	std::string myWork;
	currentTarget.get(myTarget);
	currentWork.get(myWork);
	
	int64_t time_start = std::clock();

	while(!stop_thread) {
		if (work_submitted) {
			while (!work_changed || !target_changed) { // After submitting an new work, the target should also change accordingly.
				boost::this_thread::sleep_for(boost::chrono::milliseconds(250));
			}
			currentTarget.get(myTarget);
			currentWork.get(myWork);
			work_changed = false;
			work_submitted = false;
			target_changed = false;


		} else if (target_changed) { // Work can only change when the user submit an job, work are address specific so only target can change without miner input.
			while (!target_changed)
				boost::this_thread::sleep_for(boost::chrono::milliseconds(250));

			currentTarget.get(myTarget);
			currentWork.get(myWork);
			work_changed = false;
			work_submitted = false;
			target_changed = false;

		}
		std::string job = myWork + minerAddress + getnNonceHex(nNonce);

		std::string solutionHex = toHex(dev::sha3(job, true));

		std::stringstream ss;
		ss << std::hex << solutionHex;
		ss >> solution;
		
		if (hashes % hashes_timer == 0) {
			currentStatus.statusLock.lock();
			currentStatus.AverageHash = boost::lexical_cast<std::string>((hashes / (diffclock(std::clock(), time_start) / 1000)));
			currentStatus.statusLock.unlock();
			hashes = 0;
			time_start = std::clock();
		}
		

		if ((solution < myTarget) && !work_submitted) {
			SignWorkTransaction(s, minerAddress, getnNonceHex(nNonce));
			work_submitted = true;
			currentStatus.statusLock.lock();
			++currentStatus.solutionsFound;
			currentStatus.statusLock.unlock();
		}
		++hashes;
		++nNonce;
	}
	
	return;
}

void getCurrentWork(safeWork &currentWork, std::string minerAddress) {
	
	std::string apiWork;
	std::stringstream query;
	
	query << "/api?module=proxy&action=eth_call&to=0x407DcE91060Ee45dE7b8B7013Ea1f323ec4285FC&data=0x83a0a6e1000000000000000000000000";
	query << minerAddress;
	query << "&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	apiWork = httpGetRequest(query.str());
	
	json_spirit::mValue jsonResult;
	json_spirit::read_string(apiWork, jsonResult);
	std::string finalWork = objectItem(jsonResult, "result").get_str();
	
	if (finalWork[0] == '0' && finalWork[1] == 'x')
		finalWork.erase(0,2);
	
	std::string savedWork;
	currentWork.get(savedWork);
	
	if (savedWork != finalWork) {
		work_changed = true;
	}
	
	currentWork.set(finalWork);

	return;
}

void getCurrentTarget(safeTarget &currentTarget) {
	
	std::string apiWork;
	std::stringstream query;
	
	query << "/api?module=proxy&action=eth_call&to=0x407DcE91060Ee45dE7b8B7013Ea1f323ec4285FC&data=0xb5c0418f&tag=latest&apikey=6342MIVP4CD1ZFDN3HEZZG4QB66NGFZ6RZ";
	
	apiWork = httpGetRequest(query.str());
	
	json_spirit::mValue jsonResult;
    json_spirit::read_string(apiWork, jsonResult);
    std::string finalTarget = objectItem(jsonResult, "result").get_str();
	
	u256 savedTarget;
	currentTarget.get(savedTarget);
	u256 uTarget = boost::lexical_cast<HexTo<u256>>(finalTarget);
	
	if (savedTarget != uTarget) {
		target_changed = true;
	}
	currentTarget.set(uTarget);

	return;
}

void targetThread(safeTarget &currentTarget) {
	while(!stop_thread) {
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
		getCurrentTarget(boost::ref(currentTarget));
	}
	return;
}

void workThread(safeWork &currentWork, std::string minerAddress) {
	while(!stop_thread) {
		boost::this_thread::sleep_for(boost::chrono::seconds(1));
		getCurrentWork(boost::ref(currentWork), minerAddress);
	}
}


void StartMining(KeyManager myWallet, MiningStatus &currentStatus) {
	stop_thread = false;
	static safeTarget currentTarget;
	static safeWork currentWork;
	std::string minerAddress = GetMinerAddress(myWallet);
	if (minerAddress == "")
		return;

	std::cout << "Please inform the password of your miner account..." << std::endl;
	Secret s = getSecret(minerAddress, myWallet);

	getCurrentTarget(currentTarget);
	getCurrentWork(currentWork, minerAddress);
	
	target_changed = false;
	work_changed = false;

	boost::thread minerThread(miner, boost::ref(currentTarget), boost::ref(currentWork), boost::ref(currentStatus), s, minerAddress, 1);

	minerThread.detach();
	currentStatus.CoresRunning = 1;
	
	boost::thread workThreadStart(workThread, boost::ref(currentWork), minerAddress);
	boost::thread targetThreadStart(targetThread, boost::ref(currentTarget));
	workThreadStart.detach();
	targetThreadStart.detach();

	
	return;
}
