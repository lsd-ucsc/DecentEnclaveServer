// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <DecentEnclave/Common/AuthList.hpp>
#include <DecentEnclave/Common/AesGcmPackager.hpp>
#include <DecentEnclave/Common/Platform/Print.hpp>
#include <DecentEnclave/Common/Sgx/MbedTlsInit.hpp>
#include <DecentEnclave/Untrusted/Sgx/IasRequesterImpl.hpp>
#include <DecentEnclave/Untrusted/Config/AuthList.hpp>
#include <DecentEnclave/Untrusted/Config/EndpointsMgr.hpp>
#include <DecentEnclave/Untrusted/Hosting/BoostAsioService.hpp>
#include <DecentEnclave/Untrusted/Hosting/LambdaFuncServer.hpp>

#include <SimpleConcurrency/Threading/ThreadPool.hpp>
#include <SimpleJson/SimpleJson.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleObjects/SimpleObjects.hpp>
#include <SimpleSysIO/SysCall/Files.hpp>

#include "DecentServer.hpp"


using namespace DecentEnclave;
using namespace DecentEnclave::Untrusted;
using namespace DecentEnclaveServer;
using namespace SimpleObjects;
using namespace SimpleConcurrency::Threading;


namespace DecentEnclaveServer
{
	volatile std::atomic_int g_sigVal(0);

	inline const char* GetSignalName(int sig)
	{
		switch (sig)
		{
		case SIGINT:
			return "SIGINT";
		case SIGTERM:
			return "SIGTERM";
		default:
			return "Unknown";
		}
	}
} // namespace DecentEnclaveServer


extern "C" void SignalHandler(int sig)
{
	Common::Platform::Print::StrInfo(
		std::string("Signal received: ") +
		DecentEnclaveServer::GetSignalName(sig)
	);

	DecentEnclaveServer::g_sigVal = sig;
}


int main(int argc, char* argv[]) {
	std::string configPath;
	if (argc == 1)
	{
		configPath = "../../src/components_config.json";
	}
	else if (argc == 2)
	{
		configPath = argv[1];
	}
	else
	{
		Common::Platform::Print::StrErr("Unexpected number of arguments.");
		Common::Platform::Print::StrErr(
			"Only the path to the components configuration file is needed."
		);
		return -1;
	}

	// Init MbedTLS
	Common::Sgx::MbedTlsInit::Init();

	// Read in components config
	auto configFile = SimpleSysIO::SysCall::RBinaryFile::Open(configPath);
	auto configJson = configFile->ReadBytes<std::string>();
	auto config = SimpleJson::LoadStr(configJson);
	std::vector<uint8_t> authListAdvRlp = Config::ConfigToAuthListAdvRlp(config);

	// SPID and IAS Requester with IAS subscription key
	const auto& iasConfig = config.AsDict()[String("IAS")].AsDict();
	std::string iasUrl = iasConfig[String("Url")].AsString().c_str();
	std::string spidHex = iasConfig[String("SPID")].AsString().c_str();
	std::string subKey = iasConfig[String("SubscriptionKey")].AsString().c_str();
	sgx_spid_t spid = Sgx::IasRequesterImpl::ParseSpid(spidHex);

	std::unique_ptr<Sgx::IasRequesterImpl> iasReq =
		Internal::make_unique<Sgx::IasRequesterImpl>(iasUrl, subKey);

	// Create thread pool
	std::shared_ptr<ThreadPool> threadPool =
		std::make_shared<ThreadPool>(3);

	// BoostAsioService
	std::shared_ptr<boost::asio::io_service> ioService =
			std::make_shared<boost::asio::io_service>();
	std::unique_ptr<Hosting::BoostAsioService> asioService =
		Internal::make_unique<Hosting::BoostAsioService>(ioService);
	threadPool->AddTask(std::move(asioService));

	// EndpointsMgr
	auto endpointMgr = Config::EndpointsMgr::GetInstancePtr(&config, ioService);

	// API call server
	Hosting::LambdaFuncServer lambdaFuncSvr(
		endpointMgr,
		threadPool
	);

	// DecentServer
	const auto& imgConfig = config.AsDict()[String("EnclaveImage")].AsDict();
	std::string imgPath = imgConfig[String("ImagePath")].AsString().c_str();
	std::string tokenPath = imgConfig[String("TokenPath")].AsString().c_str();
	std::shared_ptr<DecentServer> enclave = std::make_shared<DecentServer>(
		spid,
		std::move(iasReq),
		authListAdvRlp,
		imgPath,
		tokenPath
	);


	// Setup Lambda call handlers and start to run multi-threaded-ly
	lambdaFuncSvr.AddFunction("DecentServer", enclave);

	// preparing going into update loop
	std::signal(SIGINT, SignalHandler);
	std::signal(SIGTERM, SignalHandler);


	// update loop
	while (g_sigVal == 0)
	{
		threadPool->Update();
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}


	threadPool->Terminate();

	return 0;
}
