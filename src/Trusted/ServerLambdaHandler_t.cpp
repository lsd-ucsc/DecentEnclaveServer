// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <memory>
#include <string>

#include <sgx_error.h>
#include <DecentEnclave/Common/CertStore.hpp>
#include <DecentEnclave/Common/Logging.hpp>
#include <DecentEnclave/Trusted/Sgx/ComponentConnection.hpp>
#include <SimpleJson/SimpleJson.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleObjects/SimpleObjects.hpp>

#include "AppRequestHandler.hpp"

extern "C" sgx_status_t ecall_decent_server_lambda_handler(
	void* sock_ptr
)
{
	using namespace DecentEnclave::Common;
	using namespace DecentEnclave::Trusted::Sgx;

	SimpleSysIO::StreamSocketBase* realSockPtr =
		static_cast<SimpleSysIO::StreamSocketBase*>(sock_ptr);

	std::unique_ptr<StreamSocket> sock =
		SimpleObjects::Internal::make_unique<StreamSocket>(realSockPtr);

	try
	{
		auto reqJson = sock->SizedRecvBytes<std::string>();
		auto req = SimpleJson::LoadStr(reqJson);

		std::string method =
			req.AsDict()[SimpleObjects::String("method")].AsString().c_str();

		if (method == "req_app_cert")
		{
			DecentEnclaveServer::HandleAppCertRequest(std::move(sock));
		}
		else if (method == "get_svr_cert")
		{
			const auto& params =
				req.AsDict()[SimpleObjects::String("params")].AsList();
			if (params.size() != 1)
			{
				throw std::runtime_error("Invalid number of parameters.");
			}
			std::string keyName = params[0].AsString().c_str();

			SimpleObjects::String certPem =
				CertStore::GetInstance()[keyName].GetCertBase()->GetPem();

			SimpleObjects::Dict resp;
			resp[SimpleObjects::String("result")] = certPem;
			sock->SizedSendBytes(SimpleJson::DumpStr(resp));
		}
	}
	catch(const std::exception& e)
	{
		static auto logger =
			LoggerFactory::GetLogger("DecentServerLambdaHandler");

		logger.Error(
			std::string("Decent Server Failed to handle App's request: ") +
			e.what()
		);
	}


	return SGX_SUCCESS;
}
