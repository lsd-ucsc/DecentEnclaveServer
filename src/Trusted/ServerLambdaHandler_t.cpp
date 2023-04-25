// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <memory>

#include <sgx_error.h>
#include <DecentEnclave/Common/Platform/Print.hpp>
#include <DecentEnclave/Trusted/Sgx/ComponentConnection.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>

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
		DecentEnclaveServer::HandleAppCertRequest(std::move(sock));
	}
	catch(const std::exception& e)
	{
		Platform::Print::StrErr(
			std::string("Decent Server Failed to handle App's certificate request: ") +
			e.what()
		);
	}


	return SGX_SUCCESS;
}
